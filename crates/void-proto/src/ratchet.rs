//! The hybrid post-quantum Double Ratchet (FR-MSG-01).
//!
//! This is the Signal Double Ratchet with the asymmetric step performed by
//! **both** an X25519 Diffie-Hellman and an ML-KEM-1024 encapsulation, whose
//! outputs are combined in the root-key KDF. Every ratchet step therefore
//! injects entropy that a classical attacker cannot compute and entropy that a
//! quantum attacker cannot compute.
//!
//! ## Properties and where they come from
//!
//! - **Forward secrecy** — the symmetric chain step (`kdf::chain_step`) is
//!   one-way and the previous chain key is overwritten. Compromising the device
//!   at time T does not decrypt messages from before T, provided the skipped-key
//!   store has been pruned.
//! - **Post-compromise security** — each asymmetric step mixes a fresh DH and a
//!   fresh KEM secret into the root key. An attacker who stole the full state
//!   is locked out again after one round trip in which they do not interfere.
//! - **Harvest-now-decrypt-later resistance** — the KEM half means a recorded
//!   transcript is not decryptable by a future quantum computer, which is G1.
//!
//! The Diffie-Hellman half of the step runs on every direction change, as in
//! the original construction. The ML-KEM half runs every
//! [`KEM_RATCHET_INTERVAL`] steps, for the bandwidth reason set out on that
//! constant. Read that comment before changing it: the interval is not a
//! tuning knob, it is a documented security/bandwidth trade.
//!
//! ## Cost, stated plainly
//!
//! A header carrying an ML-KEM step holds an encapsulation key (1,568 B) and a
//! ciphertext (1,568 B) on top of the X25519 public key (32 B) — about 3.2 KB,
//! which at a 1,024-byte record size (FR-MSG-02) fragments into four records.
//! A header without one is 56 bytes, so an ordinary message fits in a single
//! record, which is what NFR-PERF-06 asks for.
//! `docs/PROTOCOL.md#ratchet-cost` has the full accounting.
//!
//! ## Denial-of-service bounds
//!
//! `MAX_SKIP` caps how many message keys a single header may force us to
//! derive, and `MAX_SKIPPED_STORED` caps the total retained. Without both, a
//! peer who claims message number 2^32 makes the receiver burn CPU and memory
//! on demand. Exceeding either is an error, not a silent truncation.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use void_crypto::{aead, kdf, mlkem, x25519, Zeroize};

use crate::wire::{concat_labeled, Reader, Writer};
use crate::{ProtoError, Result};

/// Maximum message keys derivable from one received header.
pub const MAX_SKIP: u32 = 1000;
/// Maximum skipped message keys retained across all chains.
pub const MAX_SKIPPED_STORED: usize = 2000;

/// How many Diffie-Hellman ratchet steps happen between ML-KEM ratchet steps.
///
/// ## Why this is not 1
///
/// A KEM step must carry a 1,568-byte encapsulation key and a 1,568-byte
/// ciphertext, and — this is the part that is easy to miss — it must repeat
/// them in **every** header of that sending chain. Otherwise, losing the first
/// message of a chain leaves the peer unable to perform the matching step and
/// the session is dead. That repetition is what makes a KEM step on every DH
/// step unaffordable: a 50-message unidirectional burst would carry 3.2 KB of
/// KEM material fifty times, which at four records per message is 200 records
/// where 50 would do, and NFR-PERF-03's 50 MB/month budget does not survive it.
///
/// So the KEM ratchet runs on a schedule. With an interval of 4, a rapid
/// back-and-forth conversation averages about 1.75 records per message instead
/// of 4, and post-compromise security against a quantum adversary is restored
/// within four ratchet steps of an intrusion rather than one.
///
/// This is the same structural choice Apple's PQ3 and Signal's SPQR make, and
/// for the same reason. What is **not** on a schedule is the initial handshake,
/// which is fully hybrid on the first message — so G1 (harvest-now,
/// decrypt-later against recorded traffic) holds unconditionally from the
/// first byte. The schedule only affects how quickly PQ post-compromise
/// security recovers after a device compromise. `docs/DECISIONS.md#d-005`.
pub const KEM_RATCHET_INTERVAL: u32 = 4;

/// How many previous ML-KEM decapsulation keys to retain.
///
/// A peer's in-flight chain may have encapsulated to the key we held before our
/// last step. Retaining one previous generation covers reordering across a
/// single step; retaining more would widen the window in which a stolen device
/// can decrypt old traffic, which is the opposite of what the ratchet is for.
pub const KEM_RETAINED_GENERATIONS: usize = 1;

/// Version tag for [`Ratchet::serialize`]'s wire format. Bumped whenever the
/// layout changes, so a store holding an old-format blob fails loudly on
/// restore instead of misparsing it.
pub const RATCHET_STATE_VERSION: u8 = 1;

/// A ratchet message header. Authenticated as AEAD associated data, so it
/// cannot be altered without breaking the tag.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header {
    /// Sender's current ratchet X25519 public key.
    pub dh_public: [u8; 32],
    /// Epoch of the sender's ML-KEM key advertised below. Zero, with empty key
    /// material, when this chain performs no KEM step.
    pub kem_epoch: u32,
    /// Which epoch of *our* ML-KEM key the sender encapsulated to.
    pub kem_target_epoch: u32,
    /// Sender's new ML-KEM encapsulation key. Empty when no KEM step.
    pub kem_encaps_key: Vec<u8>,
    /// ML-KEM ciphertext to our key at `kem_target_epoch`. Empty when no KEM
    /// step.
    pub kem_ciphertext: Vec<u8>,
    /// Number of messages in the previous sending chain.
    pub previous_chain_len: u32,
    /// Message number within the current chain.
    pub message_number: u32,
}

impl Header {
    /// Does this header carry an ML-KEM ratchet step?
    #[must_use]
    pub fn has_kem_step(&self) -> bool {
        !self.kem_encaps_key.is_empty()
    }

    /// Canonical encoding, used verbatim as AEAD associated data.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(
            32 + 8 + 4 + self.kem_encaps_key.len() + 4 + self.kem_ciphertext.len() + 8,
        );
        w.raw(&self.dh_public)
            .u32(self.kem_epoch)
            .u32(self.kem_target_epoch)
            .bytes16(&self.kem_encaps_key)
            .bytes16(&self.kem_ciphertext)
            .u32(self.previous_chain_len)
            .u32(self.message_number);
        w.finish()
    }

    /// Decode and validate lengths.
    ///
    /// The two KEM fields must be either both absent or both present at their
    /// exact standard sizes. A header with one but not the other is malformed;
    /// accepting it would let a peer force a step with material we cannot use.
    pub fn decode(bytes: &[u8]) -> Result<Header> {
        let mut r = Reader::new(bytes);
        let dh = r.array::<32>()?;
        let kem_epoch = r.u32()?;
        let kem_target_epoch = r.u32()?;
        let ek = r.bytes16()?.to_vec();
        let ct = r.bytes16()?.to_vec();
        let pn = r.u32()?;
        let n = r.u32()?;
        r.finish()?;
        match (ek.is_empty(), ct.is_empty()) {
            (true, true) => {}
            (false, false) => {
                if ek.len() != mlkem::ENCAPS_KEY_LEN || ct.len() != mlkem::CIPHERTEXT_LEN {
                    return Err(ProtoError::Malformed);
                }
            }
            _ => return Err(ProtoError::Malformed),
        }
        Ok(Header {
            dh_public: dh,
            kem_epoch,
            kem_target_epoch,
            kem_encaps_key: ek,
            kem_ciphertext: ct,
            previous_chain_len: pn,
            message_number: n,
        })
    }
}

/// An encrypted ratchet message: header plus AEAD ciphertext.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
    /// The header.
    pub header: Header,
    /// AEAD ciphertext with tag appended.
    pub ciphertext: Vec<u8>,
}

impl Message {
    /// Canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let h = self.header.encode();
        let mut w = Writer::with_capacity(h.len() + self.ciphertext.len() + 8);
        w.bytes32(&h).bytes32(&self.ciphertext);
        w.finish()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Message> {
        let mut r = Reader::new(bytes);
        let h = r.bytes32_max(16 * 1024)?;
        let ct = r.bytes32_max(4 * 1024 * 1024)?.to_vec();
        r.finish()?;
        Ok(Message {
            header: Header::decode(h)?,
            ciphertext: ct,
        })
    }
}

/// Key identifying a skipped message: (ratchet public key, message number).
type SkippedKey = ([u8; 32], u32);

/// Our own ML-KEM key at a given epoch.
struct KemSelf {
    epoch: u32,
    encaps: Vec<u8>,
    decaps: Vec<u8>,
}

impl Drop for KemSelf {
    fn drop(&mut self) {
        self.decaps.zeroize();
    }
}

/// Everything a receive would change, held aside until the message's AEAD tag
/// verifies.
///
/// ## Why the receive path is staged and the send path is not
///
/// Anyone can put bytes into our queue. Deposits are deliberately
/// unauthenticated so that senders stay anonymous to the relay
/// (`crate::queue`), which means the relay can hand back a record it kept from
/// weeks ago, and anyone who copied one off the wire can hand back a mangled
/// version of it. Both arrive here as a `Message` whose header is structurally
/// valid and cryptographically meaningless.
///
/// A header alone can therefore ask us to do three destructive things: consume
/// a stored skipped key, derive up to [`MAX_SKIP`] more, and — the expensive
/// one — perform an asymmetric ratchet step that overwrites the root key. Do
/// any of them before the tag verifies and a replayed record from a chain we
/// have already left ratchets us onto a root key the peer will never reach.
/// The session is then dead, permanently, at a cost to the attacker of
/// resending one blob it cannot even read.
///
/// So the receive path computes into this struct, which owns copies and
/// zeroizes them on drop, and touches `Ratchet` only in
/// [`Ratchet::commit`] — reached only after [`Ratchet::try_open`] returns.
/// Sending needs none of this: nothing an attacker controls reaches it.
struct Staged {
    /// The key this message must open under.
    message_key: [u8; 32],
    /// A stored skipped key this message claims. Removed on commit — and only
    /// on commit, or one forged byte would delete the key its genuine message
    /// still needs.
    consume_skipped: Option<SkippedKey>,
    /// Keys derived for the messages this one arrived ahead of.
    derive_skipped: Vec<(SkippedKey, [u8; 32])>,
    /// Set when the header opens a chain we have not seen.
    step: Option<StagedStep>,
    /// The receiving chain and counter this message leaves behind. Copies of
    /// the current values when nothing moves them.
    chain_recv: Option<[u8; 32]>,
    n_recv: u32,
}

impl Drop for Staged {
    fn drop(&mut self) {
        self.message_key.zeroize();
        for (_, k) in self.derive_skipped.iter_mut() {
            k.zeroize();
        }
        if let Some(ref mut c) = self.chain_recv {
            c.zeroize();
        }
    }
}

/// The asymmetric step a staged receive would take.
struct StagedStep {
    root_key: [u8; 32],
    chain_recv: [u8; 32],
    dh_remote: [u8; 32],
    /// The sender's new ML-KEM key and its epoch, when the step carried one.
    kem_remote: Option<(Vec<u8>, u32)>,
}

impl Drop for StagedStep {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.chain_recv.zeroize();
    }
}

/// The material a sending chain repeats in every header until the chain ends.
#[derive(Clone)]
struct PendingKem {
    epoch: u32,
    target_epoch: u32,
    encaps: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// One end of a ratchet session.
pub struct Ratchet {
    root_key: [u8; 32],

    dh_self: x25519::KeyPair,
    dh_remote: Option<[u8; 32]>,

    kem_self: KemSelf,
    kem_self_prev: Option<KemSelf>,
    kem_remote_encaps: Option<Vec<u8>>,
    kem_remote_epoch: u32,
    kem_pending: Option<PendingKem>,
    dh_steps_since_kem: u32,

    chain_send: Option<[u8; 32]>,
    chain_recv: Option<[u8; 32]>,

    n_send: u32,
    n_recv: u32,
    previous_chain_len: u32,

    skipped: BTreeMap<SkippedKey, [u8; 32]>,

    /// Set when we have received a new remote ratchet key and owe a step on
    /// our next send.
    pending_step: bool,
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut c) = self.chain_send {
            c.zeroize();
        }
        if let Some(ref mut c) = self.chain_recv {
            c.zeroize();
        }
        for (_, v) in self.skipped.iter_mut() {
            v.zeroize();
        }
    }
}

impl Ratchet {
    /// Initialise the **initiator** side after a handshake.
    ///
    /// The initiator has the responder's signed prekey and KEM prekey from the
    /// bundle, so it can send immediately without a round trip. Its first
    /// sending step is forced to include a KEM step, because the responder does
    /// not yet know any ML-KEM key of ours to encapsulate to.
    pub fn init_initiator(
        root_key: [u8; 32],
        remote_dh: [u8; 32],
        remote_kem_encaps: Vec<u8>,
    ) -> Result<Ratchet> {
        let dh_self = x25519::KeyPair::generate().map_err(|_| ProtoError::Crypto)?;
        Ok(Ratchet {
            root_key,
            dh_self,
            dh_remote: Some(remote_dh),
            kem_self: KemSelf {
                epoch: 0,
                encaps: Vec::new(),
                decaps: Vec::new(),
            },
            kem_self_prev: None,
            kem_remote_encaps: Some(remote_kem_encaps),
            kem_remote_epoch: 0,
            kem_pending: None,
            // Force a KEM step on the first send.
            dh_steps_since_kem: KEM_RATCHET_INTERVAL,
            chain_send: None,
            chain_recv: None,
            n_send: 0,
            n_recv: 0,
            previous_chain_len: 0,
            skipped: BTreeMap::new(),
            pending_step: true,
        })
    }

    /// Initialise the **responder** side after a handshake.
    ///
    /// The responder holds the prekey pair the initiator used, so its first
    /// ratchet key is that prekey, and its ML-KEM prekey is already epoch 0 —
    /// the initiator learned it from the bundle.
    #[must_use]
    pub fn init_responder(
        root_key: [u8; 32],
        prekey: x25519::KeyPair,
        kem_prekey_encaps: Vec<u8>,
        kem_prekey_decaps: Vec<u8>,
    ) -> Ratchet {
        Ratchet {
            root_key,
            dh_self: prekey,
            dh_remote: None,
            kem_self: KemSelf {
                epoch: 0,
                encaps: kem_prekey_encaps,
                decaps: kem_prekey_decaps,
            },
            kem_self_prev: None,
            kem_remote_encaps: None,
            kem_remote_epoch: 0,
            kem_pending: None,
            dh_steps_since_kem: 0,
            chain_send: None,
            chain_recv: None,
            n_send: 0,
            n_recv: 0,
            previous_chain_len: 0,
            skipped: BTreeMap::new(),
            pending_step: false,
        }
    }

    /// Perform an asymmetric ratchet step on the sending side.
    fn step_sending(&mut self) -> Result<()> {
        let remote_dh = self.dh_remote.ok_or(ProtoError::NotReady)?;

        self.dh_self = x25519::KeyPair::generate().map_err(|_| ProtoError::Crypto)?;
        let mut dh_secret = self
            .dh_self
            .dh(&remote_dh)
            .map_err(|_| ProtoError::InvalidKey)?;

        let do_kem = self.dh_steps_since_kem + 1 >= KEM_RATCHET_INTERVAL;

        if do_kem {
            let remote_kem = self.kem_remote_encaps.clone().ok_or(ProtoError::NotReady)?;
            let kem = mlkem::keygen().map_err(|_| ProtoError::Crypto)?;
            let (ciphertext, mut kem_secret) =
                mlkem::encaps(&remote_kem).map_err(|_| ProtoError::InvalidKey)?;

            let new_epoch = self.kem_self.epoch + 1;
            let old = core::mem::replace(
                &mut self.kem_self,
                KemSelf {
                    epoch: new_epoch,
                    encaps: kem.encaps_key.clone(),
                    decaps: kem.decaps_key.clone(),
                },
            );
            // Retain exactly one previous generation.
            self.kem_self_prev = if old.encaps.is_empty() {
                None
            } else if KEM_RETAINED_GENERATIONS > 0 {
                Some(old)
            } else {
                None
            };

            self.kem_pending = Some(PendingKem {
                epoch: new_epoch,
                target_epoch: self.kem_remote_epoch,
                encaps: kem.encaps_key.clone(),
                ciphertext,
            });
            self.dh_steps_since_kem = 0;

            let combined = concat_labeled(&[&dh_secret, &kem_secret]);
            let (new_root, chain) = kdf::root_step(&self.root_key, &[&combined]);
            self.root_key.zeroize();
            self.root_key = new_root;
            self.set_send_chain(chain);
            kem_secret.zeroize();
        } else {
            self.dh_steps_since_kem += 1;
            self.kem_pending = None;

            let combined = concat_labeled(&[&dh_secret]);
            let (new_root, chain) = kdf::root_step(&self.root_key, &[&combined]);
            self.root_key.zeroize();
            self.root_key = new_root;
            self.set_send_chain(chain);
        }

        self.previous_chain_len = self.n_send;
        self.n_send = 0;
        self.pending_step = false;
        dh_secret.zeroize();
        Ok(())
    }

    fn set_send_chain(&mut self, chain: [u8; 32]) {
        if let Some(ref mut c) = self.chain_send {
            c.zeroize();
        }
        self.chain_send = Some(chain);
    }

    fn set_recv_chain(&mut self, chain: [u8; 32]) {
        if let Some(ref mut c) = self.chain_recv {
            c.zeroize();
        }
        self.chain_recv = Some(chain);
    }

    /// Compute the asymmetric ratchet step this header asks for, without
    /// taking it. Nothing here writes to `self`; see [`Staged`].
    fn stage_step(&self, header: &Header) -> Result<StagedStep> {
        let mut dh_secret = self
            .dh_self
            .dh(&header.dh_public)
            .map_err(|_| ProtoError::InvalidKey)?;

        let take_kem = header.has_kem_step() && header.kem_epoch > self.kem_remote_epoch;

        let stepped = (|| {
            let mut combined = if take_kem {
                // Pick the decapsulation key the sender actually encapsulated
                // to. If it names a generation we no longer hold, failing here
                // is correct: silently deriving the wrong secret would produce
                // an undecryptable session with a confusing cause.
                let decaps = if header.kem_target_epoch == self.kem_self.epoch {
                    &self.kem_self.decaps
                } else if let Some(prev) = self
                    .kem_self_prev
                    .as_ref()
                    .filter(|p| p.epoch == header.kem_target_epoch)
                {
                    &prev.decaps
                } else {
                    return Err(ProtoError::NotReady);
                };

                let mut kem_secret = mlkem::decaps(decaps, &header.kem_ciphertext)
                    .map_err(|_| ProtoError::InvalidKey)?;
                let combined = concat_labeled(&[&dh_secret, &kem_secret]);
                kem_secret.zeroize();
                combined
            } else {
                concat_labeled(&[&dh_secret])
            };

            let (root_key, chain_recv) = kdf::root_step(&self.root_key, &[&combined]);
            combined.zeroize();

            Ok(StagedStep {
                root_key,
                chain_recv,
                dh_remote: header.dh_public,
                kem_remote: take_kem.then(|| (header.kem_encaps_key.clone(), header.kem_epoch)),
            })
        })();

        dh_secret.zeroize();
        stepped
    }

    /// Encrypt a message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Message> {
        if self.pending_step {
            self.step_sending()?;
        }

        let ck = self.chain_send.ok_or(ProtoError::NotReady)?;
        let (next_ck, mut message_key) = kdf::chain_step(&ck);
        self.set_send_chain(next_ck);

        // The KEM material is repeated in every header of this chain, so that
        // whichever message arrives first lets the peer take the step.
        let (kem_epoch, kem_target_epoch, kem_encaps_key, kem_ciphertext) = match &self.kem_pending
        {
            Some(p) => (
                p.epoch,
                p.target_epoch,
                p.encaps.clone(),
                p.ciphertext.clone(),
            ),
            None => (0, 0, Vec::new(), Vec::new()),
        };

        let header = Header {
            dh_public: self.dh_self.public,
            kem_epoch,
            kem_target_epoch,
            kem_encaps_key,
            kem_ciphertext,
            previous_chain_len: self.previous_chain_len,
            message_number: self.n_send,
        };
        self.n_send += 1;

        let aad = header.encode();
        let nonce = aead::nonce_from_counter(header.message_number as u64);
        let ciphertext = aead::seal(&message_key, &nonce, &aad, plaintext);
        message_key.zeroize();

        Ok(Message { header, ciphertext })
    }

    /// Decrypt a message, handling out-of-order and skipped messages.
    ///
    /// A message that does not authenticate changes nothing: not the root key,
    /// not either chain, not a counter, not one entry of the skipped-key map.
    /// [`Staged`] explains why that has to be true, and
    /// `a_failed_decrypt_leaves_no_trace_in_the_state` holds it to it.
    pub fn decrypt(&mut self, message: &Message) -> Result<Vec<u8>> {
        // `?` here drops the staged work, which zeroizes it. Nothing reaches
        // `commit` that has not opened.
        let mut staged = self.stage(message)?;
        let plaintext = Self::try_open(&mut staged.message_key, message)?;
        self.commit(staged);
        Ok(plaintext)
    }

    /// Work out what decrypting this message would take, deriving keys but
    /// writing nothing. Takes `&self`, which is the invariant stated in the
    /// type system rather than in a comment.
    fn stage(&self, message: &Message) -> Result<Staged> {
        let header = &message.header;

        // 1. A message we already skipped past: its key is waiting for it.
        //    Chain and counter stay exactly where they are.
        let sk: SkippedKey = (header.dh_public, header.message_number);
        if let Some(message_key) = self.skipped.get(&sk) {
            return Ok(Staged {
                message_key: *message_key,
                consume_skipped: Some(sk),
                derive_skipped: Vec::new(),
                step: None,
                chain_recv: self.chain_recv,
                n_recv: self.n_recv,
            });
        }

        let mut staged = Staged {
            message_key: [0u8; 32],
            consume_skipped: None,
            derive_skipped: Vec::new(),
            step: None,
            chain_recv: self.chain_recv,
            n_recv: self.n_recv,
        };

        // 2. A ratchet key we have not seen opens a new chain. Set keys aside
        //    for whatever is still in flight on the old one, then step.
        if self.dh_remote != Some(header.dh_public) {
            if let Some(old_remote) = self.dh_remote {
                self.derive_skips(&mut staged, header.previous_chain_len, old_remote)?;
            }
            let step = self.stage_step(header)?;
            staged.chain_recv = Some(step.chain_recv);
            staged.n_recv = 0;
            staged.step = Some(step);
        }

        // 3. Skip forward within this chain to reach the message itself.
        self.derive_skips(&mut staged, header.message_number, header.dh_public)?;

        let chain = staged.chain_recv.ok_or(ProtoError::NotReady)?;
        let (next_chain, message_key) = kdf::chain_step(&chain);
        staged.chain_recv = Some(next_chain);
        staged.n_recv += 1;
        staged.message_key = message_key;
        Ok(staged)
    }

    /// Apply a staged receive. Called only after the message opened.
    fn commit(&mut self, mut staged: Staged) {
        if let Some(step) = staged.step.take() {
            self.root_key.zeroize();
            self.root_key = step.root_key;
            self.dh_remote = Some(step.dh_remote);
            if let Some((encaps, epoch)) = &step.kem_remote {
                self.kem_remote_encaps = Some(encaps.clone());
                self.kem_remote_epoch = *epoch;
            }
            // We hold a new remote ratchet key, so our next send owes a step.
            self.pending_step = true;
        }
        if let Some(sk) = staged.consume_skipped.take() {
            if let Some(mut used) = self.skipped.remove(&sk) {
                used.zeroize();
            }
        }
        for (sk, key) in core::mem::take(&mut staged.derive_skipped) {
            self.skipped.insert(sk, key);
        }
        if let Some(chain) = staged.chain_recv {
            self.set_recv_chain(chain);
        }
        self.n_recv = staged.n_recv;
    }

    fn try_open(message_key: &mut [u8; 32], message: &Message) -> Result<Vec<u8>> {
        let aad = message.header.encode();
        let nonce = aead::nonce_from_counter(message.header.message_number as u64);
        aead::open(message_key, &nonce, &aad, &message.ciphertext)
            .map_err(|_| ProtoError::DecryptionFailed)
    }

    /// Derive message keys for the messages between where the staged chain sits
    /// and `until`, indexing them under the ratchet key `remote` whose chain
    /// they belong to.
    ///
    /// Both bounds are checked against what is already stored *plus* what this
    /// message has staged so far, so a single header cannot slip past
    /// [`MAX_SKIPPED_STORED`] by splitting its demand across the two calls the
    /// receive path makes.
    fn derive_skips(&self, staged: &mut Staged, until: u32, remote: [u8; 32]) -> Result<()> {
        let Some(mut chain) = staged.chain_recv else {
            return Ok(());
        };
        if until <= staged.n_recv {
            return Ok(());
        }
        let count = until - staged.n_recv;
        if count > MAX_SKIP {
            return Err(ProtoError::TooManySkipped);
        }
        if self.skipped.len() + staged.derive_skipped.len() + count as usize > MAX_SKIPPED_STORED {
            return Err(ProtoError::TooManySkipped);
        }
        for _ in 0..count {
            let (next_chain, message_key) = kdf::chain_step(&chain);
            staged
                .derive_skipped
                .push(((remote, staged.n_recv), message_key));
            chain = next_chain;
            staged.n_recv += 1;
        }
        staged.chain_recv = Some(chain);
        Ok(())
    }

    /// How many skipped message keys are currently retained.
    #[must_use]
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Drop all retained skipped keys.
    ///
    /// Closes the forward-secrecy gap at the cost of permanently losing any
    /// still-in-flight out-of-order messages. Called by the retention sweep
    /// (FR-STOR-04) and by duress destruction.
    pub fn forget_skipped(&mut self) {
        for (_, v) in self.skipped.iter_mut() {
            v.zeroize();
        }
        self.skipped.clear();
    }

    /// Our current ratchet public key, for the session summary UI.
    #[must_use]
    pub fn current_public(&self) -> [u8; 32] {
        self.dh_self.public
    }

    /// The current ML-KEM epoch of our own key. Surfaced so the UI can show
    /// how recently post-quantum post-compromise security was refreshed.
    #[must_use]
    pub fn kem_epoch(&self) -> u32 {
        self.kem_self.epoch
    }

    /// DH steps taken since the last ML-KEM step.
    #[must_use]
    pub fn steps_since_kem_ratchet(&self) -> u32 {
        self.dh_steps_since_kem
    }

    /// Serialize the full ratchet state for persistence (FR-STOR-01).
    ///
    /// Covers everything needed to resume a conversation exactly where it
    /// left off: the root key, both chain keys, the X25519 keypair, both
    /// ML-KEM keypairs (current and the one retained generation), every
    /// epoch and message counter, and the skipped-key map. The skipped map is
    /// the one easy to forget — dropping it on restart would silently reopen
    /// a forward-secrecy gap the ratchet had already closed by consuming
    /// those keys out of the ordinary chain.
    ///
    /// Hand-encoded via `wire`, matching `Header::encode`'s style — see the
    /// reasoning at the top of `wire.rs`. The caller is responsible for
    /// storing the result somewhere already encrypted at rest; this is raw
    /// key material with no encryption of its own.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4096);
        w.u8(RATCHET_STATE_VERSION);
        w.raw(&self.root_key);
        w.raw(&self.dh_self.secret);
        Self::write_optional_key(&mut w, self.dh_remote);

        Self::write_kem_self(&mut w, &self.kem_self);
        w.u8(self.kem_self_prev.is_some() as u8);
        if let Some(prev) = &self.kem_self_prev {
            Self::write_kem_self(&mut w, prev);
        }

        w.u8(self.kem_remote_encaps.is_some() as u8);
        if let Some(ek) = &self.kem_remote_encaps {
            w.bytes16(ek);
        }
        w.u32(self.kem_remote_epoch);

        w.u8(self.kem_pending.is_some() as u8);
        if let Some(p) = &self.kem_pending {
            w.u32(p.epoch)
                .u32(p.target_epoch)
                .bytes16(&p.encaps)
                .bytes16(&p.ciphertext);
        }
        w.u32(self.dh_steps_since_kem);

        Self::write_optional_key(&mut w, self.chain_send);
        Self::write_optional_key(&mut w, self.chain_recv);

        w.u32(self.n_send);
        w.u32(self.n_recv);
        w.u32(self.previous_chain_len);
        w.u8(self.pending_step as u8);

        w.u32(self.skipped.len() as u32);
        for ((pk, n), key) in &self.skipped {
            w.raw(pk).u32(*n).raw(key);
        }

        w.finish()
    }

    /// Restore a ratchet previously written by [`Ratchet::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Ratchet> {
        let mut r = Reader::new(bytes);
        if r.u8()? != RATCHET_STATE_VERSION {
            return Err(ProtoError::Malformed);
        }
        let root_key = r.array::<32>()?;
        let dh_self = x25519::KeyPair::from_secret(r.array::<32>()?);
        let dh_remote = Self::read_optional_key(&mut r)?;

        let kem_self = Self::read_kem_self(&mut r)?;
        let kem_self_prev = if r.u8()? == 1 {
            Some(Self::read_kem_self(&mut r)?)
        } else {
            None
        };

        let kem_remote_encaps = if r.u8()? == 1 {
            Some(r.bytes16()?.to_vec())
        } else {
            None
        };
        let kem_remote_epoch = r.u32()?;

        let kem_pending = if r.u8()? == 1 {
            let epoch = r.u32()?;
            let target_epoch = r.u32()?;
            let encaps = r.bytes16()?.to_vec();
            let ciphertext = r.bytes16()?.to_vec();
            Some(PendingKem {
                epoch,
                target_epoch,
                encaps,
                ciphertext,
            })
        } else {
            None
        };
        let dh_steps_since_kem = r.u32()?;

        let chain_send = Self::read_optional_key(&mut r)?;
        let chain_recv = Self::read_optional_key(&mut r)?;

        let n_send = r.u32()?;
        let n_recv = r.u32()?;
        let previous_chain_len = r.u32()?;
        let pending_step = r.u8()? == 1;

        let skipped_count = r.u32()? as usize;
        // Bound to MAX_SKIPPED_STORED so a corrupted or hostile serialized
        // blob cannot drive an unbounded allocation before we even get to
        // check whether it authenticates.
        if skipped_count > MAX_SKIPPED_STORED {
            return Err(ProtoError::Malformed);
        }
        let mut skipped = BTreeMap::new();
        for _ in 0..skipped_count {
            let pk = r.array::<32>()?;
            let n = r.u32()?;
            let key = r.array::<32>()?;
            skipped.insert((pk, n), key);
        }
        r.finish()?;

        Ok(Ratchet {
            root_key,
            dh_self,
            dh_remote,
            kem_self,
            kem_self_prev,
            kem_remote_encaps,
            kem_remote_epoch,
            kem_pending,
            dh_steps_since_kem,
            chain_send,
            chain_recv,
            n_send,
            n_recv,
            previous_chain_len,
            skipped,
            pending_step,
        })
    }

    fn write_optional_key(w: &mut Writer, key: Option<[u8; 32]>) {
        w.u8(key.is_some() as u8);
        if let Some(k) = key {
            w.raw(&k);
        }
    }

    fn read_optional_key(r: &mut Reader) -> Result<Option<[u8; 32]>> {
        if r.u8()? == 1 {
            Ok(Some(r.array::<32>()?))
        } else {
            Ok(None)
        }
    }

    fn write_kem_self(w: &mut Writer, k: &KemSelf) {
        w.u32(k.epoch).bytes16(&k.encaps).bytes16(&k.decaps);
    }

    fn read_kem_self(r: &mut Reader) -> Result<KemSelf> {
        let epoch = r.u32()?;
        let encaps = r.bytes16()?.to_vec();
        let decaps = r.bytes16()?.to_vec();
        Ok(KemSelf {
            epoch,
            encaps,
            decaps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Ratchet, Ratchet) {
        // Simulate what the handshake hands to each side.
        let root = [7u8; 32];
        let bob_prekey = x25519::KeyPair::from_secret([9u8; 32]);
        let bob_kem = mlkem::keygen_derand(&[11u8; 32], &[12u8; 32]);
        let bob_prekey_public = bob_prekey.public;

        let alice =
            Ratchet::init_initiator(root, bob_prekey_public, bob_kem.encaps_key.clone()).unwrap();
        let bob = Ratchet::init_responder(
            root,
            bob_prekey,
            bob_kem.encaps_key.clone(),
            bob_kem.decaps_key.clone(),
        );
        (alice, bob)
    }

    #[test]
    fn single_message_roundtrip() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"hello").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"hello");
    }

    #[test]
    fn full_duplex_conversation() {
        let (mut a, mut b) = pair();
        for i in 0..20u32 {
            let msg = alloc::format!("a->b {i}");
            let c = a.encrypt(msg.as_bytes()).unwrap();
            assert_eq!(b.decrypt(&c).unwrap(), msg.as_bytes());

            let reply = alloc::format!("b->a {i}");
            let c = b.encrypt(reply.as_bytes()).unwrap();
            assert_eq!(a.decrypt(&c).unwrap(), reply.as_bytes());
        }
    }

    #[test]
    fn ratchet_actually_steps() {
        let (mut a, mut b) = pair();
        let m1 = a.encrypt(b"1").unwrap();
        b.decrypt(&m1).unwrap();
        let r1 = b.encrypt(b"r1").unwrap();
        a.decrypt(&r1).unwrap();
        let m2 = a.encrypt(b"2").unwrap();

        assert_ne!(
            m1.header.dh_public, m2.header.dh_public,
            "a reply must force a new ratchet key"
        );
        // The initiator's first chain always carries KEM material, because the
        // responder does not yet know any ML-KEM key of ours.
        assert!(m1.header.has_kem_step());
        assert_eq!(m1.header.kem_epoch, 1);
        assert_eq!(m1.header.kem_target_epoch, 0, "encapsulated to the prekey");
        // The second step is a plain DH step: no KEM material, one record.
        assert!(!m2.header.has_kem_step());
    }

    #[test]
    fn kem_ratchet_runs_on_schedule() {
        let (mut a, mut b) = pair();
        let mut kem_steps = 0;
        let mut dh_steps = 0;
        // Twelve full round trips: each direction change is a DH step.
        for _ in 0..12 {
            let m = a.encrypt(b"ping").unwrap();
            dh_steps += 1;
            if m.header.has_kem_step() {
                kem_steps += 1;
            }
            b.decrypt(&m).unwrap();

            let r = b.encrypt(b"pong").unwrap();
            dh_steps += 1;
            if r.header.has_kem_step() {
                kem_steps += 1;
            }
            a.decrypt(&r).unwrap();
        }
        // Roughly one KEM step per KEM_RATCHET_INTERVAL DH steps, plus the
        // forced first one.
        let expected = dh_steps / KEM_RATCHET_INTERVAL;
        assert!(
            kem_steps >= expected && kem_steps <= expected + 2,
            "kem steps {kem_steps} for {dh_steps} dh steps"
        );
        assert!(a.kem_epoch() >= 2, "the KEM key must have rotated");
        assert!(b.kem_epoch() >= 1);
    }

    #[test]
    fn a_kem_step_survives_losing_the_first_message_of_its_chain() {
        // The reason KEM material is repeated in every header of a chain: if
        // only the first message carried it, this session would be dead.
        let (mut a, mut b) = pair();
        let first = a.encrypt(b"lost in transit").unwrap();
        let second = a.encrypt(b"arrives").unwrap();
        assert!(first.header.has_kem_step() && second.header.has_kem_step());
        assert_eq!(first.header.kem_epoch, second.header.kem_epoch);

        // Drop `first` entirely.
        assert_eq!(b.decrypt(&second).unwrap(), b"arrives");
        // And the session continues normally afterwards.
        let reply = b.encrypt(b"got it").unwrap();
        assert_eq!(a.decrypt(&reply).unwrap(), b"got it");
    }

    #[test]
    fn steady_state_headers_are_small() {
        // NFR-PERF-06: a typical message must fit in one record. A non-KEM
        // header plus a short body must stay well under RECORD_BODY_CAPACITY.
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"x").unwrap();
        b.decrypt(&m).unwrap();
        let r = b.encrypt(b"y").unwrap();
        a.decrypt(&r).unwrap();
        let steady = a.encrypt(b"see you at the usual place").unwrap();
        assert!(!steady.header.has_kem_step());
        assert!(
            steady.encode().len() < crate::record::RECORD_BODY_CAPACITY,
            "steady-state message is {} bytes",
            steady.encode().len()
        );
    }

    #[test]
    fn out_of_order_within_a_chain() {
        let (mut a, mut b) = pair();
        let msgs: Vec<_> = (0..5).map(|i| a.encrypt(&[i as u8]).unwrap()).collect();
        // Deliver 4, 0, 3, 1, 2.
        for &i in &[4usize, 0, 3, 1, 2] {
            assert_eq!(b.decrypt(&msgs[i]).unwrap(), alloc::vec![i as u8]);
        }
        assert_eq!(b.skipped_count(), 0, "all skipped keys must be consumed");
    }

    #[test]
    fn out_of_order_across_ratchet_steps() {
        let (mut a, mut b) = pair();
        let a1 = a.encrypt(b"a1").unwrap();
        let a2 = a.encrypt(b"a2").unwrap();
        b.decrypt(&a1).unwrap();
        let b1 = b.encrypt(b"b1").unwrap();
        a.decrypt(&b1).unwrap();
        let a3 = a.encrypt(b"a3").unwrap(); // new chain

        // a3 arrives before a2, which belongs to the previous chain.
        assert_eq!(b.decrypt(&a3).unwrap(), b"a3");
        assert_eq!(b.decrypt(&a2).unwrap(), b"a2");
    }

    #[test]
    fn replay_is_rejected() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"once").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"once");
        // The message key is consumed; a replay finds no key and fails.
        assert!(b.decrypt(&m).is_err(), "replayed message must not decrypt");
    }

    #[test]
    fn tampering_is_detected_everywhere() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"authentic").unwrap();

        // Ciphertext.
        let mut bad = m.clone();
        bad.ciphertext[0] ^= 1;
        assert!(b.decrypt(&bad).is_err());

        // Header field bound as AAD.
        let mut bad = m.clone();
        bad.header.previous_chain_len ^= 1;
        assert!(b.decrypt(&bad).is_err());

        let mut bad = m.clone();
        bad.header.message_number = 7;
        assert!(b.decrypt(&bad).is_err());

        // The genuine message must still work: failed attempts must not
        // desynchronise the chain.
        assert_eq!(b.decrypt(&m).unwrap(), b"authentic");
    }

    #[test]
    fn skip_limits_are_enforced() {
        let (mut a, mut b) = pair();
        let _ = a.encrypt(b"x").unwrap();
        let mut m = a.encrypt(b"y").unwrap();
        m.header.message_number = MAX_SKIP + 5;
        assert!(matches!(b.decrypt(&m), Err(ProtoError::TooManySkipped)));
    }

    #[test]
    fn forget_skipped_closes_the_gap() {
        let (mut a, mut b) = pair();
        let msgs: Vec<_> = (0..5).map(|i| a.encrypt(&[i as u8]).unwrap()).collect();
        b.decrypt(&msgs[4]).unwrap();
        assert_eq!(b.skipped_count(), 4);
        b.forget_skipped();
        assert_eq!(b.skipped_count(), 0);
        assert!(b.decrypt(&msgs[0]).is_err(), "forgotten keys must be gone");
    }

    #[test]
    fn header_encoding_roundtrips_and_validates() {
        let (mut a, _b) = pair();
        let m = a.encrypt(b"x").unwrap();
        let enc = m.header.encode();
        assert_eq!(Header::decode(&enc).unwrap(), m.header);

        let msg_enc = m.encode();
        assert_eq!(Message::decode(&msg_enc).unwrap(), m);

        // Wrong-size KEM key must be refused.
        let mut h = m.header.clone();
        h.kem_encaps_key.truncate(10);
        assert!(Header::decode(&h.encode()).is_err());

        // A wrong-size (non-empty) KEM ciphertext must be refused.
        let mut h = m.header.clone();
        h.kem_ciphertext = alloc::vec![0u8; 5];
        assert!(Header::decode(&h.encode()).is_err());
    }

    #[test]
    fn distinct_sessions_do_not_interoperate() {
        let (mut a, _b) = pair();
        let root2 = [8u8; 32];
        let bob_prekey = x25519::KeyPair::from_secret([9u8; 32]);
        let bob_kem = mlkem::keygen_derand(&[11u8; 32], &[12u8; 32]);
        let mut other_b = Ratchet::init_responder(
            root2,
            bob_prekey,
            bob_kem.encaps_key.clone(),
            bob_kem.decaps_key.clone(),
        );
        let m = a.encrypt(b"secret").unwrap();
        assert!(
            other_b.decrypt(&m).is_err(),
            "a different root key must not decrypt"
        );
    }

    #[test]
    fn large_payloads_survive() {
        let (mut a, mut b) = pair();
        let big = alloc::vec![0xABu8; 100_000];
        let m = a.encrypt(&big).unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), big);
    }

    #[test]
    fn serialize_deserialize_is_byte_stable() {
        let (mut a, _b) = pair();
        // Force a KEM step so kem_self_prev, kem_pending, and a send chain
        // are all populated — the empty-session case is the easy one.
        let _ = a.encrypt(b"x").unwrap();
        let bytes1 = a.serialize();
        let restored = Ratchet::deserialize(&bytes1).unwrap();
        let bytes2 = restored.serialize();
        assert_eq!(
            bytes1, bytes2,
            "round trip must be exact, not merely equivalent"
        );
    }

    #[test]
    fn ratchet_state_roundtrips_and_conversation_continues_after_restore() {
        let (mut a, mut b) = pair();
        // Cross several direction changes, so both sides carry a KEM
        // generation, a previous generation, and populated chain keys.
        for i in 0..6u32 {
            let out = alloc::format!("a{i}");
            let m = a.encrypt(out.as_bytes()).unwrap();
            assert_eq!(b.decrypt(&m).unwrap(), out.as_bytes());

            let reply = alloc::format!("b{i}");
            let r = b.encrypt(reply.as_bytes()).unwrap();
            assert_eq!(a.decrypt(&r).unwrap(), reply.as_bytes());
        }

        let a_bytes = a.serialize();
        let b_bytes = b.serialize();
        let mut a2 = Ratchet::deserialize(&a_bytes).unwrap();
        let mut b2 = Ratchet::deserialize(&b_bytes).unwrap();

        assert_eq!(a2.current_public(), a.current_public());
        assert_eq!(a2.kem_epoch(), a.kem_epoch());
        assert_eq!(b2.kem_epoch(), b.kem_epoch());
        assert_eq!(a2.steps_since_kem_ratchet(), a.steps_since_kem_ratchet());

        // The conversation continues from the restored state with no
        // renegotiation, on both sides, across another set of direction
        // changes including further KEM ratchet steps.
        for i in 0..6u32 {
            let out = alloc::format!("post-restore a{i}");
            let m = a2.encrypt(out.as_bytes()).unwrap();
            assert_eq!(b2.decrypt(&m).unwrap(), out.as_bytes());

            let reply = alloc::format!("post-restore b{i}");
            let r = b2.encrypt(reply.as_bytes()).unwrap();
            assert_eq!(a2.decrypt(&r).unwrap(), reply.as_bytes());
        }
    }

    #[test]
    fn a_restored_ratchet_still_rejects_replays_and_keeps_its_skipped_keys() {
        let (mut a, mut b) = pair();
        let msgs: Vec<_> = (0..5).map(|i| a.encrypt(&[i as u8]).unwrap()).collect();

        // Deliver only message 4: this skips deriving keys for 0..=3 and
        // stores them, then consumes message 4's own key.
        assert_eq!(b.decrypt(&msgs[4]).unwrap(), alloc::vec![4u8]);
        assert_eq!(b.skipped_count(), 4);

        let bytes = b.serialize();
        let mut restored = Ratchet::deserialize(&bytes).unwrap();
        assert_eq!(
            restored.skipped_count(),
            4,
            "the skipped-key map must survive a restart"
        );

        // A message that was skipped but never delivered still decrypts —
        // its key really did survive the round trip, not just the count.
        assert_eq!(restored.decrypt(&msgs[2]).unwrap(), alloc::vec![2u8]);
        assert_eq!(restored.skipped_count(), 3);

        // Message 4 was already consumed *before* serialization. Replaying
        // it against the restored ratchet must still fail — if it didn't,
        // forward secrecy would have quietly weakened on every restart.
        assert!(
            restored.decrypt(&msgs[4]).is_err(),
            "a message consumed before serialization must not decrypt again after restore"
        );
    }

    #[test]
    fn a_relay_replaying_an_old_chain_cannot_kill_the_session() {
        // The relay is untrusted and holds every sealed record it ever
        // accepted (§9.1 assumes the machine is seized with its disk). It
        // cannot read them, but it can hand one back a second time, after the
        // ratchet has moved on. That replay carries a stale ratchet public
        // key, which looks exactly like the start of a new chain — so a
        // receiver that steps before it authenticates would ratchet its root
        // key on the attacker's schedule and never decrypt anything again.
        let (mut a, mut b) = pair();

        let a1 = a.encrypt(b"a1").unwrap();
        assert_eq!(b.decrypt(&a1).unwrap(), b"a1");
        let b1 = b.encrypt(b"b1").unwrap();
        a.decrypt(&b1).unwrap();
        // A's next message opens a new chain under a new ratchet key.
        let a2 = a.encrypt(b"a2").unwrap();
        assert_eq!(b.decrypt(&a2).unwrap(), b"a2");

        assert!(
            b.decrypt(&a1).is_err(),
            "a replayed record must not decrypt twice"
        );

        // And the session must be exactly where it was: still B's turn to
        // receive on A's current chain.
        let a3 = a.encrypt(b"a3").unwrap();
        assert_eq!(
            b.decrypt(&a3).unwrap(),
            b"a3",
            "the replay must not have moved the ratchet"
        );
    }

    #[test]
    fn a_forgery_cannot_destroy_a_stored_skipped_key() {
        // Skipped keys are the only way an out-of-order message ever decrypts.
        // Anyone who can see a record on the wire can copy its header onto a
        // corrupted body; if that lookup consumed the key before checking the
        // tag, one forged byte would permanently silence the real message.
        let (mut a, mut b) = pair();
        let msgs: Vec<_> = (0..3).map(|i| a.encrypt(&[i as u8]).unwrap()).collect();

        assert_eq!(b.decrypt(&msgs[2]).unwrap(), alloc::vec![2u8]);
        assert_eq!(b.skipped_count(), 2);

        let mut forged = msgs[0].clone();
        forged.ciphertext[0] ^= 1;
        assert!(b.decrypt(&forged).is_err());
        assert_eq!(
            b.skipped_count(),
            2,
            "a failed open must not consume the stored key"
        );

        assert_eq!(b.decrypt(&msgs[0]).unwrap(), alloc::vec![0u8]);
        assert_eq!(b.decrypt(&msgs[1]).unwrap(), alloc::vec![1u8]);
    }

    #[test]
    fn a_failed_decrypt_leaves_no_trace_in_the_state() {
        // The general form of both attacks above: a message that does not
        // authenticate must change nothing at all. Serialized state is the
        // strictest way to say "nothing" — it covers the root key, both
        // chains, every counter, and the skipped map in one comparison.
        let (mut a, mut b) = pair();
        let a1 = a.encrypt(b"real").unwrap();
        b.decrypt(&a1).unwrap();
        let before = b.serialize();

        let mut junk = a1.clone();
        junk.ciphertext[0] ^= 1;
        assert!(b.decrypt(&junk).is_err());

        let mut far_ahead = a.encrypt(b"never sent").unwrap();
        far_ahead.header.message_number = 400;
        assert!(b.decrypt(&far_ahead).is_err());

        let mut fake_chain = a1.clone();
        fake_chain.header.dh_public = [0x5a; 32];
        assert!(b.decrypt(&fake_chain).is_err());

        assert_eq!(
            b.serialize(),
            before,
            "an unauthenticated message must not move a single byte of state"
        );
    }

    #[test]
    fn deserialize_rejects_truncated_or_wrong_version_state() {
        let (mut a, _b) = pair();
        let _ = a.encrypt(b"x").unwrap();
        let bytes = a.serialize();

        for n in 0..bytes.len() {
            assert!(
                Ratchet::deserialize(&bytes[..n]).is_err(),
                "truncation to {n} bytes must not decode"
            );
        }

        let mut wrong_version = bytes.clone();
        wrong_version[0] = RATCHET_STATE_VERSION.wrapping_add(1);
        assert!(Ratchet::deserialize(&wrong_version).is_err());
    }
}
