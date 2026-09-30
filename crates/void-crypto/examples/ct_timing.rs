//! A dudect-style timing check of operations NFR-SEC-03 says must run in
//! constant time. Run it optimized, as CI does:
//!
//! ```text
//! cargo run --release -p void-crypto --example ct_timing
//! ```
//!
//! ## Method
//!
//! Reparaz, Balasch and Verbauwhede's *dudect* (2017): run the operation on two
//! classes of input, interleaved at random, time every run, and ask with
//! Welch's t-test whether the two timing distributions differ. An operation
//! whose running time depends on the secret-dependent difference between the
//! classes shows a large |t|; one that does not stays near zero. The slowest
//! tenth of samples is discarded first: on a shared machine those are
//! interruptions, not the operation.
//!
//! ## What a pass does and does not mean
//!
//! A pass means this machine, with this compiler, showed no difference at this
//! sample size — not that the code is constant time everywhere. A difference
//! smaller than a shared runner's noise goes unseen, and the binary measured is
//! the host's, not a phone's. It is a tripwire for regressions as gross as an
//! early-exit comparison, which is the realistic mistake, and not a proof; the
//! CI job stays informational for that reason. `PinVerifier::check` is not
//! here: it runs Argon2, and a sample size that means anything would take hours.

use std::hint::black_box;
use std::time::Instant;

use void_crypto::{aead, ct, mlkem, rand};

/// dudect's bound for "definitely not constant time".
const LEAK: f64 = 10.0;

/// dudect's bound below which there is no evidence of a leak.
const CLEAR: f64 = 4.5;

/// Welford's running mean and variance, for one class of input.
#[derive(Default, Clone, Copy)]
struct Stats {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Stats {
    fn push(&mut self, x: f64) {
        self.n += 1.0;
        let delta = x - self.mean;
        self.mean += delta / self.n;
        self.m2 += delta * (x - self.mean);
    }

    fn variance(&self) -> f64 {
        if self.n > 1.0 {
            self.m2 / (self.n - 1.0)
        } else {
            0.0
        }
    }
}

/// Welch's t between the two classes.
fn welch(a: &Stats, b: &Stats) -> f64 {
    let se = (a.variance() / a.n + b.variance() / b.n).sqrt();
    if se == 0.0 {
        0.0
    } else {
        (a.mean - b.mean) / se
    }
}

/// Time `batch` runs of `op` per sample, `samples` times, each sample's class
/// drawn at random; print and return |t|.
fn check(name: &str, samples: usize, batch: usize, mut op: impl FnMut(usize)) -> f64 {
    let mut classes = vec![0u8; samples];
    rand::fill(&mut classes).expect("entropy");
    let mut timings = Vec::with_capacity(samples);
    for c in classes {
        let class = usize::from(c & 1);
        let start = Instant::now();
        for _ in 0..batch {
            op(class);
        }
        timings.push((class, start.elapsed().as_nanos() as f64));
    }
    let mut sorted: Vec<f64> = timings.iter().map(|&(_, t)| t).collect();
    sorted.sort_by(f64::total_cmp);
    let cutoff = sorted[sorted.len() * 9 / 10];
    let mut stats = [Stats::default(); 2];
    for (class, t) in timings {
        if t <= cutoff {
            stats[class].push(t);
        }
    }
    let t = welch(&stats[0], &stats[1]).abs();
    let verdict = if t > LEAK {
        "LEAK"
    } else if t > CLEAR {
        "inconclusive"
    } else {
        "no evidence of a leak"
    };
    println!(
        "{name:<48} |t| = {t:>6.2}  {verdict} ({} samples)",
        stats[0].n + stats[1].n
    );
    t
}

fn main() {
    let mut worst = 0f64;

    // Equal inputs against inputs that differ in their first byte: an
    // early-exit comparison is quickest on the second.
    let secret = rand::bytes32().expect("entropy");
    let mut differs = secret;
    differs[0] ^= 1;
    worst = worst.max(check(
        "ct::eq — equal vs differing at once",
        200_000,
        64,
        |class| {
            let other = if class == 0 { &secret } else { &differs };
            black_box(ct::eq(black_box(&secret), black_box(other)));
        },
    ));

    // Two forged tags, wrong in the first byte and in the last: a tag check
    // that stopped at the first mismatch would reject the first sooner.
    let key = rand::bytes32().expect("entropy");
    let nonce = [0u8; aead::NONCE_LEN];
    let sealed = aead::seal(&key, &nonce, b"", &[0u8; 32]);
    let tag_start = sealed.len() - aead::TAG_LEN;
    let mut wrong_first = sealed.clone();
    wrong_first[tag_start] ^= 1;
    let mut wrong_last = sealed;
    wrong_last[tag_start + aead::TAG_LEN - 1] ^= 1;
    worst = worst.max(check(
        "aead::open — tag wrong in its first vs last byte",
        100_000,
        8,
        |class| {
            let forged = if class == 0 {
                &wrong_first
            } else {
                &wrong_last
            };
            black_box(aead::open(&key, &nonce, b"", black_box(forged)).is_err());
        },
    ));

    // A valid ciphertext against a random one, which decapsulation must reject
    // implicitly — in the same time, or the rejection is an oracle.
    let pair = mlkem::keygen().expect("entropy");
    let (valid, _) = mlkem::encaps(&pair.encaps_key).expect("encaps");
    let mut random = vec![0u8; mlkem::CIPHERTEXT_LEN];
    rand::fill(&mut random).expect("entropy");
    worst = worst.max(check(
        "mlkem::decaps — valid vs random ciphertext",
        10_000,
        1,
        |class| {
            let ciphertext = if class == 0 { &valid } else { &random };
            black_box(mlkem::decaps(&pair.decaps_key, black_box(ciphertext)).ok());
        },
    ));

    if worst > LEAK {
        println!("FAIL: at least one operation's timing depends on its input");
        std::process::exit(1);
    }
    println!("ok — no operation's timing clearly depended on its input on this machine");
}
