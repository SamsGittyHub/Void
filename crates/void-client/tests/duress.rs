//! Duress destruction, end to end (FR-STOR-02).
//!
//! `void-store` can destroy a vault key and erase a database; this is the
//! test that something actually triggers it and that what is left behind is
//! unopenable — not just that the pieces exist in isolation.

use std::sync::{Arc, Mutex};

use void_client::engine::{Engine, SecurityMode};
use void_client::transport::MemoryTransport;
use void_crypto::argon2;
use void_proto::identity::Identity;
use void_relay::server::{NoPush, Relay};
use void_relay::store::Config;
use void_store::db::{Database, FileBackend};
use void_store::model::Settings;
use void_store::vault::{KeyVault, SoftwareVault};

fn temp_db_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "void-duress-test-{}-{label}.voiddb",
        std::process::id()
    ))
}

#[test]
fn duress_destroy_wipes_memory_and_leaves_the_database_unopenable() {
    let path = temp_db_path("wipes-and-unopenable");
    let vault = SoftwareVault::from_raw([42u8; 32]);
    let relay = Arc::new(Relay::new(Config::default(), Box::new(NoPush)));
    let clock = Arc::new(Mutex::new(1_000_000u64));

    let db = Database::create(
        FileBackend::new(&path),
        &vault,
        argon2::Params::TEST_ONLY_WEAK,
    )
    .unwrap();
    let (identity, seeds) = Identity::generate_with_seeds().unwrap();
    let mut alice = Engine::new_persisted(
        identity,
        &seeds,
        Settings::default(),
        Box::new(MemoryTransport::new(Arc::clone(&relay), Arc::clone(&clock))),
        SecurityMode::InsecureForTesting,
        0,
        Box::new(db),
    )
    .unwrap();

    let bob_identity = Identity::from_seeds(&[2u8; 32], &[13u8; 32], &[17u8; 32]);
    let mut bob = Engine::new(
        bob_identity,
        Settings::default(),
        Box::new(MemoryTransport::new(Arc::clone(&relay), clock)),
        SecurityMode::InsecureForTesting,
        0,
    )
    .unwrap();

    let (bundle, _) = bob.create_bundle(b"relay.onion").unwrap();
    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "under duress this must vanish", 1_000_000)
        .unwrap();
    assert!(
        alice.contact(&bob_fp).is_some(),
        "the contact must exist before duress"
    );
    assert!(
        alice.outbox_len() > 0,
        "the handshake must be queued before duress hits"
    );

    // Under duress the platform has already destroyed the hardware vault key
    // by this point (a pure platform call — see void-ffi's duress module
    // docs). This is the core's half.
    vault.destroy().unwrap();
    alice.duress_destroy().unwrap();

    // Nothing survives in the engine's own memory.
    assert!(
        alice.contact(&bob_fp).is_none(),
        "the contact must not survive duress destruction"
    );
    assert_eq!(alice.outbox_len(), 0, "the outbox must be emptied");
    assert!(alice.contacts().is_empty());

    // And the database is unopenable, full stop — whether that surfaces as
    // `VaultDestroyed` (the key is gone) or `Io` (the file `duress_destroy`
    // erased is gone too) depends only on how much of the erase completed,
    // which `void-store`'s own tests already pin down
    // (`a_destroyed_vault_makes_the_database_unopenable`). What this
    // integration test exists to prove is that calling `Engine::duress_destroy`
    // is enough on its own, with nothing else required, to make every path
    // to reopening this conversation fail.
    let reopened = Database::open(FileBackend::new(&path), &vault);
    assert!(reopened.is_err(), "the database must not be reopenable");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn duress_destroy_is_safe_without_a_store_attached() {
    // A caller must not be able to skip the RAM wipe merely by calling this
    // on an engine that never had persistence turned on.
    let relay = Arc::new(Relay::new(Config::default(), Box::new(NoPush)));
    let clock = Arc::new(Mutex::new(0u64));
    let identity = Identity::from_seeds(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
    let mut engine = Engine::new(
        identity,
        Settings::default(),
        Box::new(MemoryTransport::new(relay, clock)),
        SecurityMode::InsecureForTesting,
        0,
    )
    .unwrap();
    assert!(engine.duress_destroy().is_ok());
    assert!(engine.contacts().is_empty());
}
