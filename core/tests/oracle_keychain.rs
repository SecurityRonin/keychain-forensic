//! Tier-2 real-artifact validation (Doer-Checker).
//!
//! The fixture `tests/data/test-login.keychain-db` was minted by macOS's own
//! `security` tool (see `tests/data/README.md`) — the operating system wrote the
//! PBKDF2 salt, derived and 3DES-wrapped the DBKey, and encrypted the SSGP
//! payload through Apple's production keychain code. It is an **independent
//! oracle**: recovering the exact known secret from it proves this crate agrees
//! with Apple, not merely with itself.
//!
//! Ground truth (fixed by the minting command line; see `tests/data/README.md`):
//!   login password : `TestPass123!`
//!   secret 1       : account `alice`,  service `MySecretService`     => `S3cr3t-KC-Value!`
//!   secret 2       : account `Chrome`, service `Chrome Safe Storage` => `SafeStorageKeyDemo00`
//! Both were confirmed with Apple's own `security find-generic-password -w`
//! before this crate was pointed at the file, so the expected values are the
//! OS's output, not ours (an independent oracle, not circular self-agreement).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use keychain_core::{Keychain, KeychainError};

const KEYCHAIN: &[u8] = include_bytes!("../../tests/data/test-login.keychain-db");
const LOGIN_PASSWORD: &[u8] = b"TestPass123!";

#[test]
fn recovers_known_secret_from_os_minted_keychain() {
    let kc = Keychain::open(KEYCHAIN).expect("parse the OS-minted keychain");
    let unlocked = kc
        .unlock(LOGIN_PASSWORD)
        .expect("unlock with the correct login password");

    let secrets = unlocked.generic_secrets();
    assert!(!secrets.is_empty(), "expected at least one generic secret");

    let hit = secrets
        .iter()
        .find(|s| s.account == "alice" && s.service == "MySecretService")
        .expect("the known alice/MySecretService record");

    assert_eq!(
        hit.as_text(),
        Some("S3cr3t-KC-Value!"),
        "recovered secret must equal the value the OS stored"
    );
}

#[test]
fn recovers_chromium_safe_storage_key() {
    // The headline forensic use case: recover the `Chrome Safe Storage` generic
    // password, which is the AES key wrapping Chrome/Edge cookies and logins.
    let kc = Keychain::open(KEYCHAIN).expect("parse");
    let unlocked = kc.unlock(LOGIN_PASSWORD).expect("unlock");

    let hit = unlocked
        .generic_secrets()
        .into_iter()
        .find(|s| s.service == "Chrome Safe Storage")
        .expect("the Chrome Safe Storage record");

    assert_eq!(hit.account, "Chrome");
    assert_eq!(hit.as_text(), Some("SafeStorageKeyDemo00"));
}

#[test]
fn wrong_password_reports_locked_not_a_fabricated_secret() {
    let kc = Keychain::open(KEYCHAIN).expect("parse");
    let err = kc
        .unlock(b"wrong-password")
        .expect_err("a wrong password must not unlock");
    assert_eq!(err, KeychainError::Locked);
}
