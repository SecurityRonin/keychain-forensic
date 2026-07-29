//! End-to-end coverage of the `kc4n6` decision layer (`audit`, `classify`,
//! `to_finding`, `Cli::run`, `CliError` rendering) against the OS-minted
//! fixture — the same independent oracle the core crate validates against
//! (`tests/data/README.md`). Ground truth (fixed by the minting command):
//!   login password : `TestPass123!`
//!   alice  / `MySecretService`     => `S3cr3t-KC-Value!`
//!   Chrome / `Chrome Safe Storage` => `SafeStorageKeyDemo00`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use keychain_forensic::{audit, render_text, Cli, CliError, FindingKind};

/// Absolute path to the repo-root fixture, independent of the test's cwd.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/data/test-login.keychain-db"
);
const PASSWORD: &[u8] = b"TestPass123!";

#[test]
fn audit_recovers_and_classifies_real_secrets() {
    let data = std::fs::read(FIXTURE).expect("read the OS-minted keychain fixture");
    let report = audit(&data, PASSWORD).expect("audit unlocks the OS-minted keychain");

    // `audit` unwrapped at least the two known record keys.
    assert!(report.key_count >= 1, "expected recovered record keys");

    // `to_finding` + `classify` exercised for a Safe Storage item...
    let safe = report
        .findings
        .iter()
        .find(|f| f.service == "Chrome Safe Storage")
        .expect("the Chrome Safe Storage finding");
    assert_eq!(safe.kind, FindingKind::SafeStorageKey);
    assert_eq!(safe.account, "Chrome");
    assert_eq!(safe.secret, "SafeStorageKeyDemo00");

    // ...and for an ordinary generic secret.
    let generic = report
        .findings
        .iter()
        .find(|f| f.service == "MySecretService")
        .expect("the alice/MySecretService finding");
    assert_eq!(generic.kind, FindingKind::GenericSecret);
    assert_eq!(generic.secret, "S3cr3t-KC-Value!");

    // A populated report renders both tags (non-empty branch of `render_text`).
    let text = render_text(&report);
    assert!(text.contains("SAFE-STORAGE"));
    assert!(text.contains("[generic]"));
}

#[test]
fn cli_run_success_against_real_fixture() {
    let cli = Cli {
        keychain: PathBuf::from(FIXTURE),
        password: "TestPass123!".into(),
        json: false,
    };
    let report = cli.run().expect("run recovers secrets from the fixture");
    assert!(!report.findings.is_empty());
}

#[test]
fn cli_run_io_error_on_missing_file_is_loud() {
    let cli = Cli {
        keychain: PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/does-not-exist.keychain-db"
        )),
        password: "x".into(),
        json: false,
    };
    let err = cli
        .run()
        .expect_err("a missing file must fail loud, not empty");
    assert!(matches!(err, CliError::Io(_)));
    let msg = err.to_string();
    assert!(msg.contains("io error"), "got: {msg}");
    assert!(msg.contains("does-not-exist.keychain-db"), "got: {msg}");
}

#[test]
fn cli_run_wrong_password_reports_locked_not_a_fabricated_secret() {
    let cli = Cli {
        keychain: PathBuf::from(FIXTURE),
        password: "wrong-password".into(),
        json: false,
    };
    let err = cli
        .run()
        .expect_err("a wrong password must report LOCKED, never a guessed secret");
    assert!(matches!(err, CliError::Locked(_)));
    assert!(err.to_string().contains("LOCKED"));
}

#[test]
fn cli_run_parse_error_on_non_keychain_bytes() {
    let mut path = std::env::temp_dir();
    path.push(format!("kc4n6-garbage-{}.keychain-db", std::process::id()));
    std::fs::write(&path, b"NOTAKEYCHAINxxxxxxxxxxxx").expect("write garbage fixture");

    let cli = Cli {
        keychain: path.clone(),
        password: "irrelevant".into(),
        json: false,
    };
    let err = cli.run().expect_err("garbage is not a usable keychain");
    assert!(matches!(err, CliError::Parse(_)));
    assert!(err.to_string().contains("not a usable keychain"));

    let _ = std::fs::remove_file(&path);
}
