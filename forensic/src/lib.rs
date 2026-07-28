//! `kc4n6` — the forensic analyzer over [`keychain_core`].
//!
//! Audits an acquired macOS `login.keychain-db` **offline**: given the account
//! login password it recovers every generic-password secret and flags the
//! high-value **Chromium Safe Storage** key (which in turn unlocks Chrome / Edge
//! cookie and login stores). A wrong or absent password yields a loud
//! *present-but-locked* report with a non-zero exit, never a guessed secret.
//!
//! Decision logic lives in this library (the testable [`audit`] / [`classify`]
//! functions + [`Cli::run`]); `main.rs` is a thin shell (Humble Object).

pub use keychain_core;

use std::path::PathBuf;

use clap::Parser;
use keychain_core::{GenericSecret, Keychain, KeychainError};
use serde::Serialize;

/// The class of a recovered item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    /// An ordinary generic-password secret.
    GenericSecret,
    /// The Chromium `Safe Storage` key — unlocks Chrome/Edge cookie & login DBs.
    SafeStorageKey,
}

/// One recovered secret, classified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub account: String,
    pub service: String,
    pub label: String,
    /// Display form: UTF-8 text, or `hex:...` for a binary key.
    pub secret: String,
}

/// The audit result: recovered findings plus recovery context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditReport {
    pub findings: Vec<Finding>,
    /// Number of per-record keys the login password unwrapped.
    pub key_count: usize,
}

/// Classify a record by its service attribute.
///
/// Chromium stores its master cookie key as a generic password whose service is
/// `Chrome Safe Storage` (Edge: `Microsoft Edge Safe Storage`, Brave:
/// `Brave Safe Storage`, …). The general rule is a `Safe Storage` service
/// suffix — not a hard-coded allowlist of one browser.
#[must_use]
pub fn classify(service: &str) -> FindingKind {
    if service.ends_with("Safe Storage") {
        FindingKind::SafeStorageKey
    } else {
        FindingKind::GenericSecret
    }
}

fn to_finding(s: GenericSecret) -> Finding {
    Finding {
        kind: classify(&s.service),
        secret: s.display(),
        account: s.account,
        service: s.service,
        label: s.label,
    }
}

/// Audit a keychain image with the login password.
///
/// Returns [`KeychainError::Locked`] when the password does not unwrap the
/// DBKey — the caller reports the store present-but-locked, never a secret.
pub fn audit(data: &[u8], password: &[u8]) -> Result<AuditReport, KeychainError> {
    let kc = Keychain::open(data)?;
    let unlocked = kc.unlock(password)?;
    let findings = unlocked
        .generic_secrets()
        .into_iter()
        .map(to_finding)
        .collect();
    Ok(AuditReport {
        findings,
        key_count: unlocked.key_count(),
    })
}

/// A typed CLI failure surfaced to the user (never a guessed secret).
#[derive(Debug)]
pub enum CliError {
    /// Reading the keychain file failed.
    Io(String),
    /// The container could not be parsed as a keychain.
    Parse(KeychainError),
    /// The store is present but the password did not unlock it.
    Locked(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Io(s) => write!(f, "io error: {s}"),
            CliError::Parse(e) => write!(f, "not a usable keychain: {e}"),
            CliError::Locked(path) => write!(
                f,
                "{path}: keychain present but LOCKED — the supplied login password did not unwrap the DBKey"
            ),
        }
    }
}

impl std::error::Error for CliError {}

/// `kc4n6` — recover secrets from an acquired macOS `login.keychain-db`.
#[derive(Debug, Parser)]
#[command(
    name = "kc4n6",
    version,
    about = "Offline macOS keychain secret recovery"
)]
pub struct Cli {
    /// Path to the `login.keychain-db` file.
    pub keychain: PathBuf,
    /// The account login password that protects the keychain.
    #[arg(long)]
    pub password: String,
    /// Emit the report as JSON instead of a human table.
    #[arg(long)]
    pub json: bool,
}

impl Cli {
    /// Read the keychain and audit it, returning the report or a typed error.
    pub fn run(&self) -> Result<AuditReport, CliError> {
        let data = std::fs::read(&self.keychain)
            .map_err(|e| CliError::Io(format!("{}: {e}", self.keychain.display())))?;
        match audit(&data, self.password.as_bytes()) {
            Ok(report) => Ok(report),
            Err(KeychainError::Locked) => {
                Err(CliError::Locked(self.keychain.display().to_string()))
            }
            Err(e) => Err(CliError::Parse(e)),
        }
    }
}

/// Render an [`AuditReport`] as a human-readable table.
#[must_use]
pub fn render_text(report: &AuditReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if report.findings.is_empty() {
        let _ = writeln!(
            out,
            "Unlocked ({} record keys) but recovered no generic secrets.",
            report.key_count
        );
        return out;
    }
    for f in &report.findings {
        let tag = match f.kind {
            FindingKind::SafeStorageKey => "SAFE-STORAGE",
            FindingKind::GenericSecret => "generic",
        };
        let _ = writeln!(
            out,
            "[{tag}] service={} account={} secret={}",
            f.service, f.account, f.secret
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_detects_safe_storage_variants() {
        assert_eq!(classify("Chrome Safe Storage"), FindingKind::SafeStorageKey);
        assert_eq!(
            classify("Microsoft Edge Safe Storage"),
            FindingKind::SafeStorageKey
        );
        assert_eq!(classify("Brave Safe Storage"), FindingKind::SafeStorageKey);
        assert_eq!(classify("MySecretService"), FindingKind::GenericSecret);
    }

    #[test]
    fn cli_parses_positional_and_flags() {
        let cli = Cli::try_parse_from(["kc4n6", "/tmp/login.keychain-db", "--password", "pw"])
            .expect("parse");
        assert_eq!(cli.keychain, PathBuf::from("/tmp/login.keychain-db"));
        assert_eq!(cli.password, "pw");
        assert!(!cli.json);
    }

    #[test]
    fn cli_version_flag_supported() {
        let err = Cli::try_parse_from(["kc4n6", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn empty_report_renders_key_count() {
        let r = AuditReport {
            findings: vec![],
            key_count: 3,
        };
        assert!(render_text(&r).contains("3 record keys"));
    }
}
