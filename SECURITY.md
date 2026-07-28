# Security Policy

`keychain-forensic` parses and decrypts **untrusted macOS keychain artifacts** —
`login.keychain-db` files extracted from compromised or actively hostile systems.
Hostile input is the expected case, not an edge case. Robustness against crafted
containers is a core design goal, and we take reports of crashes, hangs, or
memory-safety issues seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current release line, receives security fixes |
| < 0.1   | ❌ — pre-release, unsupported |

Security fixes are released against the latest published `0.1.x` line.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`keychain-forensic` repository](https://github.com/SecurityRonin/keychain-forensic/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include:

- the affected version and target triple,
- a minimal reproducing keychain container or byte buffer,
- the observed behaviour (panic, hang, excessive allocation, mis-parse) and the
  expected behaviour.

We aim to acknowledge a report within a few business days and to coordinate
disclosure once a fix is available.

## Security posture

`keychain-forensic` is hardened against adversarial input by construction:

- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe`, anywhere.
- **Audited cryptography only** — the login-keychain unlock chain (PBKDF2-HMAC-SHA1
  master-key derivation, 3DES-EDE3-CBC DBKey/record/secret decryption, the CMS key
  unwrap) uses the RustCrypto crates (`pbkdf2`, `des`, `cbc`, `cipher`, `hmac`,
  `sha1`); no primitive is hand-rolled. The library decrypts evidence given the
  login password and never fabricates plausible-but-wrong output: a wrong password
  or a bad key/IV/padding surfaces as a typed `KeychainError` (`Locked` for a wrong
  password), never a guessed secret.
- **Bounds-checked parsing** — fixed-width integer fields are read through the
  fuzzed `safe-read` crate, and every length/offset in the container is validated
  against the actual buffer before use; out-of-range reads fall back rather than
  panic.
- **No panics on malicious input** — `clippy::unwrap_used` / `expect_used` are
  denied in production, and `cargo-fuzz` targets (`fuzz_container`, `fuzz_ssgp`)
  drive the container navigation and crypto edges over arbitrary bytes with a
  never-panic invariant.
