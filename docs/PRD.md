# keychain-forensic — Product Requirements

## Executive Summary

`keychain-forensic` recovers secrets from an acquired macOS `login.keychain-db`
**offline** — no live target, no macOS API, no I/O beyond reading the artifact an
analyst already extracted. It ships two things: `keychain-core`, a pure-`&[u8]`
library that parses Apple's `AppleDatabase` keychain container and, given the
account login password, runs the full unlock chain (PBKDF2-HMAC-SHA1 →
3DES-EDE3-CBC DBKey unwrap → CMS per-record key unwrap → 3DES-CBC secret
decrypt); and `kc4n6`, the CLI an examiner runs against the file. The headline
capability is recovering the Chromium **Safe Storage** key (service
`Chrome Safe Storage`, and the Edge/Brave variants), which decrypts that
browser's saved cookies and logins on a mounted image.

`login.keychain-db` is the macOS analogue of Windows DPAPI: one password guards a
key hierarchy over every stored secret. The login password is the analyst's
**input**; when it is wrong or absent the DBKey fails its padding check and the
tool reports the store *present but locked* (non-zero exit), never a guessed
secret. All cryptography is audited RustCrypto — the tool refuses rather than
fabricate plausible-but-wrong plaintext, because in a forensic tool fabricated
plaintext is fabricated evidence.

## 1. Problem

macOS keychains hold the credential material a DFIR examiner most wants —
browser Safe Storage keys, saved Wi-Fi and app secrets, tokens — but they are
encrypted at rest under the login password. Existing recovery tooling is Python
(`chainbreaker`: slow, dependency-heavy, hard to embed) or requires a live,
unlocked session. An examiner working from an acquired disk wants a single static
binary that decodes the keychain offline, given a password they already have, and
that is honest when it cannot unlock — not a tool that emits a plausible-looking
wrong secret.

## 2. Users

- **DFIR analysts / incident responders** — recover the browser Safe Storage key
  to then decrypt Chrome/Edge cookies and logins from a mounted image, plus other
  generic-password secrets, to reconstruct account access.
- **Malware / intrusion analysts** — decrypt credentials an adversary would have
  targeted, given a recovered or known login password.
- **Fleet tools (library consumers)** — an orchestrator or `4n6mount` supplies
  the keychain path; a browser-forensic pipeline consumes the recovered Safe
  Storage key.

## 3. What it does

`keychain-core` (library, byte-oriented, no I/O):

- **`Keychain::open(&[u8])`** — parse the `AppleDatabase` header, schema, and
  table directory; locate the metadata (DbBlob), symmetric-key, and
  generic-password tables.
- **`Keychain::unlock(password)`** — derive the master key, 3DES-unwrap the
  DBKey, and CMS-unwrap every per-record key; a wrong password → `Locked`.
- **`UnlockedKeychain::generic_secrets()`** — decrypt every generic-password
  SSGP payload whose per-record key was recovered, returning account, service,
  label, and the secret bytes.
- **`crypto`** — the audited primitives: `derive_master_key` (PBKDF2-HMAC-SHA1),
  `kcdecrypt` (3DES-EDE3-CBC + PKCS#7 unpad), `unwrap_key_blob` (CMS two-pass).

`kc4n6` (CLI, thin Humble-Object shell):

- One positional keychain path + `--password`; `--json` or a human table.
- `classify()` flags any `… Safe Storage` service as the high-value browser key.
- A store present but not unlockable → typed `Locked` with a non-zero exit.

## 4. Scope (in)

- Offline decode/decrypt of `login.keychain-db` generic-password secrets from a
  file the analyst supplies, given the login password.
- Chromium/Edge/Brave Safe Storage key recovery.
- The `kc4n6` CLI as the analyst-facing surface.

## 5. Non-goals (out)

- **No acquisition and no live target.** The tool reads a file; it does not attach
  to the running Security Server, mount images, or walk a filesystem (an
  orchestrator or `4n6mount` supplies the path).
- **No password guessing / brute force.** The login password is an input; a
  separate cracking tool (e.g. hashcat over the extracted DbBlob) is the place for
  that. The library exposes the salt/IV/ciphertext but does not crack.
- **Internet-password / certificate / private-key records (yet).** The current
  release targets generic-password secrets (which include Safe Storage); the same
  container parser reaches the internet-password and key tables and those decoders
  are the next increment.
- **`keychain-2.db` (the SQLite iCloud/data-protection keychain).** This crate
  handles the file-based `login.keychain-db` (`kych` AppleDatabase), a different
  format.
- **No hand-rolled crypto.** Every primitive is a RustCrypto crate (ADR 0001).

## 6. Artifact family

| Item | Where | Decoder |
|---|---|---|
| Login master key | `DbBlob` in the metadata table | `crypto::derive_master_key` + `kcdecrypt` |
| Per-record keys | symmetric-key table (`ssgp`-tagged) | `crypto::unwrap_key_blob` |
| Generic secrets | generic-password table SSGP blobs | `Keychain::unlock` + `generic_secrets` |
| Chromium Safe Storage key | generic secret, service `… Safe Storage` | `keychain-forensic::classify` |

## 7. Validation approach

Correctness is proven against an **independent oracle** — Apple's own
`/usr/bin/security` — not only self-authored fixtures. The fixture is minted by
`security create-keychain` / `add-generic-password`, and both stored secrets are
confirmed with `security find-generic-password` before the crate decrypts them
(tier-2). The KDF wiring is a tier-1 RFC 6070 known-answer test. The library is
`forbid(unsafe)` with `unwrap_used`/`expect_used` denied and is fuzzed; a wrong
key or padding is a typed `KeychainError`, never a panic or a fabricated secret.
See [`validation.md`](validation.md) and ADRs under [`decisions/`](decisions/).

---

[Privacy Policy](https://securityronin.github.io/keychain-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/keychain-forensic/terms/) · © 2026 Security Ronin Ltd
