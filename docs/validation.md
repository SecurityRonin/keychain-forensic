# Validation

`keychain-core` recovers real secrets from real macOS keychains, so its
correctness is checked against an **independent oracle** — Apple's own Keychain
Services — not only against fixtures we authored.

## Tier-2: Apple-minted keychain, Apple-confirmed secrets

The decryption path is a value-producing, oracle-feasible operation (it emits a
plaintext secret that another tool can check), so a self-authored round-trip
would be circular. Instead the fixture and its ground truth both come from
Apple's `/usr/bin/security`:

```sh
KC=/tmp/test-login.keychain-db
security create-keychain -p "TestPass123!" "$KC"
security unlock-keychain  -p "TestPass123!" "$KC"
security set-keychain-settings "$KC"
security add-generic-password -a "alice"  -s "MySecretService"     -w "S3cr3t-KC-Value!"     "$KC"
security add-generic-password -a "Chrome" -s "Chrome Safe Storage" -w "SafeStorageKeyDemo00" "$KC"

# Apple's OWN tool prints the stored secret back (the oracle):
security find-generic-password -a "alice"  -s "MySecretService"     -w "$KC"  # -> S3cr3t-KC-Value!
security find-generic-password -a "Chrome" -s "Chrome Safe Storage" -w "$KC"  # -> SafeStorageKeyDemo00
```

The macOS `security` tool wrote the PBKDF2 salt, derived and 3DES-wrapped the
DBKey, and encrypted the SSGP payloads through Apple's production CDSA/keychain
code — none of which this crate authored. `security find-generic-password`
confirmed both secrets *before* `keychain-core` was pointed at the file.

`core/tests/oracle_keychain.rs` then opens the committed fixture, unlocks it with
`TestPass123!`, and asserts:

- account `alice`, service `MySecretService` → `S3cr3t-KC-Value!`;
- account `Chrome`, service `Chrome Safe Storage` → `SafeStorageKeyDemo00`
  (the headline Chromium Safe Storage key path);
- a wrong password returns `KeychainError::Locked`, never a fabricated secret.

Recovering byte-identical values that Apple independently confirmed is a genuine
tier-2 real-artifact validation (real engine output, independent oracle), not a
self-consistent round-trip. Provenance and hashes are in
[`tests/data/README.md`](https://github.com/SecurityRonin/keychain-forensic/blob/main/tests/data/README.md).

Environment note: the fixture is small, clearly-owned, and committed, so the
suite runs from committed bytes alone — no macOS host or live `security` tool is
needed on CI.

## Tier-1: KDF known-answer tests

`derive_master_key` is checked at the primitive level with **RFC 6070**
PBKDF2-HMAC-SHA1 vectors (c=1 and c=4096), authored by the RFC, plus a
consistency assertion that the keychain KDF is exactly 1000 rounds over
(password, salt) to 24 bytes.

## Robustness

- `#![forbid(unsafe_code)]`; `clippy::unwrap_used` / `expect_used` denied in
  production. A bad key, IV length, or padding is a typed `KeychainError`.
- Every integer field read goes through the fuzzed `safe-read` crate; every
  length/offset from the image is bounds-checked before use.
- `cargo-fuzz` targets (`fuzz_container`, `fuzz_ssgp`) drive the container
  navigation and the crypto edges over arbitrary bytes; the invariant is that
  no input ever panics.

## Reference implementation

The format decode follows the community `chainbreaker` tool (n0fate) and Apple's
open-source `securityd` / `libsecurity_cdsa_*`; `chainbreaker` also serves as a
cross-check oracle for the container layout.
