# Test Data — keychain-forensic

Per-file provenance for the forensic test corpus. The single machine-readable
fleet index is `ronin-issen/docs/test-data-catalog.md`; this README is the
co-located human-facing detail. Cross-reference, do not duplicate.

Straight ASCII is used in all paths / commands.

## Classification

| File | Class | Ground truth |
|---|---|---|
| `test-login.keychain-db` | REAL-self (OS-minted) | login password + two known generic secrets (incl. Chrome Safe Storage) |

`REAL-self` = a genuine artifact produced by the operating system's own tooling
(`/usr/bin/security`, the macOS Keychain Services CLI) rather than a byte buffer
we hand-encoded. The `security` tool is the **independent oracle**: it wrote the
PBKDF2 salt, derived and 3DES-wrapped the DBKey, and encrypted the SSGP payload
using Apple's production CDSA/keychain code path — none of which this crate
authored. Decrypting it back to the exact known secret is therefore a genuine
tier-2 real-artifact validation (Doer-Checker), not a self-consistent round-trip.

## Files

#### `test-login.keychain-db`

- **Source:** minted on this host with Apple's Keychain Services CLI
  (`/usr/bin/security`). Not downloaded — reproducible with the commands below.
- **Minting host:** macOS 15.7.8 (build 24G809), `security` (Keychain Services).
- **Verbatim generator commands:**
  ```sh
  KC=/tmp/test-login.keychain-db
  security create-keychain -p "TestPass123!" "$KC"
  security unlock-keychain  -p "TestPass123!" "$KC"
  security set-keychain-settings "$KC"          # no auto-lock timeout
  security add-generic-password -a "alice" -s "MySecretService" \
      -w "S3cr3t-KC-Value!" "$KC"
  security add-generic-password -a "Chrome" -s "Chrome Safe Storage" \
      -w "SafeStorageKeyDemo00" "$KC"
  # readback oracle (Apple's own tool prints the stored secret):
  security find-generic-password -a "alice"  -s "MySecretService"     -w "$KC"  # -> S3cr3t-KC-Value!
  security find-generic-password -a "Chrome" -s "Chrome Safe Storage" -w "$KC"  # -> SafeStorageKeyDemo00
  cp "$KC" tests/data/test-login.keychain-db
  ```
- **Login password (ground truth):** `TestPass123!`
- **Known secrets (ground truth):**
  - account `alice`, service `MySecretService`, password `S3cr3t-KC-Value!`;
  - account `Chrome`, service `Chrome Safe Storage`, password `SafeStorageKeyDemo00`
    (the Chromium Safe Storage key path — the headline forensic use case).
- **MD5:** `9384c3a0547aebf47c407c7b5e4a3bab`
- **SHA-256:** `8dfecb9b2c8939687b60a81e86ed75f247117126ac971a4d9b6aac842854e6d1`
- **Size:** 23376 bytes
- **Redistribution:** self-created throwaway; no real credentials. The login
  password and the sole secret are deliberately public test values. Safe to
  commit (small, clearly-owned, no third-party data). Apache-2.0 with the repo.
- **Consumed by:** `core/tests/oracle_keychain.rs` (decrypts with the login
  password and asserts the recovered secret) and the `keychain-forensic` CLI
  smoke test.

## Regenerating

The fixture is committed, so no regeneration is needed to run the suite. To mint
a fresh one on a macOS host, run the commands above (the byte layout varies run
to run — salt, IV, and 3DES keys are randomised by `security` — but the login
password and secret are fixed by the command line, so update the hashes here if
you replace the file).
