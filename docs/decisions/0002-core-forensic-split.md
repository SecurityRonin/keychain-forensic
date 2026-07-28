# 2. Two-crate split: `keychain-core` reader + `keychain-forensic` analyzer

Date: 2026-07-29
Status: Accepted

## Context

The fleet crate-structure standard mandates one workspace repo named
`<x>-forensic` with two members: a `<x>-core` reader that owns the raw
parsing/crypto and emits no findings, and a `<x>-forensic` analyzer that consumes
it and produces the DFIR-facing output. The keychain problem splits cleanly:

1. the byte-format decode + the audited decrypt-given-password crypto — pure,
   reusable, medium-agnostic;
2. classifying the recovered secrets and running the `kc4n6` CLI — the examiner's
   tool.

## Decision

1. **One workspace, two members** (`members = ["core", "forensic"]`):
   `keychain-core` (library) and `keychain-forensic` (analyzer + `kc4n6`).
2. **`keychain-core` performs no I/O and emits no findings** — every entry point
   takes `&[u8]` (`Keychain::open`, `unlock`, `generic_secrets`; the `crypto`
   primitives). `core`'s `&[u8]` API already exposes everything the analyzer
   needs, so the analyzer builds on `-core` (no drop below it, unlike ntfs/ewf).
3. **`keychain-forensic` depends on `keychain-core`**, adds the `classify` rule
   (any `… Safe Storage` service is the high-value browser key) and the `kc4n6`
   CLI, with all decisions in the library (Humble Object) and a thin `main.rs`.
4. **The two crates version independently** — `version` is not hoisted into
   `[workspace.package]`.

## Consequences

- `keychain-core` is a standalone crates.io library a browser-forensic pipeline
  or an orchestrator can link for the Safe Storage key without pulling clap,
  serde, or any I/O.
- `kc4n6` follows the fleet `<x>4n6` binary convention; the crate stays
  `keychain-forensic` (Pattern A single-format repo).
- `classify` uses the general `… Safe Storage` suffix rule, not a hard-coded
  one-browser allowlist, so Edge/Brave/Vivaldi keys are flagged by construction.
