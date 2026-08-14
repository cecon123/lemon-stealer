# Manual verification — Chrome ABE v20 path

Real-host check that decrypting browser data works end-to-end on a Chrome 127+
machine, including the v20 (`krug`) master-key path.

## Prerequisites
- Windows machine with Chrome **> 127** installed (this run: Chrome 151).
- Release build: `cargo build --release --workspace`.

## Procedure
1. Smoke-test the full decrypt + export on real data:
   ```powershell
   .\target\release\LemonStealer.exe -b chrome -c password,cookie,creditcard -f csv -d verify
   ```
2. Confirm output contains non-empty CSV per profile + category.
3. **Verify values, not just rows**: spot-check that the `password`/`value`
   columns decrypt to real text (empty columns = decryption failure, see the
   APPB bug below).

## Observed result (2026-08-15, Huyy/catcat1204, Chrome 151 + forced ABE)

Chrome 151 rolls out **App-Bound Encryption** (ABE): every cookie/password is
v20-encrypted and the v10 DPAPI key in `Local State` is a dummy.

| Category | Default | Profile 1 | Profile 2 | Profile 3 | Profile 4 | Profile 7 |
|---|---|---|---|---|---|---|
| password | 210/224 | 40/47 | 86/86 | 13/14 | 7/7 | – |
| cookie | 3413/3437 | 690/692 | 623/625 | 515/516 | 411/412 | 199/200 |

Remaining empty rows have a genuinely empty `password_value` in the DB
(verified by prefix probe: `210 × v20`, `14 × empty`), not decrypt failures.
No `v20: retriever failed` warning any more.

## Root cause fixed this session
`crates/keyring/src/abe.rs` forwarded the APPB blob to the injector **with the
`APPB` prefix intact**. The elevation service's `IElevator::DecryptData`
expects the bare ciphertext (Go upstream: `decoded[len("APPB"):]`; xaitax
RESEARCH.md: "the APPB prefix is stripped"). Passing the prefix back made
`DecryptData` reject with `0x8004a004` (`ERROR_INVALID_DATA`), the v20 tier
failed, and every value came out empty.

Fix: strip `APPB_PREFIX` in `read_app_bound_blob` (now returns the bare
ciphertext); a non-`APPB`/undersized blob is a hard error (Go: "unexpected
prefix"), only an *absent* `app_bound_encrypted_key` stays "not applicable".
Unit tests updated (`appb_blob_survives_round_trip` expects stripped bytes,
`dpapi_prefixed_key_is_a_hard_error`).

## Notes
- Inject works via an isolated `--user-data-dir` spawn (issue #576), no
  running Chrome needed.
- `cookie.csv` may be missing for profiles whose Cookies file is locked by a
  running Chrome (`os error 32`); the `copyLocked` fallback is not yet ported
  (Phase 2b, crates/abi). Expected until that lands.