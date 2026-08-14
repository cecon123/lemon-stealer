# LemonStealer

Port **Windows-only, Chromium-only** của [`hack-browser-data`](https://github.com/moonD4rk/HackBrowserData)
(Go → Rust, workspace `crates/*`, edition 2024). Giải mã & xuất dữ liệu trình duyệt Chromium
(cookie, password, lịch sử, download, bookmark, extension, credit card, localStorage/sessionStorage)
trên Windows — bao gồm cả **App-Bound Encryption (v20)** của Chrome 127+.

> ⚠️ Chỉ dùng trên máy/máy ảo bạn sở hữu hoặc được phép kiểm tra. Tool giải mã dữ liệu trình
> duyệt local — là dual-use, tuân theo các quy định liên quan.

## Tính năng

- **ABE v20 (App-Bound Encryption)**: inject reflective payload vào browser thật (spawn suspended
  với temp `--user-data-dir`) để mượn `IElevator::DecryptData` của chính browser lấy key → chạy đúng
  trên **Chrome 151 forced-ABE** (key v10 trong `Local State` là dummy; mọi mật khẩu/cookie đều v20).
- **Popup browser bị đưa ngoài màn hình** khi inject: thêm `--window-position=-32000,-32000
  --window-size=1,1` vào command line spawn — cửa sổ vẫn được tạo (payload ổn định) nhưng không hiện
  lên desktop.
- DPAPI v10 (key trong `Local State`), Yandex (v10 + per-row AAD), Opera/Opec, credit card, storage
  qua LevelDB reader tự viết (Snappy, không dùng goleveldb).
- Output theo profile: `results/<browser>/<profile>/<category>.<ext>` với 3 format
  (`csv`/`json`/`cookie-editor`), tùy chọn `--zip`.

## Build

```powershell
cargo build --release
.\target\release\LemonStealer.exe --help
```

Yêu cầu: Rust toolchain. Payload ABE C được build sẵn thành `crates/abi/payload/abe_extractor_amd64.bin`
(từ `crates/abi/abe_native/`, `zig cc` — xem `Makefile.frag`) và embed qua `include_bytes!`.

## Usage

```
LemonStealer [-b <browser>] [-c <categories>] [-f <format>] [-d <dir>] [-p <profile-path>] [--zip] [-v]
```

Subcommand (khớp `hack-browser-data`):

| Subcommand | Mô tả | Trạng thái |
|---|---|---|
| `dump` (default) | extract + decrypt + xuất file | ✅ |
| `dumpkeys` | xuất master keys JSON (stdout hoặc `-o`) | ✅ |
| `list` | liệt kê browser & profile; `--detail` kèm số entry | ✅ |
| `archive` | đóng gói profile để restore cross-host | 🚧 chưa implement |
| `restore` | giải mã dữ liệu đã copy bằng keys | 🚧 chưa implement |
| `version` | version + commit + build date | ✅ |

Ví dụ:

```powershell
# Toàn bộ browser, mọi loại data, JSON, gộp zip
.\target\release\LemonStealer.exe -b all -c all -f json -d results --zip

# Chỉ Chrome, mật khẩu + cookie, CSV, verbose
.\target\release\LemonStealer.exe -b chrome -c password,cookie -f csv -v

# Xuất keys để giải mã trên máy khác
.\target\release\LemonStealer.exe dumpkeys -b chrome -o keys.json
```

## Kiến trúc

```
core ← crypto ← keyring ← browser ← cli
        abi (cực dưới, mọi unsafe/WinAPI)  ← keyring/browser/filemanager
```

| Crate | Vai trò (port từ package Go) |
|---|---|
| `core` | `*Entry`, `Category`, `BrowserKind`, `BrowserConfig`, `BrowserData`, `Profile`, `ChromeTime` |
| `crypto` | `DetectVersion`, AES-256-GCM, AES-128-CBC + `kEmptyKey`, Yandex intermediate key, DPAPI wrapper |
| `keyring` | `MasterKeys {v10, v20}` + retrievers: DPAPIRetriever, AbeRetriever (inject), static (dumpkeys) |
| `browser` | discovery (config table 17 browser windows), profile scan, Chromium + Yandex + Opera extractors, LevelDB, dump JSON |
| `abi` | toàn bộ unsafe: DPAPI, process spawn/inject, PE parse, IAT patch, winpaths, payload embed |
| `filemanager` | Session/Acquire (copy + WAL/SHM, skip LOCK), compress/zip/unzip (zip-slip guard) |
| `output` | Writer per-profile, formatters csv/json/cookie-editor, BOM CSV |
| `cli` | clap CLI, logging backend, `format_duration`/timing |

Chi tiết thiết kế, quy tắc port, bảng rủi ro: **[PORTING.md](PORTING.md)** + **[PLAN.md](PLAN.md)**.

## Kiểm thử

```powershell
cargo test --workspace        # 179 tests green
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check
cargo audit                   # 0 lỗ hổng trên 136 deps
```

Verify thật trên Chrome 151 (forced ABE): **docs/VERIFY.md**.

## Tiến độ

- ✅ Phase 0–3: scaffold, crypto core, extractor Chromium (toàn bộ loại data), filemanager/Session,
  DPAPI keyring — 179 tests.
- ✅ Phase 4 (phần lớn): Writer + formatters + CLI `dump`/`dumpkeys`/`list`/`version`, logging,
  zip 3 hành vi, build date/version.
- ✅ Phase 5: ABE v20 injector — verified trên Chrome 151 (passwords 210/224, cookies ~99.7%;
  hàng trống còn lại là giá trị rỗng thật trong DB).
- 🚧 Còn lại: `archive`, `restore`, double-click mode, `copyLocked` (file bị khóa bởi Chrome đang
  chạy → cookie exports bỏ qua, log `os error 32`), golden-file parity diff.