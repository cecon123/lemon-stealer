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
│   ├── abi/                   # (unsafe) WinAPI: DPAPI, PE injection, process, handle scan — ISOLATE
│   ├── output/                # csv / json / cookie-editor / zip (CompressDir/ZipDir/Unzip)
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

### Phase 1 — Crypto core (pure Rust, không unsafe)
- [ ] `DetectVersion` (prefix 3B: `v10/v11/v12/v20`, ngược lại → DPAPI pre-80; `strip_prefix`)
- [ ] `decrypt_chromium_gcm` (AES-256-GCM: 3B prefix + nonce 12B + ct+tag; bounds check `<3+12` → Err)
- [ ] `decrypt_chromium_cbc` (AES-128-CBC, IV cố định 0x20×16, PKCS5/7; **kEmptyKey fallback**: PBKDF2("", "saltysalt", 1, 16, SHA1) — retry khi KWallet race crbug.com/40055416 → **giữ lại pbkdf2 + sha1, không phải Firefox-only!**)
- [ ] `decrypt_yandex` (key fix, AES-CBC) + `aes_gcm_decrypt_blob` (AAD support)
- [ ] `decrypt_dpapi` — gọi wrapper OS (stub trả Err trên non-Windows)
- [ ] **Verify**: port test vectors từ `crypto/*_test.go` + `browser/chromium/decrypt_*_test.go` (ciphertext mẫu có sẵn trong repo Go)

### Phase 2 — SQLite util + extractor Chromium
- [ ] `browser`: trait `Browser { browser_name(); user_data_dir(); profiles(); extract(cats); count_entries(cats) }` + trait `KeyManager { set_retrievers(); export_keys(); browser_key(); kind() }` + trait `Archivable { browser_key(); archive_sources(cats) }` (y hệt Go)
- [ ] Windows config table (17 browser entries — xem bảng trên), resolve glob `*` (Arc/DuckDuckGo) = crate `glob`
- [ ] `discover` + filter theo `-b` + override `-p`
- [ ] **Profile discovery** (chromium.go): skip dirs (`System Profile`, `Guest Profile`, `Snapshot`); markers `Preferences` + `Preferences_02` (QQ/Sogou); 3-tier fallback: (1) marker-scan → (2) flat layout cho Opera (data ngay dưới UserDataDir) → (3) subdir có chứa source file (tree đã copy/restore thiếu Preferences)
- [ ] **source path priority**: `sourcePath { rel, is_dir }`, candidates thử theo thứ tự (`Network/Cookies` → `Cookies`), match cả loại file/dir
- [ ] **timeEpoch**: Chromium base::Time µs-since-1601 → UTC (offset `11644473600000000`), guard epoch<=0 và year ngoài 1..9999 → zero time
- [ ] Chromium: đọc `Local State` (serde_json) → encrypted_key; extract theo loại:
  - password (`Login Data`, query + sort CreatedAt desc), cookie (schema cũ + mới; **stripCookieHash**: Chrome 130+ prepend SHA256(host_key) 32B — decrypt xong phải strip nếu match; samesite int→string: -1 unspecified/0 none/1 lax/2 strict; sort desc), history/download, bookmark JSON, extension (`Secure Preferences`), creditcard (`Web Data`), storage (LevelDB `Local Storage/leveldb`, `Session Storage` — key prefix `_` data / `META:` / `METAACCESS:`; format byte 0x00=UTF-16LE, 0x01=Latin-1; **truncate value ≥2048B**)
- [ ] **Opera**: extractor override extensions từ `opsettings`; flat profile layout
- [ ] **Yandex**: sources `Ya Passman Data`/`Ya Credit Cards`; pipeline `loadYandexDataKey`: gate master-password (missing `meta` table hoặc `sealed_key` rỗng → false; set → warn + skip) → `meta.value WHERE key='local_encryptor_data'` → tìm marker `v10` → AES-GCM decrypt 96B blob (nonce 12B + ct + tag 16B) → verify protobuf signature `08 01 12 20` → lấy 32B đầu = data key; per-row GCM AAD = `SHA1(origin_url \0 user_elem \0 user_val \0 pass_elem \0 signon_realm)` (password) / `guid` (creditcard); creditcards đọc table `records(guid, public_data, private_data)` JSON blobs
- [ ] `decrypt_value` dispatch v10/v11/v12/v20/DPAPI — port nguyên logic key-length dispatch (32B→GCM, 16B→CBC)
- [ ] **sqliteutil** (port y hệt): guard file tồn tại trước khi mở (tránh sqlite tạo file rỗng), scan-row lỗi → skip + debug log (ngược lại CountRows fail-fast), `PRAGMA journal_mode=off` flag (giữ API cho parity; chromium truyền false)
- [ ] **LevelDB reader** (Chromium Local + Session Storage): open dir leveldb (log + table files), iterate key/value, decode Snappy (crate `snap`) — port theo hành vi `goleveldb`
- [ ] **Verify**: fixture test với DB giả lập (SQLite temp theo schema thật, insert hàng đã encrypt bằng key mẫu, assert giá trị giải mã)

### Phase 2b — filemanager (Session + copyLocked) — Windows-critical
- [ ] `Session/Acquire` (session.go): temp dir per run; copy file + **WAL/SHM companion** (`-wal`, `-shm`); copy dir skip suffix `lock`; normal copy fail → fallback
- [ ] **copyLocked** (copy_windows.go): đọc file bị khoá độc quyền (Chrome `PRAGMA locking_mode=EXCLUSIVE`) qua `NtQuerySystemInformation(SystemHandleInformation)` → enumerate handle toàn hệ thống → match path (suffix từ `AppData\Local\`/`Roaming\`, fallback 3 component cuối) → `DuplicateHandle` → verify `GetFileType`==disk → `GetFinalPathNameByHandleW` match → đọc qua `CreateFileMapping`+`MapViewOfFile` (đọc cả WAL data từ kernel cache, gọn hơn ReadFile; ReadFile fallback)
- [ ] **Verify**: port 6 test của `copy_windows_test.go` (exclusive lock, write-then-read, large file 64KB, not-found, acquire fallback) + session tests

### Phase 3 — Keyring Windows (master keys)
- [ ] Trait `Retriever { fn retrieve(&self, hints) -> Option<Vec<u8>> }` + `MasterKeys { v10, v20 }` (v11 = Linux-only → bỏ; có `has_any`); `NewMasterKeys` join per-tier error, retriever trả `(nil, nil)` = tier không áp dụng
- [ ] `Hints { keychain_label (bỏ), windows_abe_key, local_state_path }`
- [ ] DPAPIRetriever: đọc Local State → `os_crypt.encrypted_key` → base64 → verify prefix `DPAPI` (5B) → `CryptUnprotectData` (CRYPTPROTECT_UI_FORBIDDEN) — unsafe nằm trong `abi`
- [ ] **Dump JSON schema** (dumpkeys): `{version:"2", created_at, host:{os,arch,hostname,user}, vaults:[{browser,kind("chromium"|"chromium-yandex"|"chromium-opera"), user_data_dir, profiles[], keys{v10,v20 base64}}]}`; WriteJSON indent 2sp; ReadJSON **strict version==2**, lỗi rõ nếu khác; vault bỏ khi `!has_any`
- [ ] ABE retriever (v20): detail ở Phase 5
- [ ] **Verify**: static retriever + round-trip encrypt/decrypt DPAPI trên CI Windows

### Phase 4 — Output + CLI hoàn chỉnh
- [ ] `Writer { dir, format }` + formatter trait; `Add(browser, profile, data)`; `Write()`: **aggregate per-category** → 1 file/category không rỗng (`password.csv`, `cookie.json`...), **format vào buffer trước** rồi mới tạo file (formatter rỗng → không tạo file), BOM `EF BB BF` chỉ cho CSV, summary log "Exported to X/" + từng file + count
- [ ] json: indent 2 spaces, `SetEscapeHTML(false)` parity, flat `{browser, profile, ...fields}` đúng thứ tự Go reflect
- [ ] csv: header `browser,profile,<fields>`, UTF-8 BOM, thứ tự cột y hệt
- [ ] **cookie-editor**: chỉ dùng cho CookieEntry, ngược lại fallback json; `expirationDate` = Unix float (0 → omit + session=true), `sameSite`: "none"→"no_restriction", ""/"unspecified"→null; `hostOnly` = host không bắt đầu "."; `httpOnly`/`secure`/`session` bool
- [ ] **fileutil zip 3 hành vi riêng biệt**: `CompressDir` (--zip: flatten basename, **xóa file gốc sau khi zip**), `ZipDir` (archive: giữ relative layout forward-slash, không xóa), `Unzip` (restore: **zip-slip guard**, file 0600); `FileExists`
- [ ] **CLI commands đầy đủ**:
  - `dump` (default): flags `-b -c -f -d -p --zip -v`; extractAndWrite port y hệt (log per-browser, lỗi extract không fail cả run)
  - **`dumpkeys`** (lưu ý: tên command là `dumpkeys`, không phải dump-keys!): `-b`, `-o` (mặc định stdout, file mode 0600), dùng DiscoverBrowsersWithKeys → BuildDump
  - **`restore`**: `--keys` (required; `-` = stdin), `--data-dir` XOR `--data-zip` (mutually exclusive); unzip vào temp rồi cleanup; BuildFromDump: layout detect archive (`<data-dir>/<browser>`) vs single User Data (cần `-b` khi nhiều vault), error khi filter không match vault
  - **`archive`**: `-b -c -o` (default browser-data.zip); Archivable → ArchiveSources (Local State + resolved sources/ + Preferences markers, rel forward-slash, dedup, skip phantom level cho flat layout) → staging qua session (Acquire xử lý file bị lock) → ZipDir → `<browser-key>/<rel>` layout
  - **`list`**: tabwriter 3 cột `Browser Profile Path`; `--detail` → cột per-category counts qua CountEntries (không decrypt)
  - `version`: commit 8 chars từ VCS + build date (Rust: `build.rs` chạy git, github-actions env — không có debug.ReadBuildInfo)
  - **double-click mode** (main_windows.go): detect Explorer-launch (mousetrap equivalent qua console/PPID check) → HideConsoleWindow (User32 ShowWindow SW_HIDE / FreeConsole)
- [ ] logging: level DBG/INF/WRN/ERR/FTL (`-v` → Debug); Fatal → exit(1); parity format
- [ ] **Verify**: golden-file test — chạy Go binary vs Rust binary trên cùng profile mẫu, diff output

### Phase 5 — Windows ABE v20 (App-Bound Encryption) — Phần khó nhất, làm sau cùng

#### Cơ chế ABE (tóm tắt từ repo Go)
Chrome 127+ gắn key master vào app identity → DPAPI hết hiệu lực. Repo Go **không phá mã hóa** mà
"mượn quyền giải mã hợp lệ" của chính browser: spawn browser thật ở trạng thái suspended (kèm temp
`--user-data-dir` để né ProcessSingleton), bơm reflective payload vào process, payload tự map chính
nó (base relocations → link IAT → section protections → DllMain), gọi COM `IElevator::DecryptData`
(CLSID/IID per-vendor, vtable slot 5=Chrome/Brave/CocCoc, 8=Edge, 13=Avast; IElevator2 rồi fallback
v1) với ciphertext `os_crypt.app_bound_encrypted_key` (prefix `APPB`), rồi publish 32-byte key +
status/err (marker 12-byte header) vào scratch region mà host đọc qua ReadProcessMemory.

#### Phân công port
- [ ] `keyring`/`abe.rs`: orchestrator — đọc Local State, verify prefix `APPB`, base64, set env `HBD_ABE_ENC_B64`, gọi injector, nhận key, check len==32 (Rust thuần, dễ)
- [ ] `abi`/`injector.rs`: CreateProcess (CREATE_SUSPENDED + UDD temp), VirtualAllocEx, WriteProcessMemory, ResumeThread + sleep 500ms, CreateRemoteThread, WaitForSingleObject (timeout 30s), ReadProcessMemory scratch, TerminateProcess — qua crate `windows` (trung bình)
- [ ] `abi`/`pe.rs` (pure Rust): parse PE bao gồm `DetectPEArch` (chỉ support amd64 → error nếu khác), `FindExportFileOffset(payload, "Bootstrap")` (RVA export → raw file offset) dùng để launch thread; port từ `injector/pe_windows.go`
- [ ] `abi`/`patch.rs`: `patch_preresolved_imports` — patch 5 function pointer vào DOS stub payload (nhờ KnownDlls + ASLR cùng session) (Rust thuần đọc/write bytes)
- [ ] `browser/winutil.rs`: browser meta — ExeName, InstallFallbacks (registry App Paths + fallback paths), `ABEKind`, valid `WindowsABE: true` (Rust thuần, dễ)
- [ ] **Payload C GIỮ NGUYÊN** (`abe_extractor.c`, `bootstrap.c`, `com_iid.c`, `bootstrap_layout.h` + Go-side layout constants): không viết lại Rust — phụ thuộc `__builtin_return_address` + `noinline`, không có runtime, COM vtable thủ công; mọi nỗ lực port là rủi ro không đáng. Build bằng `build.rs` gọi zig/cc → `abe_extractor_amd64.bin`, embed bằng `include_bytes!` (tương đương `//go:embed` + tag `abe_embed` của Go). Check layout offsets (`bootstrap_layout.h` low-level vs `layout.go` high-level) trùng khớp — sinh 1 lần bằng script, có test assert `size_of`/offset
- [ ] `chrome.exe` path resolution port từ `winutil/browser_path_windows.go` — **ExecutablePath 4-tier**: (1) registry App Paths HKLM → (2) HKCU → (3) probe process đang chạy (EnumProcesses + QueryFullProcessImageNameW, match leaf name case-insensitive) → (4) InstallFallbacks (expand `%ProgramFiles%` qua ExpandEnvironmentStringsW)
- [ ] ABE session key → localStorage leveldb decrypt (DPAPI + entropy) — port logic `LocalState`-independent
- [ ] **Verify**: chỉ test thủ công trên máy Windows có Chrome 127+ (không có fixture an toàn). Fallback nếu thất bại: giữ DPAPI v10 + trả lỗi rõ khi gặp ciphertext v20 (như Go phiên bản cũ)

### Phase 6 — Parity & hardening
- [ ] Chạy cả 2 binary trên cùng profile thật + **mọi subcommand** (lesson Bun: loop qua từng subcommand: dump/dumpkeys/archive/restore/list/version) → `diff` output & counts
- [ ] Port toàn bộ test Go còn lại (R5: 0 test bị bỏ); rà lại test nào đang skip vì lý do gì
- [ ] `cargo clippy -- -D warnings`, fmt, audit deps, release profile (LTO, strip, panic=abort, tối ưu kích thước cho binary portable)
- [ ] Đọc lại `rfcs/` trong repo Go — port các RFC đang active
- [ ] Refactor idiomatic Rust (chỉ SAU khi parity xanh — R0): giảm unsafe, tách module, cleanup

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
| **ABE v20 (reflective PE injection + payload encryption)** | Cao nhất | Defer Phase 5; isolate toàn bộ unsafe trong `abi`; test thủ công trên Chrome 127+. Fallback: DPAPI v10 + lỗi rõ khi gặp v20. |
| **copyLocked (file bị khoá độc quyền)** | Cao | NtQuerySystemInformation + DuplicateHandle + FileMapping — nhiều unsafe; port test có sẵn trong `copy_windows_test.go`; đơn giản hoá: fallback trả lỗi rõ nếu handle không tìm thấy (Go cũng vậy — lỗi rõ, không panic) |
| **LevelDB reader (Chromium storage)** | Trung bình | Tự viết tối thiểu log+table, xử lý Snappy (`snap` crate); verify bằng fixture LevelDB dir thật |
| `reflect`-based output parity | Trung bình | Snapshot JSON/CSV chính xác thứ tự field (Go reflect order = struct order — Rust struct order giống hệt). |
| Chromium v12 (SecretPortal) | Thấp | Linux-only → không cần implement; giữ error "unsupported" giống Go. |
| Glob profile `*` (Arc/DuckDuckGo) | Thấp | crate `glob`, port logic `resolve_globs`. |
| DPAPI entropy/scope khác phiên bản | Thấp | Dùng đúng flags `CRYPTPROTECT_UI_FORBIDDEN`; test round-trip trên CI Windows. |

## 6. Ước lượng & thứ tự làm

```
Phase 0-1 (core + crypto)   → nền móng, test sớm nhất
Phase 2 (chromium extract)  → giá trị nhất, toàn bộ browsers Windows (kèm 2b: filemanager/copyLocked)
Phase 3 (DPAPI keyring)     → mở khóa được v10 (chiếm phần lớn dữ liệu)
Phase 4 (output + CLI)      → MVP dùng được: dump/dumpkeys/archive/restore/list/version === Go binary (trừ Chrome 127+ / v20)
Phase 5 (ABE v20)           → phủ Chrome 127+, Edge, Brave trên Windows (phần còn thiếu)
Phase 6 (parity)            → đóng gói
```

Checkpoint "MVP dùng được": sau Phase 4, `LemonStealer dump -b chrome -c all -f json` output
khớp Go binary trên Windows cho profile pre-127. Sau Phase 5: khớp cả Chrome 127+ (v20).