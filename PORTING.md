# PORTING.md — Go → Rust mapping (bắt buộc khi port)

Nguồn: `D:\Code\rust\HackBrowserData` (@moond4rk/hackbrowserdata, go 1.20)
Đích: workspace `LemonStealer` (`crates/*`), **Windows-only, Chromium-only**.

Đây là bảng mapping **bắt buộc** (PLAN.md R0): port theo hành vi, không phải cú pháp.
Khi port file nào, dùng đúng dòng trong bảng này. Nếu cần lệch, ghi chú lý do.

## 0. Nguyên tắc chung

- Port **cơ học**: 1 file Go → 1 file Rust cùng tên/cùng module (`types/category.go` →
  `crates/core/src/category.rs`). Không thiết kế lại trong lúc port (R0).
- Mọi unsafe/WinAPI **chỉ** được nằm ở `crates/abi` (R4). Workspace đã `forbid unsafe`
  toàn cục; abi override và ghi `// SAFETY:` cho từng block.
- Rust phải biên dịch với `cargo clippy -- -D warnings` (CI từ Phase 0).
- **Không có** `unwrap()/expect()/panic!` ngoài test (R3). Entry-level lỗi → skip +
  `log::warn/debug`, không fail cả profile.

## 1. Bảng mapping Go → Rust

| Go | Rust | Ghi chú |
|---|---|---|
| `type Category int` + `iota` | `struct Category(i32)` + associated consts | Giữ khả năng `Category(999)` như Go (test parity). `String()` default arm = `"unknown"` |
| `type BrowserKind int` | `enum BrowserKind` + `Display` | Wire form của keys dump: `chromium`/`chromium-yandex`/`chromium-opera` — không đổi |
| `type X struct { F string \`json:"f"\` }` | `struct X { f: String }` + `derive(Serialize, Deserialize)` | Field order = thứ tự Go (output reflect-flatten phụ thuộc) |
| `time.Time` | `core::time::ChromeTime(DateTime<Utc>)` | Zero = `0001-01-01T00:00:00Z` (KHÔNG phải Unix epoch); JSON = RFC3339Nano, fraction trim, `Z`. Dùng `ChromeTime::from_chromium_micros` cho base::Time µs-since-1601 |
| interface | `trait` (object-safe) | `Browser`, `KeyManager`, `Archivable`, `Retriever` |
| `nil` slice/pointer | `Option<T>` / `Vec::new()` | `(nil, nil)` retriever = `Ok(None)` = "tier not applicable" |
| `error` (open) | `thiserror` enum + `Box<dyn Error + Send + Sync>` | `RetrieverError::Other` cho lỗi ngoài |
| `errors.Join(errs...)` | `Vec<Error>` hoặc join string | `new_master_keys` join kèm tier name: `"v10: <err>"` |
| `sort.Slice` (KHÔNG stable) | `slice::sort_by` (stable) | Lệch thứ tự entries bằng key khi diff parity — chấp nhận + ghi chú |
| `json.Encoder SetIndent("", "  ")` | `serde_json::to_string_pretty` | Cần kiểm tra khác biệt escaping HTML: Go `SetEscapeHTML(false)` vs serde_json mặc định escape `<>&` → Phase 4 phải xử lý (post-process `\u003c`→`<` hoặc custom serializer) |
| `gjson` (lỏng) | `serde_json::Value` | `.Exists()` true với mọi path parse-được → kiểm tra `Value::Null`/missing đúng như Go |
| `time.Time.MarshalJSON` | `ChromeTime` custom `Serialize` | Zero → `"0001-01-01T00:00:00Z"`; year ngoài 1..=9999 → zero |
| `os.MkdirAll` | `std::fs::create_dir_all` | Tương đương |
| `filepath.Glob` | crate `glob` | Phim `*` cho Arc/DuckDuckGo (Phase 2) |
| `reflect` (output flatten) | struct field order + `serde` | Go reflect order = struct order → giữ struct order |
| `io.Writer` | `&mut dyn Write` / `Box<dyn Write>` | – |
| `sync.Once` | `OnceLock` | `k_empty_key()` |
| `time.Now().UTC()` | `Utc::now()` | chrono |
| `strings.EqualFold` | `eq_ignore_ascii_case` | Category "all" parse |
| `%q` trong error | `{:?}` trên String | `unknown category: "x", ...` |
| `0o600` file mode | `OpenOptions` + `PermissionsExt` | dumpkeys output |
| `//go:embed` payload | `include_bytes!` | ABE payload (Phase 5) |
| `debug.ReadBuildInfo` | `build.rs` + env vars | version command (Phase 4) |
| `expand env %VAR%` | **KHÔNG dùng `std::env`** | kernel32 `ExpandEnvironmentStringsW` qua abi (Phase 5) |

## 2. Bẫy semantic (đã biết — R2)

1. **sort stability**: Go `sort.Slice` không stable, Rust `sort_by` stable → entries
   "bằng nhau" có thể lệch thứ tự khỏi Go. Chấp nhận; ghi chú khi diff parity.
2. **serde_json Map**: mặc định BTreeMap (sorted). Row JSON phải giữ thứ tự field như
   Go — dùng struct (không dùng map) cho row.
3. **HTML escape**: serde_json luôn escape `<>&` (`\u003c`…). Go `SetEscapeHTML(false)`
   không escape. Phase 4 phải bù.
4. **CBC padding**: `cbc::block_padding::Pkcs7` == Go's pkcs5 (PKCS7 trên AES-128).
5. **DKIM**: GCM nonce luôn 12B (Chromium). `aes-gcm` crate `U12`.
6. **ChromeTime zero vs 1970**: `DateTime<Utc>::default()` = 1970 — KHÔNG dùng, luôn
   `ChromeTime::zero()` (year 1).
7. **`expand` env**: Windows `%VAR%` không tự expand — gọi kernel32 qua abi.
8. **`readdir` order**: filesystem-dependent; Go sort profile dirs? → đối chiếu
   chromium.go khi port profile discovery (Phase 2).
9. **3DES/DES**: Safari-only → đã bỏ (không port). Firefox NSS PBE/ASN.1 → bỏ.

## 3. Layer dependency (cấm vòng — R1)

```
core ← crypto ← keyring ← browser ← cli
abi (đáy, dùng bởi keyring/browser/filemanager)
```

- `core` không depend gì (chỉ serde/chrono).
- `crypto` pure Rust, tuyệt đối không windows-API.
- `browser` depend `core` + `keyring` + (sau) `filemanager`/`abi` → nhưng `abi` không
  depend ngược lại.
- `cli` depend mọi thứ (boundary, dùng `anyhow`).
- CI chạy `cargo machete`/`cargo-udeps` + `cargo check --workspace`.

## 4. Test conventions

- Port **toàn bộ** test Go, 0 test bỏ (R5). Test bỏ/lệch lý do phải có comment:
  - `DES3*` tests → Safari-only, đã bỏ khỏi plan.
  - `TestDump*/TestArchive*` → port ở phase của nó.
- Test vector từ `*_test.go`: key/ciphertext/plaintext có sẵn, không tự bịa.
- `#[cfg(test)] mod tests` đặt trong từng file (đối chiếu `*_test.go` cùng file).

## 5. Commit conventions

- Phase = chuỗi commit nhỏ; mỗi commit `cargo build` + `cargo test` + clippy pass.
- Không commit thay đổi repo Go gốc; không copy fixture >5MB vào git.