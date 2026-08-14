//! ABE payload embedding + scratch-layout constants (Go: `crypto/windows/payload`
//! `//go:embed` + `abe_native/bootstrap/layout.go`).
//!
//! The payload binary (`abe_extractor_amd64.bin`, built from the C sources in
//! `../abe_native/` — kept byte-identical to the Go repo, MINUS toolchain:
//! build via `zig cc` as in the Go `Makefile.frag`) is embedded here. The
//! numeric offsets below are the Rust mirror of `bootstrap_layout.h` (the
//! single source of truth for the C side); `#[test]`s pin them so any drift
//! breaks the build (Go keeps the same guarantee via cgo -godefs + _Static_assert).

/// Compiled reflective ABE payload (amd64). Go: `abePayloadAmd64` (//go:embed).
pub const PAYLOAD_AMD64: &[u8] = include_bytes!("../payload/abe_extractor_amd64.bin");

/// `offsetof(BootstrapScratch, marker)` — progress marker during Bootstrap.
pub const MARKER_OFFSET: usize = 0x28;
/// `offsetof(BootstrapScratch, key_status)` — 0x01 = key ready.
pub const KEY_STATUS_OFFSET: usize = 0x29;
pub const KEY_STATUS_READY: u8 = 0x01;
/// `offsetof(BootstrapScratch, extract_err_code)` — ABE_ERR_* category.
pub const EXTRACT_ERR_CODE_OFFSET: usize = 0x2A;
/// `offsetof(BootstrapScratch, hresult)` — COM HRESULT on failure (LE u32).
pub const HRESULT_OFFSET: usize = 0x2C;
/// `offsetof(BootstrapScratch, com_err)` — DecryptData out DWORD (LE u32).
pub const COMERR_OFFSET: usize = 0x30;
/// Key lands at shared.key — the same region the import pointers occupy
/// pre-Bootstrap (time-shared union, see bootstrap_layout.h).
pub const KEY_OFFSET: usize = 0x40;
pub const KEY_LEN: usize = 32;

/// Pre-resolved import pointer slots (patch.rs writes, Bootstrap reads).
pub const IMP_LOADLIBRARYA_OFFSET: usize = 0x40;
pub const IMP_GETPROCADDRESS_OFFSET: usize = 0x48;
pub const IMP_VIRTUALALLOC_OFFSET: usize = 0x50;
pub const IMP_VIRTUALPROTECT_OFFSET: usize = 0x58;
pub const IMP_NTFLUSHIC_OFFSET: usize = 0x60;

/// Bootstrap progress markers (written by bootstrap.c).
pub const MARK_MZ_FOUND: u8 = 0x02;
pub const MARK_IMPORTS_OK: u8 = 0x05;
pub const MARK_ALLOC_OK: u8 = 0x06;
pub const MARK_COPIED: u8 = 0x07;
pub const MARK_RELOCATED: u8 = 0x08;
pub const MARK_IMPORTS_FIXED: u8 = 0x09;
pub const MARK_PERMISSIONS: u8 = 0x0A;
pub const MARK_CACHE_FLUSHED: u8 = 0x0B;
pub const MARK_DONE: u8 = 0xFF;
pub const MARK_ERR_IMPORTS: u8 = 0xE3;
pub const MARK_ERR_ALLOC: u8 = 0xE4;

/// ABE failure categories (written by abe_extractor.c).
pub const ABE_ERR_OK: u8 = 0x00;
pub const ABE_ERR_BASENAME: u8 = 0x01;
pub const ABE_ERR_BROWSER_UNKNOWN: u8 = 0x02;
pub const ABE_ERR_ENV_MISSING: u8 = 0x03;
pub const ABE_ERR_BASE64: u8 = 0x04;
pub const ABE_ERR_BSTR_ALLOC: u8 = 0x05;
pub const ABE_ERR_COM_CREATE: u8 = 0x06;
pub const ABE_ERR_DECRYPT_DATA: u8 = 0x07;
pub const ABE_ERR_KEY_LEN: u8 = 0x08;

/// Human-readable failure category (Go: `formatABEError` builds
/// "status/err(hresult/com_err)" — the caller formats; here just the name).
pub fn abe_err_name(code: u8) -> &'static str {
    match code {
        ABE_ERR_OK => "ok",
        ABE_ERR_BASENAME => "basename",
        ABE_ERR_BROWSER_UNKNOWN => "browser_unknown",
        ABE_ERR_ENV_MISSING => "env_missing",
        ABE_ERR_BASE64 => "base64",
        ABE_ERR_BSTR_ALLOC => "bstr_alloc",
        ABE_ERR_COM_CREATE => "com_create",
        ABE_ERR_DECRYPT_DATA => "decrypt_data",
        ABE_ERR_KEY_LEN => "key_len",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Numeric pins are the Rust mirror of bootstrap_layout.h's _Static_asserts.
    #[test]
    fn layout_offsets_match_bootstrap_layout_h() {
        assert_eq!(0x28, MARKER_OFFSET, "marker offset");
        assert_eq!(0x29, KEY_STATUS_OFFSET, "key_status offset");
        assert_eq!(0x2A, EXTRACT_ERR_CODE_OFFSET, "extract_err_code offset");
        assert_eq!(0x2C, HRESULT_OFFSET, "hresult offset");
        assert_eq!(0x30, COMERR_OFFSET, "com_err offset");
        assert_eq!(0x40, KEY_OFFSET, "shared/key offset");
        assert_eq!(32, KEY_LEN, "key length");
        assert_eq!(0x40, IMP_LOADLIBRARYA_OFFSET, "import LoadLibraryA slot");
        assert_eq!(
            0x48, IMP_GETPROCADDRESS_OFFSET,
            "import GetProcAddress slot"
        );
        assert_eq!(0x50, IMP_VIRTUALALLOC_OFFSET, "import VirtualAlloc slot");
        assert_eq!(
            0x58, IMP_VIRTUALPROTECT_OFFSET,
            "import VirtualProtect slot"
        );
        assert_eq!(
            0x60, IMP_NTFLUSHIC_OFFSET,
            "import NtFlushInstructionCache slot"
        );
    }

    #[test]
    fn payload_is_embedded_and_sane() {
        assert!(
            PAYLOAD_AMD64.starts_with(b"MZ"),
            "payload must be a PE image"
        );
        assert!(
            PAYLOAD_AMD64.len() > IMP_NTFLUSHIC_OFFSET + 8,
            "payload big enough for the import patch"
        );
    }

    #[test]
    fn import_patch_region_overlaps_key_region_by_design() {
        // bootstrap_layout.h documents the union: imports at 0x40..0x68 are
        // overwritten by the 32-byte key at 0x40..0x60 post-DllMain. The Rust
        // constants must agree so patch.rs and the injector's scratch read
        // are consistent.
        assert_eq!(KEY_OFFSET, IMP_LOADLIBRARYA_OFFSET);
        // Imports occupy 0x40..0x68 (5 x 8B). The key overwrites 0x40..0x60,
        // ending exactly where the persisting NtFlushInstructionCache slot starts.
        assert_eq!(KEY_OFFSET + KEY_LEN, IMP_NTFLUSHIC_OFFSET);
    }

    #[test]
    fn abe_error_names_cover_all_codes() {
        for code in 0x00..=0x08 {
            assert_ne!("unknown", abe_err_name(code), "code {code:#x}");
        }
        assert_eq!("unknown", abe_err_name(0xEE));
    }
}
