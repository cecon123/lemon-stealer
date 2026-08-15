//! DPAPI wrapper — port of `utils/winapi/dpapi_windows.go` (Go's `DecryptDPAPI`).
//!
//! Calls `CryptUnprotectData` (crypt32) with the caller's ciphertext and copies the
//! output out of the OS-owned allocation before `LocalFree` (kernel32), so no
//! dangling pointer ever escapes this module.
//!
//! Invariant mirrors Go: `dwFlags = 0` (no `CRYPTPROTECT_UI_FORBIDDEN` — the Go
//! caller passes zero; DPAPI never prompts for Chrome's user-scope blobs).
//! No optional entropy: Chrome's os_crypt v10 uses user-scope DPAPI without it.
//!
//! Note: windows-rs ≥0.61 names `DATA_BLOB` `CRYPT_INTEGER_BLOB`; same layout
//! (`{ cbData: u32, pbData: *mut u8 }`).

use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;
use windows::core::{Error, HRESULT, PCWSTR};

use crate::AbiError;
use crate::apitable::{crypt32, kernel32};

/// Win32 error code → `windows::core::Error` (windows-core 0.62 dropped
/// `Error::from_win32`; HRESULT::from_win32 is the sanctioned conversion).
fn win32_err() -> Error {
    Error::from_hresult(HRESULT::from_win32(
        unsafe { (kernel32().get_last_error)() }.0,
    ))
}

/// Builds a blob borrowing `bytes`. Like Go's `newBlob`, an empty input is allowed:
/// `cbData = 0` and the pointer is never dereferenced by the callee.
fn blob_from_bytes(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    }
}

/// Decrypts a DPAPI-protected blob using the current user's master key
/// (Go: `winapi.DecryptDPAPI`, called from `crypto.DecryptDPAPI`).
pub fn decrypt_dpapi(ciphertext: &[u8]) -> Result<Vec<u8>, AbiError> {
    let in_blob = blob_from_bytes(ciphertext);
    let mut out_blob = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `in_blob` borrows `ciphertext` for the duration of the call and
    // CryptUnprotectData does not retain it after returning. `out_blob` is
    // zero-initialized; on success the callee replaces it with a freshly
    // LocalAlloc'd buffer (cbData + pbData) that we copy out and free below.
    // Params 2-5 mirror Go's all-zero arguments (description/entropy/reserved/
    // prompt all NULL, dwFlags = 0). Raw ABI returns BOOL, not Result.
    let c = crypt32();
    let ok = unsafe {
        (c.crypt_unprotect_data)(
            &in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out_blob,
        )
    };

    if ok.as_bool() {
        // SAFETY: on success, out_blob.pbData points to a LocalAlloc'd buffer
        // of out_blob.cbData bytes owned by us until LocalFree below; the
        // bounds come from the OS, not from our input.
        let out = unsafe {
            std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
        };
        // SAFETY: LocalFree releases the buffer allocated by CryptUnprotectData;
        // `out` is an independent copy, so freeing here cannot dangle it.
        unsafe {
            (kernel32().local_free)(HLOCAL(out_blob.pbData.cast()));
        }
        Ok(out)
    } else {
        Err(AbiError::CryptUnprotectData(win32_err()))
    }
}

/// Protects a blob with the current user's DPAPI master key
/// (Go: `CryptProtectData`; the inverse of [`decrypt_dpapi`]).
///
/// Public so keyring's DPAPI retriever tests can build a real fixture
/// (PLAN.md Phase 3: "round-trip encrypt/decrypt DPAPI trên CI Windows").
pub fn protect_dpapi(plaintext: &[u8]) -> Result<Vec<u8>, AbiError> {
    let in_blob = blob_from_bytes(plaintext);
    let mut out_blob = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `in_blob` borrows `plaintext` for the duration of the call and
    // CryptProtectData does not retain it after returning. `out_blob` is
    // zero-initialized; on success the callee fills it with a freshly
    // LocalAlloc'd buffer (cbData + pbData) that we copy out and free below.
    let c = crypt32();
    let ok = unsafe {
        (c.crypt_protect_data)(
            &in_blob,
            PCWSTR::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out_blob,
        )
    };

    if ok.as_bool() {
        // SAFETY: on success, out_blob.pbData points to a LocalAlloc'd buffer
        // of out_blob.cbData bytes owned by us until LocalFree below; the
        // bounds come from the OS, not from our input.
        let out = unsafe {
            std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
        };
        // SAFETY: LocalFree releases the buffer allocated by CryptProtectData;
        // `out` is an independent copy, so freeing here cannot dangle it.
        unsafe {
            (kernel32().local_free)(HLOCAL(out_blob.pbData.cast()));
        }
        Ok(out)
    } else {
        Err(AbiError::CryptProtectData(win32_err()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reverse of `decrypt_dpapi` for round-trip testing (Go: `encryptWithDPAPI`
    /// in browser/chromium/decrypt_windows_test.go). Same dwFlags = 0 contract.
    fn protect(bytes: &[u8]) -> Result<Vec<u8>, AbiError> {
        protect_dpapi(bytes)
    }

    // Port of the DPAPI round-trip coverage from decrypt_windows_test.go
    // (TestDecryptValue_DPAPI uses the same protect/unprotect pair).
    #[test]
    fn dpapi_round_trip() {
        let plaintext = b"test_dpapi_secret";
        let blob = protect(plaintext).unwrap();
        assert_eq!(
            plaintext.as_slice(),
            decrypt_dpapi(&blob).unwrap().as_slice()
        );
    }

    #[test]
    fn dpapi_round_trip_empty() {
        let blob = protect(b"").unwrap();
        assert_eq!(0, decrypt_dpapi(&blob).unwrap().len());
    }

    #[test]
    fn dpapi_wrong_blob_fails() {
        // Garbage that is not a valid DPAPI blob must error, not panic.
        assert!(decrypt_dpapi(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err());
    }
}
