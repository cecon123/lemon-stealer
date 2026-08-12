//! Port of Go package `crypto` (Windows + Chromium-only subset).
//!
//! Pure Rust, no unsafe. Dropped for this build (PLAN.md §2 "Bỏ khỏi plan"):
//! DES/3DES (Safari-only), ASN.1 PBE / NSS (Firefox-only).
//!
//! `decrypt_dpapi` delegates to `abi::dpapi` on Windows (Go:
//! crypto_windows.go → utils/winapi) and returns a not-supported error elsewhere.

pub mod aead;
pub mod aes_cbc;
pub mod chromium;
pub mod errors;
pub mod pbkdf2;
pub mod version;
pub mod yandex;

pub use aes_cbc::{aes_cbc_decrypt, aes_cbc_encrypt};
pub use chromium::{decrypt_chromium_cbc, decrypt_chromium_gcm};
pub use errors::CryptoError;
pub use version::{CipherVersion, detect_version, strip_prefix};
pub use yandex::decrypt_yandex_intermediate_key;

/// AES-GCM standard nonce size used by Chromium's v10/v20 cipher formats.
/// Cross-platform: the v20 ciphertext layout is identical regardless of host OS.
pub const GCM_NONCE_SIZE: usize = 12;

/// Length of the version prefix on Chromium ciphertexts ("v10", "v11", ...).
pub const VERSION_PREFIX_LEN: usize = 3;

/// The fixed IV Chromium uses for AES-CBC v10/v11 (Go: `chromiumCBCIV`).
pub const CHROMIUM_CBC_IV: [u8; 16] = [0x20; 16];

/// Decrypts a DPAPI-protected blob using the current user's master key.
///
/// Signature matches Go exactly (`crypto.DecryptDPAPI(ciphertext)` — no entropy
/// argument; Chrome's os_crypt v10 uses user-scope DPAPI without it).
/// Non-Windows targets behave like Go's darwin/linux stubs.
#[cfg(not(windows))]
pub fn decrypt_dpapi(_ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::DpapiNotSupported)
}

#[cfg(windows)]
pub fn decrypt_dpapi(ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    abi::decrypt_dpapi(ciphertext).map_err(|e| CryptoError::Dpapi(e.to_string()))
}
