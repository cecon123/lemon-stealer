//! Port of Go package `crypto` (Windows + Chromium-only subset).
//!
//! Pure Rust, no unsafe. Dropped for this build (PLAN.md §2 "Bỏ khỏi plan"):
//! DES/3DES (Safari-only), ASN.1 PBE / NSS (Firefox-only).
//!
//! `decrypt_dpapi` is stubbed here and implemented in `keyring`/`abi` when the
//! Windows plumbing lands (Phase 1/3).

pub mod aead;
pub mod aes_cbc;
pub mod chromium;
pub mod errors;
pub mod pbkdf2;
pub mod version;

pub use aes_cbc::{aes_cbc_decrypt, aes_cbc_encrypt};
pub use chromium::{decrypt_chromium_cbc, decrypt_chromium_gcm};
pub use errors::CryptoError;
pub use version::{CipherVersion, detect_version, strip_prefix};

/// AES-GCM standard nonce size used by Chromium's v10/v20 cipher formats.
/// Cross-platform: the v20 ciphertext layout is identical regardless of host OS.
pub const GCM_NONCE_SIZE: usize = 12;

/// Length of the version prefix on Chromium ciphertexts ("v10", "v11", ...).
pub const VERSION_PREFIX_LEN: usize = 3;

/// The fixed IV Chromium uses for AES-CBC v10/v11 (Go: `chromiumCBCIV`).
pub const CHROMIUM_CBC_IV: [u8; 16] = [0x20; 16];

/// Port of Go `decrypt_dpapi`: delegates to the OS DPAPI wrapper.
///
/// Phase 1 stub: only reachable on Windows once `abi` lands; on every other target
/// it returns [`CryptoError::DpapiNotSupported`] exactly like Go's darwin/linux stubs.
#[cfg(not(windows))]
pub fn decrypt_dpapi(_ciphertext: &[u8], _entropy: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::DpapiNotSupported)
}

#[cfg(windows)]
pub fn decrypt_dpapi(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Phase 3: port crypto_windows.go over `windows` crate (CryptUnprotectData with
    // CRYPTPROTECT_UI_FORBIDDEN), exclusively inside crates/abi.
    let _ = (ciphertext, entropy);
    Err(CryptoError::DpapiNotSupported)
}
