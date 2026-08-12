//! Port of `crypto/crypto.go` — `DecryptChromiumGCM`, `DecryptChromiumCBC`, `kEmptyKey`
//! (Go: `kEmptyKey` lives in crypto.go; `decryptValue` dispatch is Phase 2, chromium.rs).

use std::sync::OnceLock;

use crate::pbkdf2::pbkdf2_sha1;
use crate::{CHROMIUM_CBC_IV, CryptoError, GCM_NONCE_SIZE, VERSION_PREFIX_LEN, aead, aes_cbc};

/// Chromium's decrypt-only fallback for data corrupted by a KWallet race in Chrome ~89
/// (crbug.com/40055416). Matches `kEmptyKey` in os_crypt_linux.cc.
///
/// Not Firefox-only: `DecryptChromiumCBC` retries with this key exactly like Go.
fn k_empty_key() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| pbkdf2_sha1(b"", b"saltysalt", 1, 16))
}

/// Decrypts a prefixed AES-GCM blob: version(3B)+nonce(12B)+ct+tag
/// (Go: `DecryptChromiumGCM`). Used by Windows v10 (AES-256) and v20; the layout is
/// identical and platform-neutral.
pub fn decrypt_chromium_gcm(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < VERSION_PREFIX_LEN + GCM_NONCE_SIZE {
        return Err(CryptoError::ShortCiphertext);
    }
    let nonce = &ciphertext[VERSION_PREFIX_LEN..VERSION_PREFIX_LEN + GCM_NONCE_SIZE];
    let payload = &ciphertext[VERSION_PREFIX_LEN + GCM_NONCE_SIZE..];
    aead::aes_gcm_decrypt(key, nonce, payload)
}

/// Decrypts a prefixed AES-CBC blob (version(3B)+ct) with Chromium's fixed IV,
/// retrying with `kEmptyKey` to recover crbug.com/40055416 KWallet-corrupted data
/// (Go: `DecryptChromiumCBC`). macOS/Linux v10 and Linux v11 — kept for parity and
/// cross-platform fixtures even though this build targets Windows.
pub fn decrypt_chromium_cbc(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < VERSION_PREFIX_LEN + 16 {
        return Err(CryptoError::ShortCiphertext);
    }
    let payload = &ciphertext[VERSION_PREFIX_LEN..];
    match aes_cbc::aes_cbc_decrypt(key, &CHROMIUM_CBC_IV, payload) {
        Ok(plaintext) => Ok(plaintext),
        Err(err) => match aes_cbc::aes_cbc_decrypt(k_empty_key(), &CHROMIUM_CBC_IV, payload) {
            Ok(alt) => Ok(alt),
            Err(_) => Err(err),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_KEY: &[u8] = b"moond4rk";

    fn key32() -> Vec<u8> {
        [BASE_KEY, BASE_KEY, BASE_KEY, BASE_KEY].concat()
    }
    fn aes_gcm_nonce() -> Vec<u8> {
        [BASE_KEY, BASE_KEY].concat()[..12].to_vec()
    }

    // Port of TestDecryptChromiumGCM_CrossPlatform.
    #[test]
    fn decrypt_chromium_gcm_cross_platform() {
        let plaintext = b"windows_v10_value";
        let gcm = aead::aes_gcm_encrypt(&key32(), &aes_gcm_nonce(), plaintext).unwrap();
        let mut ciphertext = b"v10".to_vec();
        ciphertext.extend_from_slice(&aes_gcm_nonce());
        ciphertext.extend_from_slice(&gcm);
        assert_eq!(
            plaintext.as_slice(),
            decrypt_chromium_gcm(&key32(), &ciphertext).unwrap()
        );
    }

    // Port of TestDecryptChromiumCBC_CrossPlatform.
    #[test]
    fn decrypt_chromium_cbc_cross_platform() {
        let plaintext = b"posix_v10_value";
        let enc =
            aes_cbc::aes_cbc_encrypt(&[BASE_KEY, BASE_KEY].concat(), &CHROMIUM_CBC_IV, plaintext)
                .unwrap();
        let mut ciphertext = b"v10".to_vec();
        ciphertext.extend_from_slice(&enc);
        assert_eq!(
            plaintext.as_slice(),
            decrypt_chromium_cbc(&[BASE_KEY, BASE_KEY].concat(), &ciphertext).unwrap()
        );
    }

    // Port of TestKEmptyKey_MatchesChromium (kept here where the fallback lives).
    #[test]
    fn k_empty_key_matches_chromium() {
        let want: [u8; 16] = [
            0xd0, 0xd0, 0xec, 0x9c, 0x7d, 0x77, 0xd4, 0x3a, 0xc5, 0x41, 0x87, 0xfa, 0x48, 0x18,
            0xd1, 0x7f,
        ];
        assert_eq!(want.to_vec(), k_empty_key());
        assert_eq!(16, k_empty_key().len());
    }

    // Port of TestDecryptChromiumCBC_EmptyKeyFallback.
    #[test]
    fn decrypt_chromium_cbc_empty_key_fallback() {
        let plaintext = b"legacy_kwallet_value";
        let encrypted =
            aes_cbc::aes_cbc_encrypt(k_empty_key(), &CHROMIUM_CBC_IV, plaintext).unwrap();
        let mut ciphertext = b"v11".to_vec();
        ciphertext.extend_from_slice(&encrypted);

        let wrong_key = [0xAAu8; 16];
        assert_eq!(
            plaintext.as_slice(),
            decrypt_chromium_cbc(&wrong_key, &ciphertext).unwrap()
        );
    }

    // Port of TestDecryptChromium_ShortCiphertext.
    #[test]
    fn decrypt_chromium_short_ciphertext() {
        // GCM minimum is prefix(3)+nonce(12) = 15 bytes.
        assert_eq!(
            Err(CryptoError::ShortCiphertext),
            decrypt_chromium_gcm(&key32(), b"v10nonce11")
        );
        // CBC minimum is prefix(3)+block(16) = 19 bytes.
        assert_eq!(
            Err(CryptoError::ShortCiphertext),
            decrypt_chromium_cbc(&[BASE_KEY, BASE_KEY].concat(), b"v11short")
        );
    }
}
