//! Port of `crypto/crypto.go` — AES-GCM primitives (Go: `AESGCMEncrypt`, `AESGCMDecrypt`,
//! `AESGCMDecryptBlob`).

use aes::Aes128;
use aes::Aes256;
use aes::cipher::KeyInit;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce};

use crate::{CryptoError, GCM_NONCE_SIZE};

/// Encrypts data using AES-GCM mode (Go: `AESGCMEncrypt`).
///
/// Go accepts any valid AES key size; Chromium only ever uses 16/32, so restrict
/// to those and reject the rest like `aes.NewCipher` would.
pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != GCM_NONCE_SIZE {
        return Err(CryptoError::InvalidNonceLen);
    }
    let out = match key.len() {
        16 => {
            let cipher = Aes128Gcm::new(Key::<Aes128>::from_slice(key));
            cipher
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|_| CryptoError::AeadAuthFailed)?
        }
        32 => {
            let cipher = Aes256Gcm::new(Key::<Aes256>::from_slice(key));
            cipher
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|_| CryptoError::AeadAuthFailed)?
        }
        n => return Err(CryptoError::InvalidKeyLength(n)),
    };
    Ok(out)
}

/// Decrypts data using AES-GCM mode (Go: `AESGCMDecrypt`).
pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != GCM_NONCE_SIZE {
        return Err(CryptoError::InvalidNonceLen);
    }
    let out = match key.len() {
        16 => {
            let cipher = Aes128Gcm::new(Key::<Aes128>::from_slice(key));
            cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| CryptoError::AeadAuthFailed)?
        }
        32 => {
            let cipher = Aes256Gcm::new(Key::<Aes256>::from_slice(key));
            cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| CryptoError::AeadAuthFailed)?
        }
        n => return Err(CryptoError::InvalidKeyLength(n)),
    };
    Ok(out)
}

/// Decrypts a blob shaped as `[12B nonce][ciphertext+16B GCM tag]` with caller-supplied
/// AAD (Go: `AESGCMDecryptBlob` — Yandex passwords/cards).
pub fn aes_gcm_decrypt_blob(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < GCM_NONCE_SIZE {
        return Err(CryptoError::ShortCiphertext);
    }
    aes_gcm_decrypt_with_aad(key, &blob[..GCM_NONCE_SIZE], &blob[GCM_NONCE_SIZE..], aad)
}

/// Decrypt with AAD support (AEAD `Open` with associated data) — used by Yandex AAD paths.
pub fn aes_gcm_decrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != GCM_NONCE_SIZE {
        return Err(CryptoError::InvalidNonceLen);
    }
    let out = match key.len() {
        16 => {
            let cipher = Aes128Gcm::new(Key::<Aes128>::from_slice(key));
            cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadAuthFailed)?
        }
        32 => {
            let cipher = Aes256Gcm::new(Key::<Aes256>::from_slice(key));
            cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadAuthFailed)?
        }
        n => return Err(CryptoError::InvalidKeyLength(n)),
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_KEY: &[u8] = b"moond4rk";
    fn aes_key() -> Vec<u8> {
        [BASE_KEY, BASE_KEY].concat()
    }
    fn plain_text() -> &'static [u8] {
        b"Hello, World!"
    }
    fn aes_gcm_nonce() -> Vec<u8> {
        [BASE_KEY, BASE_KEY].concat()[..12].to_vec()
    }
    const AES_GCM_CIPHERTEXT: &str = "6c49dac89992639713edab3a114c450968a08b53556872cea3919e2e9a";

    // Port of TestAESGCMEncrypt.
    #[test]
    fn aes_gcm_encrypt_parity() {
        let encrypted = aes_gcm_encrypt(&aes_key(), &aes_gcm_nonce(), plain_text()).unwrap();
        assert_eq!(AES_GCM_CIPHERTEXT, hex::encode(encrypted));
    }

    // Port of TestAESGCMDecrypt.
    #[test]
    fn aes_gcm_decrypt_parity() {
        let ciphertext = hex::decode(AES_GCM_CIPHERTEXT).unwrap();
        let decrypted = aes_gcm_decrypt(&aes_key(), &aes_gcm_nonce(), &ciphertext).unwrap();
        assert_eq!(plain_text(), decrypted.as_slice());
    }

    // Port of TestAESGCMEncrypt_WrongNonceLength.
    #[test]
    fn aes_gcm_encrypt_wrong_nonce_length() {
        assert_eq!(
            Err(CryptoError::InvalidNonceLen),
            aes_gcm_encrypt(&aes_key(), b"short", plain_text())
        );
    }

    // Port of TestAESGCMDecrypt_WrongNonceLength.
    #[test]
    fn aes_gcm_decrypt_wrong_nonce_length() {
        assert_eq!(
            Err(CryptoError::InvalidNonceLen),
            aes_gcm_decrypt(&aes_key(), b"short", &[0u8; 32])
        );
    }

    #[test]
    fn tampered_tag_fails() {
        let ciphertext = hex::decode(AES_GCM_CIPHERTEXT).unwrap();
        let mut bad = ciphertext.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert_eq!(
            Err(CryptoError::AeadAuthFailed),
            aes_gcm_decrypt(&aes_key(), &aes_gcm_nonce(), &bad)
        );
    }

    #[test]
    fn gcm_round_trip_aad() {
        // Go's public API only decrypts with AAD (Yandex); encrypt here must match.
        fn encrypt_with_aad(key: &[u8], nonce: &[u8], msg: &[u8], aad: &[u8]) -> Vec<u8> {
            let cipher = Aes256Gcm::new(Key::<Aes256>::from_slice(key));
            cipher
                .encrypt(Nonce::from_slice(nonce), Payload { msg, aad })
                .unwrap()
        }
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad = b"associated-data";
        let ct = encrypt_with_aad(&key, &nonce, b"secret", aad);
        assert_eq!(
            b"secret".as_slice(),
            aes_gcm_decrypt_with_aad(&key, &nonce, &ct, aad).unwrap()
        );
        // Wrong AAD must fail authentication.
        assert_eq!(
            Err(CryptoError::AeadAuthFailed),
            aes_gcm_decrypt_with_aad(&key, &nonce, &ct, b"wrong")
        );
    }

    #[test]
    fn decrypt_blob_layout() {
        // blob = nonce(12) ++ ct+tag.
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let ct = aes_gcm_encrypt(&key, &nonce, b"blob-value").unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ct);
        assert_eq!(
            b"blob-value".as_slice(),
            aes_gcm_decrypt_blob(&key, &blob, b"").unwrap()
        );

        // AAD mismatch must fail even though the key/nonce are right.
        assert_eq!(
            Err(CryptoError::AeadAuthFailed),
            aes_gcm_decrypt_blob(&key, &blob, b"wrong-aad")
        );
        assert_eq!(
            Err(CryptoError::ShortCiphertext),
            aes_gcm_decrypt_blob(&key, b"short", b"")
        );
    }
}
