//! Port of `crypto/yandex.go` — Yandex's per-DB intermediate key unwrap.

use crate::CryptoError;
use crate::aead::aes_gcm_decrypt_blob;

/// Protobuf wire-format header (field1 varint=1, field2 len=32) on every wrapped
/// key (Go: `yandexSignature`).
pub const YANDEX_SIGNATURE: [u8; 4] = [0x08, 0x01, 0x12, 0x20];

/// Bytes preceding the intermediate-key blob inside `meta.local_encryptor_data`
/// (Go: `localEncryptorPrefix`).
pub const LOCAL_ENCRYPTOR_PREFIX: &[u8] = b"v10";

/// Encrypted intermediate key blob: 12B nonce + 68B ciphertext + 16B GCM tag
/// (Go: `yandexIntKeyBlobLen`).
pub const YANDEX_INT_KEY_BLOB_LEN: usize = 96;

/// Length of the unwrapped per-DB data key (Go: `yandexDataKeyLen`).
pub const YANDEX_DATA_KEY_LEN: usize = 32;

/// Unwraps the per-DB data key from `meta.local_encryptor_data`
/// (Go: `DecryptYandexIntermediateKey`).
///
/// Pipeline, byte-for-byte Go parity:
/// 1. find the `v10` marker → [`CryptoError::YandexMarkerNotFound`];
/// 2. require ≥96 trailing bytes → [`CryptoError::YandexBlobShort`];
/// 3. AES-GCM decrypt the 96B blob (blob = nonce(12) ++ ct+tag), no AAD;
/// 4. require the protobuf signature prefix `08 01 12 20` (posix signature is
///    declared len=32, covers the 32-byte key we slice out) →
///    [`CryptoError::YandexBadSignature`];
/// 5. slice the first 32 bytes past the signature (trailing payload discarded).
pub fn decrypt_yandex_intermediate_key(
    master_key: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let idx = blob
        .windows(LOCAL_ENCRYPTOR_PREFIX.len())
        .position(|w| w == LOCAL_ENCRYPTOR_PREFIX)
        .ok_or(CryptoError::YandexMarkerNotFound)?;
    let payload = &blob[idx + LOCAL_ENCRYPTOR_PREFIX.len()..];
    if payload.len() < YANDEX_INT_KEY_BLOB_LEN {
        return Err(CryptoError::YandexBlobShort);
    }

    let plaintext = aes_gcm_decrypt_blob(master_key, &payload[..YANDEX_INT_KEY_BLOB_LEN], &[])?;
    if !plaintext.starts_with(&YANDEX_SIGNATURE) {
        return Err(CryptoError::YandexBadSignature);
    }
    let rest = &plaintext[YANDEX_SIGNATURE.len()..];
    if rest.len() < YANDEX_DATA_KEY_LEN {
        return Err(CryptoError::YandexKeyTooShort);
    }
    Ok(rest[..YANDEX_DATA_KEY_LEN].to_vec())
}

#[cfg(test)]
mod tests {
    use aes::cipher::KeyInit;
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    use super::*;
    use crate::{GCM_NONCE_SIZE, aead::aes_gcm_decrypt_blob};

    // Go yandex_test.go helper `encryptAESGCM` (no t.Helper in Rust).
    fn encrypt_aes_gcm(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(Key::<aes::Aes256>::from_slice(key));
        cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap()
    }

    /// Plaintext size before AES-GCM seal inside meta.local_encryptor_data:
    /// 96 (blob) - 12 (nonce) - 16 (tag) = 68 bytes (Go: `testPlaintextPayloadLen`).
    const TEST_PLAINTEXT_PAYLOAD_LEN: usize = YANDEX_INT_KEY_BLOB_LEN - GCM_NONCE_SIZE - 16;

    fn build_local_encryptor_blob(master_key: &[u8], data_key: &[u8]) -> Vec<u8> {
        let nonce = vec![0xABu8; GCM_NONCE_SIZE];
        let mut plaintext = YANDEX_SIGNATURE.to_vec();
        plaintext.extend_from_slice(data_key);
        plaintext.resize(TEST_PLAINTEXT_PAYLOAD_LEN, 0);
        let ciphertext = encrypt_aes_gcm(master_key, &nonce, &plaintext, b"");
        assert_eq!(YANDEX_INT_KEY_BLOB_LEN - GCM_NONCE_SIZE, ciphertext.len());

        let mut blob = vec![0x01, 0x02, 0x03, 0x04]; // arbitrary protobuf preamble
        blob.extend_from_slice(LOCAL_ENCRYPTOR_PREFIX);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        blob.extend_from_slice(&[0xFF, 0xFE]); // trailing junk should be ignored
        blob
    }

    // Port of TestDecryptYandexIntermediateKey_RoundTrip.
    #[test]
    fn decrypt_yandex_intermediate_key_round_trip() {
        let master_key = vec![0x11u8; 32];
        let data_key = vec![0x22u8; YANDEX_DATA_KEY_LEN];
        let blob = build_local_encryptor_blob(&master_key, &data_key);

        let got = decrypt_yandex_intermediate_key(&master_key, &blob).unwrap();
        assert_eq!(data_key, got);
    }

    // Port of TestDecryptYandexIntermediateKey_MissingMarker.
    #[test]
    fn decrypt_yandex_intermediate_key_missing_marker() {
        let master_key = vec![0x11u8; 32];
        assert_eq!(
            Err(CryptoError::YandexMarkerNotFound),
            decrypt_yandex_intermediate_key(&master_key, b"no marker here")
        );
    }

    // Port of TestDecryptYandexIntermediateKey_Truncated.
    #[test]
    fn decrypt_yandex_intermediate_key_truncated() {
        let master_key = vec![0x11u8; 32];
        let mut blob = vec![0x00, 0x00];
        blob.extend_from_slice(LOCAL_ENCRYPTOR_PREFIX);
        blob.extend_from_slice(&[0x55u8; YANDEX_INT_KEY_BLOB_LEN - 1]);
        assert_eq!(
            Err(CryptoError::YandexBlobShort),
            decrypt_yandex_intermediate_key(&master_key, &blob)
        );
    }

    // Port of TestDecryptYandexIntermediateKey_BadSignature.
    #[test]
    fn decrypt_yandex_intermediate_key_bad_signature() {
        let master_key = vec![0x11u8; 32];
        let nonce = vec![0xABu8; GCM_NONCE_SIZE];
        let mut plaintext = vec![0xDE, 0xAD, 0xBE, 0xEF];
        plaintext.extend_from_slice(&[0x22u8; YANDEX_DATA_KEY_LEN]);
        plaintext.resize(TEST_PLAINTEXT_PAYLOAD_LEN, 0);
        let ciphertext = encrypt_aes_gcm(&master_key, &nonce, &plaintext, b"");

        let mut blob = LOCAL_ENCRYPTOR_PREFIX.to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        assert_eq!(
            Err(CryptoError::YandexBadSignature),
            decrypt_yandex_intermediate_key(&master_key, &blob)
        );
    }

    // Port of TestDecryptYandexIntermediateKey_TrailingDataIgnored: bytes past
    // signature+32 are discarded (14 of the 64 payload bytes are junk here, but
    // Go's slice is declared len=32, so bytes 0..32 post-signature are the key).
    #[test]
    fn decrypt_yandex_intermediate_key_trailing_data_ignored() {
        let master_key = vec![0x11u8; 32];
        let nonce = vec![0xABu8; GCM_NONCE_SIZE];
        let mut plaintext = YANDEX_SIGNATURE.to_vec();
        plaintext.extend_from_slice(&[0x22u8; 16]); // only 16 of 32 key bytes given
        plaintext.resize(TEST_PLAINTEXT_PAYLOAD_LEN, 0); // rest zero-padded
        let ciphertext = encrypt_aes_gcm(&master_key, &nonce, &plaintext, b"");

        let mut blob = LOCAL_ENCRYPTOR_PREFIX.to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        let got = decrypt_yandex_intermediate_key(&master_key, &blob).unwrap();
        let mut want = vec![0x22u8; 16];
        want.extend_from_slice(&[0u8; 16]);
        assert_eq!(want, got);
    }

    // --- Port of the AESGCMDecryptBlob tests (Go yandex_test.go, function in crypto.go) ---

    // Port of TestAESGCMDecryptBlob_RoundTrip.
    #[test]
    fn aes_gcm_decrypt_blob_round_trip() {
        let key = vec![0x55u8; 32];
        let nonce = vec![0x66u8; GCM_NONCE_SIZE];
        let aad = b"row-aad";
        let plaintext = b"row-plaintext";
        let mut blob = nonce.clone();
        blob.extend_from_slice(&encrypt_aes_gcm(&key, &nonce, plaintext, aad));

        assert_eq!(
            plaintext.as_slice(),
            aes_gcm_decrypt_blob(&key, &blob, aad).unwrap()
        );
    }

    // Port of TestAESGCMDecryptBlob_BadAAD.
    #[test]
    fn aes_gcm_decrypt_blob_bad_aad() {
        let key = vec![0x55u8; 32];
        let nonce = vec![0x66u8; GCM_NONCE_SIZE];
        let mut blob = nonce.clone();
        blob.extend_from_slice(&encrypt_aes_gcm(&key, &nonce, b"x", b"aad-A"));

        assert_eq!(
            Err(CryptoError::AeadAuthFailed),
            aes_gcm_decrypt_blob(&key, &blob, b"aad-B")
        );
    }

    // Port of TestAESGCMDecryptBlob_TooShort (Go: errShortCiphertext).
    #[test]
    fn aes_gcm_decrypt_blob_too_short() {
        let key = vec![0x55u8; 32];
        assert_eq!(
            Err(CryptoError::ShortCiphertext),
            aes_gcm_decrypt_blob(&key, &[0x01, 0x02], b"")
        );
    }
}
