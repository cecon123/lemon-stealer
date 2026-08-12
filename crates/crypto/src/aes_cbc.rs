//! Port of `crypto/crypto.go` — AES-CBC with PKCS5/PKCS7, Chromium's exact quirks.
//!
//! `cbc::cipher::block_padding::Pkcs7` implements byte-identical PKCS5/PKCS7
//! padding to Go's manual `pkcs5Padding`/`pkcs5UnPadding` (both are the same
//! standard; Chromium only ever uses block size 16).

use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use cbc::cipher::inout::block_padding::{NoPadding, Pkcs7};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};

use crate::CryptoError;

/// AES block size in bytes (FIPS-197: fixed 16).
const AES_BLOCK_SIZE: usize = 16;

/// `paddingZero` — returns src unchanged if already long enough; otherwise a zero-padded
/// new slice (parity with Go: never mutates src).
pub fn padding_zero(src: &[u8], length: usize) -> Vec<u8> {
    if src.len() >= length {
        return src.to_vec();
    }
    let mut dst = vec![0u8; length];
    dst[..src.len()].copy_from_slice(src);
    dst
}

fn validate_iv_length(iv: &[u8]) -> Result<(), CryptoError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidIvLength);
    }
    Ok(())
}

/// Encrypts data using AES-CBC mode with PKCS5 padding (Go: `AESCBCEncrypt`).
/// Supports all AES key sizes: 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256).
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    validate_iv_length(iv)?;
    let out = match key.len() {
        16 => Encryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(16))?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
        24 => Encryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(24))?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
        32 => Encryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(32))?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
        n => return Err(CryptoError::InvalidKeyLength(n)),
    };
    Ok(out)
}

/// Decrypts data using AES-CBC mode with PKCS5 unpadding (Go: `AESCBCDecrypt`).
///
/// Error precedence matches Go's `cbcDecrypt`: IV length → short ciphertext →
/// block-size multiple → padding validity.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    validate_iv_length(iv)?;
    if ciphertext.len() < AES_BLOCK_SIZE {
        return Err(CryptoError::ShortCiphertext);
    }
    if !ciphertext.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(CryptoError::InvalidBlockSize);
    }
    let out = match key.len() {
        16 => Decryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(16))?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
        24 => Decryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(24))?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
        32 => Decryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(32))?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
        n => return Err(CryptoError::InvalidKeyLength(n)),
    };
    out.map_err(|_| CryptoError::InvalidPadding)
}

/// Chromium CBC raw decrypt without padding logic — used by Yandex (Phase 1).
#[allow(dead_code)]
pub(crate) fn cbc_decrypt_no_unpad(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_iv_length(iv)?;
    if ciphertext.len() < AES_BLOCK_SIZE {
        return Err(CryptoError::ShortCiphertext);
    }
    if !ciphertext.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(CryptoError::InvalidBlockSize);
    }
    match key.len() {
        16 => Decryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(16))?
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .map_err(|_| CryptoError::InvalidPadding),
        24 => Decryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(24))?
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .map_err(|_| CryptoError::InvalidPadding),
        32 => Decryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(32))?
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .map_err(|_| CryptoError::InvalidPadding),
        n => Err(CryptoError::InvalidKeyLength(n)),
    }
}

#[allow(dead_code)]
pub(crate) fn cbc_encrypt_no_pad(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_iv_length(iv)?;
    let out = match key.len() {
        16 => Encryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(16))?
            .encrypt_padded_vec_mut::<NoPadding>(plaintext),
        24 => Encryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(24))?
            .encrypt_padded_vec_mut::<NoPadding>(plaintext),
        32 => Encryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| CryptoError::InvalidKeyLength(32))?
            .encrypt_padded_vec_mut::<NoPadding>(plaintext),
        n => return Err(CryptoError::InvalidKeyLength(n)),
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CHROMIUM_CBC_IV;

    const BASE_KEY: &[u8] = b"moond4rk";
    fn aes_key() -> Vec<u8> {
        [BASE_KEY, BASE_KEY].concat()
    }
    fn aes_iv() -> &'static [u8] {
        b"01234567abcdef01"
    }
    fn plain_text() -> &'static [u8] {
        b"Hello, World!"
    }
    const AES128_CIPHERTEXT: &str = "19381468ecf824c0bfc7a89eed9777d2";

    // Port of TestAESCBCEncrypt.
    #[test]
    fn aes_cbc_encrypt_parity() {
        let encrypted = aes_cbc_encrypt(&aes_key(), aes_iv(), plain_text()).unwrap();
        assert!(!encrypted.is_empty());
        assert_eq!(AES128_CIPHERTEXT, hex::encode(encrypted));
    }

    // Port of TestAESCBCDecrypt.
    #[test]
    fn aes_cbc_decrypt_parity() {
        let ciphertext = hex::decode(AES128_CIPHERTEXT).unwrap();
        let decrypted = aes_cbc_decrypt(&aes_key(), aes_iv(), &ciphertext).unwrap();
        assert!(!decrypted.is_empty());
        assert_eq!(plain_text(), decrypted.as_slice());
    }

    // Port of TestAESCBCDecrypt_WrongIVLength.
    #[test]
    fn aes_cbc_decrypt_wrong_iv_length() {
        assert_eq!(
            Err(CryptoError::InvalidIvLength),
            aes_cbc_decrypt(&aes_key(), b"short", &[0u8; 16])
        );
    }

    // Port of TestAESCBCEncrypt_WrongIVLength.
    #[test]
    fn aes_cbc_encrypt_wrong_iv_length() {
        assert_eq!(
            Err(CryptoError::InvalidIvLength),
            aes_cbc_encrypt(&aes_key(), b"short", plain_text())
        );
    }

    // Port of TestAESCBCDecrypt_EmptyCiphertext.
    #[test]
    fn aes_cbc_decrypt_empty_ciphertext() {
        assert!(aes_cbc_decrypt(&aes_key(), aes_iv(), &[]).is_err());
        assert!(aes_cbc_decrypt(&aes_key(), aes_iv(), b"").is_err());
    }

    // Port of TestPkcs5Padding_NoMutation.
    // Go's manual padding wrote into a fresh dst slice; `encrypt_padded_vec_mut`
    // takes `&[u8]` so input mutation is impossible by construction — pin the
    // observable contract: input stays byte-identical after encrypt.
    #[test]
    fn pkcs5_padding_no_mutation() {
        let src = b"abc".to_vec();
        let backup = src.clone();
        let _ = aes_cbc_encrypt(&aes_key(), aes_iv(), &src).unwrap();
        assert_eq!(backup, src, "pkcs5_padding mutated the original");
    }

    // Port of TestPaddingZero_NoMutation.
    #[test]
    fn padding_zero_no_mutation() {
        let src = b"abc".to_vec();
        let backup = src.clone();
        let padded = padding_zero(&src, 20);
        assert_eq!(20, padded.len());
        assert_eq!(backup, src, "padding_zero mutated the original");
        // Short-circuit path returns a copy too (Go returns src as-is; plain text inputs
        // are never written to, so behavior is equivalent).
        assert_eq!(src, padding_zero(&src, 3));
    }

    #[test]
    fn empty_plaintext_pads_to_full_block() {
        // Go pkcs5Padding("") = one block of 0x10; CBC encrypt succeeds.
        let ct = aes_cbc_encrypt(&aes_key(), aes_iv(), b"").unwrap();
        assert_eq!(16, ct.len());
        assert_eq!(
            Vec::<u8>::new(),
            aes_cbc_decrypt(&aes_key(), aes_iv(), &ct).unwrap()
        );
    }

    #[test]
    fn round_trip_all_key_sizes() {
        for key_len in [16usize, 24, 32] {
            let key = vec![0x42u8; key_len];
            let iv = [0x20u8; 16];
            let ct = aes_cbc_encrypt(&key, &iv, b"roundtrip").unwrap();
            assert_eq!(ct.len() % 16, 0);
            assert_eq!(
                b"roundtrip".as_slice(),
                aes_cbc_decrypt(&key, &iv, &ct).unwrap()
            );
        }
    }

    #[test]
    fn invalid_key_lengths_rejected() {
        assert_eq!(
            Err(CryptoError::InvalidKeyLength(15)),
            aes_cbc_encrypt(&[0u8; 15], &[0u8; 16], b"x")
        );
        assert_eq!(
            Err(CryptoError::InvalidKeyLength(20)),
            aes_cbc_decrypt(&[0u8; 20], &[0u8; 16], &[0u8; 16])
        );
    }

    #[test]
    fn invalid_padding_rejected() {
        // Valid block but garbage padding byte.
        let ct = hex::decode("000102030405060708090a0b0c0d0e10").unwrap();
        assert_eq!(
            Err(CryptoError::InvalidPadding),
            aes_cbc_decrypt(&aes_key(), aes_iv(), &ct)
        );
    }

    #[test]
    fn chromium_cbc_iv_is_0x20_repeated_16() {
        assert_eq!(vec![0x20u8; 16], CHROMIUM_CBC_IV.to_vec());
        assert_eq!(16, CHROMIUM_CBC_IV.len());
    }
}
