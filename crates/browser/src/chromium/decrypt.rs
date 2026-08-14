//! Decrypt dispatch (Go: `browser/chromium/decrypt.go`).

use hbd_crypto::{
    CipherVersion, decrypt_chromium_cbc, decrypt_chromium_gcm, decrypt_dpapi, detect_version,
};
use keyring::MasterKeys;

/// Decrypts a Chromium-encrypted value by dispatching on the ciphertext's
/// version prefix to the matching tier in `master_keys`:
///
///   - v10 → `v10` (Windows DPAPI / macOS Keychain / Linux peanuts kV10Key)
///   - v11 → `v11` (Linux keyring kV11Key; `None` on Windows/macOS)
///   - v20 → `v20` (Windows ABE; `None` on non-Windows)
///
/// Missing tier keys surface as errors at the ciphertext level; the extract
/// layer treats those as empty plaintexts rather than fatal errors.
///
/// (Go: `decryptValue`.)
pub fn decrypt_value(
    master_keys: &MasterKeys,
    ciphertext: &[u8],
) -> Result<Vec<u8>, crate::chromium::error::ChromiumError> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }

    match detect_version(ciphertext) {
        CipherVersion::V10 => {
            // v10's cipher depends on the platform that sealed it: a 32-byte
            // AES-256 key means GCM (Windows), a 16-byte AES-128 key means CBC
            // (macOS/Linux). Dispatching on key length keeps cross-host
            // decryption OS-independent.
            match master_keys.v10.as_deref() {
                Some(k) if k.len() == 32 => Ok(decrypt_chromium_gcm(k, ciphertext)?),
                Some(k) => Ok(decrypt_chromium_cbc(k, ciphertext)?),
                None => Err("v10 key not available".into()),
            }
        }
        CipherVersion::V11 => match master_keys.v11.as_deref() {
            Some(k) => Ok(decrypt_chromium_cbc(k, ciphertext)?),
            None => Err("v11 key not available".into()),
        },
        CipherVersion::V20 => match master_keys.v20.as_deref() {
            Some(k) => Ok(decrypt_chromium_gcm(k, ciphertext)?),
            None => Err("v20 key not available".into()),
        },
        CipherVersion::V12 => Err(
            "unsupported cipher version v12 (Chromium SecretPortal / Flatpak; not yet implemented)"
                .into(),
        ),
        CipherVersion::Dpapi => Ok(decrypt_dpapi(ciphertext)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring::MasterKeys;

    #[test]
    fn empty_ciphertext_returns_empty() {
        let mk = MasterKeys::default();
        assert_eq!(Vec::<u8>::new(), decrypt_value(&mk, b"").unwrap());
    }

    #[test]
    fn v10_cbc_16_byte_key() {
        let key: Vec<u8> = (0..16).collect();
        let iv = [0x20u8; 16];
        let plain = b"hello world".to_vec();
        // Real v10 CBC blob: prefix "v10" + AES-CBC(plain, PKCS7, fixed IV).
        let ct = hbd_crypto::aes_cbc::aes_cbc_encrypt(&key, &iv, &plain).unwrap();
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&ct);

        let mk = MasterKeys {
            v10: Some(key),
            ..Default::default()
        };
        assert_eq!(plain, decrypt_value(&mk, &blob).unwrap());
    }

    #[test]
    fn v10_gcm_32_byte_key() {
        let key: Vec<u8> = (0..32).collect();
        let nonce = [7u8; 12];
        let plain = b"secret".to_vec();
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&hbd_crypto::aead::aes_gcm_encrypt(&key, &nonce, &plain).unwrap());

        let mk = MasterKeys {
            v10: Some(key),
            ..Default::default()
        };
        assert_eq!(plain, decrypt_value(&mk, &blob).unwrap());
    }

    #[test]
    fn missing_tier_is_error_not_panic() {
        let mk = MasterKeys::default();
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&[0u8; 16]);
        assert!(decrypt_value(&mk, &blob).is_err());
    }
}
