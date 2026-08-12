//! Port of `crypto/pbkdf2.go` (x/crypto/pbkdf2, HMAC-SHA1).

use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

/// Derives a key via PBKDF2-HMAC-SHA1 (Go: `PBKDF2Key(..., h func() hash.Hash)`).
///
/// Standard RFC 2898 — byte-identical to `golang.org/x/crypto/pbkdf2`.
/// Used for Chromium's `kEmptyKey` (crbug.com/40055416) and Firefox NSS.
pub fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; key_len];
    pbkdf2_hmac::<Sha1>(password, salt, iterations, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::pbkdf2_sha1;

    #[test]
    fn matches_chromium_kemptykey_reference() {
        // Go test TestKEmptyKey_MatchesChromium pins these bytes from os_crypt_linux.cc.
        let want: [u8; 16] = [
            0xd0, 0xd0, 0xec, 0x9c, 0x7d, 0x77, 0xd4, 0x3a, 0xc5, 0x41, 0x87, 0xfa, 0x48, 0x18,
            0xd1, 0x7f,
        ];
        let got = pbkdf2_sha1(b"", b"saltysalt", 1, 16);
        assert_eq!(want.to_vec(), got);
    }

    #[test]
    fn truncated_to_key_len() {
        // PBKDF2 with dkLen not a multiple of hash len — x/crypto truncates the final block.
        let got = pbkdf2_sha1(b"password", b"salt", 2, 20);
        assert_eq!(20, got.len());
        // RFC 6070 test vector (SHA-1):
        // PBKDF2("password","salt",2,20) = ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
        assert_eq!("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", hex::encode(got));
    }
}
