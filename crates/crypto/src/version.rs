//! Port of `crypto/version.go`.

use crate::VERSION_PREFIX_LEN;
use std::borrow::Cow;

/// The encryption version used by Chromium browsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherVersion {
    /// Chrome 80+ encryption (AES-GCM on Windows, AES-CBC on macOS/Linux).
    V10,
    /// Linux-only AES-CBC variant (key from libsecret/kwallet). Same algorithm as
    /// v10; only the key source differs. Recognized for parity, never used on Windows.
    V11,
    /// Chromium SecretPortalKeyProvider (Flatpak) — HKDF-SHA256 + AES-256-GCM.
    /// Recognized by `detect_version` so `decrypt_value` can emit a known-gap error.
    V12,
    /// Chrome 127+ App-Bound Encryption.
    V20,
    /// Pre-Chrome 80 raw DPAPI encryption (no version prefix).
    Dpapi,
}

/// Wire form, identical to the Go string constants.
impl std::fmt::Display for CipherVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CipherVersion::V10 => "v10",
            CipherVersion::V11 => "v11",
            CipherVersion::V12 => "v12",
            CipherVersion::V20 => "v20",
            CipherVersion::Dpapi => "dpapi",
        })
    }
}

/// Identifies the encryption version from a ciphertext prefix (Go: `DetectVersion`).
pub fn detect_version(ciphertext: &[u8]) -> CipherVersion {
    match ciphertext.get(..VERSION_PREFIX_LEN) {
        Some(b"v10") => CipherVersion::V10,
        Some(b"v11") => CipherVersion::V11,
        Some(b"v12") => CipherVersion::V12,
        Some(b"v20") => CipherVersion::V20,
        _ => CipherVersion::Dpapi,
    }
}

/// Strips the 3-byte version prefix; DPAPI (or short) ciphertext is returned
/// unchanged (Go: `stripPrefix`).
pub fn strip_prefix(ciphertext: &[u8]) -> Cow<'_, [u8]> {
    match detect_version(ciphertext) {
        CipherVersion::V10 | CipherVersion::V11 | CipherVersion::V12 | CipherVersion::V20 => {
            Cow::Borrowed(&ciphertext[VERSION_PREFIX_LEN..])
        }
        CipherVersion::Dpapi => Cow::Borrowed(ciphertext),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions() -> [(CipherVersion, &'static [u8]); 4] {
        [
            (CipherVersion::V10, b"v10encrypted_data"),
            (CipherVersion::V11, b"v11encrypted_data"),
            (CipherVersion::V12, b"v12encrypted_data"),
            (CipherVersion::V20, b"v20encrypted_data"),
        ]
    }

    // Port of TestDetectVersion.
    #[test]
    fn detect_version_parity() {
        for (want, data) in versions() {
            assert_eq!(want, detect_version(data));
        }
        assert_eq!(
            CipherVersion::Dpapi,
            detect_version(&[0x01, 0x00, 0x00, 0x00])
        );
        assert_eq!(CipherVersion::Dpapi, detect_version(&[0x01, 0x02]));
        assert_eq!(CipherVersion::Dpapi, detect_version(&[]));
        assert_eq!(CipherVersion::Dpapi, detect_version(b"xyz_data"));
    }

    // Port of Test_stripPrefix.
    #[test]
    fn strip_prefix_parity() {
        for ver in [
            CipherVersion::V10,
            CipherVersion::V11,
            CipherVersion::V12,
            CipherVersion::V20,
        ] {
            let prefixed = format!("{ver}PAYLOAD");
            assert_eq!(&b"PAYLOAD"[..], strip_prefix(prefixed.as_bytes()).as_ref());
        }
        assert_eq!(
            &[0x01, 0x00, 0x00][..],
            strip_prefix(&[0x01, 0x00, 0x00]).as_ref()
        );
        assert_eq!(&[0x01][..], strip_prefix(&[0x01]).as_ref());
        let empty: &[u8] = &[];
        assert_eq!(empty, strip_prefix(&[]).as_ref());
    }

    #[test]
    fn display_matches_go_string_constants() {
        assert_eq!("v10", CipherVersion::V10.to_string());
        assert_eq!("v11", CipherVersion::V11.to_string());
        assert_eq!("v12", CipherVersion::V12.to_string());
        assert_eq!("v20", CipherVersion::V20.to_string());
        assert_eq!("dpapi", CipherVersion::Dpapi.to_string());
    }
}
