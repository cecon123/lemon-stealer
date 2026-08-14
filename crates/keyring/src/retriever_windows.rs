//! Windows DPAPI master-key retriever (Go: `masterkey/retriever_windows.go`).
//!
//! Chrome ≤126 stores the AES-GCM master key in `Local State` under
//! `os_crypt.encrypted_key`: base64(`"DPAPI"` + DPAPI-protected 32-byte key).
//! The tier lifts it with `CryptUnprotectData` (all `unsafe` lives in `abi`).

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::retriever::{Hints, Retriever, RetrieverError};

/// The prefix Chrome prepends to the DPAPI blob inside `encrypted_key`
/// (Go: `"DPAPI"` in `retriever_windows.go`).
const DPAPI_PREFIX: &[u8] = b"DPAPI";

/// Mirrors the `Local State` slice Chromium's retriever reads (Go: `types.LocalState`,
/// only the `os_crypt` subtree is consumed).
#[derive(Debug, Deserialize, Default)]
struct LocalState {
    #[serde(default)]
    os_crypt: OsCrypt,
}

#[derive(Debug, Deserialize, Default)]
struct OsCrypt {
    encrypted_key: String,
}

/// Retailers the Chromium v10 master key from a (session-copied) `Local State`
/// file. Returns `Ok(None)` when the file is absent — the tier is "not
/// applicable" there (Go: `(nil, nil)`, e.g. an ABE-only profile gives an empty
/// `encrypted_key`).
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct DpapiRetriever;

#[cfg(windows)]
impl Retriever for DpapiRetriever {
    fn retrieve_key(&self, hints: &Hints) -> Result<Option<Vec<u8>>, RetrieverError> {
        if hints.local_state_path.as_os_str().is_empty() || !hints.local_state_path.is_file() {
            return Ok(None);
        }
        retrieve_from_local_state(&hints.local_state_path).map_err(RetrieverError::Retriever)
    }
}

/// The DPAPI half of the retriever, kept free of Windows gate so its logic
/// (JSON → base64 → prefix → decrypt) is unit-testable on any host.
fn retrieve_from_local_state(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read local state: {e}"))?;
    let state: LocalState =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse local state: {e}"))?;
    let encrypted_key = state.os_crypt.encrypted_key;
    if encrypted_key.is_empty() {
        return Ok(None);
    }

    let key = STANDARD
        .decode(encrypted_key.trim())
        .map_err(|e| format!("decode encrypted_key: {e}"))?;
    if !key.starts_with(DPAPI_PREFIX) {
        // Not a DPAPI blob (e.g. v20 "APPB" key) — this tier cannot lift it.
        return Ok(None);
    }
    let blob = &key[DPAPI_PREFIX.len()..];
    abi::decrypt_dpapi(blob)
        .map(Some)
        .map_err(|e| format!("dpapi decrypt: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retriever::RetrieverError;

    #[test]
    fn missing_local_state_is_not_applicable() {
        let r = DpapiRetriever;
        let hints = Hints {
            local_state_path: std::path::PathBuf::from("C:\\nonexistent\\Local State"),
            ..Default::default()
        };
        assert_eq!(Ok(None), r.retrieve_key(&hints));
    }

    #[test]
    fn empty_encrypted_key_is_not_applicable() {
        let dir = temp_dir("missing");
        let p = dir.join("Local State");
        std::fs::write(&p, r#"{"os_crypt": {"encrypted_key": ""}}"#).unwrap();
        let r = DpapiRetriever;
        let hints = Hints {
            local_state_path: p.clone(),
            ..Default::default()
        };
        assert_eq!(Ok(None), r.retrieve_key(&hints));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn abe_prefixed_key_is_not_applicable() {
        let dir = temp_dir("abe");
        let p = dir.join("Local State");
        // v20 keys carry an "APPB" prefix instead of "DPAPI" — must be a quiet
        // "not applicable" for this tier (Go: nil, nil → v20 retriever takes over).
        std::fs::write(&p, r#"{"os_crypt": {"encrypted_key": "QVBQQgAAAAA="}}"#).unwrap();
        let r = DpapiRetriever;
        let hints = Hints {
            local_state_path: p.clone(),
            ..Default::default()
        };
        assert_eq!(Ok(None), r.retrieve_key(&hints));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_local_state_is_an_error() {
        let dir = temp_dir("corrupt");
        let p = dir.join("Local State");
        std::fs::write(&p, b"not json").unwrap();
        let r = DpapiRetriever;
        let hints = Hints {
            local_state_path: p,
            ..Default::default()
        };
        assert!(matches!(
            r.retrieve_key(&hints),
            Err(RetrieverError::Retriever(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dpapi_round_trip_returns_master_key() {
        let dir = temp_dir("roundtrip");
        let p = dir.join("Local State");
        let key = [0xABu8; 32];
        let blob = abi::protect_dpapi(&key).unwrap();
        let mut encoded: Vec<u8> = b"DPAPI".to_vec();
        encoded.extend_from_slice(&blob);
        std::fs::write(
            &p,
            format!(
                r#"{{"os_crypt": {{"encrypted_key": "{}"}}}}"#,
                STANDARD.encode(&encoded)
            ),
        )
        .unwrap();
        let r = DpapiRetriever;
        let hints = Hints {
            local_state_path: p.clone(),
            ..Default::default()
        };
        assert_eq!(Ok(Some(key.to_vec())), r.retrieve_key(&hints));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hbd-keyring-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
