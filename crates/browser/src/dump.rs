//! Port of Go `browser/archive.go` — the `Dump` JSON schema (dumpkeys).
//!
//! `Dump` bundles the per-installation master keys (and the host identity they
//! were derived on) into one JSON file so another host can decrypt a copied
//! profile (Phase 4 `restore`). Phase 3 ships the schema + build/write/read;
//! the zip half (`ZipDir`/`Unzip`/`CompressDir`) lands with the archive command.

use std::io::Write;

use hbd_core::{BrowserKind, ChromeTime};
use serde::{Deserialize, Serialize};

/// Version of the dumpkeys JSON schema (Go: `DumpVersion`, enforced by
/// [`read_dump`] — an older/newer dump is not safe to trust).
pub const DUMP_VERSION: &str = "2";

/// One exportable host (Go: `HostInfo`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostInfo {
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub user: String,
}

/// One browser installation's keys, tied to its engine identity (Go: `Vault`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vault {
    pub browser: String,
    #[serde(rename = "kind")]
    pub kind: BrowserKind,
    pub user_data_dir: String,
    pub profiles: Vec<String>,
    pub keys: keyring::MasterKeys,
}

/// The dumpkeys document (Go: `Dump`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dump {
    pub version: String,
    pub created_at: ChromeTime,
    pub host: HostInfo,
    pub vaults: Vec<Vault>,
}

/// Errors from building/writing/reading a `Dump` (Go: plain `error`s).
#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    /// Go: `invalid dump version %s, expected %s`.
    #[error("invalid dump version {got:?}, expected {expect:?}")]
    VersionMismatch { got: String, expect: String },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Assembles the dump from discovered browsers, skipping installations without
/// usable keys (Go: `BuildDump`).
///
/// Only `KeyManager` browsers contribute vaults; a vault is dropped when
/// `ExportKeys` fails or yields `!has_any` (no tier produced a key).
pub fn build_dump(browsers: &[crate::discover::DiscoveredBrowser]) -> Result<Dump, DumpError> {
    let host = host_info();
    let mut vaults = Vec::new();
    for b in browsers {
        let keys = match b.export_keys() {
            Ok(k) => k,
            Err(e) => {
                log::debug!("dumpkeys: {}: {}", b.browser_name(), e);
                continue;
            }
        };
        if !keys.has_any() {
            continue;
        }
        vaults.push(Vault {
            browser: b.browser_name().to_string(),
            kind: b.kind(),
            user_data_dir: b.user_data_dir().to_string(),
            profiles: b.profiles().iter().map(|p| p.name.clone()).collect(),
            keys,
        });
    }
    Ok(Dump {
        version: DUMP_VERSION.to_string(),
        created_at: ChromeTime::now(),
        host,
        vaults,
    })
}

/// Host identity from the process environment (Go: `getHostInfo` —
/// `os.Hostname()` / `user.Current().Username()` on Windows read the same
/// `COMPUTERNAME` / `USERNAME` env vars).
fn host_info() -> HostInfo {
    HostInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
        user: std::env::var("USERNAME").unwrap_or_default(),
    }
}

/// Encodes a dump as pretty JSON (2-space indent, no HTML escaping, trailing
/// newline — Go: `WriteDump` with `SetIndent("", "  ")` + `SetEscapeHTML(false)`
/// + `Encoder.Encode`).
pub fn write_dump(w: &mut dyn Write, dump: &Dump) -> Result<(), DumpError> {
    let mut bytes = serde_json::to_vec_pretty(dump)?;
    bytes.push(b'\n');
    w.write_all(&bytes)?;
    Ok(())
}

/// Decodes a dump, rejecting any version other than [`DUMP_VERSION`]
/// (Go: `ReadDump`'s strict check).
pub fn read_dump(r: &mut dyn std::io::Read) -> Result<Dump, DumpError> {
    let dump: Dump = serde_json::from_reader(r)?;
    if dump.version != DUMP_VERSION {
        return Err(DumpError::VersionMismatch {
            got: dump.version,
            expect: DUMP_VERSION.to_string(),
        });
    }
    Ok(dump)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_mismatch_rejected() {
        let json = r#"{"version":"1","created_at":"0001-01-01T00:00:00Z","host":{"os":"windows","arch":"x86_64","hostname":"","user":""},"vaults":[]}"#;
        let err = read_dump(&mut json.as_bytes()).unwrap_err();
        match err {
            DumpError::VersionMismatch { got, expect } => {
                assert_eq!("1", got);
                assert_eq!("2", expect);
            }
            other => panic!("wrong error variant: {other}"),
        }
    }

    #[test]
    fn round_trip_round_trips() {
        let dump = Dump {
            version: DUMP_VERSION.to_string(),
            created_at: ChromeTime::zero(),
            host: HostInfo {
                os: "windows".into(),
                arch: "x86_64".into(),
                hostname: "HOST".into(),
                user: "USER".into(),
            },
            vaults: vec![Vault {
                browser: "chrome".into(),
                kind: BrowserKind::Chromium,
                user_data_dir: r"C:\Users\u\AppData\Local\Google\Chrome\User Data".into(),
                profiles: vec!["Default".into(), "Profile 1".into()],
                keys: keyring::MasterKeys {
                    v10: Some(vec![0x01, 0x02, 0x03]),
                    ..Default::default()
                },
            }],
        };
        let mut bytes = Vec::new();
        write_dump(&mut bytes, &dump).unwrap();
        let back = read_dump(&mut bytes.as_slice()).unwrap();
        assert_eq!(dump, back);
    }

    #[test]
    fn json_shape_matches_go() {
        let dump = Dump {
            version: DUMP_VERSION.to_string(),
            created_at: ChromeTime::zero(),
            host: HostInfo {
                os: "windows".into(),
                arch: "x86_64".into(),
                hostname: "HOST".into(),
                user: "USER".into(),
            },
            vaults: vec![Vault {
                browser: "chrome".into(),
                kind: BrowserKind::ChromiumYandex,
                user_data_dir: "dir".into(),
                profiles: vec!["Default".into()],
                keys: keyring::MasterKeys {
                    v10: Some(vec![0xAB, 0xCD]),
                    ..Default::default()
                },
            }],
        };
        let mut bytes = Vec::new();
        write_dump(&mut bytes, &dump).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        // Go field names, kebab-case kind, base64 keys, 2-space indent, no HTML
        // escaping of `<>&` (SetEscapeHTML(false) parity).
        assert!(s.contains("\"version\": \"2\""));
        assert!(s.contains("\"kind\": \"chromium-yandex\""));
        assert!(s.contains("\"v10\": \"q80=\""));
        assert!(s.contains("\"created_at\": \"0001-01-01T00:00:00Z\""));
        assert!(s.contains("  \"vaults\": ["));
        assert!(s.ends_with('\n'));
        assert!(!s.contains("\\u003c"));
    }
}
