//! Local/session storage extraction from LevelDB (Go: `browser/chromium/extract_storage.go`).

use std::path::Path;

use hbd_core::StorageEntry;

use crate::chromium::error::Result;
use crate::chromium::leveldb::LevelDb;

/// Extracts localStorage entries from `Local Storage/leveldb`.
///
/// Keys are `_<origin>\0\x01<key>` since the M85 scheme lock (older profiles:
/// `<origin>\0\x01<key>`); meta entries are `META:<origin>\0\x01<meta-key>`.
/// Values may carry a `\x01` version prefix (session storage always does).
pub fn extract_local_storage(path: &Path) -> Result<Vec<StorageEntry>> {
    let db = LevelDb::open(path)?;
    Ok(db
        .iter()
        .iter()
        .filter_map(|(k, v)| decode_storage_entry(k, v))
        .collect())
}

/// Extracts sessionStorage entries from the `Session Storage` directory:
/// one single-file LevelDB per origin, named `<origin>.localstorage`.
/// (Go: opens each file via goleveldb's log-only single-file reader.)
pub fn extract_session_storage(path: &Path) -> Result<Vec<StorageEntry>> {
    let mut storage = Vec::new();
    let entries = std::fs::read_dir(path)?;
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false)
            || !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".localstorage")
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
                .filter_map(|(k, v)| decode_storage_entry(k, v)),
        );
    }
    Ok(storage)
}

/// Decodes one LevelDB (key, value) pair into a storage entry.
/// Returns `None` for keys that don't carry the `\0\x01` separator.
fn decode_storage_entry(key: &[u8], value: &[u8]) -> Option<StorageEntry> {
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

    Some(StorageEntry {
        is_meta,
        url: String::from_utf8_lossy(url).into_owned(),
        key: String::from_utf8_lossy(entry_key).into_owned(),
        value: String::from_utf8_lossy(value).into_owned(),
    })
}

pub fn count_local_storage(path: &Path) -> Result<i64> {
    Ok(extract_local_storage(path)?.len() as i64)
}

pub fn count_session_storage(path: &Path) -> Result<i64> {
    Ok(extract_session_storage(path)?.len() as i64)
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
        let e = decode_storage_entry(b"_https://example.com\x00\x01theme", b"dark").unwrap();
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
        let e = decode_storage_entry(b"https://example.com\x00\x01k", b"v").unwrap();
        assert_eq!("https://example.com", e.url);
        assert_eq!("k", e.key);
    }

    #[test]
    fn malformed_key_rejected() {
        assert!(decode_storage_entry(b"no-separator", b"v").is_none());
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

        let entries = extract_session_storage(&dir).unwrap();
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
}
