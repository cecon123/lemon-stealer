//! Password extraction (Go: `browser/chromium/extract_password.go`).

use std::cmp::Reverse;
use std::path::Path;

use hbd_core::{ChromeTime, LoginEntry};
use keyring::MasterKeys;

use crate::chromium::decrypt::decrypt_value;
use crate::chromium::error::Result;
use crate::chromium::sqliteutil::{count_rows, query_rows};

const DEFAULT_LOGIN_QUERY: &str =
    "SELECT origin_url, username_value, password_value, date_created FROM logins";
const COUNT_LOGIN_QUERY: &str = "SELECT COUNT(*) FROM logins";

/// Extracts saved logins, sorted by created date descending
/// (Go: `extractPasswords`).
pub fn extract_passwords(master_keys: &MasterKeys, path: &Path) -> Result<Vec<LoginEntry>> {
    extract_passwords_with_query(master_keys, path, DEFAULT_LOGIN_QUERY)
}

/// The query-parameterized core shared with the Yandex variant
/// (Go: `extractPasswordsWithQuery`).
pub(crate) fn extract_passwords_with_query(
    master_keys: &MasterKeys,
    path: &Path,
    query: &str,
) -> Result<Vec<LoginEntry>> {
    let mut logins = query_rows(path, false, query, |row| {
        let url: String = row.get(0)?;
        let username: String = row.get(1)?;
        let pwd: Vec<u8> = row.get(2)?;
        let created: i64 = row.get(3)?;
        // Decrypt failure → empty plaintext, never a fatal error (Go: `_`).
        let password = decrypt_value(master_keys, &pwd).unwrap_or_default();
        Ok(LoginEntry {
            url,
            username,
            password: String::from_utf8_lossy(&password).into_owned(),
            created_at: ChromeTime::from_chromium_micros(created),
        })
    })?;

    // Go sort.Slice is NOT stable; Rust sort_by IS stable — equal keys keep DB
    // order (acceptable divergence, PLAN R2 note).
    logins.sort_by_key(|a| Reverse(a.created_at));
    Ok(logins)
}

pub fn count_passwords(path: &Path) -> Result<i64> {
    Ok(count_rows(path, false, COUNT_LOGIN_QUERY)?)
}
