//! Cookie extraction (Go: `browser/chromium/extract_cookie.go`).

use std::cmp::Reverse;
use std::path::Path;

use hbd_core::{ChromeTime, CookieEntry};
use keyring::MasterKeys;
use sha2::{Digest, Sha256};

use crate::chromium::decrypt::decrypt_value;
use crate::chromium::error::Result;
use crate::chromium::sqliteutil::{count_rows, query_rows};

const DEFAULT_COOKIE_QUERY: &str = "SELECT name, encrypted_value, host_key, path,
    creation_utc, expires_utc, is_secure, is_httponly,
    has_expires, is_persistent, samesite FROM cookies";
const COUNT_COOKIE_QUERY: &str = "SELECT COUNT(*) FROM cookies";

/// Extracts cookies, sorted by created date descending
/// (Go: `extractCookies`).
pub fn extract_cookies(master_keys: &MasterKeys, path: &Path) -> Result<Vec<CookieEntry>> {
    let mut cookies = query_rows(path, false, DEFAULT_COOKIE_QUERY, |row| {
        let name: String = row.get(0)?;
        let encrypted_value: Vec<u8> = row.get(1)?;
        let host: String = row.get(2)?;
        let cookie_path: String = row.get(3)?;
        let created_at: i64 = row.get(4)?;
        let expire_at: i64 = row.get(5)?;
        let is_secure: i64 = row.get(6)?;
        let is_http_only: i64 = row.get(7)?;
        let has_expire: i64 = row.get(8)?;
        let is_persistent: i64 = row.get(9)?;
        let same_site: i64 = row.get(10)?;

        let mut value = decrypt_value(master_keys, &encrypted_value).unwrap_or_default();
        value = strip_cookie_hash(&value, &host);
        let same_site_str = match same_site {
            0 => "none",
            1 => "lax",
            2 => "strict",
            -1 => "unspecified", // not specified by Set-Cookie
            _ => "unspecified",
        };
        Ok(CookieEntry {
            name,
            host,
            path: cookie_path,
            value: String::from_utf8_lossy(&value).into_owned(),
            is_secure: is_secure != 0,
            is_http_only: is_http_only != 0,
            has_expire: has_expire != 0,
            is_persistent: is_persistent != 0,
            expire_at: ChromeTime::from_chromium_micros(expire_at),
            created_at: ChromeTime::from_chromium_micros(created_at),
            same_site: same_site_str.to_string(),
        })
    })?;

    cookies.sort_by_key(|a| Reverse(a.created_at));
    Ok(cookies)
}

pub fn count_cookies(path: &Path) -> Result<i64> {
    Ok(count_rows(path, false, COUNT_COOKIE_QUERY)?)
}

/// Removes the SHA256(host_key) prefix from a decrypted cookie value. Chrome
/// 130+ (Cookie DB schema version 24) prepends SHA256(domain) to the cookie
/// value before encryption to prevent cross-domain cookie replay attacks. If
/// the first 32 bytes don't match SHA256(host_key), the value is returned
/// unchanged, which handles both older Chrome versions and tampered data.
/// (Go: `stripCookieHash`.)
pub fn strip_cookie_hash(value: &[u8], host_key: &str) -> Vec<u8> {
    if value.len() < 32 {
        return value.to_vec();
    }
    let hash = Sha256::digest(host_key.as_bytes());
    if value[..32] == hash[..] {
        return value[32..].to_vec(); // empty slice if value was exactly 32 bytes
    }
    value.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_matching_hash() {
        let host = "example.com";
        let hash: Vec<u8> = Sha256::digest(host.as_bytes()).to_vec();
        let mut value = hash.clone();
        value.extend_from_slice(b"session=abc");
        assert_eq!(b"session=abc".to_vec(), strip_cookie_hash(&value, host));
    }

    #[test]
    fn strip_not_matching_hash_returns_value() {
        let value = b"plain-old-value".to_vec();
        assert_eq!(value, strip_cookie_hash(&value, "example.com"));
    }

    #[test]
    fn strip_short_value_returns_value() {
        let value = b"short".to_vec();
        assert_eq!(value, strip_cookie_hash(&value, "example.com"));
    }

    #[test]
    fn strip_exactly_32_bytes_yields_empty() {
        let host = "example.com";
        let hash: Vec<u8> = Sha256::digest(host.as_bytes()).to_vec();
        assert_eq!(Vec::<u8>::new(), strip_cookie_hash(&hash, host));
    }
}
