//! Yandex-specific extraction pipeline (Go: `browser/chromium/yandex.go`).

use std::cmp::Reverse;
use std::fmt;
use std::path::Path;

use hbd_core::{ChromeTime, LoginEntry};
use keyring::MasterKeys;
use rusqlite::OptionalExtension;
use sha1::{Digest, Sha1};

use crate::chromium::sqliteutil::query_rows;

pub(crate) const YANDEX_LOGIN_QUERY: &str = "SELECT origin_url, username_element, username_value,
    password_element, password_value, signon_realm, date_created FROM logins";

/// Error from [`load_yandex_data_key`]: either transparent (SQLite/Read) or the
/// master-password gate.
#[derive(Debug)]
pub enum YandexError {
    MasterPassword,
    Other(String),
}

impl YandexError {
    /// True when the profile is sealed by a master password (Go:
    /// `errYandexMasterPasswordSet` — caller warns + skips).
    pub fn is_master_password(&self) -> bool {
        matches!(self, YandexError::MasterPassword)
    }
}

impl fmt::Display for YandexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YandexError::MasterPassword => {
                f.write_str("yandex: profile protected by master password, skipping")
            }
            YandexError::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for YandexError {}

/// AAD = SHA1(origin_url \x00 username_element \x00 username_value \x00
/// password_element \x00 signon_realm), keyID appended when the profile has a
/// master password (v1 always passes nil) (Go: `yandexLoginAAD`).
pub(crate) fn yandex_login_aad(
    origin_url: &str,
    username_elem: &str,
    username_val: &str,
    password_elem: &str,
    signon_realm: &str,
) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(origin_url.as_bytes());
    h.update([0]);
    h.update(username_elem.as_bytes());
    h.update([0]);
    h.update(username_val.as_bytes());
    h.update([0]);
    h.update(password_elem.as_bytes());
    h.update([0]);
    h.update(signon_realm.as_bytes());
    h.finalize().to_vec()
}

/// Yandex card AAD is the raw guid bytes (Go: `yandexCardAAD`).
pub(crate) fn yandex_card_aad(guid: &str) -> Vec<u8> {
    guid.as_bytes().to_vec()
}

/// Honors the master-password gate and returns the per-DB data key
/// (Go: `loadYandexDataKey`).
pub(crate) fn load_yandex_data_key(
    db_path: &Path,
    master_key: Option<&[u8]>,
) -> Result<Vec<u8>, YandexError> {
    let master_key =
        master_key.ok_or_else(|| YandexError::Other("yandex: master key not available".into()))?;
    if !db_path.is_file() {
        return Err(YandexError::Other(format!(
            "yandex db file: {}",
            db_path.display()
        )));
    }
    let conn = rusqlite::Connection::open(db_path)
        .map_err(|e| YandexError::Other(format!("yandex db file: {e}")))?;

    if has_master_password(&conn).map_err(|e| YandexError::Other(e.to_string()))? {
        return Err(YandexError::MasterPassword);
    }

    let blob: Vec<u8> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'local_encryptor_data'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| YandexError::Other(format!("read local_encryptor_data: {e}")))?;

    hbd_crypto::decrypt_yandex_intermediate_key(master_key, &blob)
        .map_err(|e| YandexError::Other(format!("derive yandex data key: {e}")))
}

/// Missing `meta`/`active_keys` tables (Ya Credit Cards has none) or an empty
/// `sealed_key` both mean "no master password" (Go: `hasMasterPassword`).
fn has_master_password(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    let sealed: Option<String> = conn
        .query_row("SELECT sealed_key FROM active_keys", [], |row| row.get(0))
        .optional()?;
    Ok(sealed.is_some_and(|s| !s.trim().is_empty()))
}

/// Extracts Yandex's Ya Passman Data. The URL column is origin_url — it's what
/// the per-row AAD is computed over (not action_url).
/// (Go: `extractYandexPasswords`.)
pub fn extract_yandex_passwords(
    master_keys: &MasterKeys,
    path: &Path,
) -> crate::chromium::error::Result<Vec<LoginEntry>> {
    let data_key = match load_yandex_data_key(path, master_keys.v10.as_deref()) {
        Ok(k) => k,
        Err(e) if e.is_master_password() => {
            log::warn!("{}: {}", path.display(), e);
            return Ok(Vec::new());
        }
        Err(e) => return Err(e.into()),
    };

    let mut logins = query_rows(path, false, YANDEX_LOGIN_QUERY, |row| {
        let origin_url: String = row.get(0)?;
        let username_elem: String = row.get(1)?;
        let username_val: String = row.get(2)?;
        let password_elem: String = row.get(3)?;
        let password_value: Vec<u8> = row.get(4)?;
        let signon_realm: String = row.get(5)?;
        let created: i64 = row.get(6)?;

        let mut entry = LoginEntry {
            url: origin_url.clone(),
            username: username_val.clone(),
            password: String::new(),
            created_at: ChromeTime::from_chromium_micros(created),
        };
        let aad = yandex_login_aad(
            &origin_url,
            &username_elem,
            &username_val,
            &password_elem,
            &signon_realm,
        );
        match hbd_crypto::aead::aes_gcm_decrypt_blob(&data_key, &password_value, &aad) {
            Ok(plaintext) => entry.password = String::from_utf8_lossy(&plaintext).into_owned(),
            Err(e) => log::debug!("yandex: decrypt password for {}: {}", origin_url, e),
        }
        Ok(entry)
    })?;

    logins.sort_by_key(|a| Reverse(a.created_at));
    Ok(logins)
}
