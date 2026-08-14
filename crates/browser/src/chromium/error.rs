//! Shared error for the chromium engine (library-layer `thiserror`, R3).
//!
//! Mirrors Go's open error surface: entry-level failures inside extractors are
//! logged and skipped by the caller, never propagated up as fatal.

use std::io;

/// Errors from extractors and leveldb reads.
#[derive(Debug, thiserror::Error)]
pub enum ChromiumError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    SqliteUtil(#[from] crate::chromium::sqliteutil::SqliteError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Crypto(#[from] hbd_crypto::CryptoError),
    #[error(transparent)]
    Yandex(#[from] crate::chromium::yandex::YandexError),
}

/// Result alias for the engine's fallible operations.
pub type Result<T> = std::result::Result<T, ChromiumError>;

impl From<&str> for ChromiumError {
    fn from(s: &str) -> Self {
        ChromiumError::Message(s.to_string())
    }
}

impl From<String> for ChromiumError {
    fn from(s: String) -> Self {
        ChromiumError::Message(s)
    }
}
