//! Port of `types/models.go`.
//!
//! Field order and JSON names match Go's struct order / `json` tags exactly — the
//! output crate relies on Go's reflect-based flattening order = struct order.

use serde::{Deserialize, Serialize};

use crate::ChromeTime;

/// A single saved login credential (Go: `LoginEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginEntry {
    pub url: String,
    pub username: String,
    pub password: String,
    pub created_at: ChromeTime,
}

/// A single browser cookie (Go: `CookieEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CookieEntry {
    pub host: String,
    pub path: String,
    pub name: String,
    pub value: String,
    pub is_secure: bool,
    pub is_http_only: bool,
    pub has_expire: bool,
    pub is_persistent: bool,
    pub expire_at: ChromeTime,
    pub created_at: ChromeTime,
    pub same_site: String,
}

/// A single browser bookmark (Go: `BookmarkEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BookmarkEntry {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub url: String,
    pub folder: String,
    pub created_at: ChromeTime,
}

/// A single browser history record (Go: `HistoryEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_count: i64,
    pub last_visit: ChromeTime,
}

/// A single browser download record (Go: `DownloadEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DownloadEntry {
    pub url: String,
    pub target_path: String,
    pub mime_type: String,
    pub total_bytes: i64,
    pub start_time: ChromeTime,
    pub end_time: ChromeTime,
}

/// A single saved credit card. CVC and Comment are Yandex-specific; Chromium leaves
/// them empty (Go: `CreditCardEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreditCardEntry {
    pub guid: String,
    pub name: String,
    pub number: String,
    pub exp_month: String,
    pub exp_year: String,
    pub nick_name: String,
    pub address: String,
    pub cvc: String,
    pub comment: String,
}

/// A single key-value pair from local or session storage (Go: `StorageEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageEntry {
    pub is_meta: bool,
    pub url: String,
    pub key: String,
    pub value: String,
}

/// A single browser extension (Go: `ExtensionEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionEntry {
    pub name: String,
    pub id: String,
    pub description: String,
    pub version: String,
    pub homepage_url: String,
    pub enabled: bool,
}
