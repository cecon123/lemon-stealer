//! Core data types: entries, categories, browser metadata and extraction results.
//!
//! Port of Go package `types` (`types/category.go`, `types/models.go`, `types/result.go`)
//! plus `parse_categories` from `cmd/hack-browser-data/dump.go` (see [`parse`]).

pub mod category;
pub mod models;
pub mod parse;
pub mod result;
pub mod time;

pub use category::{BrowserConfig, BrowserData, BrowserKind, Category, non_sensitive_categories};
pub use models::{
    BookmarkEntry, CookieEntry, CreditCardEntry, DownloadEntry, ExtensionEntry, HistoryEntry,
    LoginEntry, StorageEntry,
};
pub use parse::{CategoryParseError, category_names, parse_categories};
pub use result::{CountResult, ExtractResult, Profile};
pub use time::ChromeTime;
