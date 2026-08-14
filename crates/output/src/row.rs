//! Port of Go `output/row.go` + `output/reflect.go`.
//!
//! Go builds rows via `reflect` (dynamic struct field order); Rust keeps the
//! same browser/profile + entry-field order without reflect — the entry
//! structs in `core` are defined in Go field order, so header/value tables
//! below are hand-written to that order and locked by tests.

use serde::{Serialize, Serializer};

use hbd_core::{
    BookmarkEntry, ChromeTime, CookieEntry, CreditCardEntry, DownloadEntry, ExtensionEntry,
    HistoryEntry, LoginEntry, StorageEntry,
};

/// One output row: browser/profile context plus a typed entry.
#[derive(Debug, Clone)]
pub struct Row {
    pub browser: String,
    pub profile: String,
    pub entry: Entry,
}

/// The typed payload of a row (Go: `row.entry any`).
#[derive(Debug, Clone)]
pub enum Entry {
    Login(LoginEntry),
    Cookie(CookieEntry),
    History(HistoryEntry),
    Download(DownloadEntry),
    Bookmark(BookmarkEntry),
    CreditCard(CreditCardEntry),
    Extension(ExtensionEntry),
    Storage(StorageEntry),
}

impl Row {
    pub fn new(browser: impl Into<String>, profile: impl Into<String>, entry: Entry) -> Row {
        Row {
            browser: browser.into(),
            profile: profile.into(),
            entry,
        }
    }

    /// CSV column names: `browser`, `profile`, then the entry's csv-tagged
    /// fields in struct order (Go: `row.csvHeader`).
    pub fn csv_headers(&self) -> Vec<&'static str> {
        let mut h = vec!["browser", "profile"];
        h.extend_from_slice(self.entry.csv_headers());
        h
    }

    /// CSV field values, same order as [`Row::csv_headers`] (Go: `row.csvRow`).
    pub fn csv_values(&self) -> Vec<String> {
        let mut v = vec![self.browser.clone(), self.profile.clone()];
        v.extend(self.entry.csv_values());
        v
    }

    /// The cookie payload when this row is a cookie (cookie-editor format).
    pub fn as_cookie(&self) -> Option<&CookieEntry> {
        match &self.entry {
            Entry::Cookie(c) => Some(c),
            _ => None,
        }
    }
}

impl Entry {
    pub fn csv_headers(&self) -> &'static [&'static str] {
        match self {
            Entry::Login(_) => &["url", "username", "password", "created_at"],
            Entry::Cookie(_) => &[
                "host",
                "path",
                "name",
                "value",
                "is_secure",
                "is_http_only",
                "has_expire",
                "is_persistent",
                "expire_at",
                "created_at",
                "same_site",
            ],
            Entry::History(_) => &["url", "title", "visit_count", "last_visit"],
            Entry::Download(_) => &[
                "url",
                "target_path",
                "mime_type",
                "total_bytes",
                "start_time",
                "end_time",
            ],
            Entry::Bookmark(_) => &["id", "name", "type", "url", "folder", "created_at"],
            Entry::CreditCard(_) => &[
                "guid",
                "name",
                "number",
                "exp_month",
                "exp_year",
                "nick_name",
                "address",
                "cvc",
                "comment",
            ],
            Entry::Extension(_) => &[
                "name",
                "id",
                "description",
                "version",
                "homepage_url",
                "enabled",
            ],
            Entry::Storage(_) => &["is_meta", "url", "key", "value"],
        }
    }

    pub fn csv_values(&self) -> Vec<String> {
        match self {
            Entry::Login(e) => vec![
                e.url.clone(),
                e.username.clone(),
                e.password.clone(),
                csv_time(e.created_at),
            ],
            Entry::Cookie(e) => vec![
                e.host.clone(),
                e.path.clone(),
                e.name.clone(),
                e.value.clone(),
                csv_bool(e.is_secure),
                csv_bool(e.is_http_only),
                csv_bool(e.has_expire),
                csv_bool(e.is_persistent),
                csv_time(e.expire_at),
                csv_time(e.created_at),
                e.same_site.clone(),
            ],
            Entry::History(e) => vec![
                e.url.clone(),
                e.title.clone(),
                e.visit_count.to_string(),
                csv_time(e.last_visit),
            ],
            Entry::Download(e) => vec![
                e.url.clone(),
                e.target_path.clone(),
                e.mime_type.clone(),
                e.total_bytes.to_string(),
                csv_time(e.start_time),
                csv_time(e.end_time),
            ],
            Entry::Bookmark(e) => vec![
                e.id.to_string(),
                e.name.clone(),
                e.r#type.clone(),
                e.url.clone(),
                e.folder.clone(),
                csv_time(e.created_at),
            ],
            Entry::CreditCard(e) => vec![
                e.guid.clone(),
                e.name.clone(),
                e.number.clone(),
                e.exp_month.clone(),
                e.exp_year.clone(),
                e.nick_name.clone(),
                e.address.clone(),
                e.cvc.clone(),
                e.comment.clone(),
            ],
            Entry::Extension(e) => vec![
                e.name.clone(),
                e.id.clone(),
                e.description.clone(),
                e.version.clone(),
                e.homepage_url.clone(),
                csv_bool(e.enabled),
            ],
            Entry::Storage(e) => vec![
                csv_bool(e.is_meta),
                e.url.clone(),
                e.key.clone(),
                e.value.clone(),
            ],
        }
    }
}

/// Go `formatBool`: `true` / `false`.
fn csv_bool(b: bool) -> String {
    if b {
        "true".to_string()
    } else {
        "false".to_string()
    }
}

/// Go `formatTime`: zero time → `""`, else RFC3339 (seconds precision, no
/// fraction — Go's `time.RFC3339` layout drops subseconds).
fn csv_time(t: ChromeTime) -> String {
    if t.is_zero() {
        return String::new();
    }
    t.as_datetime().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Flat JSON: `{browser, profile, ...entry fields}` in exactly that order
/// (Go `row.MarshalJSON` builds the same struct shape via `reflect.StructOf`).
impl Serialize for Row {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // #[serde(flatten)] appends the entry's fields after the two context
        // fields, preserving each struct's declaration order (Go parity).
        #[derive(Serialize)]
        struct Flat<'a, T: Serialize> {
            browser: &'a str,
            profile: &'a str,
            #[serde(flatten)]
            entry: &'a T,
        }
        match &self.entry {
            Entry::Login(e) => Flat {
                browser: &self.browser,
                profile: &self.profile,
                entry: e,
            }
            .serialize(serializer),
            Entry::Cookie(e) => Flat {
                browser: &self.browser,
                profile: &self.profile,
                entry: e,
            }
            .serialize(serializer),
            Entry::History(e) => Flat {
                browser: &self.browser,
                profile: &self.profile,
                entry: e,
            }
            .serialize(serializer),
            Entry::Download(e) => Flat {
                browser: &self.browser,
                profile: &self.profile,
                entry: e,
            }
            .serialize(serializer),
            Entry::Bookmark(e) => Flat {
                browser: &self.browser,
                profile: &self.profile,
                entry: e,
            }
            .serialize(serializer),
            Entry::CreditCard(e) => Flat {
                browser: &self.browser,
                profile: &self.profile,
                entry: e,
            }
            .serialize(serializer),
            Entry::Extension(e) => Flat {
                browser: &self.browser,
                profile: &self.profile,
                entry: e,
            }
            .serialize(serializer),
            Entry::Storage(e) => Flat {
                browser: &self.browser,
                profile: &self.profile,
                entry: e,
            }
            .serialize(serializer),
        }
    }
}
