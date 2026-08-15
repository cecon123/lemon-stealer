//! Port of Go package `output` (Phase 4) — with one deliberate layout
//! deviation: results are split per profile instead of flattened.
//!
//! Layout: `<dir>/<browser>/<profile>/<category>.<ext>` — e.g.
//! `results/Chrome/Default/password.csv`. Go's flat mode (`results/password.csv`)
//! collapses "Default" across browsers; here every profile is its own folder
//! (Decided with the user: "chia folder theo từng profile một như Default,
//! Profile 1, Profile 2, ..."):
//!
//! ```text
//! results/
//!   Chrome/
//!     Default/
//!       password.csv
//!       cookie.csv
//!     Profile 1/
//!       password.csv
//!   Edge/
//!     Default/
//!       history.csv
//! ```
//!
//! Everything else matches Go `output/output.go`: per-category files in Go's
//! category order, CSV UTF-8 BOM, format buffered then skipped when empty,
//! `0o600`/`0o750` modes, stderr + `log.Infof` summary lines.

mod formatters;
mod row;

use std::fs;
use std::io::Write;
use std::path::Path;

use hbd_core::{BrowserData, Category};
use log::info;

pub use formatters::Formatter;
pub use row::{Entry, Row};

/// UTF-8 BOM written at the start of CSV files for Excel compatibility
/// (Go: `utf8BOM`).
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Category → extractor table. Order matters: Go's `categories` slice order is
/// password, cookie, history, download, bookmark, creditcard, extension,
/// localstorage, sessionstorage — NOT `Category::ALL` order.
type Extractor = fn(&BrowserData) -> Vec<Entry>;

static CATEGORY_TABLE: &[(Category, Extractor)] = &[
    (Category::PASSWORD, |d| {
        d.passwords.iter().cloned().map(Entry::Login).collect()
    }),
    (Category::COOKIE, |d| {
        d.cookies.iter().cloned().map(Entry::Cookie).collect()
    }),
    (Category::HISTORY, |d| {
        d.histories.iter().cloned().map(Entry::History).collect()
    }),
    (Category::DOWNLOAD, |d| {
        d.downloads.iter().cloned().map(Entry::Download).collect()
    }),
    (Category::BOOKMARK, |d| {
        d.bookmarks.iter().cloned().map(Entry::Bookmark).collect()
    }),
    (Category::CREDIT_CARD, |d| {
        d.credit_cards
            .iter()
            .cloned()
            .map(Entry::CreditCard)
            .collect()
    }),
    (Category::EXTENSION, |d| {
        d.extensions.iter().cloned().map(Entry::Extension).collect()
    }),
    (Category::LOCAL_STORAGE, |d| {
        d.local_storage
            .iter()
            .cloned()
            .map(Entry::Storage)
            .collect()
    }),
    (Category::SESSION_STORAGE, |d| {
        d.session_storage
            .iter()
            .cloned()
            .map(Entry::Storage)
            .collect()
    }),
];

/// Errors from writer construction or writing (Go: plain `error`s).
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    /// Go: `unsupported format: %s`.
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
    /// Go: `create output dir: %w` / `create %s: %w` etc.
    #[error("{message}: {source}")]
    Io {
        message: String,
        source: std::io::Error,
    },
    /// Go: `format %s: %w`.
    #[error("format {category}: {source}")]
    Format {
        category: String,
        source: std::io::Error,
    },
}

impl OutputError {
    fn io(message: impl Into<String>, source: std::io::Error) -> Self {
        OutputError::Io {
            message: message.into(),
            source,
        }
    }
}

impl From<std::io::Error> for OutputError {
    fn from(e: std::io::Error) -> Self {
        OutputError::io("io error", e)
    }
}

/// One accumulated browser profile (Go: `result`).
pub struct Acc {
    browser: String,
    profile: String,
    data: BrowserData,
}

/// One browser's aggregate counts (feeds the per-browser Telegram breakdown).
#[derive(Debug, Clone, Default)]
pub struct BrowserStats {
    pub name: String,
    pub entries: usize,
    pub files: usize,
    pub profiles: usize,
    /// Per-category totals for this browser (first-seen order).
    pub categories: Vec<(String, usize)>,
}

/// Counts produced by a [`Writer::write`] pass — feeds the Telegram caption.
#[derive(Debug, Clone, Default)]
pub struct WriteReport {
    pub entries: usize,
    pub files: usize,
    pub profiles: usize,
    /// Per-category totals (order: first-seen, i.e. Go's category order).
    pub categories: Vec<(String, usize)>,
    /// Per-browser breakdown (order: first-seen / Go's discovery order).
    pub browsers: Vec<BrowserStats>,
}

/// One (browser, profile) group with per-category non-empty rows.
struct Group {
    browser: String,
    profile: String,
    categories: Vec<(Category, Vec<Row>)>,
}

/// Collects per-profile data and writes it out (Go: `Writer`).
pub struct Writer {
    dir: String,
    formatter: Box<dyn Formatter>,
    results: Vec<Acc>,
}

impl Writer {
    /// `NewWriter(dir, format)` — resolves the format backend up front.
    pub fn new(dir: &str, format: &str) -> Result<Writer, OutputError> {
        Ok(Writer {
            dir: dir.to_string(),
            formatter: formatters::new_formatter(format)?,
            results: Vec::new(),
        })
    }

    /// Accumulates one browser profile's data (Go: `Add`). `data == nil`
    /// (Go) is `&BrowserData` empty here — skipped at aggregation, matching
    /// Go's "empty entries produce no file" behavior.
    pub fn add(&mut self, browser: &str, profile: &str, data: &BrowserData) {
        self.results.push(Acc {
            browser: browser.to_string(),
            profile: profile.to_string(),
            data: data.clone(),
        });
    }

    /// Aggregates per (browser, profile) and writes each non-empty category
    /// to `<dir>/<browser>/<profile>/<category>.<ext>` (Go: `Write`).
    /// Returns a [`WriteReport`] with the totals (for transport/caption).
    pub fn write(&mut self) -> Result<WriteReport, OutputError> {
        fs::create_dir_all(&self.dir).map_err(|e| OutputError::io("create output dir", e))?;

        // Per (browser, profile) summary: category → entry count.
        let mut summaries: Vec<(String, Vec<(String, usize)>)> = Vec::new();
        for g in &self.aggregate() {
            let base = Path::new(&self.dir)
                .join(sanitize_segment(&g.browser))
                .join(sanitize_segment(&g.profile));
            let mut cat_counts = Vec::new();
            for (category, rows) in &g.categories {
                let name = category.to_string();
                self.write_file(&base, &name, rows)?;
                cat_counts.push((name, rows.len()));
            }
            if !cat_counts.is_empty() {
                summaries.push((join_rel(&g.browser, &g.profile), cat_counts));
            }
        }
        if summaries.is_empty() {
            return Ok(WriteReport::default());
        }

        // One line per profile with per-category counts, then a total line.
        eprintln!();
        info!("Exported to {}/", self.dir);
        let mut files = 0usize;
        let mut entries = 0usize;
        for (rel, cat_counts) in &summaries {
            files += cat_counts.len();
            entries += cat_counts.iter().map(|(_, n)| n).sum::<usize>();
            let cats = cat_counts
                .iter()
                .map(|(name, n)| format!("{name} {n}"))
                .collect::<Vec<_>>()
                .join(", ");
            info!("  {rel}: {cats}");
        }
        info!(
            "Exported {} entries across {} files in {} profile(s)",
            entries,
            files,
            summaries.len()
        );

        // Aggregate per-category totals across profiles (first-seen order).
        let mut ordered: Vec<(String, usize)> = Vec::new();
        for (_, cat_counts) in &summaries {
            for (name, n) in cat_counts {
                match ordered.iter_mut().find(|(c, _)| c == name) {
                    Some((_, total)) => *total += n,
                    None => ordered.push((name.clone(), *n)),
                }
            }
        }

        // Group the same summaries per browser (rel = "browser/profile").
        let mut browsers: Vec<BrowserStats> = Vec::new();
        for (rel, cat_counts) in &summaries {
            let name = rel.split('/').next().unwrap_or("?").to_string();
            let bs = match browsers.iter_mut().find(|b| b.name == name) {
                Some(b) => b,
                None => {
                    browsers.push(BrowserStats {
                        name: name.clone(),
                        ..Default::default()
                    });
                    browsers.last_mut().expect("just pushed")
                }
            };
            bs.profiles += 1;
            bs.files += cat_counts.len();
            bs.entries += cat_counts.iter().map(|(_, n)| n).sum::<usize>();
            for (cat, n) in cat_counts {
                match bs.categories.iter_mut().find(|(c, _)| c == cat) {
                    Some((_, total)) => *total += n,
                    None => bs.categories.push((cat.clone(), *n)),
                }
            }
        }

        Ok(WriteReport {
            entries,
            files,
            profiles: summaries.len(),
            categories: ordered,
            browsers,
        })
    }

    fn aggregate(&self) -> Vec<Group> {
        let mut groups: Vec<Group> = Vec::new();
        for r in &self.results {
            let group = match groups
                .iter_mut()
                .find(|g| g.browser == r.browser && g.profile == r.profile)
            {
                Some(g) => g,
                None => {
                    groups.push(Group {
                        browser: r.browser.clone(),
                        profile: r.profile.clone(),
                        categories: Vec::new(),
                    });
                    groups.last_mut().expect("just pushed")
                }
            };
            for (category, extract) in CATEGORY_TABLE {
                let entries = extract(&r.data);
                if entries.is_empty() {
                    continue;
                }
                let rows: Vec<Row> = entries
                    .into_iter()
                    .map(|e| Row::new(&r.browser, &r.profile, e))
                    .collect();
                match group.categories.iter_mut().find(|(c, _)| c == category) {
                    Some((_, existing)) => existing.extend(rows),
                    None => group.categories.push((*category, rows)),
                }
            }
        }
        groups
    }

    fn write_file(&self, dir: &Path, category: &str, rows: &[Row]) -> Result<(), OutputError> {
        // Format to buffer first — zero formatted output means no file
        // (Go: cookie-editor skipping non-cookie data is handled by its
        // fallback; the empty-buffer path is kept for parity).
        let mut buf = Vec::new();
        self.formatter
            .format(&mut buf, rows)
            .map_err(|e| OutputError::Format {
                category: category.to_string(),
                source: e,
            })?;
        if buf.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(dir).map_err(|e| OutputError::io("create output dir", e))?;

        let filename = file_name(category, self.formatter.ext());
        let path = dir.join(&filename);
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| OutputError::io(format!("create {filename}"), e))?;
        #[cfg(unix)]
        set_mode_0600(&f);
        if self.formatter.ext() == "csv" {
            f.write_all(&UTF8_BOM)
                .map_err(|e| OutputError::io("write BOM", e))?;
        }
        f.write_all(&buf)
            .map_err(|e| OutputError::io(format!("write {filename}"), e))
    }
}

fn file_name(category: &str, ext: &str) -> String {
    format!("{category}.{ext}")
}

/// Forward-slash relative path for logging (Go logs `password.csv`; the
/// profile-split deviation logs `browser/profile/password.csv` instead).
fn join_rel(browser: &str, profile: &str) -> String {
    format!(
        "{}/{}",
        sanitize_segment(browser),
        sanitize_segment(profile)
    )
}

/// Replaces characters invalid in Windows path segments and trims leading
/// dots (profile names come from disk; be defensive).
fn sanitize_segment(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    out.trim_matches(|c| c == '.' || c == ' ').to_string()
}

#[cfg(unix)]
fn set_mode_0600(f: &fs::File) {
    use std::os::unix::fs::PermissionsExt;
    let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use hbd_core::{CookieEntry, LoginEntry};

    fn sample_data() -> BrowserData {
        let t = hbd_core::ChromeTime::from_utc(
            chrono::Utc
                .with_ymd_and_hms(2026, 1, 15, 10, 30, 0)
                .unwrap(),
        );
        BrowserData {
            passwords: vec![LoginEntry {
                url: "https://example.com".into(),
                username: "alice".into(),
                password: "secret".into(),
                created_at: t,
            }],
            cookies: vec![CookieEntry {
                host: ".example.com".into(),
                path: "/".into(),
                name: "session".into(),
                value: "abc123".into(),
                is_secure: true,
                is_http_only: true,
                has_expire: true,
                is_persistent: true,
                expire_at: t,
                created_at: t,
                same_site: String::new(),
            }],
            histories: vec![hbd_core::HistoryEntry {
                url: "https://example.com".into(),
                title: "Example".into(),
                visit_count: 5,
                last_visit: t,
            }],
            ..Default::default()
        }
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lemon-output-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn writer_rejects_unknown_format() {
        let res = Writer::new("results", "unknown");
        match res {
            Err(OutputError::UnsupportedFormat(f)) => assert_eq!("unknown", f),
            Ok(_) => panic!("expected unsupported format error"),
            Err(other) => panic!("wrong error variant: {other}"),
        }
    }

    #[test]
    fn csv_password_profile_split() {
        let dir = temp_dir("csv-pw");
        let mut w = Writer::new(dir.to_str().unwrap(), "csv").unwrap();
        let d = sample_data();
        w.add("Chrome", "Default", &d);
        w.add("Firefox", "abc123", &d);
        w.write().unwrap();

        // Profile split: one folder per (browser, profile).
        let chrome = fs::read_to_string(dir.join("Chrome/Default/password.csv")).unwrap();
        assert!(chrome.starts_with("\u{feff}"), "CSV starts with UTF-8 BOM");
        assert_eq!(
            chrome,
            "\u{feff}browser,profile,url,username,password,created_at\nChrome,Default,https://example.com,alice,secret,2026-01-15T10:30:00Z\n"
        );
        let firefox = fs::read_to_string(dir.join("Firefox/abc123/password.csv")).unwrap();
        assert!(firefox.contains("Firefox,abc123,https://example.com,alice,secret"));
        assert!(dir.join("Chrome/Default").is_dir());
        assert!(dir.join("Firefox/abc123").is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn csv_cookie_full_header() {
        let dir = temp_dir("csv-ck");
        let mut w = Writer::new(dir.to_str().unwrap(), "csv").unwrap();
        let d = sample_data();
        w.add("Chrome", "Default", &d);
        w.write().unwrap();

        let s = fs::read_to_string(dir.join("Chrome/Default/cookie.csv")).unwrap();
        let s = s.trim_start_matches('\u{feff}');
        let mut lines = s.lines();
        assert_eq!(
            lines.next().unwrap(),
            "browser,profile,host,path,name,value,is_secure,is_http_only,has_expire,is_persistent,expire_at,created_at,same_site"
        );
        assert_eq!(
            lines.next().unwrap(),
            "Chrome,Default,.example.com,/,session,abc123,true,true,true,true,2026-01-15T10:30:00Z,2026-01-15T10:30:00Z,"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn csv_history_header() {
        let dir = temp_dir("csv-his");
        let mut w = Writer::new(dir.to_str().unwrap(), "csv").unwrap();
        let d = sample_data();
        w.add("Chrome", "Profile 1", &d);
        w.write().unwrap();
        let s = fs::read_to_string(dir.join("Chrome/Profile 1/history.csv")).unwrap();
        let s = s.trim_start_matches('\u{feff}');
        let mut lines = s.lines();
        assert_eq!(
            lines.next().unwrap(),
            "browser,profile,url,title,visit_count,last_visit"
        );
        assert_eq!(
            lines.next().unwrap(),
            "Chrome,Profile 1,https://example.com,Example,5,2026-01-15T10:30:00Z"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_password_flat_order() {
        let dir = temp_dir("json-pw");
        let mut w = Writer::new(dir.to_str().unwrap(), "json").unwrap();
        let d = sample_data();
        w.add("Chrome", "Default", &d);
        w.add("Firefox", "abc123", &d);
        w.write().unwrap();

        let raw = fs::read_to_string(dir.join("Chrome/Default/password.json")).unwrap();
        assert!(!raw.starts_with('\u{feff}'), "JSON must not have BOM");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!("Chrome", v[0]["browser"]);
        assert_eq!("Default", v[0]["profile"]);
        assert_eq!("alice", v[0]["username"]);
        assert_eq!(1, v.as_array().unwrap().len());
        // field order locked: browser, profile, url, username, password, created_at
        let first_key = raw.find("\"browser\"").unwrap();
        let second_key = raw.find("\"profile\"").unwrap();
        let url_key = raw.find("\"url\"").unwrap();
        assert!(first_key < second_key && second_key < url_key);

        let ff = fs::read_to_string(dir.join("Firefox/abc123/password.json")).unwrap();
        let vf: serde_json::Value = serde_json::from_str(&ff).unwrap();
        assert_eq!("Firefox", vf[0]["browser"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_category_no_file() {
        let dir = temp_dir("empty-cat");
        let mut w = Writer::new(dir.to_str().unwrap(), "csv").unwrap();
        let d = sample_data();
        w.add("Chrome", "Default", &d);
        w.write().unwrap();
        assert!(dir.join("Chrome/Default/password.csv").exists());
        assert!(
            !dir.join("Chrome/Default/history.csv")
                .parent()
                .unwrap()
                .join("download.csv")
                .exists()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_data_no_files() {
        let dir = temp_dir("no-data");
        let mut w = Writer::new(dir.to_str().unwrap(), "csv").unwrap();
        w.write().unwrap();
        assert!(fs::read_dir(&dir).unwrap().next().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cookie_editor_over_profile_split() {
        let dir = temp_dir("ce");
        let mut w = Writer::new(dir.to_str().unwrap(), "cookie-editor").unwrap();
        let d = sample_data();
        w.add("Chrome", "Default", &d);
        w.write().unwrap();
        let raw = fs::read_to_string(dir.join("Chrome/Default/cookie.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(".example.com", v[0]["domain"]);
        assert_eq!("session", v[0]["name"]);
        assert_eq!(1768473000.0_f64, v[0]["expirationDate"].as_f64().unwrap());
        // non-cookie categories fall back to JSON rows
        let pw = fs::read_to_string(dir.join("Chrome/Default/password.json")).unwrap();
        assert!(pw.contains("\"browser\": \"Chrome\""));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_segments() {
        assert_eq!("Default", sanitize_segment("Default"));
        assert_eq!("Profile 1", sanitize_segment("Profile 1"));
        assert_eq!("a_b_c", sanitize_segment("a<b>c"));
        assert_eq!("a_b", sanitize_segment("a/b"));
        assert_eq!("a_b", sanitize_segment("a\\b"));
        assert_eq!("a_b", sanitize_segment("a:b"));
        assert_eq!("Default", sanitize_segment(" .Default.. "));
    }
}
