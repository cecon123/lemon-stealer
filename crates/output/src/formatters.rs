//! Port of Go `output/formatter.go`, `output/csv.go`, `output/json.go` and
//! `output/cookie_editor.go` — the format backends behind [`crate::Writer`].

use std::io::{self, Write};

use serde::Serialize;

use crate::row::Row;

/// Serializes rows into one output format (Go: `formatter` interface).
pub trait Formatter: Send + Sync {
    /// File extension of the output (Go: `ext()`).
    fn ext(&self) -> &'static str;
    /// Formats rows into `w`. An empty write means "don't create the file"
    /// (Go buffers first and skips zero-length output).
    fn format(&self, w: &mut dyn Write, rows: &[Row]) -> io::Result<()>;
}

/// `newFormatter` — the format names are the CLI's `-f` values.
pub fn new_formatter(name: &str) -> Result<Box<dyn Formatter>, crate::OutputError> {
    match name {
        "csv" => Ok(Box::new(CsvFormatter)),
        "json" => Ok(Box::new(JsonFormatter)),
        "cookie-editor" => Ok(Box::new(CookieEditorFormatter {
            fallback: Box::new(JsonFormatter),
        })),
        other => Err(crate::OutputError::UnsupportedFormat(other.to_string())),
    }
}

/// Go `encoding/csv` semantics: `\n` record terminator (UseCRLF=false),
/// fields quoted only when they contain `,` `"` `\r` `\n`, embedded quotes
/// doubled.
pub struct CsvFormatter;

impl Formatter for CsvFormatter {
    fn ext(&self) -> &'static str {
        "csv"
    }

    fn format(&self, w: &mut dyn Write, rows: &[Row]) -> io::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        write_row(
            w,
            &rows[0]
                .csv_headers()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )?;
        for r in rows {
            write_row(w, &r.csv_values())?;
        }
        Ok(())
    }
}

fn write_row(w: &mut dyn Write, fields: &[String]) -> io::Result<()> {
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        if f.contains([',', '"', '\r', '\n']) {
            w.write_all(b"\"")?;
            for c in f.chars() {
                if c == '"' {
                    w.write_all(b"\"\"")?;
                } else {
                    let mut buf = [0u8; 4];
                    w.write_all(c.encode_utf8(&mut buf).as_bytes())?;
                }
            }
            w.write_all(b"\"")?;
        } else {
            w.write_all(f.as_bytes())?;
        }
    }
    w.write_all(b"\n")
}

/// Go `json.Encoder` with `SetIndent("", "  ")` + `SetEscapeHTML(false)`:
/// pretty 2-space array, raw `<>&` (serde_json's `escape_html` feature is
/// NOT enabled), trailing newline.
pub struct JsonFormatter;

impl Formatter for JsonFormatter {
    fn ext(&self) -> &'static str {
        "json"
    }

    fn format(&self, w: &mut dyn Write, rows: &[Row]) -> io::Result<()> {
        serde_json::to_writer_pretty(&mut *w, rows)?;
        w.write_all(b"\n")?;
        Ok(())
    }
}

/// CookieEditor extension import format. Non-cookie categories fall back to
/// standard JSON (Go: `cookieEditorFormatter`).
pub struct CookieEditorFormatter {
    fallback: Box<dyn Formatter>,
}

impl Formatter for CookieEditorFormatter {
    fn ext(&self) -> &'static str {
        "json"
    }

    fn format(&self, w: &mut dyn Write, rows: &[Row]) -> io::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        // aggregate() guarantees all rows in a batch share one type.
        if rows[0].as_cookie().is_none() {
            return self.fallback.format(w, rows);
        }

        let entries: Vec<CookieEditorEntry> = rows
            .iter()
            .filter_map(|r| r.as_cookie())
            .map(CookieEditorEntry::from)
            .collect();
        serde_json::to_writer_pretty(&mut *w, &entries)?;
        w.write_all(b"\n")?;
        Ok(())
    }
}

/// Go `cookieEditorEntry` — note `sameSite` has no `omitempty`, so `None`
/// serializes as `null`; `expirationDate` omits the zero value. Keys match
/// Go's json tags (`httpOnly`, `hostOnly`, `expirationDate`, `sameSite`).
#[derive(Serialize)]
struct CookieEditorEntry {
    domain: String,
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    expiration_date: Option<f64>,
    #[serde(rename = "httpOnly")]
    http_only: bool,
    name: String,
    path: String,
    secure: bool,
    value: String,
    #[serde(rename = "sameSite")]
    same_site: Option<String>,
    session: bool,
    #[serde(rename = "hostOnly")]
    host_only: bool,
}

impl From<&hbd_core::CookieEntry> for CookieEditorEntry {
    fn from(c: &hbd_core::CookieEntry) -> Self {
        let expiration = if c.expire_at.is_zero() {
            None
        } else {
            Some(c.expire_at.as_datetime().timestamp() as f64)
        };
        let same_site = match c.same_site.as_str() {
            "none" => Some("no_restriction".to_string()),
            "" | "unspecified" => None,
            other => Some(other.to_string()),
        };
        CookieEditorEntry {
            domain: c.host.clone(),
            expiration_date: expiration,
            http_only: c.is_http_only,
            name: c.name.clone(),
            path: c.path.clone(),
            secure: c.is_secure,
            value: c.value.clone(),
            same_site,
            session: expiration.is_none(),
            host_only: !c.host.starts_with('.'),
        }
    }
}

/// Sanity-check that `ChromeTime` RFC3339 matches Go's `time.RFC3339` layout
/// used by the CSV formatter (seconds precision, UTC → `Z`).
#[cfg(test)]
fn time_to_rfc3339(t: hbd_core::ChromeTime) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = write!(s, "{}", t.as_datetime().format("%Y-%m-%dT%H:%M:%SZ"));
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::Entry;
    use chrono::TimeZone;
    use hbd_core::{ChromeTime, CookieEntry, LoginEntry};

    fn login(browser: &str, profile: &str) -> Row {
        Row::new(
            browser,
            profile,
            Entry::Login(LoginEntry {
                url: "https://example.com".into(),
                username: "alice".into(),
                password: "secret".into(),
                created_at: ChromeTime::zero(),
            }),
        )
    }

    #[test]
    fn csv_quotes_only_when_needed() {
        let mut buf = Vec::new();
        let row = Row::new(
            "Chrome",
            "Default",
            Entry::Login(LoginEntry {
                url: "https://a.com".into(),
                username: "a,b\"c".into(),
                password: "p\nq".into(),
                created_at: ChromeTime::zero(),
            }),
        );
        CsvFormatter.format(&mut buf, &[row]).expect("format");
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(
            s,
            "browser,profile,url,username,password,created_at\nChrome,Default,https://a.com,\"a,b\"\"c\",\"p\nq\",\n"
        );
    }

    #[test]
    fn csv_empty_zero_time_blank() {
        let mut buf = Vec::new();
        CsvFormatter.format(&mut buf, &[login("C", "D")]).unwrap();
        assert!(
            String::from_utf8(buf)
                .unwrap()
                .ends_with("C,D,https://example.com,alice,secret,\n")
        );
    }

    #[test]
    fn csv_empty_rows_no_output() {
        let mut buf = Vec::new();
        CsvFormatter.format(&mut buf, &[]).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn json_no_html_escape_and_trailing_newline() {
        let mut buf = Vec::new();
        let row = Row::new(
            "Chrome",
            "Default",
            Entry::Login(LoginEntry {
                url: "https://a.com/?q=<&>".into(),
                username: "u".into(),
                password: "p".into(),
                created_at: ChromeTime::zero(),
            }),
        );
        JsonFormatter.format(&mut buf, &[row]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("<&>"), "must not escape HTML: {s}");
        assert!(s.ends_with('\n'));
        // field order: browser, profile, then entry fields
        let keys: Vec<_> = [
            "browser",
            "profile",
            "url",
            "username",
            "password",
            "created_at",
        ]
        .iter()
        .map(|k| format!("\"{k}\""))
        .collect();
        let mut prev = 0;
        for k in keys {
            let at = s.find(&k).unwrap_or_else(|| panic!("missing {k} in {s}"));
            assert!(at > prev, "out of order {k}: {s}");
            prev = at;
        }
    }

    #[test]
    fn cookie_editor_shape() {
        let mut buf = Vec::new();
        let row = Row::new(
            "Chrome",
            "Default",
            Entry::Cookie(CookieEntry {
                host: ".example.com".into(),
                path: "/".into(),
                name: "session".into(),
                value: "abc123".into(),
                is_secure: true,
                is_http_only: true,
                has_expire: true,
                is_persistent: true,
                expire_at: ChromeTime::zero(),
                created_at: ChromeTime::zero(),
                same_site: "none".into(),
            }),
        );
        CookieEditorFormatter {
            fallback: Box::new(JsonFormatter),
        }
        .format(&mut buf, &[row])
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"domain\": \".example.com\""));
        assert!(s.contains("\"httpOnly\": true"));
        assert!(s.contains("\"sameSite\": \"no_restriction\""));
        assert!(s.contains("\"session\": true"));
        assert!(s.contains("\"hostOnly\": false"));
        assert!(!s.contains("expirationDate"), "zero expire omitted: {s}");
    }

    #[test]
    fn cookie_editor_fallback_for_non_cookie() {
        let mut buf = Vec::new();
        CookieEditorFormatter {
            fallback: Box::new(JsonFormatter),
        }
        .format(&mut buf, &[login("C", "D")])
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"browser\": \"C\""), "json fallback: {s}");
    }

    #[test]
    fn cookie_editor_same_site_mapping() {
        use hbd_core::CookieEntry;
        let cases = [
            ("none", Some("no_restriction")),
            ("", None),
            ("unspecified", None),
            ("lax", Some("lax")),
            ("strict", Some("strict")),
        ];
        for (input, want) in cases {
            let row = Row::new(
                "C",
                "D",
                Entry::Cookie(CookieEntry {
                    host: "example.com".into(),
                    path: String::new(),
                    name: String::new(),
                    value: String::new(),
                    is_secure: false,
                    is_http_only: false,
                    has_expire: false,
                    is_persistent: false,
                    expire_at: ChromeTime::zero(),
                    created_at: ChromeTime::zero(),
                    same_site: input.into(),
                }),
            );
            let c = row.as_cookie().unwrap();
            let e = CookieEditorEntry::from(c);
            assert_eq!(want, e.same_site.as_deref(), "input {input:?}");
        }
    }

    #[test]
    fn cookie_editor_expiration_omits_zero() {
        let row = Row::new(
            "C",
            "D",
            Entry::Cookie(CookieEntry {
                host: "example.com".into(),
                path: "/".into(),
                name: "n".into(),
                value: "v".into(),
                is_secure: false,
                is_http_only: false,
                has_expire: false,
                is_persistent: false,
                expire_at: ChromeTime::zero(),
                created_at: ChromeTime::zero(),
                same_site: String::new(),
            }),
        );
        let e = CookieEditorEntry::from(row.as_cookie().unwrap());
        assert!(e.expiration_date.is_none());
        assert!(e.session);
    }

    #[test]
    fn time_rfc3339_seconds_precision() {
        let t = hbd_core::ChromeTime::from_utc(
            chrono::Utc
                .with_ymd_and_hms(2026, 1, 15, 10, 30, 0)
                .unwrap(),
        );
        assert_eq!("2026-01-15T10:30:00Z", time_to_rfc3339(t));
    }
}
