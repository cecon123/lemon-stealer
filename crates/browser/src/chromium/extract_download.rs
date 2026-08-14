//! Download extraction (Go: `browser/chromium/extract_download.go`).

use std::cmp::Reverse;
use std::path::Path;

use hbd_core::{ChromeTime, DownloadEntry};

use crate::chromium::error::Result;
use crate::chromium::sqliteutil::{count_rows, query_rows};

const DEFAULT_DOWNLOAD_QUERY: &str =
    "SELECT target_path, tab_url, total_bytes, start_time, end_time,
    mime_type FROM downloads";
const COUNT_DOWNLOAD_QUERY: &str = "SELECT COUNT(*) FROM downloads";

/// Extracts download rows, sorted by start time descending
/// (Go: `extractDownloads`).
pub fn extract_downloads(path: &Path) -> Result<Vec<DownloadEntry>> {
    let mut downloads = query_rows(path, false, DEFAULT_DOWNLOAD_QUERY, |row| {
        let target_path: String = row.get(0)?;
        let url: String = row.get(1)?;
        let total_bytes: i64 = row.get(2)?;
        let start_time: i64 = row.get(3)?;
        let end_time: i64 = row.get(4)?;
        let mime_type: String = row.get(5)?;
        Ok(DownloadEntry {
            url,
            target_path,
            mime_type,
            total_bytes,
            start_time: ChromeTime::from_chromium_micros(start_time),
            end_time: ChromeTime::from_chromium_micros(end_time),
        })
    })?;

    downloads.sort_by_key(|a| Reverse(a.start_time));
    Ok(downloads)
}

pub fn count_downloads(path: &Path) -> Result<i64> {
    Ok(count_rows(path, false, COUNT_DOWNLOAD_QUERY)?)
}
