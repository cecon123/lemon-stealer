//! History extraction (Go: `browser/chromium/extract_history.go`).

use std::cmp::Reverse;
use std::path::Path;

use hbd_core::{ChromeTime, HistoryEntry};

use crate::chromium::error::Result;
use crate::chromium::sqliteutil::{count_rows, query_rows};

const DEFAULT_HISTORY_QUERY: &str = "SELECT url, title, visit_count, last_visit_time FROM urls";
const COUNT_HISTORY_QUERY: &str = "SELECT COUNT(*) FROM urls";

/// Extracts history rows, sorted by visit count descending
/// (Go: `extractHistories`).
pub fn extract_histories(path: &Path) -> Result<Vec<HistoryEntry>> {
    let mut histories = query_rows(path, false, DEFAULT_HISTORY_QUERY, |row| {
        let url: String = row.get(0)?;
        let title: String = row.get(1)?;
        let visit_count: i64 = row.get(2)?;
        let last_visit: i64 = row.get(3)?;
        Ok(HistoryEntry {
            url,
            title,
            visit_count,
            last_visit: ChromeTime::from_chromium_micros(last_visit),
        })
    })?;

    histories.sort_by_key(|a| Reverse(a.visit_count));
    Ok(histories)
}

pub fn count_histories(path: &Path) -> Result<i64> {
    Ok(count_rows(path, false, COUNT_HISTORY_QUERY)?)
}
