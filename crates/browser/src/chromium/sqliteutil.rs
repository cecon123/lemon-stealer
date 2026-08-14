//! SQLite query helpers (Go: `utils/sqliteutil` — `query.go` + `sqlite.go`).
//!
//! Guards the database file exists before opening (prevents rusqlite from
//! creating an empty database), optionally switches journal mode off, and
//! provides both the per-row-skip scan loop (`query_rows`) and fail-fast
//! counting (`count_rows`).

use std::path::Path;

use log::debug;
use rusqlite::{Connection, Row};

/// Error from the query helpers (Go surfaces `os.Stat` and `database/sql` errors).
#[derive(Debug, thiserror::Error)]
pub enum SqliteError {
    #[error("database file: {0}")]
    FileNotFound(String),
    #[error("open database: {0}")]
    Open(#[from] rusqlite::Error),
    #[error("count rows: {0}")]
    Count(String),
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Opens the database with a file-exists guard, then optionally disables the
/// journal (required for Firefox; Chromium passes `false` — kept for parity).
fn open(db_path: &Path, journal_off: bool) -> Result<Connection, SqliteError> {
    if !db_path.is_file() {
        return Err(SqliteError::FileNotFound(db_path.display().to_string()));
    }
    let conn = Connection::open(db_path)?;
    if journal_off {
        conn.execute_batch("PRAGMA journal_mode=off")?;
    }
    Ok(conn)
}

/// Runs a scalar count query (e.g. `SELECT COUNT(*) FROM ...`) and returns the
/// integer result. Unlike [`query_rows`] (which swallows per-row scan errors),
/// counting uses fail-fast semantics on scan failures (Go: `CountRows`).
pub fn count_rows(db_path: &Path, journal_off: bool, query: &str) -> Result<i64, SqliteError> {
    let conn = open(db_path, journal_off)?;
    let count: i64 = conn
        .query_row(query, [], |row| row.get(0))
        .map_err(|e| SqliteError::Count(format!("{e}")))?;
    Ok(count)
}

/// Runs the query and collects one typed value per row. Rows that fail to scan
/// are skipped, logged at debug level, and iteration continues — mirroring Go
/// which logs `scan row error` and keeps going (Go: `QuerySQLite` +
/// `QueryRows`).
pub fn query_rows<T>(
    db_path: &Path,
    journal_off: bool,
    query: &str,
    scan: impl Fn(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>, SqliteError> {
    let conn = open(db_path, journal_off)?;
    let mut stmt = conn.prepare(query)?;
    let mut rows = stmt.query([])?;

    let mut items = Vec::new();
    loop {
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(e) => return Err(SqliteError::Open(e)),
        };
        match scan(row) {
            Ok(item) => items.push(item),
            Err(e) => {
                debug!("scan row error: {e}");
                continue;
            }
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn make_db(rows: &[(&str, i64)], tag: &str) -> (std::path::PathBuf, Connection) {
        let dir =
            std::env::temp_dir().join(format!("hbd-sqlite-test-{}-{}", tag, std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE items (id INTEGER, name TEXT)")
            .unwrap();
        for (name, id) in rows {
            conn.execute(
                "INSERT INTO items VALUES (?1, ?2)",
                rusqlite::params![id, name],
            )
            .unwrap();
        }
        (path, conn)
    }

    #[test]
    fn query_rows_collects_ok_rows() {
        let (path, conn) = make_db(&[("alpha", 1), ("beta", 2), ("gamma", 3)], "collect");
        drop(conn);
        let got = query_rows(&path, false, "SELECT name FROM items ORDER BY id", |row| {
            row.get::<_, String>(0)
        })
        .unwrap();
        assert_eq!(vec!["alpha", "beta", "gamma"], got);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn query_rows_skips_scan_errors() {
        let dir = std::env::temp_dir().join(format!("hbd-sqlite-test-skip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE items (id INTEGER, name)")
            .unwrap();
        conn.execute("INSERT INTO items VALUES (?1, ?2)", rusqlite::params![1, 1])
            .unwrap();
        conn.execute(
            "INSERT INTO items VALUES (?1, ?2)",
            rusqlite::params![2, "beta"],
        )
        .unwrap();
        drop(conn);
        // Scan as i64 fails for the TEXT column except the INTEGER "1" → only one row kept.
        let got = query_rows(&path, false, "SELECT name FROM items", |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
        assert_eq!(1, got.len(), "scan errors skipped, not fatal");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn query_rows_file_not_found_errors() {
        let err = query_rows(Path::new("/nonexistent/path.db"), false, "SELECT 1", |_| {
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, SqliteError::FileNotFound(_)));
    }

    #[test]
    fn query_rows_bad_query_errors() {
        let (path, conn) = make_db(&[], "empty");
        drop(conn);
        assert!(query_rows(&path, false, "SELECT nonexistent FROM t", |_| Ok(())).is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn count_rows_counts_and_fail_fast() {
        let (path, _conn) = make_db(&[("a", 1), ("b", 2), ("c", 3)], "count");
        assert_eq!(
            3,
            count_rows(&path, false, "SELECT COUNT(*) FROM items").unwrap()
        );
        // Bad table → fail-fast error (no silent 0), matching Go CountRows.
        assert!(count_rows(&path, false, "SELECT COUNT(*) FROM empty").is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn journal_off_flag_accepted() {
        let (path, conn) = make_db(&[("ok", 1)], "journal");
        drop(conn);
        let got = query_rows(&path, true, "SELECT name FROM items", |row| {
            row.get::<_, String>(0)
        })
        .unwrap();
        assert_eq!(vec!["ok"], got);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
