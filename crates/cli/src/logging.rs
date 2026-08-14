//! Go `log` package parity backend for the `log` facade.
//!
//! Output format (Go `logger.go`):
//!
//! ```text
//! [DBG] file.go:42: message
//! [INF] message
//! [WRN] message
//! [ERR] message
//! ```
//!
//! Multi-line messages indent continuations with 6 spaces (`[DBG] ` width),
//! tracing is folded into `[DBG]`, and everything goes to stderr like Go
//! (`newBase(os.Stderr)`, default level Info).

use std::io::Write;
use std::path::Path;

use log::{Level, LevelFilter, Log, Metadata, Record};

/// Level labels (Go `level.go`).
fn label(level: Level) -> &'static str {
    match level {
        Level::Trace | Level::Debug => "DBG",
        Level::Info => "INF",
        Level::Warn => "WRN",
        Level::Error => "ERR",
    }
}

/// The `[DBG] `-width continuation indent for multi-line messages.
const CONTINUATION: &str = "      ";

/// Caller-reference depth for debug lines. Rust's `log` facade gives us
/// `Record::file()`/`line()` directly, so no manual caller skip is needed.
pub struct LemonLogger {
    min: LevelFilter,
}

impl LemonLogger {
    pub fn new(verbose: bool) -> LemonLogger {
        LemonLogger {
            min: if verbose {
                LevelFilter::Debug
            } else {
                LevelFilter::Info
            },
        }
    }

    /// Installs the logger as the process-wide `log` handler (Go:
    /// `SetVerbose()` before any log call; cli main does this first).
    pub fn init(self) {
        let min = self.min;
        let _ = log::set_boxed_logger(Box::new(self)).map(|()| log::set_max_level(min));
    }
}

impl Log for LemonLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.min
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let msg = record.args().to_string();
        let msg = msg.trim_end_matches('\n');
        let msg = msg.replace('\n', &format!("\n{CONTINUATION}"));

        let line = match record.level() {
            Level::Trace | Level::Debug => {
                let file = record.file().map(Path::new);
                let file = match file {
                    Some(p) => p
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "???".to_string()),
                    None => "???".to_string(),
                };
                let num = record.line().unwrap_or(0);
                format!("[DBG] {file}:{num}: {msg}\n")
            }
            lvl => format!("[{}] {msg}\n", label(lvl)),
        };

        let stderr = std::io::stderr();
        let mut lock = stderr.lock();
        let _ = lock.write_all(line.as_bytes());
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_labels_match_go() {
        assert_eq!("DBG", label(Level::Debug));
        assert_eq!("INF", label(Level::Info));
        assert_eq!("WRN", label(Level::Warn));
        assert_eq!("ERR", label(Level::Error));
    }

    #[test]
    fn default_level_suppresses_debug() {
        let logger = LemonLogger::new(false);
        assert!(!logger.enabled(&metadata(Level::Debug)));
        assert!(logger.enabled(&metadata(Level::Info)));
        assert!(logger.enabled(&metadata(Level::Error)));
    }

    #[test]
    fn verbose_enables_debug() {
        let logger = LemonLogger::new(true);
        assert!(logger.enabled(&metadata(Level::Debug)));
    }

    fn metadata(level: Level) -> Metadata<'static> {
        Metadata::builder().level(level).target("test").build()
    }
}
