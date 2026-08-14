//! Session: temp-dir staging for one extraction run (Go: `filemanager/session.go`).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::copy::{copy_dir, copy_file, is_file_exists};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Manages temporary files for a single browser extraction run. Creates an isolated
/// temp directory and copies browser files into it; call [`Session::cleanup`] when
/// done (Go: `Session`).
pub struct Session {
    temp_dir: PathBuf,
}

impl Session {
    /// Creates a session with a unique temporary directory (Go: `NewSession` —
    /// `os.MkdirTemp("", "hbd-*")`).
    pub fn new() -> Result<Self, std::io::Error> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("hbd-{}-{}", std::process::id(), id));
        fs::create_dir(&dir)?;
        Ok(Session { temp_dir: dir })
    }

    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    /// Copies a browser file (or directory) from `src` to `dst` (Go: `Acquire`).
    ///
    /// For regular files, also copies SQLite WAL/SHM companions (`-wal`, `-shm`)
    /// if present. For directories (LevelDB) copies the whole tree, skipping
    /// files/dirs whose path ends with `lock` (lowercase, like Go). On Windows,
    /// a normal-copy failure falls back to `copyLocked` (handled via abi in
    /// Phase 2b; until then the fallback reports a clear error).
    pub fn acquire(&self, src: &Path, dst: &Path, is_dir: bool) -> Result<(), AcquireError> {
        if is_dir {
            return copy_dir(src, dst, "lock").map_err(AcquireError::Copy);
        }

        // Try normal copy first. On non-Windows Go returns the original error
        // directly; on Windows it falls back to copyLocked and joins all errors.
        if let Err(e) = copy_file(src, dst) {
            #[cfg(windows)]
            {
                return locked_fallback(src, dst, &e);
            }
            #[cfg(not(windows))]
            {
                return Err(AcquireError::Copy(e));
            }
        }

        // Copy SQLite WAL/SHM companion files if present (Go: identical loop;
        // suffix appended to the raw path string).
        let mut wal_errs = Vec::new();
        for suffix in ["-wal", "-shm"] {
            let wal_src = src.to_string_lossy().to_string() + suffix;
            if is_file_exists(Path::new(&wal_src)) {
                let wal_dst = dst.to_string_lossy().to_string() + suffix;
                if let Err(e) = copy_file(Path::new(&wal_src), Path::new(&wal_dst)) {
                    wal_errs.push(format!("copy {suffix}: {e}"));
                }
            }
        }
        if wal_errs.is_empty() {
            Ok(())
        } else {
            Err(AcquireError::Copy(std::io::Error::other(
                wal_errs.join("\n"),
            )))
        }
    }

    /// Removes the session's temporary directory and all its contents
    /// (Go: `Cleanup`).
    pub fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

/// Go's Windows fallback path: `copyLocked(src, dst)`; both errors joined.
/// The actual copyLocked (DuplicateHandle + FileMapping) lands in Phase 2b
/// (`abi`); until then the fallback fails with a clear error so nothing is
/// silently missing.
#[cfg(windows)]
fn locked_fallback(src: &Path, dst: &Path, copy_err: &std::io::Error) -> Result<(), AcquireError> {
    let locked_err = copy_locked_stub(src, dst);
    match locked_err {
        Ok(()) => Ok(()), // Phase 2b: proceed to WAL stage
        Err(locked) => Err(AcquireError::Locked {
            copy: format!("{}", copy_err),
            locked,
        }),
    }
}

/// Placeholder for `copy_windows.go` — replaced by `abi::copy_locked` in Phase 2b.
#[cfg(windows)]
fn copy_locked_stub(_src: &Path, _dst: &Path) -> Result<(), String> {
    Err("copyLocked: not yet ported (Phase 2b, crates/abi)".to_string())
}

/// Errors from [`Session::acquire`].
#[derive(Debug, thiserror::Error)]
pub enum AcquireError {
    #[error("copy: {0}")]
    Copy(std::io::Error),
    /// Go `errors.Join(copy, locked copy)` — Windows only, joined with newline.
    #[error("copy: {copy}\nlocked copy: {locked}")]
    Locked { copy: String, locked: String },
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cleanup();
    }
}
