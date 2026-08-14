//! File copy helpers (Go: `filemanager/copy.go` + `copy_other.go`).
//!
//! Go uses `otiai10/copy` with a Skip callback for `copyDir`; here the recursive
//! walk is written by hand (same semantics, one less dependency — R6).

use std::fs;
use std::io;
use std::path::Path;

/// Copies a single file from src to dst. Go writes with mode 0o600; on Windows
/// `std::fs` ignores the mode, matching Go's behavior (Unix modes are no-ops on
/// Windows).
pub fn copy_file(src: &Path, dst: &Path) -> Result<(), io::Error> {
    let data = fs::read(src)?;
    fs::write(dst, data)
}

/// Copies a directory tree from src to dst, skipping any entry whose (lowercased)
/// path ends with `skip` (e.g. LevelDB's `LOCK`) — Go `copyDir` via
/// `otiai10/copy{Skip: fn(info, src, _) -> HasSuffix(lower(src), skip)}`.
pub fn copy_dir(src: &Path, dst: &Path, skip: &str) -> Result<(), io::Error> {
    write_dir(src, dst, skip)
}

fn write_dir(src: &Path, dst: &Path, skip: &str) -> Result<(), io::Error> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let src_str = src_path.to_string_lossy().to_lowercase();
        if src_str.ends_with(skip) {
            continue;
        }
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            write_dir(&src_path, &dst_path, skip)?;
        } else {
            copy_file(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Checks whether a file (not a directory) exists at the given path
/// (Go: `isFileExists`).
pub fn is_file_exists(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(m) => m.is_file(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::session::Session;

    // Port of TestNewSession.
    #[test]
    fn new_session_creates_hbd_temp_dir() {
        let s = Session::new().unwrap();
        assert!(s.temp_dir().is_dir());
        assert!(
            s.temp_dir().to_string_lossy().contains("hbd-"),
            "temp dir name carries hbd- prefix: {}",
            s.temp_dir().display()
        );
        s.cleanup();
    }

    // Port of TestSession_Cleanup.
    #[test]
    fn session_cleanup_removes_dir() {
        let s = Session::new().unwrap();
        let dir = s.temp_dir().to_path_buf();
        assert!(dir.is_dir());
        s.cleanup();
        assert!(!dir.exists());
    }

    // Port of TestSession_Acquire_File.
    #[test]
    fn session_acquire_file() {
        let s = Session::new().unwrap();
        let src_dir = std::env::temp_dir().join(format!("hbd-test-src-{}", std::process::id()));
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("Login Data");
        fs::write(&src_file, "test data").unwrap();

        let dst = s.temp_dir().join("Login Data");
        s.acquire(&src_file, &dst, false).unwrap();
        assert_eq!("test data", fs::read_to_string(&dst).unwrap());
        let _ = fs::remove_dir_all(&src_dir);
    }

    // Port of TestSession_Acquire_WAL.
    #[test]
    fn session_acquire_wal_and_shm() {
        let s = Session::new().unwrap();
        let src_dir = std::env::temp_dir().join(format!("hbd-test-wal-{}", std::process::id()));
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("Cookies");
        fs::write(&src_file, "db").unwrap();
        fs::write(src_file.to_string_lossy().to_string() + "-wal", "wal").unwrap();
        fs::write(src_file.to_string_lossy().to_string() + "-shm", "shm").unwrap();

        let dst = s.temp_dir().join("Cookies");
        s.acquire(&src_file, &dst, false).unwrap();
        assert!(dst.is_file());
        assert!(!(dst.to_string_lossy().to_string() + "-wal").is_empty());
        let wal = std::path::PathBuf::from(dst.to_string_lossy().to_string() + "-wal");
        let shm = std::path::PathBuf::from(dst.to_string_lossy().to_string() + "-shm");
        assert!(wal.is_file(), "WAL companion copied");
        assert!(shm.is_file(), "SHM companion copied");
        let _ = fs::remove_dir_all(&src_dir);
    }

    // Port of TestSession_Acquire_Dir (LOCK skipped by copyDir).
    #[test]
    fn session_acquire_dir_skips_lock() {
        let s = Session::new().unwrap();
        let src_dir = std::env::temp_dir().join(format!("hbd-test-dir-{}", std::process::id()));
        fs::create_dir_all(src_dir.join("leveldb")).unwrap();
        fs::write(src_dir.join("leveldb/000001.ldb"), "data").unwrap();
        fs::write(src_dir.join("leveldb/LOCK"), "").unwrap();

        let dst = s.temp_dir().join("leveldb");
        s.acquire(&src_dir.join("leveldb"), &dst, true).unwrap();
        assert!(dst.join("000001.ldb").is_file());
        assert!(!dst.join("LOCK").exists(), "LOCK file skipped");
        let _ = fs::remove_dir_all(&src_dir);
    }

    // Port of TestSession_Acquire_NotFound.
    #[test]
    fn session_acquire_not_found_errors() {
        let s = Session::new().unwrap();
        let dst = s.temp_dir().join("nope");
        assert!(
            s.acquire(std::path::Path::new("/nonexistent/file"), &dst, false)
                .is_err()
        );
    }
}
