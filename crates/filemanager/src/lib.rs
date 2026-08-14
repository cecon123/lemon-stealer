//! Port of Go package `filemanager` (Windows subset).
//!
//! Session + Acquire temp-dir copying (with `-wal`/`-shm` companions), implementing
//! Go `filemanager/session.go` + `copy.go`. `copyLocked` (reading EXCLUSIVE-locked
//! SQLite via DuplicateHandle + FileMapping) is Phase 2b via `crates/abi`.
//! `zip` ports Go `utils/fileutil/fileutil.go` (Phase 4).

pub mod copy;
pub mod session;
pub mod zip;

pub use session::{AcquireError, Session};
pub use zip::{ZipError, compress_dir, file_exists, unzip, zip_dir};
