//! Port of Go `utils/filemanager` (placeholder for Phase 2b).
//!
//! `Session`/`Acquire` temp-dir copying (with `-wal`/`-shm` companions) and
//! `copyLocked` (reading EXCLUSIVE-locked SQLite files via handle duplication +
//! file mapping) land here.
