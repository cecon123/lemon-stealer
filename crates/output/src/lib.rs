//! Port of Go package `output` (placeholder for Phase 4).
//!
//! Go `output.Writer` → csv/json/cookie-editor with UTF-8 BOM and reflection-based
//! flatten. Rust port keeps exact column/field order without reflect: entries already
//! carry Go-identical serde field order (see `core`).
