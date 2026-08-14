//! Port of Go package `masterkey` (Windows subset).
//!
//! Holds one key per cipher tier and the `Retriever` trait (DPAPI v10, ABE v20, static).
//! Phase 0: type/trait skeletons only; the Windows retrievers land in Phase 3, the
//! Dump JSON schema (dumpkeys) in Phase 3 too.

#[cfg(windows)]
mod abe;
pub mod masterkeys;
pub mod retriever;
#[cfg(windows)]
mod retriever_windows;

#[cfg(windows)]
pub use abe::AbeRetriever;
pub use masterkeys::{MasterKeys, Retrievers};
pub use retriever::{ChainRetriever, Hints, Retriever, RetrieverError, new_chain};
#[cfg(windows)]
pub use retriever_windows::DpapiRetriever;
