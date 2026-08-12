//! Port of Go package `masterkey` (Windows subset).
//!
//! Holds one key per cipher tier and the `Retriever` trait (DPAPI v10, ABE v20, static).
//! Phase 0: type/trait skeletons only; the Windows retrievers land in Phase 3, the
//! Dump JSON schema (dumpkeys) in Phase 3 too.

pub mod masterkeys;
pub mod retriever;

pub use masterkeys::{MasterKeys, Retrievers};
pub use retriever::{ChainRetriever, Hints, Retriever, RetrieverError, new_chain};

/// Version of the dumpkeys JSON schema (Go: `DumpVersion`). The full `Dump`/`Vault`
/// types plus strict version==2 ReadJSON land in Phase 3 with `dumpkeys`.
pub const DUMP_VERSION: &str = "2";
