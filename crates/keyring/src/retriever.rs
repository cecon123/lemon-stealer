//! Port of `masterkey/retriever.go` (Windows subset).

use std::path::PathBuf;

/// Bundles inputs for `Retriever`; each retriever reads only the field that applies
/// to it (Go: `Hints`).
#[derive(Debug, Clone, Default)]
pub struct Hints {
    /// macOS Keychain account / Linux D-Bus Secret Service label ("" = none — dropped
    /// chains still keep the field for Go parity; never populated on Windows).
    pub keychain_label: String,
    /// Windows ABE browser key (e.g. "chrome"); "" → ABE not applicable.
    pub windows_abe_key: String,
    /// Path to (temp-copied) Local State JSON; only used on Windows.
    pub local_state_path: PathBuf,
}

/// Error from a [`Retriever`]. Mirrors Go's open `error` with per-tier context at the
/// `new_master_keys` boundary.
#[derive(Debug, thiserror::Error)]
pub enum RetrieverError {
    /// A single retriever failed; tier name added by `new_master_keys`.
    #[error("retriever failed: {0}")]
    Retriever(String),
    /// Tier-labeled failure from `new_master_keys`'s error join (Go: `v10: <err>`).
    #[error("{tier}: {source}")]
    Tier {
        tier: String,
        #[source]
        source: Box<RetrieverError>,
    },
    /// All chain retrievers failed (Go: `all retrievers failed: <joined>`).
    #[error("all retrievers failed: {0}")]
    Chain(String),
    /// Underlying OS/IO error (DPAPI, local state read).
    #[error(transparent)]
    Os(#[from] std::io::Error),
}

impl PartialEq for RetrieverError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RetrieverError::Retriever(a), RetrieverError::Retriever(b)) => a == b,
            (
                RetrieverError::Tier { tier, source },
                RetrieverError::Tier {
                    tier: t2,
                    source: s2,
                },
            ) => tier == t2 && source == s2,
            (RetrieverError::Chain(a), RetrieverError::Chain(b)) => a == b,
            _ => false,
        }
    }
}

impl Clone for RetrieverError {
    fn clone(&self) -> Self {
        match self {
            RetrieverError::Retriever(s) => RetrieverError::Retriever(s.clone()),
            RetrieverError::Tier { tier, source } => RetrieverError::Tier {
                tier: tier.clone(),
                source: source.clone(),
            },
            RetrieverError::Chain(s) => RetrieverError::Chain(s.clone()),
            // io::Error is not Clone; rebuild from kind + message (lossless enough
            // for logging / error surface).
            RetrieverError::Os(e) => {
                RetrieverError::Os(std::io::Error::new(e.kind(), e.to_string()))
            }
        }
    }
}

/// Obtains a Chromium master key from one platform source (DPAPI, ABE, static, …)
/// (Go: `Retriever`).
///
/// `Ok(None)` = "tier not applicable" (Go's `(nil, nil)`) — contributes no key and no
/// error. `Err` = that tier failed, surfaced in [`crate::masterkeys::new_master_keys`].
pub trait Retriever: Send + Sync {
    fn retrieve_key(&self, hints: &Hints) -> Result<Option<Vec<u8>>, RetrieverError>;
}

/// Tries retrievers in order, first success wins (Go: `ChainRetriever` — macOS only,
/// kept for trait parity).
pub struct ChainRetriever {
    retrievers: Vec<Box<dyn Retriever>>,
}

/// Constructor mirroring Go's `new_chain` (renamed to idiomatic snake_case).
pub fn new_chain(retrievers: Vec<Box<dyn Retriever>>) -> ChainRetriever {
    ChainRetriever { retrievers }
}

impl Retriever for ChainRetriever {
    fn retrieve_key(&self, hints: &Hints) -> Result<Option<Vec<u8>>, RetrieverError> {
        let mut errs = Vec::new();
        for r in &self.retrievers {
            match r.retrieve_key(hints) {
                Ok(Some(k)) => return Ok(Some(k)),
                Ok(None) => {}
                Err(e) => errs.push(e.to_string()),
            }
        }
        if errs.is_empty() {
            Ok(None)
        } else {
            Err(RetrieverError::Chain(errs.join("; ")))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub struct StaticDummy(pub Option<Vec<u8>>, pub Option<RetrieverError>);

    impl Retriever for StaticDummy {
        fn retrieve_key(&self, _hints: &Hints) -> Result<Option<Vec<u8>>, RetrieverError> {
            match &self.1 {
                Some(e) => Err(e.clone()),
                None => Ok(self.0.clone()),
            }
        }
    }

    #[test]
    fn static_retriever_ok_none_means_tier_not_applicable() {
        let r = StaticDummy(None, None);
        assert_eq!(Ok(None), r.retrieve_key(&Hints::default()));
    }

    #[test]
    fn chain_first_success_wins() {
        let chain = new_chain(vec![
            Box::new(StaticDummy(
                None,
                Some(RetrieverError::Retriever("boom".into())),
            )),
            Box::new(StaticDummy(Some(vec![9, 9]), None)),
            Box::new(StaticDummy(Some(vec![1, 1]), None)),
        ]);
        assert_eq!(Ok(Some(vec![9, 9])), chain.retrieve_key(&Hints::default()));
    }

    #[test]
    fn chain_all_failed_joins() {
        let chain = new_chain(vec![
            Box::new(StaticDummy(
                None,
                Some(RetrieverError::Retriever("a".into())),
            )),
            Box::new(StaticDummy(
                None,
                Some(RetrieverError::Retriever("b".into())),
            )),
        ]);
        match chain.retrieve_key(&Hints::default()) {
            Err(RetrieverError::Chain(msg)) => assert!(msg.contains("a") && msg.contains("b")),
            other => panic!("expected Chain error, got {other:?}"),
        }
    }
}
