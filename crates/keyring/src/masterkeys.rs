//! Port of `masterkey/masterkeys.go`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::retriever::{Hints, Retriever, RetrieverError};

/// serde adapter: Go marshals `[]byte` as base64 (standard alphabet, padded),
/// identical to Go's `encoding/json`.
mod b64 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => serializer.serialize_str(&STANDARD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let opt = Option::<String>::deserialize(deserializer)?;
        opt.map(|s| STANDARD.decode(&s).map_err(de::Error::custom))
            .transpose()
    }
}

/// One key per cipher tier; a profile can mix tiers (Win v10+v20, Linux v10+v11),
/// so each is populated independently. `None` = that cipher version can't be decrypted
/// (Go: nil tier).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterKeys {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64")]
    pub v10: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64")]
    pub v11: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64")]
    pub v20: Option<Vec<u8>>,
}

impl MasterKeys {
    pub fn has_any(&self) -> bool {
        self.v10.is_some() || self.v11.is_some() || self.v20.is_some()
    }
}

/// Per-tier retriever configuration; unused slots stay `None` (Go: `Retrievers`).
#[derive(Default)]
pub struct Retrievers {
    pub v10: Option<Box<dyn Retriever>>,
    pub v11: Option<Box<dyn Retriever>>,
    pub v20: Option<Box<dyn Retriever>>,
}

/// Fetches each non-nil tier and joins per-tier errors. A retriever returning
/// `Ok(None)` means "tier not applicable" and contributes no key.
///
/// Phase 3: full parity (Go `NewMasterKeys`, including error joining with tier names).
#[allow(dead_code)]
pub fn new_master_keys(r: &Retrievers, hints: Hints) -> Result<MasterKeys, Vec<RetrieverError>> {
    let (keys, errs) = new_master_keys_partial(r, hints);
    if errs.is_empty() { Ok(keys) } else { Err(errs) }
}

/// Like [`new_master_keys`] but always hands back the partial keys, so callers
/// (Go: `ExportKeys` + `masterKeys`) can keep the tiers that succeeded even when
/// another tier failed — a Chrome 127+ profile mixes v10+v20, so a v20-only
/// failure must not discard a usable v10 key.
pub fn new_master_keys_partial(r: &Retrievers, hints: Hints) -> (MasterKeys, Vec<RetrieverError>) {
    let mut keys = MasterKeys::default();
    let mut errs = Vec::new();
    for (name, retriever, dst) in [
        ("v10", r.v10.as_ref(), &mut keys.v10),
        ("v11", r.v11.as_ref(), &mut keys.v11),
        ("v20", r.v20.as_ref(), &mut keys.v20),
    ] {
        let Some(retriever) = retriever else { continue };
        match retriever.retrieve_key(&hints) {
            Ok(Some(k)) => *dst = Some(k),
            Ok(None) => {}
            Err(e) => errs.push(RetrieverError::Tier {
                tier: name.to_string(),
                source: Box::new(e),
            }),
        }
    }
    (keys, errs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retriever::StaticDummy;

    #[test]
    fn has_any_matches_go() {
        assert!(!MasterKeys::default().has_any());
        let v10 = MasterKeys {
            v10: Some(vec![1, 2, 3]),
            ..Default::default()
        };
        assert!(v10.has_any());
        let v20_v10 = MasterKeys {
            v10: Some(vec![1]),
            v20: Some(vec![2]),
            ..Default::default()
        };
        assert!(v20_v10.has_any());
    }

    #[test]
    fn json_omitempty_matches_go_dump_format() {
        let mk = MasterKeys {
            v10: Some(vec![0xAB, 0xCD]),
            ..Default::default()
        };
        let s = serde_json::to_string(&mk).unwrap();
        // Go: {"v10":"q80="} — v11/v20 omitted entirely (omitempty).
        assert_eq!(r#"{"v10":"q80="}"#, s);
    }

    #[test]
    fn new_master_keys_fetches_non_nil_tiers() {
        let r = Retrievers {
            v10: Some(Box::new(StaticDummy(Some(vec![1, 2]), None))),
            v20: Some(Box::new(StaticDummy(Some(vec![3]), None))),
            ..Default::default()
        };
        let keys = new_master_keys(&r, Hints::default()).unwrap();
        assert_eq!(Some(vec![1, 2]), keys.v10);
        assert_eq!(None, keys.v11, "nil tier stays nil");
        assert_eq!(Some(vec![3]), keys.v20);
    }

    #[test]
    fn new_master_keys_tier_not_applicable_ok_none() {
        // (Ok, None) from a retriever = tier not applicable → no key, no error.
        let r = Retrievers {
            v10: Some(Box::new(StaticDummy(None, None))),
            ..Default::default()
        };
        let keys = new_master_keys(&r, Hints::default()).unwrap();
        assert_eq!(None, keys.v10);
        assert!(!keys.has_any());
    }

    #[test]
    fn new_master_keys_joins_tier_errors_with_names() {
        let r = Retrievers {
            v10: Some(Box::new(StaticDummy(
                None,
                Some(RetrieverError::Retriever("boom".into())),
            ))),
            v20: Some(Box::new(StaticDummy(Some(vec![7]), None))),
            ..Default::default()
        };
        let errs = new_master_keys(&r, Hints::default()).unwrap_err();
        assert_eq!(1, errs.len());
        let s = errs[0].to_string();
        assert!(s.starts_with("v10: "), "tier name in join, got {s}");
    }
}
