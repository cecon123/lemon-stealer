//! Extension extraction (Go: `browser/chromium/extract_extension.go`).

use std::path::Path;

use hbd_core::ExtensionEntry;
use serde_json::Value;

use crate::chromium::error::{ChromiumError, Result};

/// JSON paths tried for standard Chromium browsers (Go: `defaultExtensionKeys`).
const DEFAULT_EXTENSION_KEYS: [&str; 3] = [
    "extensions.settings",
    "settings.extensions",
    "settings.settings",
];

/// Extracts non-system extensions from Secure Preferences, skipping component
/// extensions (location == 5 || 10) and entries without a manifest
/// (Go: `extractExtensions`).
pub fn extract_extensions(path: &Path) -> Result<Vec<ExtensionEntry>> {
    extract_extensions_with_keys(path, &DEFAULT_EXTENSION_KEYS)
}

/// Reads Secure Preferences and looks for extension settings under the given
/// JSON key paths; this lets browser variants (e.g. Opera's
/// "extensions.opsettings") reuse the same parsing logic
/// (Go: `extractExtensionsWithKeys`).
pub(crate) fn extract_extensions_with_keys(
    path: &Path,
    keys: &[&str],
) -> Result<Vec<ExtensionEntry>> {
    let data = std::fs::read(path)?;
    let json: Value = serde_json::from_slice(&data)
        .map_err(|e| ChromiumError::Message(format!("parse Secure Preferences: {e}")))?;

    let settings = keys
        .iter()
        .find_map(|key| json_get_dotted(&json, key))
        .ok_or_else(|| ChromiumError::Message("cannot find extensions in settings".to_string()))?;

    let mut extensions = Vec::new();
    if let Value::Object(settings) = settings {
        for (id, ext) in settings {
            // Skip system/component extensions
            // https://source.chromium.org/chromium/chromium/src/+/main:extensions/common/mojom/manifest.mojom
            if ext.get("location").and_then(Value::as_i64) == Some(5)
                || ext.get("location").and_then(Value::as_i64) == Some(10)
            {
                continue;
            }
            let Some(manifest) = ext.get("manifest") else {
                continue;
            };
            extensions.push(ExtensionEntry {
                name: manifest
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                id: id.clone(),
                description: manifest
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                version: manifest
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                homepage_url: manifest
                    .get("homepage_url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                enabled: is_extension_enabled(ext),
            });
        }
    }
    Ok(extensions)
}

/// Checks whether an extension is enabled. Modern Chrome uses
/// `disable_reasons` (array): empty [] = enabled; older Chrome uses `state`
/// (int): 1 = enabled (Go: `isExtensionEnabled`).
fn is_extension_enabled(ext: &Value) -> bool {
    if let Some(reasons) = ext.get("disable_reasons") {
        return reasons.as_array().is_some_and(|arr| arr.is_empty());
    }
    ext.get("state").and_then(Value::as_i64) == Some(1)
}

/// Opera stores extension data under "extensions.opsettings"
/// (Go: `extractOperaExtensions`).
pub fn extract_opera_extensions(path: &Path) -> Result<Vec<ExtensionEntry>> {
    extract_extensions_with_keys(path, &["extensions.opsettings"])
}

pub fn count_extensions(path: &Path) -> Result<i64> {
    count_extensions_with_keys(path, &DEFAULT_EXTENSION_KEYS)
}

pub fn count_opera_extensions(path: &Path) -> Result<i64> {
    count_extensions_with_keys(path, &["extensions.opsettings"])
}

/// Counts non-system extensions without building full entries. Mirrors the
/// filtering in `extract_extensions_with_keys`; a missing settings key counts
/// as 0, not an error (Go: `countExtensionsWithKeys`).
fn count_extensions_with_keys(path: &Path, keys: &[&str]) -> Result<i64> {
    let data = std::fs::read(path)?;
    let json: Value = serde_json::from_slice(&data)
        .map_err(|e| ChromiumError::Message(format!("parse Secure Preferences: {e}")))?;

    let Some(settings) = keys.iter().find_map(|key| json_get_dotted(&json, key)) else {
        return Ok(0);
    };

    let mut count = 0;
    if let Value::Object(settings) = settings {
        for ext in settings.values() {
            if ext.get("location").and_then(Value::as_i64) == Some(5)
                || ext.get("location").and_then(Value::as_i64) == Some(10)
            {
                continue;
            }
            if ext.get("manifest").is_none() {
                continue;
            }
            count += 1;
        }
    }
    Ok(count)
}

/// Navigates a dot-separated JSON path (gjson equivalent — plain object keys,
/// no array indices; missing intermediate keys → `None`).
pub(crate) fn json_get_dotted<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = value;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECURE_PREFS: &str = r#"{
        "extensions": {
            "settings": {
                "user_ext": {"location": 1, "state": 1, "manifest": {"name": "User Ext", "version": "1.0"}},
                "disabled_ext": {"location": 1, "disable_reasons": [1], "manifest": {"name": "Disabled"}},
                "empty_reasons": {"location": 1, "disable_reasons": [], "manifest": {"name": "Enabled"}},
                "component_ext": {"location": 5, "manifest": {"name": "Component"}},
                "policy_ext": {"location": 10, "manifest": {"name": "Policy"}},
                "no_manifest": {"location": 1}
            }
        }
    }"#;

    #[test]
    fn extracts_non_system_extensions() {
        let path = write_json("full", SECURE_PREFS);
        let exts = extract_extensions(&path).unwrap();
        assert_eq!(3, exts.len());
        assert!(exts.iter().any(|e| e.name == "User Ext" && e.enabled));
        assert!(exts.iter().any(|e| e.name == "Enabled" && e.enabled));
        assert!(exts.iter().any(|e| e.name == "Disabled" && !e.enabled));
    }

    #[test]
    fn counts_matches_extraction_filter() {
        let path = write_json("full2", SECURE_PREFS);
        assert_eq!(3, count_extensions(&path).unwrap());
    }

    #[test]
    fn missing_settings_key_counts_zero() {
        let path = write_json("empty", r#"{"other": 1}"#);
        assert_eq!(0, count_extensions(&path).unwrap());
        assert!(extract_extensions(&path).is_err());
    }

    #[test]
    fn opera_opsettings_path() {
        let path = write_json(
            "opera",
            r#"{"extensions": {"opsettings": {"x": {"location": 1, "manifest": {"name": "Op"}}}}}"#,
        );
        let exts = extract_opera_extensions(&path).unwrap();
        assert_eq!(1, exts.len());
        assert_eq!("Op", exts[0].name);
    }

    fn write_json(tag: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hbd-ext-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Secure Preferences");
        std::fs::write(&path, content).unwrap();
        path
    }
}
