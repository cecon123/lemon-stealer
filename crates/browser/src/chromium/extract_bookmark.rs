//! Bookmark extraction (Go: `browser/chromium/extract_bookmark.go`).

use std::cmp::Reverse;
use std::path::Path;

use hbd_core::{BookmarkEntry, ChromeTime};
use serde_json::Value;

use crate::chromium::error::{ChromiumError, Result};

/// Extracts bookmark URLs from the Bookmarks JSON, recursively walking each
/// root, sorted by creation date descending (Go: `extractBookmarks`).
pub fn extract_bookmarks(path: &Path) -> Result<Vec<BookmarkEntry>> {
    let data = std::fs::read(path)?;
    let json: Value = serde_json::from_slice(&data)
        .map_err(|e| ChromiumError::Message(format!("parse bookmarks: {e}")))?;

    let mut bookmarks = Vec::new();
    if let Some(roots) = json.get("roots")
        && let Value::Object(roots) = roots
    {
        for (key, value) in roots {
            if key == "bookmark_bar" {
                // The bar is a root, not a folder — its children are
                // top-level bookmarks (Go: skips the bar's name).
                if let Some(children) = value.get("children").and_then(Value::as_array) {
                    for child in children {
                        walk_bookmarks(child, "", &mut bookmarks);
                    }
                }
            } else {
                walk_bookmarks(value, "", &mut bookmarks);
            }
        }
    }

    bookmarks.sort_by_key(|a| Reverse(a.created_at));
    Ok(bookmarks)
}

/// Recursively traverses the bookmark tree, collecting URL entries
/// (Go: `walkBookmarks`).
fn walk_bookmarks(node: &Value, folder: &str, out: &mut Vec<BookmarkEntry>) {
    if node.get("type").and_then(Value::as_str) == Some("url") {
        out.push(BookmarkEntry {
            id: node.get("id").and_then(Value::as_i64).unwrap_or(0),
            name: node
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            r#type: "url".to_string(),
            url: node
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            folder: folder.to_string(),
            created_at: ChromeTime::from_chromium_micros(
                node.get("date_added").and_then(Value::as_i64).unwrap_or(0),
            ),
        });
    }

    let Some(children) = node.get("children") else {
        return;
    };
    let Some(children) = children.as_array() else {
        return;
    };
    let current_folder = node.get("name").and_then(Value::as_str).unwrap_or("");
    for child in children {
        walk_bookmarks(child, current_folder, out);
    }
}

pub fn count_bookmarks(path: &Path) -> Result<i64> {
    let data = std::fs::read(path)?;
    let json: Value = serde_json::from_slice(&data)
        .map_err(|e| ChromiumError::Message(format!("parse bookmarks: {e}")))?;

    let mut count = 0;
    if let Some(roots) = json.get("roots")
        && let Value::Object(roots) = roots
    {
        for value in roots.values() {
            count += walk_count_bookmarks(value);
        }
    }
    Ok(count)
}

/// Recursively counts URL nodes in the bookmark tree (Go: `walkCountBookmarks`).
fn walk_count_bookmarks(node: &Value) -> i64 {
    let mut count = 0;
    if node.get("type").and_then(Value::as_str) == Some("url") {
        count += 1;
    }
    if let Some(children) = node.get("children").and_then(Value::as_array) {
        for child in children {
            count += walk_count_bookmarks(child);
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOKMARKS: &str = r#"{
        "roots": {
            "bookmark_bar": {
                "type": "folder",
                "name": "Bookmarks bar",
                "children": [
                    {
                        "id": "1",
                        "type": "url",
                        "name": "Example",
                        "url": "https://example.com",
                        "date_added": 13350000000000000
                    },
                    {
                        "type": "folder",
                        "name": "Sub",
                        "children": [
                            {
                                "id": "2",
                                "type": "url",
                                "name": "Nested",
                                "url": "https://nested.test",
                                "date_added": 13340000000000000
                            }
                        ]
                    }
                ]
            },
            "other": {
                "type": "folder",
                "name": "Other bookmarks",
                "children": [
                    {
                        "id": "3",
                        "type": "url",
                        "name": "Plain",
                        "url": "https://plain.test",
                        "date_added": 13290000000000000
                    }
                ]
            }
        }
    }"#;

    #[test]
    fn extracts_urls_with_folder_path() {
        let path = write_json(BOOKMARKS);
        let bookmarks = extract_bookmarks(&path).unwrap();
        assert_eq!(3, bookmarks.len());
        // Sorted by date desc: Example > Nested > Plain.
        assert_eq!("Example", bookmarks[0].name);
        assert_eq!("", bookmarks[0].folder);
        assert_eq!("Sub", bookmarks[1].folder);
        assert_eq!("Other bookmarks", bookmarks[2].folder);
    }

    #[test]
    fn counts_url_nodes() {
        let path = write_json(BOOKMARKS);
        assert_eq!(3, count_bookmarks(&path).unwrap());
    }

    fn write_json(content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hbd-bookmark-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Bookmarks");
        std::fs::write(&path, content).unwrap();
        path
    }
}
