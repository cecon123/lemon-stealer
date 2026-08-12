//! Port of `parseCategories` / `categoryNames` from `cmd/hack-browser-data/dump.go`.
//!
//! Lives in `core` (not `cli`) per PLAN.md Phase 0 because `archive` and `restore`
//! share it.

use crate::Category;

/// Error produced by [`parse_categories`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CategoryParseError {
    /// `unknown category: "x", available: all|...` — mirrors Go's `%q` quoting.
    #[error("unknown category: {name:?}, available: all|{available}")]
    Unknown { name: String, available: String },
    /// Go: `no categories specified`.
    #[error("no categories specified")]
    Empty,
}

/// Converts a comma-separated string into a `Category` slice. "all" (case-insensitive)
/// returns all categories.
pub fn parse_categories(s: &str) -> Result<Vec<Category>, CategoryParseError> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("all") {
        return Ok(Category::ALL.to_vec());
    }

    let mut categories: Vec<Category> = Vec::new();
    for name in s.split(',') {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let category = Category::ALL
            .iter()
            .copied()
            .find(|c| c.to_string() == name);
        match category {
            Some(c) => categories.push(c),
            None => {
                return Err(CategoryParseError::Unknown {
                    name,
                    available: category_names(),
                });
            }
        }
    }
    if categories.is_empty() {
        return Err(CategoryParseError::Empty);
    }
    Ok(categories)
}

/// Comma-joined names of all categories (Go: `categoryNames`), for help text.
pub fn category_names() -> String {
    Category::ALL
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_returns_all_categories() {
        assert_eq!(Category::ALL.to_vec(), parse_categories("all").unwrap());
        assert_eq!(Category::ALL.to_vec(), parse_categories(" ALL ").unwrap());
        assert_eq!(Category::ALL.to_vec(), parse_categories("All").unwrap());
    }

    #[test]
    fn single_category() {
        assert_eq!(
            vec![Category::PASSWORD],
            parse_categories("password").unwrap()
        );
    }

    #[test]
    fn comma_separated_trims_and_lowercases() {
        let got = parse_categories(" Password , cookie,  ").unwrap();
        assert_eq!(vec![Category::PASSWORD, Category::COOKIE], got);
    }

    #[test]
    fn unknown_category_error_mentions_available() {
        let err = parse_categories("nope").unwrap_err();
        match err {
            CategoryParseError::Unknown {
                name,
                ref available,
            } => {
                assert_eq!("nope", name);
                assert_eq!(category_names(), *available);
            }
            _ => panic!("expected Unknown, got {err:?}"),
        }
    }

    #[test]
    fn empty_input_errors() {
        let err = parse_categories("").unwrap_err();
        assert!(matches!(err, CategoryParseError::Empty));
        let err = parse_categories(" , ").unwrap_err();
        assert!(matches!(err, CategoryParseError::Empty));
    }

    #[test]
    fn category_names_joined_with_comma() {
        assert_eq!(
            "password,cookie,bookmark,history,download,creditcard,extension,localstorage,sessionstorage",
            category_names()
        );
    }
}
