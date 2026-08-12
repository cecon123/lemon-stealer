//! Port of `types/result.go`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{BrowserData, Category};

/// Identifies one browser profile — a leaf under an installation (Go: `Profile`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub dir: String,
}

/// Pairs a profile with the data extracted from it (Go: `ExtractResult`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractResult {
    pub profile: Profile,
    pub data: BrowserData,
}

/// Pairs a profile with its per-category entry counts (Go: `CountResult`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CountResult {
    pub profile: Profile,
    pub counts: HashMap<Category, usize>,
}
