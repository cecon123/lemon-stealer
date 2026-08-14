//! One Chromium profile under an installation — the leaf extraction unit
//! (Go: `browser/chromium/profile.go`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hbd_core::{BrowserData, BrowserKind, Category};
use keyring::MasterKeys;

use crate::chromium::error::{ChromiumError, Result};
use crate::chromium::extract_bookmark::{count_bookmarks, extract_bookmarks};
use crate::chromium::extract_cookie::{count_cookies, extract_cookies};
use crate::chromium::extract_creditcard::{
    count_credit_cards, count_yandex_credit_cards, extract_credit_cards,
};
use crate::chromium::extract_download::{count_downloads, extract_downloads};
use crate::chromium::extract_extension::{
    count_extensions, count_opera_extensions, extract_extensions,
};
use crate::chromium::extract_history::{count_histories, extract_histories};
use crate::chromium::extract_password::{count_passwords, extract_passwords};
use crate::chromium::extract_storage::{
    count_local_storage, count_session_storage, extract_local_storage, extract_session_storage,
};
use crate::chromium::source::{CategoryExtractor, ResolvedPath};
use filemanager::Session;

/// One profile: reads its own source files but reuses the installation's
/// master keys (Go: `profile`).
pub struct Profile {
    pub(crate) profile_dir: PathBuf,
    pub(crate) browser_name: String,
    pub(crate) kind: BrowserKind,
    pub(crate) extractors: HashMap<Category, CategoryExtractor>,
    pub(crate) source_paths: HashMap<Category, ResolvedPath>,
}

impl Profile {
    /// Base name of the profile directory (Go: `name`).
    pub fn name(&self) -> String {
        if self.profile_dir.as_os_str().is_empty() {
            return String::new();
        }
        self.profile_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    pub fn label(&self) -> String {
        format!("{}/{}", self.browser_name, self.name())
    }

    /// Copies the profile's source files to a temp directory and extracts the
    /// requested categories, decrypting with the installation's master keys
    /// (Go: `extract`).
    pub fn extract(&self, master_keys: &MasterKeys, categories: &[Category]) -> BrowserData {
        let session = match Session::new() {
            Ok(s) => s,
            Err(e) => {
                log::debug!("new session for {}: {}", self.label(), e);
                return BrowserData::default();
            }
        };

        let temp_paths = self.acquire_files(&session, categories);
        let mut data = BrowserData::default();
        for cat in categories {
            let Some(path) = temp_paths.get(cat) else {
                continue;
            };
            self.extract_category(&mut data, *cat, master_keys, path);
        }
        data
    }

    /// Counts entries per category without decryption (Go: `count`).
    pub fn count(&self, categories: &[Category]) -> HashMap<Category, usize> {
        let session = match Session::new() {
            Ok(s) => s,
            Err(e) => {
                log::debug!("new session for {}: {}", self.label(), e);
                return HashMap::new();
            }
        };

        let temp_paths = self.acquire_files(&session, categories);
        let mut counts = HashMap::new();
        for cat in categories {
            let Some(path) = temp_paths.get(cat) else {
                continue;
            };
            counts.insert(*cat, self.count_category(*cat, path));
        }
        counts
    }

    /// Copies source files to the session temp directory (Go: `acquireFiles`).
    /// The destination is `<temp>/<category-name>` — a flat staging area that
    /// the extractors then read without touching the live browser files.
    pub(crate) fn acquire_files(
        &self,
        session: &Session,
        categories: &[Category],
    ) -> HashMap<Category, PathBuf> {
        let mut temp_paths = HashMap::new();
        for cat in categories {
            let Some(rp) = self.source_paths.get(cat) else {
                continue;
            };
            let dst = session.temp_dir().join(cat.to_string());
            match session.acquire(&rp.abs, &dst, rp.is_dir) {
                Ok(()) => {
                    temp_paths.insert(*cat, dst);
                }
                Err(e) => log::debug!("acquire {}: {}", cat, e),
            }
        }
        temp_paths
    }

    /// Calls the appropriate extract function for a category. A custom
    /// extractor (registered per kind) takes precedence over the switch
    /// (Go: `extractCategory`).
    fn extract_category(
        &self,
        data: &mut BrowserData,
        cat: Category,
        master_keys: &MasterKeys,
        path: &Path,
    ) {
        if let Some(ext) = self.extractors.get(&cat) {
            if let Err(e) = ext.extract(master_keys, path, data) {
                log::debug!("extract {} for {}: {}", cat, self.label(), e);
            }
            return;
        }

        if let Err(e) = self.extract_category_default(data, cat, master_keys, path) {
            log::debug!("extract {} for {}: {}", cat, self.label(), e);
        }
    }

    /// The default switch-based dispatch for categories without custom
    /// extractors (Go: `extractCategory`, the `switch cat` half).
    fn extract_category_default(
        &self,
        data: &mut BrowserData,
        cat: Category,
        master_keys: &MasterKeys,
        path: &Path,
    ) -> Result<()> {
        match cat {
            Category::PASSWORD => {
                data.passwords = extract_passwords(master_keys, path)?;
            }
            Category::COOKIE => {
                data.cookies = extract_cookies(master_keys, path)?;
            }
            Category::HISTORY => {
                data.histories = extract_histories(path)?;
            }
            Category::DOWNLOAD => {
                data.downloads = extract_downloads(path)?;
            }
            Category::BOOKMARK => {
                data.bookmarks = extract_bookmarks(path)?;
            }
            Category::CREDIT_CARD => {
                data.credit_cards = extract_credit_cards(master_keys, path)?;
            }
            Category::EXTENSION => {
                data.extensions = extract_extensions(path)?;
            }
            Category::LOCAL_STORAGE => {
                data.local_storage = extract_local_storage(path)?;
            }
            Category::SESSION_STORAGE => {
                data.session_storage = extract_session_storage(path)?;
            }
            _ => return Err(ChromiumError::Message(format!("unknown category {cat}"))),
        }
        Ok(())
    }

    /// Calls the appropriate count function for a category
    /// (Go: `countCategory`).
    fn count_category(&self, cat: Category, path: &Path) -> usize {
        let result = match cat {
            Category::PASSWORD => count_passwords(path),
            Category::COOKIE => count_cookies(path),
            Category::HISTORY => count_histories(path),
            Category::DOWNLOAD => count_downloads(path),
            Category::BOOKMARK => count_bookmarks(path),
            Category::CREDIT_CARD => match self.kind {
                BrowserKind::ChromiumYandex => count_yandex_credit_cards(path),
                _ => count_credit_cards(path),
            },
            Category::EXTENSION => match self.kind {
                BrowserKind::ChromiumOpera => count_opera_extensions(path),
                _ => count_extensions(path),
            },
            Category::LOCAL_STORAGE => count_local_storage(path),
            Category::SESSION_STORAGE => count_session_storage(path),
            _ => return 0,
        };
        match result {
            Ok(n) => n as usize,
            Err(e) => {
                log::debug!("count {} for {}: {}", cat, self.label(), e);
                0
            }
        }
    }
}
