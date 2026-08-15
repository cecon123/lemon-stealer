//! Minimal LevelDB reader for Chromium Local/Session Storage
//! (Go uses `goleveldb`; this is a hand-rolled reader per PLAN.md R6 —
//! read-only, Snappy-only, no Write/Compaction).
//!
//! Pipeline mirrors what goleveldb does on `OpenFile`:
//!   1. `CURRENT` → MANIFEST file name → parse version edits for the live
//!      `.ldb`/`.sst` table set + the WAL log number.
//!   2. Fallback when CURRENT/MANIFEST is missing or corrupt: scan every
//!      `.ldb`/`.sst` in the dir (handles hand-copied trees).
//!   3. Decode each table (footer → index block → data blocks, Snappy
//!      decompress, internal-key trailers) plus the WAL write batches.
//!   4. Merge by (user key, sequence desc), dropping deletion tombstones —
//!      LevelDB DBIterator semantics (a deletion entry hides the key).

use std::path::{Path, PathBuf};

use crate::chromium::error::{ChromiumError, Result};

const LOG_BLOCK_SIZE: usize = 32768; // 32 KiB log blocks
const TABLE_FOOTER_LEN: usize = 48;
/// Footer magic: 0xdb4775248b80fb57 big-endian (reads as little-endian bytes).
const TABLE_MAGIC: [u8; 8] = [0x57, 0xfb, 0x80, 0x8b, 0x24, 0x75, 0x47, 0xdb];

#[cfg(test)]
const TYPE_VALUE: u8 = 1;
const TYPE_DELETION: u8 = 0;

// Log record types.
const RECORD_FULL: u8 = 1;
const RECORD_FIRST: u8 = 2;
const RECORD_MIDDLE: u8 = 3;
const RECORD_LAST: u8 = 4;

/// A decoded entry: user key, sequence, type (value/deletion), value.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) key: Vec<u8>,
    seq: u64,
    typ: u8,
    pub(crate) value: Vec<u8>,
}

/// A read-only LevelDB database handle (Go: `leveldb.DB`).
pub struct LevelDb {
    /// All user entries, sorted by (user key, seq desc), tombstones dropped —
    /// this IS the iterator order (`db.NewIterator(nil, nil)` + `iter.Next()`).
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl LevelDb {
    /// Opens the LevelDB directory and loads every live key/value pair.
    pub fn open(dir: &Path) -> Result<LevelDb> {
        let mut tables: Vec<PathBuf> = Vec::new();
        let mut log_number: Option<u64> = None;

        if let Some(manifest) = read_current(dir) {
            match read_manifest(&manifest) {
                Ok((numbers, log)) => {
                    for n in numbers {
                        if let Some(p) = table_path(dir, n) {
                            tables.push(p);
                        }
                    }
                    log_number = log;
                }
                Err(e) => {
                    log::debug!(
                        "leveldb: manifest {} unreadable ({}); falling back to dir scan",
                        manifest.display(),
                        e
                    );
                }
            }
        }

        if tables.is_empty() {
            tables = scan_table_files(dir);
        }

        let mut entries = Vec::new();
        for f in &tables {
            match read_table(f) {
                Ok(mut e) => entries.append(&mut e),
                Err(e) => {
                    log::debug!(
                        "leveldb: table {} unreadable ({}); skipping — live trees may carry torn/corrupt tables",
                        f.display(),
                        e
                    );
                }
            }
        }

        // With no manifest (hand-copied trees) the WAL may still be the only
        // live data — fall back to scanning log files.
        let logs: Vec<PathBuf> = if log_number.is_some() {
            log_number
                .map(|n| dir.join(format!("{n:06}.log")))
                .into_iter()
                .collect()
        } else if tables.is_empty() {
            scan_log_files(dir)
        } else {
            Vec::new()
        };
        for log_path in logs {
            if log_path.is_file() {
                match read_wal(&log_path) {
                    Ok(mut e) => entries.append(&mut e),
                    Err(e) => log::debug!("leveldb: wal {} unreadable: {}", log_path.display(), e),
                }
            }
        }

        Ok(LevelDb {
            entries: merge_entries(entries),
        })
    }

    /// Opens a single-file LevelDB (Chromium Session Storage: one `.localstorage`
    /// file per origin, log-only, no CURRENT/MANIFEST — goleveldb reads it via
    /// its WAL recovery).
    pub fn open_log_only(path: &Path) -> Result<LevelDb> {
        let entries = read_wal(path)?;
        Ok(LevelDb {
            entries: merge_entries(entries),
        })
    }

    /// Indexable view over the entry list — callers iterate it in order.
    pub fn iter(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.entries
    }
}

/// Sorts by (user key asc, seq desc) — LevelDB internal order — then keeps the
/// highest-sequence version of each key, dropping keys whose newest record is a
/// deletion tombstone (Go: goleveldb iterator semantics).
fn merge_entries(mut entries: Vec<Entry>) -> Vec<(Vec<u8>, Vec<u8>)> {
    entries.sort_by(|a, b| match a.key.cmp(&b.key) {
        std::cmp::Ordering::Equal => b.seq.cmp(&a.seq),
        other => other,
    });

    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
    let mut i = 0;
    while i < entries.len() {
        let key = &entries[i].key;
        if entries[i].typ == TYPE_DELETION {
            // Deleted: skip every record for this key.
            while i < entries.len() && entries[i].key == *key {
                i += 1;
            }
            continue;
        }
        out.push((entries[i].key.clone(), entries[i].value.clone()));
        i += 1;
        while i < entries.len() && entries[i].key == *key {
            i += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Log file reading (MANIFEST + WAL share the format)
// ---------------------------------------------------------------------------

/// LevelDB seals the on-disk CRC with `Mask(crc) = ((crc>>15)|(crc<<17)) +
/// 0xa282ead8` (Chromium `crc32c::Mask`; the top bit is masked into bit 15/17,
/// and the constant is added mod 2^32). Chrome's `WriteRawBlock` stores
/// `Mask(crc32c(data+type))`; the log writer stores `Mask(crc32c(type+payload))`.
pub(crate) fn mask_crc(raw: u32) -> u32 {
    raw.rotate_right(15).wrapping_add(0xa282_ead8)
}

/// Reads every log record in a .log/MANIFEST file as raw byte slices.
/// Records span FULL/FIRST/MIDDLE/LAST chunks across 32 KiB blocks.
fn read_log_records(path: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes = std::fs::read(path)?;
    let mut records = Vec::new();
    let mut current: Option<Vec<u8>> = None;

    let mut off = 0;
    while off + 7 <= bytes.len() {
        let header = &bytes[off..off + 7];
        let crc = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let len = u16::from_le_bytes([header[4], header[5]]) as usize;
        let rtype = header[6];
        off += 7;

        if len == 0 {
            // Zero-length record: rest of the block is padding — skip to the
            // next block boundary (goleveldb terminates on this).
            let block_remain = LOG_BLOCK_SIZE - (off % LOG_BLOCK_SIZE);
            off += block_remain.min(bytes.len().saturating_sub(off));
            continue;
        }
        if off + len > bytes.len() {
            break; // truncated tail — clean EOF
        }
        let data = &bytes[off..off + len];
        off += len;

        // Chrome/LevelDB seal the CRC with `Mask`: data (type byte + payload)
        // → CRC-32C → `((crc>>15)|(crc<<17)) + 0xa282ead8`. Covered: type byte
        // (the byte at `off - len - 1`) plus the `len` payload bytes.
        let raw = crc32c::crc32c(&bytes[off - len - 1..off]);
        let expect = mask_crc(raw);
        if crc != expect && crc != raw & 0x7fff_ffff {
            return Err(ChromiumError::Message(format!(
                "log {}: crc mismatch at offset {}",
                path.display(),
                off - len
            )));
        }

        match rtype {
            RECORD_FULL => records.push(data.to_vec()),
            RECORD_FIRST => current = Some(data.to_vec()),
            RECORD_MIDDLE => {
                if let Some(c) = current.as_mut() {
                    c.extend_from_slice(data);
                } else {
                    return Err(ChromiumError::Message(format!(
                        "log {}: MIDDLE without FIRST",
                        path.display()
                    )));
                }
            }
            RECORD_LAST => {
                if let Some(mut c) = current.take() {
                    c.extend_from_slice(data);
                    records.push(c);
                } else {
                    return Err(ChromiumError::Message(format!(
                        "log {}: LAST without FIRST",
                        path.display()
                    )));
                }
            }
            _ => {}
        }
    }
    Ok(records)
}

/// Parses a MANIFEST log into (table file numbers, WAL log number).
fn read_manifest(path: &Path) -> Result<(Vec<u64>, Option<u64>)> {
    let mut tables = Vec::new();
    let mut log_number: Option<u64> = None;

    for record in read_log_records(path)? {
        parse_version_edit(&record, &mut tables, &mut log_number);
    }
    Ok((tables, log_number))
}

/// Decodes one VersionEdit record (LevelDB `version_edit` format).
fn parse_version_edit(record: &[u8], tables: &mut Vec<u64>, log_number: &mut Option<u64>) {
    let mut p = Cursor::new(record);
    while let Some(tag) = p.next_u8() {
        match tag {
            1 => {
                // comparator name — length-prefixed string
                let _ = p.next_bytes();
            }
            2 => *log_number = p.next_u64(),
            3 | 4 | 8 => {
                // next file number / last sequence / prev log number
                let _ = p.next_u64();
            }
            5 => {
                // compact pointer: level + internal key
                let _ = p.next_u32();
                let _ = p.next_internal_key();
            }
            6 => {
                // deleted file: level + file number
                let _ = p.next_u32();
                let _ = p.next_u64();
            }
            7 => {
                // new file: level + number + size + smallest + largest key
                let level = p.next_u32();
                let number = p.next_u64();
                let _ = p.next_u64(); // file size
                let _ = p.next_internal_key();
                let _ = p.next_internal_key();
                if let (Some(l), Some(n)) = (level, number) {
                    let _ = l;
                    tables.push(n);
                }
            }
            _ => break, // unknown tag — stop decoding this edit
        }
    }
}

/// Simple little-endian varint cursor.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn next_u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn next_u32(&mut self) -> Option<u32> {
        self.next_u64().map(|v| v as u32)
    }

    fn next_u64(&mut self) -> Option<u64> {
        let mut shift = 0;
        let mut value: u64 = 0;
        loop {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            value |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
    }

    /// Length-prefixed byte slice (varint32 length then bytes).
    fn next_bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.next_u64()? as usize;
        let end = self.pos.checked_add(len)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// A length-prefixed internal key (empty length = empty key).
    fn next_internal_key(&mut self) -> Option<&'a [u8]> {
        self.next_bytes()
    }

    fn peek(&self, len: usize) -> Option<&'a [u8]> {
        self.data.get(self.pos..self.pos + len)
    }

    fn skip(&mut self, len: usize) {
        self.pos += len;
    }
}

/// WAL log: replays every WriteBatch into entries (Go replays the log after
/// the tables; batch sequence numbers resolve conflicts).
fn read_wal(path: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for record in read_log_records(path)? {
        let mut p = Cursor::new(&record);
        let Some(seq) = p.next_u64() else { continue };
        let Some(count) = p.next_u64() else { continue };
        for i in 0..count {
            let Some(typ) = p.next_u8() else { break };
            let Some(key) = p.next_bytes() else { break };
            if typ == TYPE_DELETION {
                entries.push(Entry {
                    key: key.to_vec(),
                    seq: seq + i,
                    typ,
                    value: Vec::new(),
                });
                continue;
            }
            let Some(value) = p.next_bytes() else { break };
            entries.push(Entry {
                key: key.to_vec(),
                seq: seq + i,
                typ,
                value: value.to_vec(),
            });
        }
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Table (.ldb / .sst) reading
// ---------------------------------------------------------------------------

/// Reads a table file: footer → metaindex handle → index block → data blocks.
pub(crate) fn read_table(path: &Path) -> Result<Vec<Entry>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < TABLE_FOOTER_LEN {
        return Err(ChromiumError::Message(format!(
            "table {}: too short ({} bytes)",
            path.display(),
            bytes.len()
        )));
    }

    let footer = &bytes[bytes.len() - TABLE_FOOTER_LEN..];
    if footer[TABLE_FOOTER_LEN - 8..] != TABLE_MAGIC {
        return Err(ChromiumError::Message(format!(
            "table {}: bad magic",
            path.display()
        )));
    }

    let mut p = Cursor::new(&footer[..TABLE_FOOTER_LEN - 8]);
    let _meta_handle = read_handle(&mut p);
    let Some(index_handle) = read_handle(&mut p) else {
        return Err(ChromiumError::Message(format!(
            "table {}: no index handle",
            path.display()
        )));
    };

    let index_block = decode_block(&bytes, index_handle)?;
    let index_entries = parse_block_entries(&index_block);

    let mut entries = Vec::new();
    for (_key, value) in index_entries {
        let Some(data_handle) = read_handle_buf(&value) else {
            continue;
        };
        if data_handle.1 == 0 {
            continue;
        }
        let block = decode_block(&bytes, data_handle)?;
        for (key, value) in parse_block_entries(&block) {
            if key.len() < 8 {
                continue; // malformed internal key
            }
            let seq = seq_of(&key);
            let typ = key[key.len() - 1];
            entries.push(Entry {
                key: key[..key.len() - 8].to_vec(),
                seq,
                typ,
                value,
            });
        }
    }
    Ok(entries)
}

/// BlockHandle = varint64 offset + varint64 size.
type BlockHandle = (u64, u64);

fn read_handle(p: &mut Cursor) -> Option<BlockHandle> {
    let offset = p.next_u64()?;
    let size = p.next_u64()?;
    Some((offset, size))
}

fn read_handle_buf(data: &[u8]) -> Option<BlockHandle> {
    let mut p = Cursor::new(data);
    read_handle(&mut p)
}

/// Reads a block (data or index) at the handle, verifies the trailer, and
/// decompresses Snappy blocks (Go: `goleveldb` block reader; the metaindex is
/// skipped — nothing there is needed for iteration).
fn decode_block(file: &[u8], handle: BlockHandle) -> Result<Vec<u8>> {
    let offset = handle.0 as usize;
    let size = handle.1 as usize;
    let end = offset + size;
    // Trailer: 1 compression byte + 4 crc bytes.
    if end + 5 > file.len() {
        return Err(ChromiumError::Message("block out of bounds".into()));
    }
    let ctype = file[end];
    let stored_crc =
        u32::from_le_bytes([file[end + 1], file[end + 2], file[end + 3], file[end + 4]]);
    // Chrome/LevelDB: CRC-32C over the block payload PLUS the compression-type
    // byte, then sealed with `mask_crc` (Chromium `WriteRawBlock` appends the
    // trailer with the type byte, then stores Mask(crc32c(data+type))).
    let expect = mask_crc(crc32c::crc32c(&file[offset..=end]));
    // Accept the masked seal and the legacy unmasked form (goleveldb cross-reads).
    if stored_crc != expect && stored_crc != crc32c::crc32c(&file[offset..=end]) & 0x7fff_ffff {
        return Err(ChromiumError::Message(format!(
            "block crc mismatch: off={offset} size={size} stored={stored_crc:#010x} expect={expect:#010x}"
        )));
    }

    let raw = &file[offset..end];
    match ctype {
        0 => Ok(raw.to_vec()),
        1 => snap::raw::Decoder::new()
            .decompress_vec(raw)
            .map_err(|e| ChromiumError::Message(format!("snappy: {e}"))),
        other => Err(ChromiumError::Message(format!(
            "unsupported block compression {other} (goleveldb errors here too)"
        ))),
    }
}

/// Decodes a block into (key, value) pairs with prefix sharing, ending with
/// the restart-array size (4-byte LE). Keys stay raw (internal keys for data
/// blocks, separator keys for the index block).
fn parse_block_entries(block: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    if block.len() < 4 {
        return Vec::new();
    }
    let restarts_off = block.len() - 4;
    let restart_count = u32::from_le_bytes([
        block[restarts_off],
        block[restarts_off + 1],
        block[restarts_off + 2],
        block[restarts_off + 3],
    ]) as usize;
    if restart_count == 0 {
        return Vec::new();
    }
    let restart_array = restarts_off - restart_count * 4;
    if restart_array == 0 {
        return Vec::new();
    }

    let mut p = Cursor::new(&block[..restart_array]);
    let mut prev_key = Vec::new();
    let mut out = Vec::new();
    while p.pos < restart_array {
        let Some(shared) = p.next_u64() else { break };
        let Some(nonshared) = p.next_u64() else { break };
        let Some(value_len) = p.next_u64() else { break };
        let key_len = shared as usize + nonshared as usize;
        let Some(entry_bytes) = p.peek(key_len + value_len as usize) else {
            break;
        };
        p.skip(key_len + value_len as usize);
        if prev_key.len() < shared as usize {
            break; // corrupt: shared prefix longer than previous key
        }
        let value_bytes = &entry_bytes[key_len..];
        let mut key = prev_key[..shared as usize].to_vec();
        key.extend_from_slice(&entry_bytes[shared as usize..key_len]);
        prev_key = key.clone();
        out.push((key, value_bytes.to_vec()));
    }
    out
}

/// Sequence number from an internal key's 8-byte trailer (7B big-endian seq +
/// 1B type).
fn seq_of(internal_key: &[u8]) -> u64 {
    let mut seq: u64 = 0;
    for &b in &internal_key[internal_key.len() - 8..internal_key.len() - 1] {
        seq = (seq << 8) | b as u64;
    }
    seq
}

// ---------------------------------------------------------------------------
// Directory-level helpers
// ---------------------------------------------------------------------------

/// Reads the `CURRENT` file: the one-line MANIFEST file name.
fn read_current(dir: &Path) -> Option<PathBuf> {
    let current = dir.join("CURRENT");
    let mut f = std::fs::File::open(current).ok()?;
    let mut line = String::new();
    use std::io::Read;
    f.read_to_string(&mut line).ok()?;
    let name = line.trim();
    if name.is_empty() {
        return None;
    }
    Some(dir.join(name))
}

/// Fallback listing: every `.ldb`/`.sst` table file, name-sorted
/// (hand-copied trees; goleveldb would refuse these dirs, so this is strictly
/// more lenient — what portable dump/restore needs).
fn scan_table_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".ldb") || name.ends_with(".sst") {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files
}

/// Fallback listing: every `.log` WAL file, name-sorted (used only when no
/// manifest directed us to the live log number).
fn scan_log_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".log") {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files
}

/// Maps a manifest-listed file number to its table path, or `None` when the
/// file doesn't exist (stale manifest entries are skipped — Chrome cleans
/// obsolete tables asynchronously).
fn table_path(dir: &Path, number: u64) -> Option<PathBuf> {
    for ext in [".ldb", ".sst"] {
        let p = dir.join(format!("{number:06}{ext}"));
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs;

    // -----------------------------------------------------------------
    // Test-only writers (build real LevelDB-format bytes)
    // -----------------------------------------------------------------

    fn varint(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut v = v;
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return out;
            }
        }
    }

    fn internal_key(user: &[u8], seq: u64, typ: u8) -> Vec<u8> {
        let mut key = user.to_vec();
        for shift in (0..56).step_by(8).rev() {
            key.push(((seq >> shift) & 0xff) as u8);
        }
        key.push(typ);
        key
    }

    /// Encodes entries with prefix sharing + one restart point.
    fn block_bytes(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut prev: Vec<u8> = Vec::new();
        for (key, value) in entries {
            let shared = prev
                .iter()
                .zip(key.iter())
                .take_while(|(a, b)| a == b)
                .count();
            let nonshared = key.len() - shared;
            body.extend_from_slice(&varint(shared as u64));
            body.extend_from_slice(&varint(nonshared as u64));
            body.extend_from_slice(&varint(value.len() as u64));
            body.extend_from_slice(&key[shared..]);
            body.extend_from_slice(value);
            prev = key.to_vec();
        }
        let mut block = body;
        block.extend_from_slice(&[0, 0, 0, 0]); // restart offset 0
        block.extend_from_slice(&[1, 0, 0, 0]); // restart count 1
        block
    }

    pub fn compress_type(block: &[u8], snappy: bool) -> Vec<u8> {
        let (ctype, data) = if snappy {
            let mut enc = snap::raw::Encoder::new();
            (1u8, enc.compress_vec(block).unwrap())
        } else {
            (0u8, block.to_vec())
        };
        let mut out = Vec::new();
        out.extend_from_slice(&data);
        out.push(ctype);
        // Real Chrome/LevelDB: CRC-32C over data + type byte, sealed with Mask
        // (`WriteRawBlock` stores Mask(crc32c(block_contents+type))).
        let crc = mask_crc(crc32c::crc32c(&out));
        let crc_bytes = crc.to_le_bytes();
        out.extend_from_slice(&crc_bytes);
        out
    }

    fn handle_bytes(h: BlockHandle) -> Vec<u8> {
        let mut out = varint(h.0);
        out.extend_from_slice(&varint(h.1));
        out
    }

    /// Builds a full table file: [data][meta][metaindex][index][footer].
    /// Entries are internal keys already (test constructors build them via
    /// [`internal_key`]).
    fn table_from_internal(entries: &[(&[u8], &[u8])], snappy: bool) -> Vec<u8> {
        let mut file = Vec::new();

        // Data block. Handles point at the block payload and exclude the 5-byte
        // compression trailer (ctype + crc) — decode_block recomputes `end`
        // from the handle and reads the trailer from there.
        let data = block_bytes(entries);
        let data_with_trailer = compress_type(&data, snappy);
        let data_payload = data_with_trailer.len() - 5;
        let data_handle = (0u64, data_payload as u64);
        file.extend_from_slice(&data_with_trailer);

        // Meta block (empty — Chromium tables carry no bloom filter entries).
        let meta = block_bytes(&[]);
        let meta_handle = (file.len() as u64, meta.len() as u64);
        file.extend_from_slice(&meta);

        // Metaindex block: one entry naming the filter (offset 0 in meta).
        // Written uncompressed like goleveldb (and never read by this reader).
        let mut metaindex = Vec::new();
        metaindex.extend_from_slice(&varint(0)); // shared
        metaindex.extend_from_slice(&varint(b"filter.leveldb.BuiltinBloomFilter2".len() as u64));
        metaindex.extend_from_slice(&varint(handle_bytes(meta_handle).len() as u64));
        metaindex.extend_from_slice(b"filter.leveldb.BuiltinBloomFilter2");
        metaindex.extend_from_slice(&handle_bytes(meta_handle));
        metaindex.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        let metaindex_handle = (file.len() as u64, metaindex.len() as u64);
        file.extend_from_slice(&metaindex);

        // Index block: last data key → data handle. Compressed like the data
        // block — the reader's `decode_block` always expects a compression
        // trailer (real LevelDB tables carry one on every block).
        let mut index_body = Vec::new();
        let last_key = entries.last().expect("entries").0;
        index_body.extend_from_slice(&varint(0));
        index_body.extend_from_slice(&varint(last_key.len() as u64));
        index_body.extend_from_slice(&varint(handle_bytes(data_handle).len() as u64));
        index_body.extend_from_slice(last_key);
        index_body.extend_from_slice(&handle_bytes(data_handle));
        index_body.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        let index_with_trailer = compress_type(&index_body, snappy);
        let index_payload = index_with_trailer.len() - 5;
        let index_handle = (file.len() as u64, index_payload as u64);
        file.extend_from_slice(&index_with_trailer);

        // Footer: [metaindex handle][index handle][padding][magic].
        let mut footer = handle_bytes(metaindex_handle);
        footer.extend_from_slice(&handle_bytes(index_handle));
        while footer.len() < TABLE_FOOTER_LEN - 8 {
            footer.push(0);
        }
        footer.extend_from_slice(&TABLE_MAGIC);
        assert_eq!(TABLE_FOOTER_LEN, footer.len());
        file.extend_from_slice(&footer);
        file
    }

    /// Convenience: internal-key table from (user key, seq, type, value).
    pub fn table_bytes(entries: &[(&[u8], u64, u8, &[u8])], snappy: bool) -> Vec<u8> {
        let internal: Vec<(Vec<u8>, &[u8])> = entries
            .iter()
            .map(|(k, seq, typ, v)| (internal_key(k, *seq, *typ), *v))
            .collect();
        let refs: Vec<(&[u8], &[u8])> = internal.iter().map(|(k, v)| (k.as_slice(), *v)).collect();
        table_from_internal(&refs, snappy)
    }

    /// Builds a log file containing one record per given payload.
    pub fn log_bytes_for_tests(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for record in records {
            let mut header = Vec::new();
            let mut payload = vec![RECORD_FULL];
            payload.extend_from_slice(record);
            let crc = mask_crc(crc32c::crc32c(&payload));
            header.extend_from_slice(&crc.to_le_bytes());
            header.extend_from_slice(&(record.len() as u16).to_le_bytes());
            header.push(RECORD_FULL);
            out.extend_from_slice(&header);
            out.extend_from_slice(record);
        }
        out
    }

    /// A VersionEdit "new file" record (tag 7).
    fn version_edit_new_file(level: u32, number: u64, size: u64) -> Vec<u8> {
        let mut e = Vec::new();
        e.push(7);
        e.extend_from_slice(&varint(level as u64));
        e.extend_from_slice(&varint(number));
        e.extend_from_slice(&varint(size));
        // smallest/largest internal keys (empty).
        e.push(0);
        e.push(0);
        e
    }

    fn version_edit_log_number(n: u64) -> Vec<u8> {
        let mut e = Vec::new();
        e.push(2);
        e.extend_from_slice(&varint(n));
        e
    }

    pub fn write_batch_for_tests(seq: u64, ops: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&varint(seq));
        b.extend_from_slice(&varint(ops.len() as u64));
        for (typ, key, value) in ops {
            b.push(*typ);
            b.extend_from_slice(&varint(key.len() as u64));
            b.extend_from_slice(key);
            if *typ == TYPE_VALUE {
                b.extend_from_slice(&varint(value.len() as u64));
                b.extend_from_slice(value);
            }
        }
        b
    }

    fn fixture_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hbd-leveldb-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -----------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------

    #[test]
    fn open_reads_snappy_table_via_manifest() {
        let dir = fixture_dir("snappy");
        fs::write(
            dir.join("000001.ldb"),
            table_bytes(
                &[(b"a", 10, TYPE_VALUE, b"1"), (b"b", 10, TYPE_VALUE, b"2")],
                true,
            ),
        )
        .unwrap();
        fs::write(dir.join("CURRENT"), b"MANIFEST-000002\n").unwrap();
        fs::write(
            dir.join("MANIFEST-000002"),
            log_bytes_for_tests(&[version_edit_new_file(0, 1, 100)]),
        )
        .unwrap();

        let db = LevelDb::open(&dir).unwrap();
        assert_eq!(
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"2".to_vec())
            ],
            db.iter()
        );
    }

    #[test]
    fn open_fallback_scans_ldb_without_manifest() {
        let dir = fixture_dir("nomanifest");
        fs::write(
            dir.join("000003.ldb"),
            table_bytes(&[(b"x", 7, TYPE_VALUE, b"9")], false),
        )
        .unwrap();

        let db = LevelDb::open(&dir).unwrap();
        assert_eq!(vec![(b"x".to_vec(), b"9".to_vec())], db.iter());
    }

    #[test]
    fn wal_batch_merged_and_tombstone_hides_key() {
        let dir = fixture_dir("wal");
        // Tables carry seq 5 — the WAL (seq 10) is newer and must win.
        fs::write(
            dir.join("000001.ldb"),
            table_bytes(
                &[(b"a", 5, TYPE_VALUE, b"t"), (b"b", 5, TYPE_VALUE, b"old")],
                false,
            ),
        )
        .unwrap();
        fs::write(dir.join("CURRENT"), b"MANIFEST-000002\n").unwrap();
        fs::write(
            dir.join("MANIFEST-000002"),
            log_bytes_for_tests(&[version_edit_log_number(2), version_edit_new_file(0, 1, 100)]),
        )
        .unwrap();
        // WAL: seq 10 — update a, delete b.
        fs::write(
            dir.join("000002.log"),
            log_bytes_for_tests(&[write_batch_for_tests(
                10,
                &[(TYPE_VALUE, b"a", b"new"), (TYPE_DELETION, b"b", b"")],
            )]),
        )
        .unwrap();

        let db = LevelDb::open(&dir).unwrap();
        let want: Vec<(Vec<u8>, Vec<u8>)> = vec![(b"a".to_vec(), b"new".to_vec())];
        assert_eq!(want, db.iter(), "b hidden by tombstone, a updated by WAL");
    }

    #[test]
    fn highest_seq_wins_across_files() {
        let dir = fixture_dir("dup");
        fs::write(
            dir.join("000001.ldb"),
            table_bytes(&[(b"k", 100, TYPE_VALUE, b"v1")], false),
        )
        .unwrap();
        fs::write(
            dir.join("000002.ldb"),
            table_bytes(&[(b"k", 200, TYPE_VALUE, b"v2")], false),
        )
        .unwrap();
        fs::write(dir.join("CURRENT"), b"MANIFEST-000003\n").unwrap();
        fs::write(
            dir.join("MANIFEST-000003"),
            log_bytes_for_tests(&[
                version_edit_new_file(0, 1, 100),
                version_edit_new_file(0, 2, 100),
            ]),
        )
        .unwrap();

        let db = LevelDb::open(&dir).unwrap();
        let got = db.iter();
        assert_eq!(1, got.len(), "duplicate keys collapse to one entry");
        assert_eq!(b"v2", got[0].1.as_slice(), "highest sequence wins");
    }

    #[test]
    fn tombstone_in_table_hides_key() {
        let dir = fixture_dir("tombstone");
        fs::write(
            dir.join("000001.ldb"),
            table_bytes(
                &[
                    (b"k", 300, TYPE_VALUE, b"present"),
                    (b"gone", 400, TYPE_DELETION, b""),
                ],
                false,
            ),
        )
        .unwrap();

        let db = LevelDb::open(&dir).unwrap();
        assert_eq!(vec![(b"k".to_vec(), b"present".to_vec())], db.iter());
    }

    #[test]
    fn empty_dir_yields_empty_db() {
        let dir = fixture_dir("empty");
        let db = LevelDb::open(&dir).unwrap();
        assert!(db.iter().is_empty());
    }

    #[test]
    fn seq_of_parses_big_endian() {
        // 7-byte big-endian sequence — max value fits 56 bits.
        let key = internal_key(b"k", 0x00fe_dcba_9876_5432, TYPE_VALUE);
        assert_eq!(0x00fe_dcba_9876_5432, seq_of(&key));
        assert_eq!(TYPE_VALUE, key[key.len() - 1]);
    }
}
