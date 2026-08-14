//! Pure-Rust PE parsing for the reflective injector (Go: `utils/injector/pe_windows.go`
//! + `arch_windows.go`). No WinAPI and no `unsafe` here — bytes in, RVAs out.
//!
//! Only the surfaces the injector needs are ported: architecture detection and
//! export lookup (RVA → raw file offset) for the `Bootstrap` entry point.

use std::fmt;

/// Errno-free parse error; messages mirror Go's `debug/pe`-era strings so the
/// injector's log lines stay byte-comparable with the Go binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    Parse(String),
    NotPe32(String),
    NoDataDirectories,
    NoExportDirectory,
    NotInAnySection(u32),
    ExportNotFound(String),
    OutsideSection(u32, String),
    BeyondRaw(u32),
    SlotOutOfRange(String),
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::Parse(e) => write!(f, "parse PE: {e}"),
            PeError::NotPe32(e) => write!(f, "expected PE32+ (64-bit) image: {e}"),
            PeError::NoDataDirectories => write!(f, "PE has no data directories"),
            PeError::NoExportDirectory => write!(f, "PE has no export directory"),
            PeError::NotInAnySection(rva) => {
                write!(f, "RVA 0x{rva:x} not in any section")
            }
            PeError::ExportNotFound(name) => write!(f, "export \"{name}\" not found"),
            PeError::OutsideSection(rva, sec) => {
                write!(f, "RVA 0x{rva:x} outside section \"{sec}\"")
            }
            PeError::BeyondRaw(rva) => write!(f, "RVA 0x{rva:x} beyond raw section data"),
            PeError::SlotOutOfRange(name) => {
                write!(f, "function slot for \"{name}\" out of range")
            }
        }
    }
}

impl std::error::Error for PeError {}

/// Mirror of Go's `injector.Arch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArch {
    Amd64,
    I386,
    Unknown,
}

impl PeArch {
    /// Go: `ArchAMD64` ("amd64") / `Arch386` ("386") / `ArchUnknown` ("unknown").
    pub fn as_str(self) -> &'static str {
        match self {
            PeArch::Amd64 => "amd64",
            PeArch::I386 => "386",
            PeArch::Unknown => "unknown",
        }
    }
}

/// `IMAGE_FILE_MACHINE_AMD64` / `IMAGE_FILE_MACHINE_I386` (winnt.h).
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_I386: u16 = 0x014C;

const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
/// `IMAGE_DIRECTORY_ENTRY_EXPORT` index in the data directory array.
const DIR_ENTRY_EXPORT: usize = 0;

/// DOS header offset of `e_lfanew` (offsetof(IMAGE_DOS_HEADER, e_lfanew)).
const PE_OFFSET: usize = 0x3C;

#[derive(Debug, Clone, Copy)]
struct NtHeaders {
    /// Offset of `IMAGE_FILE_HEADER` (pe + 4).
    file_header: u32,
    /// Offset of `IMAGE_OPTIONAL_HEADER64` (file_header + 20).
    optional: u32,
}

/// Reads `e_lfanew` + validates DOS/NT signatures. Mirrors what Go's
/// `pe.NewFile` enforces for the fields we consume.
fn nt_headers(bytes: &[u8]) -> Result<NtHeaders, PeError> {
    if bytes.len() < PE_OFFSET + 4 {
        return Err(PeError::Parse("truncated DOS header".into()));
    }
    if u16::from_le_bytes([bytes[0], bytes[1]]) != DOS_SIGNATURE {
        return Err(PeError::Parse("missing MZ signature".into()));
    }
    let pe = u32::from_le_bytes(bytes[PE_OFFSET..PE_OFFSET + 4].try_into().unwrap());
    let pe = pe as usize;
    if bytes.len() < pe + 4 + 4 {
        return Err(PeError::Parse("truncated NT headers".into()));
    }
    if u32::from_le_bytes(bytes[pe..pe + 4].try_into().unwrap()) != NT_SIGNATURE {
        return Err(PeError::Parse("bad PE signature".into()));
    }
    Ok(NtHeaders {
        file_header: (pe + 4) as u32,
        optional: (pe + 4 + 20) as u32,
    })
}

/// Machine field of `IMAGE_FILE_HEADER` (offset 0 — the first field).
fn machine(bytes: &[u8], nt: &NtHeaders) -> u16 {
    let off = nt.file_header as usize;
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}

/// Port of `DetectPEArch` (`arch_windows.go`): machine → arch, non-amd64 is
/// `Unknown` with `Ok` (Go behavior) so the injector can name the arch in its
/// error.
pub fn detect_pe_arch(bytes: &[u8]) -> Result<PeArch, PeError> {
    let nt = nt_headers(bytes)?;
    match machine(bytes, &nt) {
        MACHINE_AMD64 => Ok(PeArch::Amd64),
        MACHINE_I386 => Ok(PeArch::I386),
        _ => Ok(PeArch::Unknown),
    }
}

/// `IMAGE_OPTIONAL_HEADER64.Magic` (offset optional + 0) — 0x20B for PE32+.
fn is_pe32_plus(bytes: &[u8], nt: &NtHeaders) -> bool {
    let off = nt.optional as usize;
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) == 0x20B
}

/// Data directory array lives at optional + 112 (`NumberOfRvaAndSizes` may be
/// smaller; Go reads it as part of the struct parse and we validate the bounds).
fn export_directory(bytes: &[u8], nt: &NtHeaders) -> Result<(u32, u32), PeError> {
    let num_dirs_off = nt.optional as usize + 108;
    let num_dirs = u32::from_le_bytes(bytes[num_dirs_off..num_dirs_off + 4].try_into().unwrap());
    if num_dirs == 0 {
        return Err(PeError::NoDataDirectories);
    }
    let dirs_off = nt.optional as usize + 112;
    let idx = DIR_ENTRY_EXPORT;
    if (idx as u32) >= num_dirs {
        return Err(PeError::NoExportDirectory);
    }
    let off = dirs_off + idx * 8;
    let rva = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    let size = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap());
    if rva == 0 || size == 0 {
        return Err(PeError::NoExportDirectory);
    }
    Ok((rva, size))
}

/// `IMAGE_SECTION_HEADER` slice (`VirtualAddress` +4, `SizeOfRawData` +16,
/// `PointerToRawData` +20, `Characteristics` +36). 40 bytes each.
struct Section {
    name: [u8; 8],
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

fn sections(bytes: &[u8], nt: &NtHeaders) -> Vec<Section> {
    let num_secs = u16::from_le_bytes(
        bytes[nt.file_header as usize + 2..nt.file_header as usize + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let opt_size = u16::from_le_bytes(
        bytes[nt.file_header as usize + 16..nt.file_header as usize + 18]
            .try_into()
            .unwrap(),
    ) as usize;
    let first = (nt.optional as usize) + opt_size;
    (0..num_secs)
        .filter_map(|i| {
            let off = first + i * 40;
            if bytes.len() < off + 40 {
                return None;
            }
            let mut name = [0u8; 8];
            name.copy_from_slice(&bytes[off..off + 8]);
            Some(Section {
                name,
                virtual_address: u32::from_le_bytes(bytes[off + 12..off + 16].try_into().unwrap()),
                size_of_raw_data: u32::from_le_bytes(bytes[off + 16..off + 20].try_into().unwrap()),
                pointer_to_raw_data: u32::from_le_bytes(
                    bytes[off + 20..off + 24].try_into().unwrap(),
                ),
            })
        })
        .collect()
}

fn section_name(s: &Section) -> String {
    String::from_utf8_lossy(&s.name)
        .trim_end_matches('\0')
        .to_string()
}

/// First section that contains `rva` (Go: `findSectionForRVA`).
fn find_section_for_rva(sections: &[Section], rva: u32) -> Option<&Section> {
    sections
        .iter()
        .find(|s| rva >= s.virtual_address && rva < s.virtual_address + s.size_of_raw_data)
}

/// rva → file offset within a section's raw data (Go: `rvaToOff`).
fn rva_to_off(s: &Section, rva: u32) -> Result<usize, PeError> {
    if rva < s.virtual_address || rva >= s.virtual_address + s.size_of_raw_data {
        return Err(PeError::OutsideSection(rva, section_name(s)));
    }
    Ok((rva - s.virtual_address) as usize)
}

/// Zero-terminated C string within `raw` (Go: `readCString`).
fn read_cstring(raw: &[u8]) -> &str {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    std::str::from_utf8(&raw[..end]).unwrap_or("")
}

/// `IMAGE_EXPORT_DIRECTORY` (winnt.h) fields consumed by the port.
#[derive(Debug, Clone, Copy)]
struct ExportDirectory {
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

const EXPORT_DIR_SIZE: usize = 40;

fn read_export_directory(raw: &[u8], off: usize) -> Result<ExportDirectory, PeError> {
    if raw.len() < off + EXPORT_DIR_SIZE {
        return Err(PeError::Parse("truncated export directory".into()));
    }
    Ok(ExportDirectory {
        number_of_names: u32::from_le_bytes(raw[off + 24..off + 28].try_into().unwrap()),
        address_of_functions: u32::from_le_bytes(raw[off + 28..off + 32].try_into().unwrap()),
        address_of_names: u32::from_le_bytes(raw[off + 32..off + 36].try_into().unwrap()),
        address_of_name_ordinals: u32::from_le_bytes(raw[off + 36..off + 40].try_into().unwrap()),
    })
}

/// Full port of `findExportRVA` + `rvaToFileOffset` (`pe_windows.go`): locate
/// the `Bootstrap` export by name and return its RVA converted to a raw file
/// offset — the address `CreateRemoteThread` starts at.
pub fn find_export_file_offset(bytes: &[u8], name: &str) -> Result<u32, PeError> {
    let nt = nt_headers(bytes)?;
    if !is_pe32_plus(bytes, &nt) {
        return Err(PeError::NotPe32("bad magic".into()));
    }
    let (dir_rva, _dir_size) = export_directory(bytes, &nt)?;
    let secs = sections(bytes, &nt);
    let exp_sec = find_section_for_rva(&secs, dir_rva).ok_or(PeError::NotInAnySection(dir_rva))?;
    let raw = &bytes[exp_sec.pointer_to_raw_data as usize
        ..(exp_sec.pointer_to_raw_data + exp_sec.size_of_raw_data) as usize];
    let ed_off = rva_to_off(exp_sec, dir_rva)?;
    let ed = read_export_directory(raw, ed_off)?;
    if ed.number_of_names == 0 {
        return Err(PeError::Parse("PE has no named exports".into()));
    }

    let names_off = rva_to_off(exp_sec, ed.address_of_names)?;
    let funcs_off = rva_to_off(exp_sec, ed.address_of_functions)?;
    let ords_off = rva_to_off(exp_sec, ed.address_of_name_ordinals)?;

    for i in 0..ed.number_of_names as usize {
        let name_rva = u32::from_le_bytes(
            raw[names_off + i * 4..names_off + i * 4 + 4]
                .try_into()
                .unwrap(),
        );
        let Ok(name_off) = rva_to_off(exp_sec, name_rva) else {
            continue;
        };
        if read_cstring(&raw[name_off..]) != name {
            continue;
        }
        let ord = u16::from_le_bytes(
            raw[ords_off + i * 2..ords_off + i * 2 + 2]
                .try_into()
                .unwrap(),
        );
        let slot = funcs_off + ord as usize * 4;
        if slot + 4 > raw.len() {
            return Err(PeError::SlotOutOfRange(name.into()));
        }
        let rva = u32::from_le_bytes(raw[slot..slot + 4].try_into().unwrap());
        // Go: rvaToFileOffset — section by virtual size, raw offset = rva - VA + PointerToRawData.
        let sec = secs
            .iter()
            .find(|s| rva >= s.virtual_address && rva < s.virtual_address + s.size_of_raw_data);
        let Some(sec) = sec else {
            return Err(PeError::NotInAnySection(rva));
        };
        return Ok(rva - sec.virtual_address + sec.pointer_to_raw_data);
    }
    Err(PeError::ExportNotFound(name.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = include_bytes!("../payload/abe_extractor_amd64.bin");

    #[test]
    fn payload_is_amd64_with_bootstrap_export() {
        assert_eq!(PeArch::Amd64, detect_pe_arch(PAYLOAD).unwrap());
        let off = find_export_file_offset(PAYLOAD, "Bootstrap").unwrap();
        assert!(
            (off as usize) < PAYLOAD.len(),
            "Bootstrap offset {off:#x} inside payload"
        );
    }

    #[test]
    fn fake_payload_fails_cleanly() {
        let junk = [0u8; 64];
        assert!(detect_pe_arch(&junk).is_err());
        assert!(matches!(
            find_export_file_offset(&junk, "Bootstrap"),
            Err(PeError::Parse(_))
        ));
    }

    #[test]
    fn missing_export_reports_name() {
        assert!(matches!(
            find_export_file_offset(PAYLOAD, "Nope"),
            Err(PeError::ExportNotFound(n)) if n == "Nope"
        ));
    }
}
