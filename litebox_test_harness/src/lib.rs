// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Library interface for the litebox test harness.
//!
//! Re-exports modules shared between the binary (`main.rs`) and the
//! integration test (`tests/integration.rs`).

pub mod coordinator;
pub mod protocol;
pub mod test_registry;

/// Find the non-PIE test harness binary.
///
/// In Docker: bind-mounted at `/opt/nonpie/litebox_test_harness`.
/// Locally: sibling of current exe with `_nonpie` or `-nonpie` suffix.
pub fn find_nonpie_binary() -> Option<String> {
    let candidates: &[&str] = &[
        "/opt/nonpie/litebox_test_harness",
        "/litebox-test-harness-nonpie",
    ];
    for &path in candidates {
        if std::path::Path::new(path).exists() {
            eprintln!("[harness] nonpie binary: {path}");
            return Some(path.to_string());
        }
    }
    // Fallback: sibling of current exe.
    if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent().unwrap_or(std::path::Path::new("."));
        let stem = exe
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        for suffix in ["_nonpie", "-nonpie"] {
            let candidate = dir.join(format!("{stem}{suffix}"));
            if candidate.exists() {
                let path = candidate.to_string_lossy().to_string();
                eprintln!("[harness] nonpie binary: {path}");
                return Some(path.clone());
            }
        }
    }
    None
}

/// Like [`find_nonpie_binary`] but panics if the binary is missing.
///
/// Tests that exercise non-PIE code paths require the non-PIE binary
/// as a hard dependency; rather than degrade to a "FAIL: binary not
/// found" outcome, panic with a clear message so the harness logs
/// surface the missing dependency immediately.
///
/// Use [`find_nonpie_binary`] only in non-test infrastructure
/// (e.g., `coordinator::TestRunner::spawn_tree`) that legitimately
/// wants to skip work when the binary isn't mounted.
#[must_use]
pub fn nonpie_binary() -> String {
    find_nonpie_binary().unwrap_or_else(|| {
        panic!(
            "non-PIE test harness binary not found. Required at \
             /opt/nonpie/litebox_test_harness (Docker) or as \
             *_nonpie / *-nonpie sibling of current exe."
        )
    })
}
