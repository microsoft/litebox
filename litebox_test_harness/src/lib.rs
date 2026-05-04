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
                return Some(path.to_string());
            }
        }
    }
    None
}
