// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Enforcement: the harness has **no expected-failure mechanism**.
//!
//! `CLAUDE.md` is explicit (in five separate sections) that test
//! outcomes are strictly `pass` or `FAIL`. A litebox test that does
//! not work fails for real, every run, until the product code is
//! fixed in the shim. There is no `xfail`, no `XPASS`, no allowlist,
//! no dynamic skip path, no `expected_fail_on_litebox()` annotation.
//!
//! This test scans the harness source for any reintroduction of the
//! mechanism and fails the build if it finds one. It exists because a
//! subagent (or human) editing without reading CLAUDE.md end-to-end
//! could otherwise reintroduce the pattern and have it merged. The
//! review burden is high — explicit machinery is cheap.
//!
//! If you genuinely need to mark a tuple as known-failing, **don't**.
//! Fix the product code instead. That's the entire contract.

use std::fs;
use std::path::{Path, PathBuf};

/// Tokens whose appearance in harness code indicates a reintroduction
/// of the forbidden mechanism. The comparison is case-insensitive so
/// `XFAIL`, `xfail`, `Xfail` all trip.
const FORBIDDEN_TOKENS: &[&str] = &[
    "expected_fail",
    "expectedfail",
    "xfail",
    "xpass",
    "known_fail",
    "knownfail",
];

/// Files that are allowed to mention the forbidden tokens because
/// they describe the prohibition itself.
fn is_allowlisted(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.ends_with("tests/no_expected_fail.rs") || s.ends_with("/CLAUDE.md")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs" || e == "md") {
            out.push(path);
        }
    }
}

#[test]
fn harness_must_not_introduce_expected_fail_mechanism() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&crate_root.join("src"), &mut files);
    walk(&crate_root.join("tests"), &mut files);

    let mut violations: Vec<String> = Vec::new();
    for file in &files {
        if is_allowlisted(file) {
            continue;
        }
        let Ok(contents) = fs::read_to_string(file) else {
            continue;
        };
        let lower = contents.to_lowercase();
        for tok in FORBIDDEN_TOKENS {
            if lower.contains(tok) {
                for (lineno, line) in contents.lines().enumerate() {
                    if line.to_lowercase().contains(tok) {
                        violations.push(format!(
                            "{}:{}: forbidden token '{}' — {}",
                            file.display(),
                            lineno + 1,
                            tok,
                            line.trim(),
                        ));
                    }
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "litebox_test_harness must not introduce any expected-fail / XFAIL / XPASS \
         mechanism. CLAUDE.md is explicit (lines 659-664, 720-723, 731-734, \
         868-870, 1068-1072 of the current file): outcomes are strictly `pass` \
         or `FAIL`, and a litebox failure is a real product bug to be fixed in \
         the shim, not annotated away.\n\nViolations:\n  {}",
        violations.join("\n  ")
    );
}
