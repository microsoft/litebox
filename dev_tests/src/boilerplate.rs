// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Result, bail};
use fs::File;
use fs_err as fs;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsString;
use std::io::BufReader;
use std::io::Read as _;

#[test]
#[expect(clippy::needless_continue, reason = "consistency")]
fn copyright_header() -> Result<()> {
    let all_source_files = crate::all_source_files()?;
    let mut errors: Vec<String> = Vec::new();

    let required_headers: HashMap<&str, &str> = HEADERS_REQUIRED_PREFIX.iter().copied().collect();
    let skipped_files: HashSet<OsString> = SKIP_FILES.iter().map(|&s| OsString::from(s)).collect();

    let auto_include_headers = std::env::var("AUTO_INCLUDE_HEADERS").is_ok();

    for file in all_source_files {
        if skipped_files.contains(file.as_os_str()) {
            continue;
        }
        let Some(ext) = file.extension() else {
            errors.push(format!("extension-less file {file:?}"));
            continue;
        };
        let ext = ext.to_str().unwrap();
        let Some(expected) = required_headers.get(ext) else {
            errors.push(format!(
                "unknown header requirements for .{ext} files (e.g., {file:?})"
            ));
            continue;
        };
        let mut data = BufReader::new(File::open(&file).unwrap());
        let mut buf = vec![0u8; expected.len()];
        let len = data.read(&mut buf).unwrap();
        if len != expected.len() || expected.as_bytes() != buf {
            if auto_include_headers {
                errors.push(format!("auto-including header into {file:?}"));
                let data = fs::read_to_string(&file).unwrap();
                if data.contains(/*C*/ "opyright") || data.contains(/*L*/ "icensed") {
                    errors.push(format!("!!! Refusing to auto-include header for {file:?} since it already mentions licensing"));
                    continue;
                }
                let data = String::from(*expected) + &data;
                fs::write(&file, &data).unwrap();
            } else {
                errors.push(format!(
                    "expected prefix {expected:?} missing from {file:?}"
                ));
            }
            continue;
        }
        // Successfully matched on `file`
    }

    if !errors.is_empty() {
        let help = "Help: re-run this test with AUTO_INCLUDE_HEADERS env variable to automatically include headers wherever possible.";
        bail!(
            "Copyright headers test failed:\n\n{}\n\n{}",
            errors.join("\n\n"),
            help
        );
    }

    Ok(())
}

// Each particular file type has a common prefix, these prefixes are defined here. Please do NOT
// modify this unless you have a very compelling reason to.
const HEADERS_REQUIRED_PREFIX: &[(&str, &str)] = &[
    (
        "rs",
        "// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\n",
    ),
    (
        "h",
        "// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\n",
    ),
    (
        "c",
        "// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\n",
    ),
    (
        "sh",
        "#! /bin/bash\n\n# Copyright (c) Microsoft Corporation.\n# Licensed under the MIT license.\n\n",
    ),
    (
        "S",
        "/* Copyright (c) Microsoft Corporation.\n   Licensed under the MIT license. */\n\n",
    ),
    ("2", ""),
    ("6", ""),
    ("elf", ""),
    ("hooked", ""),
    ("json", ""),
    ("ld", ""),
    ("lock", ""),
    ("md", ""),
    ("png", ""),
    ("snap", ""),
    ("so", ""),
    ("svg", ""),
    ("tar", ""),
    ("toml", ""),
    ("txt", ""),
];

// Skipped files have their own custom requirements on why they are not checked via the regular
// tests. Please do NOT modify this unless you have a very compelling reason to.
const SKIP_FILES: &[&str] = &[
    "LICENSE",
    "litebox/src/sync/mutex.rs",
    "litebox/src/sync/rwlock.rs",
    "litebox_rtld_audit/Makefile",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_exec_nolibc",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_thread",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_thread_static",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_world_dyn",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_world_static",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/thread_static",
    "litebox_syscall_rewriter/tests/hello",
    "litebox_syscall_rewriter/tests/hello-32",
];
