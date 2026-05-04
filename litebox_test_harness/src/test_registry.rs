// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test registry utilities.

/// Check whether a (suite, group) pair matches a --filter= argument.
///
/// - None -> run everything
/// - Some("fork") -> run all groups in fork suite
/// - Some("fork,shell") -> run all groups in fork and shell suites
/// - Some("fork.exit_data_integrity") -> run only that group
pub fn matches_filter(filter: Option<&str>, suite: &str, group: &str) -> bool {
    match filter {
        None => true,
        Some(f) => f.split(',').any(|part| {
            if let Some((fs, fg)) = part.split_once('.') {
                suite == fs && group == fg
            } else {
                suite == part
            }
        }),
    }
}
