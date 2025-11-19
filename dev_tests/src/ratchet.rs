use anyhow::{Result, bail};
use fs::File;
use fs_err as fs;
use std::io::BufRead as _;
use std::io::BufReader;

#[test]
fn ratchet_transmutes() -> Result<()> {
    ratchet(
        &[
            ("dev_tests/", 2),
            ("litebox/", 1),
            ("litebox_shim_linux/", 1),
            ("litebox_platform_linux_userland/", 2),
        ],
        |file| {
            Ok(file
                .lines()
                .filter(|line| line.as_ref().unwrap().contains("transmute"))
                .count())
        },
    )
}

#[test]
fn ratchet_globals() -> Result<()> {
    ratchet(
        &[
            ("litebox/", 7),
            ("litebox_platform_linux_kernel/", 5),
            ("litebox_platform_linux_userland/", 6),
            ("litebox_platform_lvbs/", 19),
            ("litebox_platform_multiplex/", 1),
            ("litebox_platform_windows_userland/", 8),
            ("litebox_runner_linux_userland/", 1),
            ("litebox_shim_linux/", 10),
            ("litebox_shim_optee/", 6),
        ],
        |file| {
            Ok(file
                .lines()
                .filter(|line| {
                    // Heuristic: detect "static" at the start of a line, excluding whitespace. This should
                    // prevent us from accidentally including code that contains the word in a comment, or
                    // is referring to the `'static` lifetime.
                    let trimmed = line.as_ref().unwrap().trim_start();
                    trimmed.starts_with("static ")
                        || trimmed.split_once(' ').is_some_and(|(a, b)| {
                            // Account for `pub`, `pub(crate)`, ...
                            a.starts_with("pub") && b.starts_with("static ")
                        })
                })
                .count())
        },
    )
}

#[test]
fn ratchet_maybe_uninit() -> Result<()> {
    ratchet(
        &[
            ("dev_tests/", 1),
            ("litebox/", 1),
            ("litebox_platform_linux_kernel/", 1),
            ("litebox_platform_linux_userland/", 3),
            ("litebox_platform_lvbs/", 6),
            ("litebox_shim_linux/", 5),
        ],
        |file| {
            Ok(file
                .lines()
                .filter(|line| line.as_ref().unwrap().contains("MaybeUninit"))
                .count())
        },
    )
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Convenience function to set up a ratchet test, see below for examples.
///
/// `expected` is a list of (file name prefix, expected count) pairs.
#[track_caller]
fn ratchet(expected: &[(&str, usize)], f: impl Fn(BufReader<File>) -> Result<usize>) -> Result<()> {
    let all_rs_files = crate::all_rs_files()?.collect::<Vec<std::path::PathBuf>>();
    let mut errors = Vec::new();

    for (i, (prefix_i, _)) in expected.iter().enumerate() {
        if !prefix_i.ends_with('/') {
            errors.push(format!(
                "The prefix '{prefix_i}' should end with a '/'. Please make sure all prefixes end with a '/' to avoid accidental overlaps."
            ));
        }
        for (j, (prefix_j, _)) in expected.iter().enumerate() {
            if i != j && prefix_i.starts_with(prefix_j) {
                errors.push(format!(
                    "The prefix '{prefix_j}' is a prefix of '{prefix_i}'. Please make sure the prefixes are unique and non-overlapping."
                ));
            }
        }
        for (prefix, _) in expected {
            if !all_rs_files
                .iter()
                .any(|p| p.to_string_lossy().starts_with(prefix))
            {
                errors.push(format!(
                    "The prefix '{prefix}' does not match any file. Please make sure all prefixes match at least one file."
                ));
            }
        }
    }
    for p in &all_rs_files {
        let file_name = p.to_string_lossy();
        if !expected
            .iter()
            .any(|(prefix, _)| file_name.starts_with(prefix))
            && f(BufReader::new(File::open(p).unwrap()))? > 0
        {
            errors.push(format!(
                "The file '{file_name}'  that with a non-zero ratchet value is not covered by any prefix.\nPlease make sure all files are covered by some prefix."
            ));
        }
    }

    for (prefix, expected_count) in expected {
        let count = all_rs_files
            .iter()
            .filter(|p| p.to_string_lossy().starts_with(prefix))
            .map(|p| BufReader::new(File::open(p).unwrap()))
            .map(&f)
            .sum::<Result<usize>>()?;

        match count.cmp(expected_count) {
            std::cmp::Ordering::Less => {
                errors.push(format!(
                    "Good news!! Ratched count for paths starting with '{prefix}' decreased! :)\n\nPlease reduce the expected count in the ratchet to {count}"
                ));
            }
            std::cmp::Ordering::Equal => {
                if count == 0 {
                    errors.push(format!(
                        "The prefix {prefix} should be removed from the list since the ratchet has succesfully worked! :)"
                    ));
                }
            }
            std::cmp::Ordering::Greater => {
                errors.push(format!(
                    "Ratcheted count for paths starting with '{prefix}' increased by {} :(\n\nYou might be using a feature that is ratcheted (i.e., we are aiming to reduce usage of in the codebase).\nTips:\n\tTry if you can work without using this feature.\n\tIf you think the heuristic detection is incorrect, you might need to update the ratchet's heuristic.\n\tIf the heuristic is correct, you might need to update the count.",
                    count - expected_count
                ));
            }
        }
    }

    if !errors.is_empty() {
        bail!(
            "Ratchet test failed in {}:\n{}",
            std::panic::Location::caller(),
            errors.join("\n\n")
        );
    }

    Ok(())
}
