use anyhow::{Result, bail};
use fs::File;
use fs_err as fs;
use std::io::BufRead as _;
use std::io::BufReader;

// Convenience function to set up a ratchet test, see below for examples.
fn ratchet(expected: usize, f: impl Fn(BufReader<File>) -> Result<usize>) -> Result<()> {
    let count = crate::all_rs_files()?
        .map(|p| BufReader::new(File::open(&p).unwrap()))
        .map(f)
        .sum::<Result<usize>>()?;

    match count.cmp(&expected) {
        std::cmp::Ordering::Less => {
            bail!(
                "Good news!! Ratched count decreased! :)\n\nPlease reduce the expected count in the ratchet to {count}"
            )
        }
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Greater => {
            bail!(
                "Ratcheted count increased by {} :(\n\nYou might be using a feature that is ratcheted.\nTips:\n\tTry if you can work without using this feature.\n\tIf you think the heuristic detection is incorrect, you might need to update the ratchet's heuristic.\n\tIf the heuristic is correct, you might need to update the count.",
                count - expected
            )
        }
    }
}

#[test]
fn ratchet_transmutes() -> Result<()> {
    ratchet(7, |file| {
        Ok(file
            .lines()
            .filter(|line| line.as_ref().unwrap().contains("transmute"))
            .count())
    })
}

#[test]
fn ratchet_globals() -> Result<()> {
    ratchet(58, |file| {
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
    })
}
