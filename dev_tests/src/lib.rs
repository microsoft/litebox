//! This crate only makes sense in testing mode
#![cfg(test)]

use anyhow::{Result, anyhow};
use std::path::PathBuf;

mod ratchet;

/// Finds and switches to the project root directory.
///
/// This is to make the rest of the reasoning easier.
pub(crate) fn project_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir().ok().unwrap();
    loop {
        if dir.join("target").is_dir() {
            std::env::set_current_dir(&dir)?;
            eprintln!(
                "Changed working directory to project root: {}",
                dir.display()
            );
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(anyhow!("Could not find project root"));
        }
    }
}

/// Get all `.rs` source files
///
/// Skips files in `target/` directory since we might have build artifacts there.
pub(crate) fn all_rs_files() -> Result<impl Iterator<Item = PathBuf>> {
    let _ = project_root()?;
    glob::glob("**/*.rs").map_err(|e| anyhow!(e)).map(|paths| {
        paths
            .filter_map(Result::ok)
            .filter(|p| !p.components().any(|c| c.as_os_str() == "target"))
    })
}
