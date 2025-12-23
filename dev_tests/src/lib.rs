// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This crate only makes sense in testing mode
#![cfg(test)]

use anyhow::{Result, anyhow};
use std::path::PathBuf;

mod boilerplate;
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

/// Get all source files by taking all files that are not ignored by `.gitignore`.
pub(crate) fn all_source_files() -> Result<Vec<PathBuf>> {
    let root = project_root()?;
    Ok(ignore::WalkBuilder::new(&root)
        // all normal `.gitignore` / `.git/info/exclude` are already handled, but we need to make it
        // explicitly aware of Jujutsu local-only excludes (which are equiv to git's excludes, just
        // in a deeper directory).
        .add_custom_ignore_filename(".jj/repo/store/git/info/exclude")
        .build()
        .collect::<Result<Vec<_>, ignore::Error>>()?
        .into_iter()
        .map(|ent| ent.path().strip_prefix(&root).unwrap().to_owned())
        .filter(|p| p.is_file())
        .collect())
}

/// Get all `.rs` source files
///
/// Skips files in `target/` directory since we might have build artifacts there.
// TODO(jayb): Clear away `glob` and switch entirely to `ignore` instead.
pub(crate) fn all_rs_files() -> Result<impl Iterator<Item = PathBuf>> {
    let _ = project_root()?;
    glob::glob("**/*.rs").map_err(|e| anyhow!(e)).map(|paths| {
        paths
            .filter_map(Result::ok)
            .filter(|p| !p.components().any(|c| c.as_os_str() == "target"))
    })
}
