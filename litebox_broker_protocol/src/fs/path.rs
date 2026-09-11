// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::vec::Vec;

/// An absolute, lexically normalized fs path.
///
/// Normalization removes redundant separators and `.` components, and processes `..` without
/// going above the root. It does not perform filesystem lookup, resolve symbolic links, or
/// establish that the path exists or is accessible.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedPath {
    components: Vec<String>,
}

impl ResolvedPath {
    /// The root path.
    #[must_use]
    pub const fn root() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Normalize `path`, using this path as the base when `path` is relative.
    #[must_use]
    pub fn resolve(&self, path: &str) -> Self {
        let mut components = if path.starts_with('/') {
            Vec::new()
        } else {
            self.components.clone()
        };
        for component in path.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    let _ = components.pop();
                }
                _ => components.push(component.into()),
            }
        }
        Self { components }
    }

    /// Normalized components, excluding the root separator.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// The parent components and final name, or `None` for the root.
    #[must_use]
    pub fn parent_and_name(&self) -> Option<(&[String], &str)> {
        let (name, parent) = self.components.split_last()?;
        Some((parent, name.as_str()))
    }
}

impl core::fmt::Display for ResolvedPath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for component in &self.components {
            write!(formatter, "/{component}")?;
        }
        if self.components.is_empty() {
            formatter.write_str("/")?;
        }
        Ok(())
    }
}
