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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString as _;

    #[test]
    fn paths_are_absolute_and_lexically_normalized() {
        let base = ResolvedPath::root().resolve("/work/dir");
        for (path, expected) in [
            ("", "/work/dir"),
            (".", "/work/dir"),
            ("./file", "/work/dir/file"),
            ("../file", "/work/file"),
            ("sub/../../file", "/work/file"),
            ("../../../../file", "/file"),
            ("/etc//passwd/", "/etc/passwd"),
            ("/.././", "/"),
            ("////", "/"),
        ] {
            let resolved = base.resolve(path);
            assert_eq!(resolved.to_string(), expected);
            assert_eq!(base.resolve(&resolved.to_string()), resolved);
        }
        assert_eq!(base.to_string(), "/work/dir");
        assert_eq!(ResolvedPath::default(), ResolvedPath::root());
        assert_eq!(ResolvedPath::root().to_string(), "/");
    }

    #[test]
    fn components_and_parent_preserve_normalized_names() {
        let path = ResolvedPath::root().resolve("/a//b/../c");
        assert_eq!(path.components(), ["a", "c"]);
        let (parent, name) = path.parent_and_name().unwrap();
        assert_eq!(parent, ["a"]);
        assert_eq!(name, "c");

        let path = ResolvedPath::root().resolve("/file");
        let (parent, name) = path.parent_and_name().unwrap();
        assert!(parent.is_empty());
        assert_eq!(name, "file");
        assert_eq!(ResolvedPath::root().parent_and_name(), None);
    }
}
