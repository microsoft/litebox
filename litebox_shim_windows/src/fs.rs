// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-shim file access with registry namespace isolation.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox::LiteBox;
#[cfg(test)]
use litebox::fs::errors::ChmodError;
use litebox::fs::errors::{
    FileStatusError, MkdirError, OpenError, PathError, ReadDirError, RmdirError, UnlinkError,
};
use litebox::fs::{Context, File};
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileMode, FileOpenFlags, FileStatus,
};

/// Broker filesystem subtree reserved for registry storage.
pub(crate) const REGISTRY_ROOT: &str = "/registry";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Namespace {
    Regular,
    Registry,
}

impl Namespace {
    fn resolve_path(self, context: &Context, path: &str) -> Result<String, PathError> {
        let path = context.resolve(path).to_string();
        match (self, is_registry_path(&path)) {
            (Self::Regular, false) | (Self::Registry, true) => Ok(path),
            (Self::Regular, true) => Err(PathError::MissingComponent),
            (Self::Registry, false) => Err(PathError::InvalidPathname),
        }
    }

    fn hides_registry_entry(self, context: &Context, directory_path: &str) -> bool {
        self == Self::Regular && context.resolve(directory_path).to_string() == "/"
    }
}

/// File facade that confines operations to one Windows shim namespace.
pub(crate) struct Fs<Platform: crate::ShimPlatform> {
    litebox: Arc<LiteBox<Platform>>,
    namespace: Namespace,
}

impl<Platform: crate::ShimPlatform> Fs<Platform> {
    pub(crate) fn regular(litebox: Arc<LiteBox<Platform>>) -> Self {
        Self {
            litebox,
            namespace: Namespace::Regular,
        }
    }

    pub(crate) fn registry(litebox: Arc<LiteBox<Platform>>) -> Self {
        Self {
            litebox,
            namespace: Namespace::Registry,
        }
    }

    fn resolve_path(&self, context: &Context, path: &str) -> Result<String, PathError> {
        self.namespace.resolve_path(context, path)
    }

    pub(crate) fn open_file(
        &self,
        context: &Context,
        path: &str,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
    ) -> Result<File<Platform>, OpenError> {
        let path = self.resolve_path(context, path)?;
        self.litebox
            .open_file(context, path.as_str(), access, flags, mode)
    }

    pub(crate) fn read_file_directory(
        &self,
        context: &Context,
        directory_path: &str,
        file: &File<Platform>,
    ) -> Result<Vec<FileDirectoryEntry>, ReadDirError> {
        let mut entries = file.read_directory()?;
        if self.namespace.hides_registry_entry(context, directory_path) {
            entries.retain(|entry| {
                !entry
                    .name
                    .eq_ignore_ascii_case(REGISTRY_ROOT.trim_start_matches('/'))
            });
        }
        Ok(entries)
    }

    pub(crate) fn path_file_status(
        &self,
        context: &Context,
        path: &str,
    ) -> Result<FileStatus, FileStatusError> {
        let path = self.resolve_path(context, path)?;
        self.litebox.path_file_status(context, path.as_str(), true)
    }

    #[cfg(test)]
    pub(crate) fn chmod_file(
        &self,
        context: &Context,
        path: &str,
        mode: FileMode,
    ) -> Result<(), ChmodError> {
        let path = self.resolve_path(context, path)?;
        self.litebox.chmod_file(context, path.as_str(), mode)
    }

    pub(crate) fn unlink_file(&self, context: &Context, path: &str) -> Result<(), UnlinkError> {
        let path = self.resolve_path(context, path)?;
        self.litebox.unlink_file(context, path.as_str())
    }

    pub(crate) fn mkdir_file(
        &self,
        context: &Context,
        path: &str,
        mode: FileMode,
    ) -> Result<(), MkdirError> {
        let path = self.resolve_path(context, path)?;
        self.litebox.mkdir_file(context, path.as_str(), mode)
    }

    pub(crate) fn rmdir_file(&self, context: &Context, path: &str) -> Result<(), RmdirError> {
        let path = self.resolve_path(context, path)?;
        self.litebox.rmdir_file(context, path.as_str())
    }
}

fn is_registry_path(path: &str) -> bool {
    path.split('/')
        .find(|component| !component.is_empty())
        .is_some_and(|component| {
            component.eq_ignore_ascii_case(REGISTRY_ROOT.trim_start_matches('/'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_path_resolution_is_symmetric() {
        let context = Context::new();

        assert_eq!(
            Namespace::Regular
                .resolve_path(&context, "/tmp/../file")
                .unwrap(),
            "/file"
        );
        assert!(matches!(
            Namespace::Regular.resolve_path(&context, "/tmp/../Registry/machine"),
            Err(PathError::MissingComponent)
        ));
        assert_eq!(
            Namespace::Registry
                .resolve_path(&context, "/tmp/../Registry/machine")
                .unwrap(),
            "/Registry/machine"
        );
        assert!(matches!(
            Namespace::Registry.resolve_path(&context, "/tmp"),
            Err(PathError::InvalidPathname)
        ));
    }

    #[test]
    fn regular_namespace_hides_registry_for_root_aliases() {
        let context = Context::new();

        for path in ["/", "/.", "//", "/tmp/..", "."] {
            assert!(Namespace::Regular.hides_registry_entry(&context, path));
        }
        assert!(!Namespace::Regular.hides_registry_entry(&context, "/tmp"));
        assert!(!Namespace::Registry.hides_registry_entry(&context, "/registry"));
    }
}
