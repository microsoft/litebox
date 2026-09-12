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
    CloseError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError, ReadError,
    RmdirError, SeekError, UnlinkError, WriteError,
};
use litebox::fs::{Context, FileFd};
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileMode, FileOpenFlags, FileSeekWhence, FileStatus,
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
        let path = context.resolve(path)?.to_string();
        match (self, is_registry_path(&path)) {
            (Self::Regular, false) | (Self::Registry, true) => Ok(path),
            (Self::Regular, true) => Err(PathError::MissingComponent),
            (Self::Registry, false) => Err(PathError::InvalidPathname),
        }
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
    ) -> Result<FileFd, OpenError> {
        let path = self.resolve_path(context, path)?;
        self.litebox
            .open_file(context, path.as_str(), access, flags, mode)
    }

    pub(crate) fn close_file(&self, fd: &FileFd) -> Result<(), CloseError> {
        self.litebox.close_file(fd)
    }

    pub(crate) fn read_file(
        &self,
        fd: &FileFd,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        self.litebox.read_file(fd, buf, offset)
    }

    pub(crate) fn write_file(
        &self,
        fd: &FileFd,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        self.litebox.write_file(fd, buf, offset)
    }

    pub(crate) fn seek_file(
        &self,
        fd: &FileFd,
        offset: isize,
        whence: FileSeekWhence,
    ) -> Result<usize, SeekError> {
        self.litebox.seek_file(fd, offset, whence)
    }

    pub(crate) fn read_file_directory(
        &self,
        directory_path: &str,
        fd: &FileFd,
    ) -> Result<Vec<FileDirectoryEntry>, ReadDirError> {
        let mut entries = self.litebox.read_file_directory(fd)?;
        if self.namespace == Namespace::Regular && directory_path == "/" {
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
        self.litebox.path_file_status(context, path.as_str())
    }

    pub(crate) fn file_status(&self, fd: &FileFd) -> Result<FileStatus, FileStatusError> {
        self.litebox.file_status(fd)
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
}
