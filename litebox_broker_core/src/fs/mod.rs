// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File-system related functionality
//!
//! A file-system consists of a [`Resolver`](resolver::Resolver) that works alongside one or more
//! [`Backend`](backend::Backend)s. Such backends can be composed together: mounted at distinct paths
//! via the [`Composer`](composer::Composer), or stacked as a writable upper over immutable lowers
//! via the [`Overlay`](overlay::Overlay).

pub mod backend;
pub mod composer;
pub mod devices;
pub mod errors;
pub mod in_mem;
#[doc(hidden)]
pub mod inode_allocator;
pub mod nine_p;
pub mod overlay;
pub mod resolver;
mod service;
pub mod tar_ro;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub(crate) use service::File;
pub use service::{
    FileResult, FileService, UnsupportedFileService, chmod, chown, handle_status, mkdir, open,
    path_status, read, read_directory, rmdir, seek, truncate, unlink, write,
};

/// The size reported as the size of a directory.
const DEFAULT_DIRECTORY_SIZE: u64 = 4096;
