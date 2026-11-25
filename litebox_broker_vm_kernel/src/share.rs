// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host directories ([`Share`]) over FUSE, e.g., virtiofsd behind a
//! virtio-fs device, read-only for now, like `litebox_broker_userland`'s
//! `--mount-ro HOST:GUEST`: only [`ReadOnly`] enforces that, as the backend
//! would write. Symlink targets are passed through unchanged: an absolute one
//! resolves from the guest's root, not from the share's.

use alloc::boxed::Box;
use alloc::string::String;
use litebox_broker_core::fs::fuse::transport::Transport;
use litebox_broker_core::fs::fuse::{self, Fuse};
use litebox_broker_core::fs::inode_allocator::InodeAllocator;
use litebox_broker_core::fs::read_only::ReadOnly;
use litebox_platform_vm_kernel::VmKernel;

/// A host directory mounted, read-only, at `path`.
pub struct Share {
    /// Must be absolute and normalized, and unlike any other mount's path
    /// (e.g., `/dev`, or `/` with a root tar), or building the broker's files
    /// panics. Should also be neither `/` nor in `/dev`, which the broker
    /// does not check: such a share would be the root, or sit among the
    /// devices.
    pub path: String,
    /// Reaches the FUSE server.
    pub transport: Box<dyn Transport>,
}

/// A [`Share`]'s directory, as `litebox_broker_userland`'s `--mount-ro` is a
/// host directory: the FUSE backend in a [`ReadOnly`] view, which refuses
/// what would change it.
pub(crate) type ShareFs = ReadOnly<Fuse<VmKernel, Box<dyn Transport>>>;

/// Connects to the FUSE server at the other end of `transport`
/// (`FUSE_INIT`).
///
/// # Errors
///
/// The server could not be reached, or refused the protocol.
pub(crate) fn connect(
    transport: Box<dyn Transport>,
    allocator: InodeAllocator,
) -> Result<ShareFs, fuse::Error> {
    Ok(ReadOnly::new(Fuse::new(transport, allocator)?))
}
