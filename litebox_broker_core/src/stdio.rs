// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host standard streams behind the `/dev` stdio devices.

use litebox_broker_protocol::readiness::ReadinessFlags;
use thiserror::Error;

use crate::readiness::ReadinessRegistration;
use crate::transfer::{CopyFromFn, CopyToFn};
use crate::{BrokerError, Result};

/// Standard stream selected by a terminal query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioStream {
    /// Process standard input.
    Stdin,
    /// Process standard output.
    Stdout,
    /// Process standard error.
    Stderr,
}

/// Standard output stream selected by a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioOutputStream {
    /// Process standard output.
    Stdout,
    /// Process standard error.
    Stderr,
}

/// Failure reported by a trusted standard-I/O provider.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StdioProviderError {
    /// The selected standard stream is closed.
    #[error("standard stream is closed")]
    Closed,
    /// The host standard-I/O operation failed internally.
    #[error("trusted standard-I/O provider failed")]
    Failed,
    /// The operation cannot make progress until the stream becomes ready.
    #[error("standard stream is not ready")]
    WouldBlock,
    /// This broker deployment does not provide standard I/O.
    #[error("standard I/O is unsupported")]
    Unsupported,
    /// The broker failed the operation itself, such as when the `CopyFromFn` or
    /// `CopyToFn` it lent bytes or room to failed (see [`crate::transfer`]) or it
    /// ran out of memory.
    #[error(transparent)]
    Broker(#[from] BrokerError),
}

/// Trusted provider of standard-I/O operations.
///
/// Operations never block. One that cannot make progress returns
/// [`StdioProviderError::WouldBlock`], and the provider later publishes the
/// stream's readiness to its watchers. Providers whose operations always make
/// progress can keep the default readiness methods.
pub trait StdioProvider: Send + Sync {
    /// Shared endpoint behind a terminal stream, if terminal control is supported.
    fn terminal(
        &self,
        _stream: StdioStream,
    ) -> Option<alloc::sync::Arc<dyn crate::terminal::TerminalEndpoint>> {
        None
    }

    /// Reads up to `length` available bytes from standard input, lending
    /// them to `copy_from` to copy out (see [`crate::transfer`]), and returns how
    /// many it read: exactly those it lent, so zero at end-of-file.
    fn read(
        &self,
        length: usize,
        copy_from: &mut CopyFromFn<'_>,
    ) -> core::result::Result<usize, StdioProviderError>;

    /// Writes up to `length` bytes to the selected standard output stream,
    /// lending room for up to `length` bytes to `copy_to` to copy them in (see
    /// [`crate::transfer`]), and returns how many it wrote, which may be
    /// fewer than it lent room for.
    fn write(
        &self,
        stream: StdioOutputStream,
        length: usize,
        copy_to: &mut CopyToFn<'_>,
    ) -> core::result::Result<usize, StdioProviderError>;

    /// Determines whether the selected standard stream is connected to a
    /// terminal.
    fn is_terminal(&self, stream: StdioStream) -> bool;

    /// Returns the selected stream's readiness: [`ReadinessFlags::READ`] once
    /// a standard-input read would not return
    /// [`StdioProviderError::WouldBlock`], or [`ReadinessFlags::WRITE`] once
    /// such a write would not.
    fn readiness(&self, stream: StdioStream) -> ReadinessFlags {
        match stream {
            StdioStream::Stdin => ReadinessFlags::READ,
            StdioStream::Stdout | StdioStream::Stderr => ReadinessFlags::WRITE,
        }
    }

    /// Publishes the selected stream's later readiness changes through
    /// `registration` until every clone of it drops.
    fn watch(&self, _stream: StdioStream, _registration: &ReadinessRegistration) -> Result<()> {
        Ok(())
    }
}

/// Standard-I/O provider for deployments that do not expose standard streams.
pub struct UnsupportedStdioProvider;

impl StdioProvider for UnsupportedStdioProvider {
    fn read(
        &self,
        _length: usize,
        _copy_from: &mut CopyFromFn<'_>,
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn write(
        &self,
        _stream: StdioOutputStream,
        _length: usize,
        _copy_to: &mut CopyToFn<'_>,
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn is_terminal(&self, _stream: StdioStream) -> bool {
        false
    }
}
