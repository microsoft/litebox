// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host standard streams behind the `/dev` stdio devices.

use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_platform::buffer::{Fault, ReadBuffer, WriteBuffer};
use thiserror::Error;

use crate::readiness::ReadinessRegistration;
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
    /// The broker failed the operation itself, such as when copying to or
    /// from the caller's buffer faulted or it ran out of memory.
    #[error(transparent)]
    Broker(#[from] BrokerError),
}

impl From<Fault> for StdioProviderError {
    fn from(fault: Fault) -> Self {
        Self::Broker(fault.into())
    }
}

/// Trusted provider of standard-I/O operations.
///
/// Operations never block. One that cannot make progress returns
/// [`StdioProviderError::WouldBlock`], and the provider later publishes the
/// stream's readiness to its watchers. Providers whose operations always make
/// progress can keep the default readiness methods.
///
/// A provider gives the guest at most one terminal, which the broker usually
/// makes the first root process's controlling terminal (see
/// [`crate::BrokerCore::with_terminal`]). Reads, writes, and readiness of each
/// standard stream that refers to it go through the terminal instead of this
/// provider. Without a
/// terminal, no stream is a terminal. Neither the terminal nor which streams
/// refer to it changes over the provider's lifetime.
pub trait StdioProvider: Send + Sync {
    /// The guest's terminal, if any.
    fn terminal(&self) -> Option<alloc::sync::Arc<dyn crate::terminal::TerminalEndpoint>> {
        None
    }

    /// Whether `stream` refers to [`terminal`](Self::terminal), which must
    /// then exist.
    fn is_terminal(&self, _stream: StdioStream) -> bool {
        false
    }

    /// Reads available bytes from standard input into the start of `output`
    /// (see [`crate::transfer`]), returning zero at end-of-file.
    fn read(&self, output: &mut dyn ReadBuffer) -> core::result::Result<usize, StdioProviderError>;

    /// Writes bytes from the start of `input` to the selected standard output
    /// stream (see [`crate::transfer`]).
    fn write(
        &self,
        stream: StdioOutputStream,
        input: &dyn WriteBuffer,
    ) -> core::result::Result<usize, StdioProviderError>;

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
        _output: &mut dyn ReadBuffer,
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn write(
        &self,
        _stream: StdioOutputStream,
        _input: &dyn WriteBuffer,
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }
}
