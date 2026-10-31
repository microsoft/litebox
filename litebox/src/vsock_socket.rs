// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned vsock stream sockets, which reach the VM's host.
//!
//! The broker owns each socket's state and readiness, so every reference,
//! including an inherited one, shares them.
//!
//! Creating fails with [`VsockSocketError::Unsupported`] without a broker
//! vsock provider and with [`VsockSocketError::PermissionDenied`] if the
//! policy denies vsock. A denied connect or listen fails with
//! [`SocketError::PolicyDenied`].

use alloc::sync::{Arc, Weak};
use litebox_broker_protocol::{
    ObjectHandle,
    error::ErrorCode,
    fs::{FileOpenFlags, FileStatusFlags},
    socket::{
        MAX_SOCKET_TRANSFER_SIZE, ReceiveSocketResponse, ShutdownMode, SocketConnectionStatus,
        SocketError, SocketOutcome,
    },
    vsock_socket::{MAX_VSOCK_LISTEN_BACKLOG, VsockAddress},
};
use litebox_platform::time::TimeProvider;

use crate::{
    LiteBox,
    broker::{
        BrokerControl, BrokerPollableRegistry,
        error::{BrokerControlError, BrokerObjectError},
        readiness_events,
    },
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::{WaitContext, WaitError},
    },
    fs::errors::StatusFlagsError,
    process::ProcessError,
    sync::RawSyncPrimitivesProvider,
};
use litebox_platform::buffer::{Buffer, ReadBuffer, WriteBuffer};

use errors::VsockSocketError;

/// A reference to a broker-owned vsock stream socket, which closes its
/// handle when dropped.
///
/// Known gap: it has no socket options, so no `SO_RCVTIMEO`/`SO_SNDTIMEO`;
/// waits are untimed.
pub struct VsockSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Creates an unbound, unconnected vsock stream socket. `flags` must be
    /// within [`FileOpenFlags::STATUS`].
    pub fn create_vsock_socket(
        &self,
        flags: FileOpenFlags,
    ) -> Result<VsockSocket<Platform>, VsockSocketError> {
        let broker = self.broker_control().ok_or(VsockSocketError::Io)?;
        let handle = broker.create_vsock_socket(flags)?;
        Ok(VsockSocket::new(
            broker,
            self.broker_pollable_registry(),
            handle,
        ))
    }

    /// Returns the vsock socket inherited from the parent as `handle`, which
    /// the socket then owns, so each handle is adopted once.
    pub fn adopt_inherited_vsock_socket(
        &self,
        handle: ObjectHandle,
    ) -> Result<VsockSocket<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(VsockSocket::new(
            broker,
            self.broker_pollable_registry(),
            handle,
        ))
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> VsockSocket<Platform> {
    fn new(
        broker: Arc<dyn BrokerControl>,
        pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
        handle: ObjectHandle,
    ) -> Self {
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            handle,
            pollable_registry,
            pollee,
        }
    }

    /// The broker handle this socket owns.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// Binds the socket to `address`.
    pub fn bind(&self, address: VsockAddress) -> Result<(), VsockSocketError> {
        flatten(self.broker.bind_vsock_socket(self.handle, address))
    }

    /// Makes a bound socket accept the host's connections, with up to
    /// `backlog` (capped at [`MAX_VSOCK_LISTEN_BACKLOG`]) pending.
    pub fn listen(&self, backlog: u32) -> Result<(), VsockSocketError> {
        flatten(
            self.broker
                .listen_vsock_socket(self.handle, backlog.min(MAX_VSOCK_LISTEN_BACKLOG)),
        )
    }

    /// Accepts a connection as a new socket with the status flags `flags`,
    /// returning it and its peer's address; waits unless `nonblock` is set
    /// or the socket is non-blocking.
    pub fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        flags: FileOpenFlags,
        nonblock: bool,
    ) -> Result<(Self, VsockAddress), VsockSocketError> {
        let accepted = self.wait(cx, nonblock, || {
            attempt(self.broker.accept_vsock_socket(self.handle, flags))
        })?;
        let socket = Self::new(
            Arc::clone(&self.broker),
            Arc::clone(&self.pollable_registry),
            accepted.handle,
        );
        Ok((socket, accepted.remote_address))
    }

    /// Connects to `address` as Linux does.
    ///
    /// Unless `nonblock` is set or the socket is non-blocking, waits for the
    /// outcome (or an earlier connect's), whose failure stays pending
    /// ([`Self::take_error`]) unless it timed out. Otherwise, fails with
    /// [`VsockSocketError::InProgress`] or [`SocketError::AlreadyInProgress`].
    ///
    /// An interrupted wait cancels the connect and fails with
    /// [`VsockSocketError::ConnectInterrupted`], unless it completed meanwhile.
    /// A wait that finds another call took the outcome fails with
    /// [`SocketError::TimedOut`], as Linux's waiter eventually does.
    pub fn connect(
        &self,
        cx: &WaitContext<'_, Platform>,
        address: VsockAddress,
        nonblock: bool,
    ) -> Result<(), VsockSocketError> {
        let in_progress = match self.broker.connect_vsock_socket(self.handle, address) {
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected)) => return Ok(()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting)) => InProgress::Started,
            Ok(SocketOutcome::Completed(_)) => return Err(VsockSocketError::Io),
            Ok(SocketOutcome::Failed(SocketError::AlreadyInProgress)) => InProgress::Found,
            result => return flatten(result).map(drop),
        };
        // The broker reports a connect in progress whether or not the socket
        // is non-blocking; if that is unknown, a connect started is cancelled.
        let nonblocking = nonblock
            || match self.broker.get_status_flags(self.handle) {
                Ok(status) => status.flags.contains(FileOpenFlags::NONBLOCKING),
                Err(error) => {
                    if let InProgress::Started = in_progress {
                        let _ = self.broker.cancel_connect_vsock_socket(self.handle);
                    }
                    return Err(error.into());
                }
            };
        if nonblocking {
            return Err(match in_progress {
                InProgress::Started => VsockSocketError::InProgress,
                InProgress::Found => VsockSocketError::Socket(SocketError::AlreadyInProgress),
            });
        }
        let result = self.wait(cx, false, || {
            // Unlike a connect, checking leaves a failure pending.
            match self.broker.check_connect_vsock_socket(self.handle) {
                Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected)) => Ok(()),
                // The attempt ended: cancelled, or another call took its outcome.
                Ok(SocketOutcome::Completed(SocketConnectionStatus::Unconnected)) => Err(
                    TryOpError::Other(VsockSocketError::Socket(SocketError::TimedOut)),
                ),
                Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting)) => {
                    Err(TryOpError::TryAgain)
                }
                Ok(SocketOutcome::Completed(_)) => Err(TryOpError::Other(VsockSocketError::Io)),
                result => attempt(result).map(drop),
            }
        });
        match result {
            Err(VsockSocketError::WaitError(WaitError::Interrupted)) => {
                match self.broker.cancel_connect_vsock_socket(self.handle)? {
                    SocketOutcome::Completed(()) => Err(VsockSocketError::ConnectInterrupted),
                    SocketOutcome::Failed(SocketError::AlreadyConnected) => Ok(()),
                    SocketOutcome::Failed(error) => Err(VsockSocketError::Socket(error)),
                }
            }
            result => result,
        }
    }

    /// Takes the socket's pending error, such as why its last connect failed.
    pub fn take_error(&self) -> Result<Option<SocketError>, VsockSocketError> {
        Ok(self.broker.take_vsock_socket_error(self.handle)?)
    }

    /// Sends all of `data`, waiting for room unless `nonblock` is set or the
    /// socket is non-blocking. A send that fails after sending some bytes
    /// returns their count.
    pub fn send(
        &self,
        cx: &WaitContext<'_, Platform>,
        data: impl WriteBuffer,
        nonblock: bool,
    ) -> Result<usize, VsockSocketError> {
        let mut sent: usize = 0;
        loop {
            let length = (data.len() - sent).min(MAX_SOCKET_TRANSFER_SIZE as usize);
            let chunk = &(&data).sub_buffer(sent, length);
            let result = self.wait(cx, nonblock, || {
                attempt(self.broker.send_vsock_socket(self.handle, chunk))
            });
            match result {
                Ok(written) => sent += written,
                Err(_) if sent != 0 => return Ok(sent),
                Err(error) => return Err(error),
            }
            if sent == data.len() {
                return Ok(sent);
            }
        }
    }

    /// Receives into `buffer`, returning zero at the end of the stream. Waits
    /// unless `nonblock` is set or the socket is non-blocking.
    ///
    /// # Errors
    ///
    /// [`VsockSocketError::Fault`] if copying into `buffer` faults; the bytes
    /// received are lost.
    pub fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
        mut buffer: impl ReadBuffer,
        nonblock: bool,
    ) -> Result<usize, VsockSocketError> {
        let response = self.wait(cx, nonblock, || {
            attempt(self.broker.receive_vsock_socket(self.handle, &mut buffer))
        })?;
        Ok(match response {
            ReceiveSocketResponse::Received(received) => received as usize,
            ReceiveSocketResponse::EndOfStream => 0,
            _ => return Err(VsockSocketError::Io),
        })
    }

    /// Shuts down receiving, sending, or both.
    pub fn shutdown(&self, mode: ShutdownMode) -> Result<(), VsockSocketError> {
        flatten(self.broker.shutdown_vsock_socket(self.handle, mode))
    }

    /// Returns the socket's address, or its connected peer's if `peer` is
    /// set, or `None` if it has none.
    pub fn name(&self, peer: bool) -> Result<Option<VsockAddress>, VsockSocketError> {
        Ok(self.broker.vsock_socket_name(self.handle, peer)?)
    }

    /// Returns the socket's access mode and status flags.
    pub fn get_status_flags(&self) -> Result<FileStatusFlags, StatusFlagsError> {
        Ok(self.broker.get_status_flags(self.handle)?)
    }

    /// Changes the status flags in `mask`, within [`FileOpenFlags::STATUS`],
    /// to their values in `flags`, for every reference to the socket.
    pub fn set_status_flags(
        &self,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<(), StatusFlagsError> {
        Ok(self.broker.set_status_flags(self.handle, mask, flags)?)
    }

    /// Runs `attempt`, retrying it on any readiness notification, unless
    /// `nonblock` is set, while it fails with [`TryOpError::TryAgain`].
    fn wait<R>(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        attempt: impl FnMut() -> Result<R, TryOpError<VsockSocketError>>,
    ) -> Result<R, VsockSocketError> {
        self.pollee
            .wait(cx, nonblock, Events::IN | Events::OUT, attempt)
            .map_err(|error| match error {
                TryOpError::TryAgain => VsockSocketError::WouldBlock,
                TryOpError::WaitError(error) => VsockSocketError::WaitError(error),
                TryOpError::Other(error) => error,
            })
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for VsockSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        self.broker
            .check_readiness(self.handle)
            .map_or(Events::ERR, readiness_events)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for VsockSocket<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

/// Whether [`VsockSocket::connect`] started the connect it waits for.
enum InProgress {
    Started,
    Found,
}

/// Maps a broker operation's `result` for a wait, which tries again if it
/// would block.
fn attempt<R>(
    result: Result<SocketOutcome<R>, BrokerControlError>,
) -> Result<R, TryOpError<VsockSocketError>> {
    match result {
        Ok(SocketOutcome::Completed(value)) => Ok(value),
        Ok(SocketOutcome::Failed(error)) => Err(TryOpError::Other(VsockSocketError::Socket(error))),
        Err(BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock)) => {
            Err(TryOpError::Other(VsockSocketError::WouldBlock))
        }
        Err(error) => match BrokerObjectError::from(error) {
            BrokerObjectError::WouldBlock => Err(TryOpError::TryAgain),
            error => Err(TryOpError::Other(error.into())),
        },
    }
}

fn flatten<R>(result: Result<SocketOutcome<R>, BrokerControlError>) -> Result<R, VsockSocketError> {
    match result? {
        SocketOutcome::Completed(value) => Ok(value),
        SocketOutcome::Failed(error) => Err(VsockSocketError::Socket(error)),
    }
}

impl From<BrokerControlError> for VsockSocketError {
    fn from(error: BrokerControlError) -> Self {
        BrokerObjectError::from(error).into()
    }
}

impl From<BrokerObjectError> for VsockSocketError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::ResourceExhausted => Self::ResourceExhausted,
            BrokerObjectError::OutOfMemory => Self::OutOfMemory,
            BrokerObjectError::PermissionDenied => Self::PermissionDenied,
            BrokerObjectError::UnsupportedOperation => Self::Unsupported,
            BrokerObjectError::Fault => Self::Fault,
            BrokerObjectError::Control
            | BrokerObjectError::InvalidObject
            | BrokerObjectError::WouldBlock
            | BrokerObjectError::PeerClosed => Self::Io,
        }
    }
}

pub mod errors {
    use thiserror::Error;

    use crate::event::wait::WaitError;

    /// Possible errors from vsock socket operations.
    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum VsockSocketError {
        /// The operation failed in a way meaningful to the guest.
        #[error(transparent)]
        Socket(litebox_broker_protocol::socket::SocketError),
        /// The operation would block and must not wait.
        #[error("vsock socket operation would block")]
        WouldBlock,
        /// A connect started, and did not wait for it to complete.
        #[error("vsock socket connect is in progress")]
        InProgress,
        /// A wait for the operation failed.
        #[error("wait error")]
        WaitError(#[source] WaitError),
        /// A connect's wait was interrupted, which cancelled the connect.
        #[error("vsock socket connect was interrupted")]
        ConnectInterrupted,
        /// The broker ran out of a resource, such as its socket quota.
        #[error("vsock socket resource exhausted")]
        ResourceExhausted,
        /// The broker could not allocate memory.
        #[error("vsock socket memory allocation failed")]
        OutOfMemory,
        /// The broker's policy denied the operation.
        #[error("vsock socket permission denied")]
        PermissionDenied,
        /// The broker has no vsock sockets, or does not support the
        /// operation or flags.
        #[error("vsock socket operation or flags are unsupported")]
        Unsupported,
        /// The broker failed, or replied outside its contract.
        #[error("vsock socket broker I/O failed")]
        Io,
        /// Copying to or from the caller's buffer faulted.
        #[error("copying the transferred bytes faulted")]
        Fault,
    }
}

#[cfg(test)]
mod tests;
