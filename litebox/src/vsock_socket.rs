// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned vsock stream sockets, which reach the VM's host.
//!
//! The broker's vsock provider owns each socket's state, including its port,
//! connection, pending error, and shutdowns, and publishes its readiness, so
//! every reference to a socket, including one inherited by another process,
//! shares them. A broker without a vsock provider fails to create sockets
//! with [`VsockSocketError::Unsupported`], and one whose policy denies vsock
//! sockets with [`VsockSocketError::PermissionDenied`]; a connect or listen
//! the policy denies fails with [`SocketError::PolicyDenied`].

use alloc::sync::{Arc, Weak};
use litebox_broker_protocol::{
    ObjectHandle,
    error::ErrorCode,
    fs::{FileOpenFlags, FileStatusFlags},
    socket::{
        MAX_SOCKET_TRANSFER_SIZE, ReceiveSocketResponse, ShutdownMode, SocketConnectionStatus,
        SocketError,
    },
    vsock::{MAX_VSOCK_LISTEN_BACKLOG, VsockAddress},
};
use litebox_platform::time::TimeProvider;

use crate::{
    LiteBox,
    broker::{
        BrokerControl, BrokerPollableRegistry, SocketResult,
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
pub struct VsockSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Creates an unbound, unconnected vsock stream socket.
    ///
    /// `flags` must be within [`FileOpenFlags::STATUS`].
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

    /// Returns the vsock socket this process inherited from its parent as
    /// `handle`.
    ///
    /// The socket owns `handle`, so callers adopt each handle once and share
    /// the socket for every other use.
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
    /// `backlog`, at most [`MAX_VSOCK_LISTEN_BACKLOG`], waiting to be
    /// accepted.
    pub fn listen(&self, backlog: u32) -> Result<(), VsockSocketError> {
        flatten(
            self.broker
                .listen_vsock_socket(self.handle, backlog.min(MAX_VSOCK_LISTEN_BACKLOG)),
        )
    }

    /// Accepts a connection as a new socket with the status flags `flags`,
    /// returning it and its peer's address.
    ///
    /// Waits while no connection is pending, unless `nonblock` is set or the
    /// socket is non-blocking.
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
        Ok((socket, accepted.peer_address))
    }

    /// Connects the socket to `address`.
    ///
    /// The broker completes a connect later, so unless `nonblock` is set or
    /// the socket is non-blocking, this waits for it, as Linux does: the
    /// connect succeeds, or fails with its error, which, as in Linux, stays
    /// pending ([`Self::take_error`]) unless the connect timed out. One that
    /// does not wait fails with [`VsockSocketError::InProgress`], or, if it
    /// found an earlier connect in progress, with
    /// [`SocketError::AlreadyInProgress`]; a blocking one waits for that one
    /// instead. As in Linux, an interrupted wait cancels the connect, leaving
    /// the socket unconnected and still bound, and fails with
    /// [`VsockSocketError::Interrupted`], unless it completed meanwhile: then
    /// this reports its outcome. A wait that finds the socket unconnected with
    /// no pending error, as when another call took it, fails with
    /// [`SocketError::TimedOut`], as Linux's waiter eventually does. If this
    /// cannot tell whether the socket is non-blocking, it cancels a connect
    /// it started and fails.
    pub fn connect(
        &self,
        cx: &WaitContext<'_, Platform>,
        address: VsockAddress,
        nonblock: bool,
    ) -> Result<(), VsockSocketError> {
        let in_progress = match self.broker.connect_vsock_socket(self.handle, address) {
            Ok(Ok(SocketConnectionStatus::Connected)) => return Ok(()),
            Ok(Ok(SocketConnectionStatus::Connecting)) => InProgress::Started,
            Ok(Ok(_)) => return Err(VsockSocketError::Io),
            Ok(Err(SocketError::AlreadyInProgress)) => InProgress::Found,
            result => return flatten(result).map(drop),
        };
        // The broker reports a connect in progress whether or not the socket
        // is non-blocking.
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
                Ok(Ok(SocketConnectionStatus::Connected)) => Ok(()),
                // The attempt ended: cancelled, or another call took its outcome.
                Ok(Ok(SocketConnectionStatus::Unconnected)) => Err(TryOpError::Other(
                    VsockSocketError::Socket(SocketError::TimedOut),
                )),
                // Checked again as the socket's readiness changes.
                Ok(Ok(SocketConnectionStatus::Connecting)) => Err(TryOpError::TryAgain),
                Ok(Ok(_)) => Err(TryOpError::Other(VsockSocketError::Io)),
                result => attempt(result).map(drop),
            }
        });
        match result {
            Err(VsockSocketError::WaitError(WaitError::Interrupted)) => {
                match self.broker.cancel_connect_vsock_socket(self.handle)? {
                    Ok(()) => Err(VsockSocketError::Interrupted),
                    Err(SocketError::AlreadyConnected) => Ok(()),
                    Err(error) => Err(VsockSocketError::Socket(error)),
                }
            }
            result => result,
        }
    }

    /// Takes the socket's pending error, such as why its last connect failed.
    pub fn take_error(&self) -> Result<Option<SocketError>, VsockSocketError> {
        Ok(self.broker.take_vsock_socket_error(self.handle)?)
    }

    /// Sends all of `data`, returning the number of bytes sent.
    ///
    /// Waits while the peer has no room, unless `nonblock` is set or the
    /// socket is non-blocking. A send that stops early after sending some
    /// bytes returns their count instead of failing.
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

    /// Receives into `buffer`, returning the number of bytes received, which
    /// is zero at the end of the stream.
    ///
    /// Waits while nothing is queued, unless `nonblock` is set or the socket
    /// is non-blocking. If copying into `buffer` faults, this fails with
    /// [`VsockSocketError::Fault`], and the bytes received are lost.
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
    pub fn address(&self, peer: bool) -> Result<Option<VsockAddress>, VsockSocketError> {
        Ok(self.broker.vsock_socket_name(self.handle, peer)?)
    }

    /// Returns the socket's access mode and status flags.
    pub fn get_status_flags(&self) -> Result<FileStatusFlags, StatusFlagsError> {
        Ok(self.broker.get_status_flags(self.handle)?)
    }

    /// Changes the status flags in `mask`, within [`FileOpenFlags::STATUS`],
    /// to their values in `flags`.
    ///
    /// Every reference to the socket sees the change.
    pub fn set_status_flags(
        &self,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<(), StatusFlagsError> {
        Ok(self.broker.set_status_flags(self.handle, mask, flags)?)
    }

    /// Runs `attempt`, retrying it, unless `nonblock` is set, while it fails
    /// with [`TryOpError::TryAgain`].
    ///
    /// The broker publishes a blocked socket's readiness when the operation
    /// may succeed, so any readiness notification retries it.
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

/// A connect in progress that [`VsockSocket::connect`] waits for.
enum InProgress {
    /// This call started it.
    Started,
    /// An earlier call started it.
    Found,
}

/// What a wait makes of a broker operation's `result`: it tries again if it
/// would block.
fn attempt<R>(result: SocketResult<R>) -> Result<R, TryOpError<VsockSocketError>> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(TryOpError::Other(VsockSocketError::Socket(error))),
        Err(BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock)) => {
            Err(TryOpError::Other(VsockSocketError::WouldBlock))
        }
        Err(error) => match BrokerObjectError::from(error) {
            BrokerObjectError::WouldBlock => Err(TryOpError::TryAgain),
            error => Err(TryOpError::Other(error.into())),
        },
    }
}

fn flatten<R>(result: SocketResult<R>) -> Result<R, VsockSocketError> {
    result?.map_err(VsockSocketError::Socket)
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
        Interrupted,
        /// The broker ran out of a resource, such as its socket quota.
        #[error("vsock socket resource exhausted")]
        ResourceExhausted,
        /// The broker could not allocate memory.
        #[error("vsock socket memory allocation failed")]
        OutOfMemory,
        /// The broker's policy denied the operation, such as creating a
        /// socket.
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
