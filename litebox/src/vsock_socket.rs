// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned vsock sockets, which reach the host through the broker's
//! vsock provider.
//!
//! The broker owns each socket's state and readiness, so every reference,
//! including an inherited one, shares them.
//!
//! Creating fails with [`VsockSocketError::Unsupported`] without a broker
//! vsock provider or for a type it does not support, and with
//! [`VsockSocketError::PermissionDenied`] if the policy denies vsock. A
//! denied connect or listen fails with [`SocketError::PolicyDenied`].

use alloc::sync::{Arc, Weak};
use litebox_broker_protocol::{
    ObjectHandle,
    error::ErrorCode,
    fs::{FileOpenFlags, FileStatusFlags},
    socket::{
        MAX_SOCKET_TRANSFER_SIZE, ReceiveSocketResponse, ShutdownMode, SocketConnectionStatus,
        SocketError, SocketOutcome, SocketType,
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

/// A reference to a broker-owned vsock socket, which closes its handle when
/// dropped.
pub struct VsockSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Creates an unbound, unconnected vsock socket of `socket_type`.
    /// `flags` must be within [`FileOpenFlags::STATUS`].
    pub fn create_vsock_socket(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<VsockSocket<Platform>, VsockSocketError> {
        let broker = self.broker_control().ok_or(VsockSocketError::Io)?;
        let handle = broker.create_vsock_socket(socket_type, flags)?;
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

    /// Waits as [`Self::receive`] does until data waits or the stream ended,
    /// without receiving any: whether data waits. Unlike a receive into a
    /// buffer that faults, this loses no data.
    pub fn probe(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
    ) -> Result<bool, VsockSocketError> {
        // An empty receive never waits, so the socket's own flag is needed.
        let nonblock = nonblock
            || self
                .broker
                .get_status_flags(self.handle)?
                .flags
                .contains(FileOpenFlags::NONBLOCKING);
        self.wait(cx, nonblock, || {
            // An empty receive checks the state, and finds the end of the stream.
            match attempt(self.broker.receive_vsock_socket(self.handle, &mut [0; 0]))? {
                ReceiveSocketResponse::EndOfStream => Ok(false),
                ReceiveSocketResponse::Received(_)
                    if self.check_io_events().contains(Events::IN) =>
                {
                    Ok(true)
                }
                ReceiveSocketResponse::Received(_) => Err(TryOpError::TryAgain),
                _ => Err(TryOpError::Other(VsockSocketError::Io)),
            }
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
        /// The broker has no vsock sockets, or does not support the type,
        /// operation, or flags.
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
mod tests {
    extern crate std;

    use alloc::collections::VecDeque;
    use alloc::format;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    use litebox_broker_local::test_support::test_broker_local;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::error::ErrorCode;
    use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult, VsockSocketRequest,
        VsockSocketResponse,
    };
    use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
    use litebox_broker_protocol::socket::{
        ConnectSocketResponse, CreateSocketResponse, MAX_SOCKET_TRANSFER_SIZE,
        ReceiveSocketResponse, SendSocketResponse, SocketConnectionStatus, SocketError, SocketType,
    };
    use litebox_broker_protocol::vsock_socket::{
        AcceptVsockSocketResponse, MAX_VSOCK_LISTEN_BACKLOG, VsockAddress, VsockCid, VsockPort,
    };
    use litebox_broker_transport::channel::LocalCallChannel;
    use litebox_broker_transport::shared_memory::HeapSharedMemory;

    use super::VsockSocket;
    use super::errors::VsockSocketError;
    use crate::event::wait::{CheckForInterrupt, WaitState};
    use crate::platform::mock::MockPlatform;

    const SOCKET: ObjectHandle = ObjectHandle(7);
    const HOST: VsockAddress = VsockAddress {
        cid: VsockCid::HOST,
        port: VsockPort(5000),
    };

    /// A broker that answers each request but a close with the next scripted
    /// result, and records those requests.
    struct ScriptedChannel {
        results: Mutex<VecDeque<BrokerResult>>,
        operations: Arc<Mutex<Vec<BrokerOperation>>>,
    }

    impl LocalCallChannel for ScriptedChannel {
        type Error = ();

        fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
            let result = if let BrokerOperation::CloseObject(_) = request.operation {
                BrokerResult::ObjectClosed
            } else {
                self.operations.lock().unwrap().push(request.operation);
                self.results
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("the request was not scripted")
            };
            Ok(BrokerResponse {
                request_id: request.request_id,
                result,
            })
        }
    }

    struct Interrupted;

    impl CheckForInterrupt for Interrupted {
        fn check_for_interrupt(&self) -> bool {
            true
        }
    }

    fn vsock(response: VsockSocketResponse) -> BrokerResult {
        BrokerResult::VsockSocket(response)
    }

    fn connect(status: SocketConnectionStatus) -> BrokerResult {
        vsock(VsockSocketResponse::Connect(ConnectSocketResponse {
            status,
        }))
    }

    fn check(status: SocketConnectionStatus) -> BrokerResult {
        vsock(VsockSocketResponse::CheckConnect(ConnectSocketResponse {
            status,
        }))
    }

    fn failed(error: SocketError) -> BrokerResult {
        vsock(VsockSocketResponse::Failed(error))
    }

    fn status_flags(flags: FileOpenFlags) -> BrokerResult {
        BrokerResult::StatusFlags(FileStatusFlags {
            access: FileAccessMode::ReadWrite,
            flags,
        })
    }

    /// Names a recorded request.
    fn name(operation: &BrokerOperation) -> &'static str {
        match operation {
            BrokerOperation::GetStatusFlags(SOCKET) => "flags",
            BrokerOperation::VsockSocket(VsockSocketRequest::Connect(request))
                if request.handle == SOCKET =>
            {
                "connect"
            }
            BrokerOperation::VsockSocket(VsockSocketRequest::CheckConnect(request))
                if request.handle == SOCKET =>
            {
                "check"
            }
            BrokerOperation::VsockSocket(VsockSocketRequest::CancelConnect(request))
                if request.handle == SOCKET =>
            {
                "cancel"
            }
            BrokerOperation::VsockSocket(VsockSocketRequest::Receive(request))
                if request.handle == SOCKET =>
            {
                "receive"
            }
            operation => panic!("unexpected request {operation:?}"),
        }
    }

    /// Runs `op` on a socket whose broker answers with `script`, interrupting any
    /// wait if `interrupt` is set; returns `op`'s result and the requests after
    /// the create.
    fn run<R>(
        script: impl IntoIterator<Item = BrokerResult>,
        interrupt: bool,
        op: impl FnOnce(
            &VsockSocket<MockPlatform>,
            &crate::event::wait::WaitContext<'_, MockPlatform>,
        ) -> R,
    ) -> (R, Vec<BrokerOperation>) {
        let platform = MockPlatform::new();
        let operations = Arc::new(Mutex::new(Vec::new()));
        let mut results =
            VecDeque::from([vsock(VsockSocketResponse::Create(CreateSocketResponse {
                handle: SOCKET,
            }))]);
        results.extend(script);
        let channel = ScriptedChannel {
            results: Mutex::new(results),
            operations: Arc::clone(&operations),
        };
        let litebox = crate::LiteBox::new_with_broker_local(
            platform,
            test_broker_local(
                channel,
                Arc::new(HeapSharedMemory::new(SHARED_BUFFER_POOL_SIZE)),
            ),
        );
        let socket = litebox
            .create_vsock_socket(SocketType::Stream, FileOpenFlags::NONE)
            .unwrap();
        let wait = WaitState::new(platform);
        let cx = wait.context();
        let result = if interrupt {
            op(&socket, &cx.with_check_for_interrupt(&Interrupted))
        } else {
            op(&socket, &cx)
        };
        drop(socket);
        let mut operations = operations.lock().unwrap().clone();
        assert!(matches!(
            operations.remove(0),
            BrokerOperation::VsockSocket(VsockSocketRequest::Create(_))
        ));
        (result, operations)
    }

    /// Checks a connect to [`HOST`]'s result (by its debug form) and requests.
    fn check_connect(
        script: impl IntoIterator<Item = BrokerResult>,
        nonblock: bool,
        interrupt: bool,
        expected: Result<(), VsockSocketError>,
        requests: &[&str],
    ) {
        let (result, operations) = run(script, interrupt, |socket, cx| {
            socket.connect(cx, HOST, nonblock)
        });
        assert_eq!(format!("{result:?}"), format!("{expected:?}"));
        assert_eq!(operations.iter().map(name).collect::<Vec<_>>(), requests);
    }

    #[test]
    fn nonblocking_connects_report_progress_without_waiting() {
        use SocketConnectionStatus::{Connected, Connecting};

        // Non-blocking by the caller's choice, which needs no request, or by the
        // socket's status flags.
        check_connect(
            [connect(Connecting)],
            true,
            false,
            Err(VsockSocketError::InProgress),
            &["connect"],
        );
        check_connect(
            [
                connect(Connecting),
                status_flags(FileOpenFlags::NONBLOCKING),
            ],
            false,
            false,
            Err(VsockSocketError::InProgress),
            &["connect", "flags"],
        );
        // One that finds another in progress reports that one.
        for (nonblock, requests) in [(true, &["connect"][..]), (false, &["connect", "flags"])] {
            check_connect(
                [
                    failed(SocketError::AlreadyInProgress),
                    status_flags(FileOpenFlags::NONBLOCKING),
                ]
                .into_iter()
                .take(requests.len()),
                nonblock,
                false,
                Err(VsockSocketError::Socket(SocketError::AlreadyInProgress)),
                requests,
            );
        }
        // A connect that ends at once never reads the status flags.
        check_connect([connect(Connected)], false, false, Ok(()), &["connect"]);
        check_connect(
            [failed(SocketError::NetworkUnreachable)],
            false,
            false,
            Err(VsockSocketError::Socket(SocketError::NetworkUnreachable)),
            &["connect"],
        );
    }

    #[test]
    fn blocking_connects_check_the_outcome_while_waiting() {
        use SocketConnectionStatus::{Connected, Connecting, Unconnected};

        let blocking = || status_flags(FileOpenFlags::NONE);
        check_connect(
            [
                connect(Connecting),
                blocking(),
                check(Connecting),
                check(Connected),
            ],
            false,
            false,
            Ok(()),
            &["connect", "flags", "check", "check"],
        );
        check_connect(
            [
                connect(Connecting),
                blocking(),
                check(Connecting),
                failed(SocketError::ConnectionReset),
            ],
            false,
            false,
            Err(VsockSocketError::Socket(SocketError::ConnectionReset)),
            &["connect", "flags", "check", "check"],
        );
        // A connect that finds another in progress waits for that one.
        check_connect(
            [
                failed(SocketError::AlreadyInProgress),
                blocking(),
                check(Connected),
            ],
            false,
            false,
            Ok(()),
            &["connect", "flags", "check"],
        );
        // Another call took the outcome; the attempt ends without reconnecting.
        check_connect(
            [connect(Connecting), blocking(), check(Unconnected)],
            false,
            false,
            Err(VsockSocketError::Socket(SocketError::TimedOut)),
            &["connect", "flags", "check"],
        );
    }

    #[test]
    fn connect_statuses_outside_the_contract_fail() {
        use SocketConnectionStatus::{Connecting, Failed, Unconnected};

        check_connect(
            [connect(Unconnected)],
            false,
            false,
            Err(VsockSocketError::Io),
            &["connect"],
        );
        check_connect(
            [
                connect(Connecting),
                status_flags(FileOpenFlags::NONE),
                check(Failed(SocketError::ConnectionReset)),
            ],
            false,
            false,
            Err(VsockSocketError::Io),
            &["connect", "flags", "check"],
        );
    }

    #[test]
    fn connects_that_cannot_read_the_status_flags_cancel_what_they_started() {
        use SocketConnectionStatus::Connecting;

        let no_flags = || BrokerResult::Error(ErrorCode::ResourceExhausted);
        check_connect(
            [
                connect(Connecting),
                no_flags(),
                vsock(VsockSocketResponse::CancelConnect),
            ],
            false,
            false,
            Err(VsockSocketError::ResourceExhausted),
            &["connect", "flags", "cancel"],
        );
        // A connect another call started is left alone.
        check_connect(
            [failed(SocketError::AlreadyInProgress), no_flags()],
            false,
            false,
            Err(VsockSocketError::ResourceExhausted),
            &["connect", "flags"],
        );
    }

    #[test]
    fn listens_bound_the_backlog() {
        for (backlog, sent) in [
            (MAX_VSOCK_LISTEN_BACKLOG, MAX_VSOCK_LISTEN_BACKLOG),
            (u32::MAX, MAX_VSOCK_LISTEN_BACKLOG),
        ] {
            let (result, operations) =
                run([vsock(VsockSocketResponse::Listen)], false, |socket, _| {
                    socket.listen(backlog)
                });
            assert!(result.is_ok());
            let [BrokerOperation::VsockSocket(VsockSocketRequest::Listen(request))] =
                &operations[..]
            else {
                panic!("unexpected requests {operations:?}");
            };
            assert_eq!((request.handle, request.backlog), (SOCKET, sent));
        }
    }

    #[test]
    fn accepts_return_the_new_socket_and_its_peer() {
        const ACCEPTED: ObjectHandle = ObjectHandle(8);
        let accepted = || {
            vsock(VsockSocketResponse::Accept(AcceptVsockSocketResponse {
                handle: ACCEPTED,
                remote_address: HOST,
            }))
        };
        let would_block = || BrokerResult::Error(ErrorCode::WouldBlock);
        let accepts = |operations: &[BrokerOperation]| {
            operations
                .iter()
                .map(|operation| match operation {
                    BrokerOperation::VsockSocket(VsockSocketRequest::Accept(request)) => {
                        (request.handle, request.flags)
                    }
                    operation => panic!("unexpected request {operation:?}"),
                })
                .collect::<Vec<_>>()
        };

        let (result, operations) = run([would_block(), accepted()], false, |socket, cx| {
            socket
                .accept(cx, FileOpenFlags::NONBLOCKING, false)
                .map(|(socket, peer)| (socket.handle(), peer))
        });
        assert_eq!(result.unwrap(), (ACCEPTED, HOST));
        assert_eq!(
            accepts(&operations),
            [(SOCKET, FileOpenFlags::NONBLOCKING); 2]
        );

        // Non-blocking by the caller's choice or the socket's.
        for (result, nonblock) in [
            (would_block(), true),
            (BrokerResult::Error(ErrorCode::NonBlockingWouldBlock), false),
        ] {
            let (result, operations) = run([result], false, |socket, cx| {
                socket.accept(cx, FileOpenFlags::NONE, nonblock).map(drop)
            });
            assert!(matches!(result, Err(VsockSocketError::WouldBlock)));
            assert_eq!(accepts(&operations), [(SOCKET, FileOpenFlags::NONE)]);
        }
    }

    #[test]
    fn interrupted_connects_are_cancelled() {
        use SocketConnectionStatus::Connecting;

        for (cancel, expected) in [
            (
                vsock(VsockSocketResponse::CancelConnect),
                Err(VsockSocketError::ConnectInterrupted),
            ),
            // The connect completed meanwhile, or failed.
            (failed(SocketError::AlreadyConnected), Ok(())),
            (
                failed(SocketError::ConnectionReset),
                Err(VsockSocketError::Socket(SocketError::ConnectionReset)),
            ),
        ] {
            check_connect(
                [
                    connect(Connecting),
                    status_flags(FileOpenFlags::NONE),
                    check(Connecting),
                    check(Connecting),
                    cancel,
                ],
                false,
                true,
                expected,
                &["connect", "flags", "check", "check", "cancel"],
            );
        }
    }

    #[test]
    fn sends_split_data_and_keep_the_count_of_a_partial_send() {
        let chunk = MAX_SOCKET_TRANSFER_SIZE as usize;
        let data = alloc::vec![1u8; chunk + 10];
        let sent = |sent: usize| {
            vsock(VsockSocketResponse::Send(SendSocketResponse {
                sent: u32::try_from(sent).unwrap(),
            }))
        };
        let lengths = |operations: &[BrokerOperation]| {
            operations
                .iter()
                .map(|operation| match operation {
                    BrokerOperation::VsockSocket(VsockSocketRequest::Send(request)) => {
                        request.buffer.length()
                    }
                    operation => panic!("unexpected request {operation:?}"),
                })
                .collect::<Vec<_>>()
        };

        let (result, operations) = run(
            [
                sent(chunk),
                sent(4),
                BrokerResult::Error(ErrorCode::NonBlockingWouldBlock),
            ],
            false,
            |socket, cx| socket.send(cx, &data[..], false),
        );
        assert_eq!(result.unwrap(), chunk + 4);
        assert_eq!(lengths(&operations), [MAX_SOCKET_TRANSFER_SIZE, 10, 6]);
        // One that sent nothing fails.
        let (result, _) = run([failed(SocketError::Shutdown)], false, |socket, cx| {
            socket.send(cx, &data[..], false)
        });
        assert!(matches!(
            result,
            Err(VsockSocketError::Socket(SocketError::Shutdown))
        ));

        let (result, operations) = run(
            [vsock(VsockSocketResponse::Receive(
                ReceiveSocketResponse::EndOfStream,
            ))],
            false,
            |socket, cx| socket.receive(cx, &mut [0u8; 4][..], false),
        );
        assert_eq!(result.unwrap(), 0);
        assert_eq!(operations.iter().map(name).collect::<Vec<_>>(), ["receive"]);
    }
}
