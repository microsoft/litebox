// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::FileOpenFlags;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, VsockRequest, VsockResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_protocol::socket::{
    AcceptSocketRequest, CheckConnectSocketRequest, GetSocketNameRequest, ListenSocketRequest,
    MAX_SOCKET_TRANSFER_SIZE, ReceiveFlags, ReceiveSocketResponse, SendFlags, SendSocketRequest,
    ShutdownMode, ShutdownSocketRequest, SocketConnectionStatus, SocketError,
    TakeSocketErrorRequest,
};
use litebox_broker_protocol::vsock::{
    AcceptVsockSocketResponse, BindVsockSocketRequest, CancelVsockConnectRequest,
    ConnectVsockSocketRequest, CreateVsockSocketRequest, ReceiveVsockSocketRequest, VsockAddress,
};
use litebox_broker_transport::channel::LocalCallChannel;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use crate::{BrokerLocal, BrokerLocalError, Result};

/// Result of a vsock operation that may fail with an ordinary socket error.
type VsockResult<T, ChannelError> = Result<core::result::Result<T, SocketError>, ChannelError>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates an unbound, unconnected vsock stream socket with the status
    /// flags `flags`.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_vsock_socket(
        &self,
        flags: FileOpenFlags,
    ) -> Result<ObjectHandle, Channel::Error> {
        match self.request_vsock(VsockRequest::Create(CreateVsockSocketRequest { flags }))? {
            VsockResponse::Create(response) => Ok(response.handle),
            response => panic!("broker returned unexpected vsock create response: {response:?}"),
        }
    }

    /// Binds a vsock socket to `address`.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn bind_vsock_socket(
        &self,
        handle: ObjectHandle,
        address: VsockAddress,
    ) -> VsockResult<(), Channel::Error> {
        match self.request_vsock(VsockRequest::Bind(BindVsockSocketRequest {
            handle,
            address,
        }))? {
            VsockResponse::Bind => Ok(Ok(())),
            VsockResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock bind response: {response:?}"),
        }
    }

    /// Makes a bound vsock socket listen for the host's connections.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn listen_vsock_socket(
        &self,
        handle: ObjectHandle,
        backlog: u32,
    ) -> VsockResult<(), Channel::Error> {
        match self.request_vsock(VsockRequest::Listen(ListenSocketRequest {
            handle,
            backlog,
        }))? {
            VsockResponse::Listen => Ok(Ok(())),
            VsockResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock listen response: {response:?}"),
        }
    }

    /// Accepts one pending connection into a socket with the status flags
    /// `flags`.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn accept_vsock_socket(
        &self,
        handle: ObjectHandle,
        flags: FileOpenFlags,
    ) -> VsockResult<AcceptVsockSocketResponse, Channel::Error> {
        match self.request_vsock(VsockRequest::Accept(AcceptSocketRequest { handle, flags }))? {
            VsockResponse::Accept(response) => Ok(Ok(response)),
            VsockResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock accept response: {response:?}"),
        }
    }

    /// Starts connecting a vsock socket, reporting it connected or
    /// connecting.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn connect_vsock_socket(
        &self,
        handle: ObjectHandle,
        address: VsockAddress,
    ) -> VsockResult<SocketConnectionStatus, Channel::Error> {
        match self.request_vsock(VsockRequest::Connect(ConnectVsockSocketRequest {
            handle,
            address,
        }))? {
            VsockResponse::Connect(response) => Ok(Ok(response.status)),
            VsockResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock connect response: {response:?}"),
        }
    }

    /// Reports the progress of a vsock connect without starting one, for a
    /// blocking connect waiting for its outcome.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn check_connect_vsock_socket(
        &self,
        handle: ObjectHandle,
    ) -> VsockResult<SocketConnectionStatus, Channel::Error> {
        match self.request_vsock(VsockRequest::CheckConnect(CheckConnectSocketRequest {
            handle,
        }))? {
            VsockResponse::CheckConnect(response) => Ok(Ok(response.status)),
            VsockResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected vsock check-connect response: {response:?}")
            }
        }
    }

    /// Cancels a vsock connect in progress.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn cancel_connect_vsock_socket(
        &self,
        handle: ObjectHandle,
    ) -> VsockResult<(), Channel::Error> {
        match self.request_vsock(VsockRequest::CancelConnect(CancelVsockConnectRequest {
            handle,
        }))? {
            VsockResponse::CancelConnect => Ok(Ok(())),
            VsockResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected vsock cancel-connect response: {response:?}")
            }
        }
    }

    /// Takes a vsock socket's pending error.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn take_vsock_socket_error(
        &self,
        handle: ObjectHandle,
    ) -> Result<Option<SocketError>, Channel::Error> {
        match self.request_vsock(VsockRequest::TakeError(TakeSocketErrorRequest { handle }))? {
            VsockResponse::TakeError(response) => Ok(response.error),
            response => {
                panic!("broker returned unexpected vsock take-error response: {response:?}")
            }
        }
    }

    /// Sends a prefix of `data` from an operation-scoped shared-buffer lease.
    ///
    /// The caller must retain exclusive ownership of the sequence's slots
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the sequence does not match `data`, or if the broker
    /// returns a mismatched or oversized response.
    pub fn send_vsock_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        data: &dyn WriteBuffer,
        flags: SendFlags,
    ) -> VsockResult<usize, Channel::Error> {
        assert!(
            buffer.length() <= MAX_SOCKET_TRANSFER_SIZE,
            "shared vsock sequence exceeds the transfer limit"
        );
        self.copy_to_shared_buffer(buffer, 0, data)?;
        match self.request_vsock(VsockRequest::Send(SendSocketRequest {
            handle,
            buffer,
            flags,
        }))? {
            VsockResponse::Send(response) => {
                let sent = response.sent as usize;
                assert!(sent <= data.len(), "broker returned oversized vsock send");
                Ok(Ok(sent))
            }
            VsockResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock send response: {response:?}"),
        }
    }

    /// Receives bytes into an operation-scoped shared-buffer lease and copies
    /// them into the start of `destination`.
    ///
    /// The caller must retain exclusive ownership of the sequence's slots
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the sequence does not match `destination`, or if the broker
    /// returns a mismatched or oversized response.
    pub fn receive_vsock_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        destination: &mut dyn ReadBuffer,
        flags: ReceiveFlags,
    ) -> VsockResult<ReceiveSocketResponse, Channel::Error> {
        assert!(
            buffer.length() <= MAX_SOCKET_TRANSFER_SIZE,
            "shared vsock sequence exceeds the transfer limit"
        );
        assert_eq!(
            destination.len(),
            buffer.length() as usize,
            "shared data must match its buffer sequence"
        );
        match self.request_vsock(VsockRequest::Receive(ReceiveVsockSocketRequest {
            handle,
            buffer,
            flags,
        }))? {
            VsockResponse::Receive(response) => {
                if let ReceiveSocketResponse::Received(received) = response {
                    assert!(
                        received <= buffer.length(),
                        "broker returned oversized vsock receive"
                    );
                    self.copy_from_shared_buffer(buffer, received as usize, destination)?;
                }
                Ok(Ok(response))
            }
            VsockResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock receive response: {response:?}"),
        }
    }

    /// Shuts down one or both directions of a vsock socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn shutdown_vsock_socket(
        &self,
        handle: ObjectHandle,
        mode: ShutdownMode,
    ) -> VsockResult<(), Channel::Error> {
        match self.request_vsock(VsockRequest::Shutdown(ShutdownSocketRequest {
            handle,
            mode,
        }))? {
            VsockResponse::Shutdown => Ok(Ok(())),
            VsockResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock shutdown response: {response:?}"),
        }
    }

    /// Returns a vsock socket's local address, or if `peer` is set, its
    /// connected peer's.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn vsock_socket_name(
        &self,
        handle: ObjectHandle,
        peer: bool,
    ) -> Result<Option<VsockAddress>, Channel::Error> {
        match self.request_vsock(VsockRequest::GetName(GetSocketNameRequest { handle, peer }))? {
            VsockResponse::GetName(response) => Ok(response.address),
            response => panic!("broker returned unexpected vsock name response: {response:?}"),
        }
    }

    fn request_vsock(&self, request: VsockRequest) -> Result<VsockResponse, Channel::Error> {
        match self.request(BrokerOperation::Vsock(request))? {
            BrokerResult::Vsock(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected vsock response: {response:?}"),
        }
    }
}
