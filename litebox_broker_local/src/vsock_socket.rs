// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::FileOpenFlags;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, VsockSocketRequest, VsockSocketResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_protocol::socket::{
    AcceptSocketRequest, CheckConnectSocketRequest, GetSocketNameRequest, ListenSocketRequest,
    MAX_SOCKET_TRANSFER_SIZE, ReceiveSocketResponse, SendFlags, SendSocketRequest, ShutdownMode,
    ShutdownSocketRequest, SocketConnectionStatus, SocketError, TakeSocketErrorRequest,
};
use litebox_broker_protocol::vsock_socket::{
    AcceptVsockSocketResponse, BindVsockSocketRequest, ConnectVsockSocketRequest,
    CreateVsockSocketRequest, ReceiveVsockSocketRequest, VsockAddress,
};
use litebox_broker_transport::channel::LocalCallChannel;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use crate::{BrokerLocal, BrokerLocalError, Result};

type VsockSocketResult<T> = core::result::Result<T, SocketError>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates an unbound, unconnected vsock stream socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_vsock_socket(
        &self,
        flags: FileOpenFlags,
    ) -> Result<ObjectHandle, Channel::Error> {
        match self.request_vsock_socket(VsockSocketRequest::Create(CreateVsockSocketRequest {
            flags,
        }))? {
            VsockSocketResponse::Create(response) => Ok(response.handle),
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
    ) -> Result<VsockSocketResult<()>, Channel::Error> {
        match self.request_vsock_socket(VsockSocketRequest::Bind(BindVsockSocketRequest {
            handle,
            address,
        }))? {
            VsockSocketResponse::Bind => Ok(Ok(())),
            VsockSocketResponse::Failed(error) => Ok(Err(error)),
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
    ) -> Result<VsockSocketResult<()>, Channel::Error> {
        match self.request_vsock_socket(VsockSocketRequest::Listen(ListenSocketRequest {
            handle,
            backlog,
        }))? {
            VsockSocketResponse::Listen => Ok(Ok(())),
            VsockSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock listen response: {response:?}"),
        }
    }

    /// Accepts one pending connection as a socket with the status flags `flags`.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn accept_vsock_socket(
        &self,
        handle: ObjectHandle,
        flags: FileOpenFlags,
    ) -> Result<VsockSocketResult<AcceptVsockSocketResponse>, Channel::Error> {
        match self.request_vsock_socket(VsockSocketRequest::Accept(AcceptSocketRequest {
            handle,
            flags,
        }))? {
            VsockSocketResponse::Accept(response) => Ok(Ok(response)),
            VsockSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock accept response: {response:?}"),
        }
    }

    /// Starts connecting a vsock socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn connect_vsock_socket(
        &self,
        handle: ObjectHandle,
        address: VsockAddress,
    ) -> Result<VsockSocketResult<SocketConnectionStatus>, Channel::Error> {
        match self.request_vsock_socket(VsockSocketRequest::Connect(ConnectVsockSocketRequest {
            handle,
            address,
        }))? {
            VsockSocketResponse::Connect(response) => Ok(Ok(response.status)),
            VsockSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock connect response: {response:?}"),
        }
    }

    /// Reports a blocking vsock connect's progress.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn check_connect_vsock_socket(
        &self,
        handle: ObjectHandle,
    ) -> Result<VsockSocketResult<SocketConnectionStatus>, Channel::Error> {
        match self.request_vsock_socket(VsockSocketRequest::CheckConnect(
            CheckConnectSocketRequest { handle },
        ))? {
            VsockSocketResponse::CheckConnect(response) => Ok(Ok(response.status)),
            VsockSocketResponse::Failed(error) => Ok(Err(error)),
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
    ) -> Result<VsockSocketResult<()>, Channel::Error> {
        match self.request_vsock_socket(VsockSocketRequest::CancelConnect(
            CheckConnectSocketRequest { handle },
        ))? {
            VsockSocketResponse::CancelConnect => Ok(Ok(())),
            VsockSocketResponse::Failed(error) => Ok(Err(error)),
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
        match self.request_vsock_socket(VsockSocketRequest::TakeError(TakeSocketErrorRequest {
            handle,
        }))? {
            VsockSocketResponse::TakeError(response) => Ok(response.error),
            response => {
                panic!("broker returned unexpected vsock take-error response: {response:?}")
            }
        }
    }

    /// Sends a prefix of `data` from an operation-scoped shared-buffer lease,
    /// whose slots the caller owns exclusively until this returns.
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
    ) -> Result<VsockSocketResult<usize>, Channel::Error> {
        assert!(
            buffer.length() <= MAX_SOCKET_TRANSFER_SIZE,
            "shared vsock sequence exceeds the transfer limit"
        );
        self.copy_to_shared_buffer(buffer, 0, data)?;
        match self.request_vsock_socket(VsockSocketRequest::Send(SendSocketRequest {
            handle,
            buffer,
            flags: SendFlags::NONE,
        }))? {
            VsockSocketResponse::Send(response) => {
                let sent = response.sent as usize;
                assert!(sent <= data.len(), "broker returned oversized vsock send");
                Ok(Ok(sent))
            }
            VsockSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock send response: {response:?}"),
        }
    }

    /// Receives into the start of `destination` through an operation-scoped
    /// shared-buffer lease, whose slots the caller owns exclusively until
    /// this returns.
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
    ) -> Result<VsockSocketResult<ReceiveSocketResponse>, Channel::Error> {
        assert!(
            buffer.length() <= MAX_SOCKET_TRANSFER_SIZE,
            "shared vsock sequence exceeds the transfer limit"
        );
        assert_eq!(
            destination.len(),
            buffer.length() as usize,
            "shared data must match its buffer sequence"
        );
        match self.request_vsock_socket(VsockSocketRequest::Receive(ReceiveVsockSocketRequest {
            handle,
            buffer,
        }))? {
            VsockSocketResponse::Receive(response) => {
                if let ReceiveSocketResponse::Received(received) = response {
                    assert!(
                        received <= buffer.length(),
                        "broker returned oversized vsock receive"
                    );
                    self.copy_from_shared_buffer(buffer, received as usize, destination)?;
                }
                Ok(Ok(response))
            }
            VsockSocketResponse::Failed(error) => Ok(Err(error)),
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
    ) -> Result<VsockSocketResult<()>, Channel::Error> {
        match self.request_vsock_socket(VsockSocketRequest::Shutdown(ShutdownSocketRequest {
            handle,
            mode,
        }))? {
            VsockSocketResponse::Shutdown => Ok(Ok(())),
            VsockSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected vsock shutdown response: {response:?}"),
        }
    }

    /// Returns a vsock socket's local address, or its peer's if `peer` is set.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn vsock_socket_name(
        &self,
        handle: ObjectHandle,
        peer: bool,
    ) -> Result<Option<VsockAddress>, Channel::Error> {
        match self.request_vsock_socket(VsockSocketRequest::GetName(GetSocketNameRequest {
            handle,
            peer,
        }))? {
            VsockSocketResponse::GetName(response) => Ok(response.address),
            response => panic!("broker returned unexpected vsock name response: {response:?}"),
        }
    }

    fn request_vsock_socket(
        &self,
        request: VsockSocketRequest,
    ) -> Result<VsockSocketResponse, Channel::Error> {
        match self.request(BrokerOperation::VsockSocket(request))? {
            BrokerResult::VsockSocket(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected vsock response: {response:?}"),
        }
    }
}
