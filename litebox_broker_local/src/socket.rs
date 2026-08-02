// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, SocketRequest, SocketResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferDescriptor;
use litebox_broker_protocol::socket::{
    AddressFamily, ConnectSocketRequest, CreateSocketRequest, IpProtocol, MAX_SOCKET_TRANSFER_SIZE,
    ReceiveSocketRequest, ReceiveSocketResponse, SendFlags, SendSocketRequest, ShutdownMode,
    ShutdownSocketRequest, SocketAddressV4, SocketConnectionStatus, SocketError,
    SocketStatusRequest, SocketStatusResponse, SocketType,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned IPv4 TCP stream socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_tcp_socket(&self) -> Result<ObjectHandle, Channel::Error> {
        let response = self.request_socket(SocketRequest::Create(CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Stream,
            protocol: IpProtocol::Tcp,
        }))?;
        let SocketResponse::Create(response) = response else {
            panic!("broker returned unexpected socket create response: {response:?}");
        };
        Ok(response.handle)
    }

    /// Starts or observes a nonblocking connect attempt.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn connect_socket(
        &self,
        handle: ObjectHandle,
        address: SocketAddressV4,
    ) -> Result<core::result::Result<SocketConnectionStatus, SocketError>, Channel::Error> {
        let response = self.request_socket(SocketRequest::Connect(ConnectSocketRequest {
            handle,
            address,
        }))?;
        match response {
            SocketResponse::Connect(response) => Ok(Ok(response.status)),
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected socket connect response: {response:?}"),
        }
    }

    /// Reads a broker socket's authoritative connection state.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn socket_status(
        &self,
        handle: ObjectHandle,
    ) -> Result<SocketStatusResponse, Channel::Error> {
        let response =
            self.request_socket(SocketRequest::Status(SocketStatusRequest { handle }))?;
        let SocketResponse::Status(response) = response else {
            panic!("broker returned unexpected socket status response: {response:?}");
        };
        Ok(response)
    }

    /// Sends bytes from an operation-scoped shared-buffer lease.
    ///
    /// The caller must retain exclusive ownership of the descriptor's slot
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the descriptor does not match `data`, or if the broker
    /// returns a mismatched or oversized response.
    pub fn send_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        data: &[u8],
        flags: SendFlags,
    ) -> Result<core::result::Result<usize, SocketError>, Channel::Error> {
        self.validate_socket_buffer(buffer, data.len());
        self.shared_buffers
            .write(buffer.slot_index, data)
            .expect("validated shared socket send range must be accessible");
        match self.request_socket(SocketRequest::Send(SendSocketRequest {
            handle,
            buffer,
            flags,
        }))? {
            SocketResponse::Send(response) => {
                let sent = response.sent as usize;
                assert!(sent <= data.len(), "broker returned oversized socket send");
                Ok(Ok(sent))
            }
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected socket send response: {response:?}"),
        }
    }

    /// Receives bytes into an operation-scoped shared-buffer lease.
    ///
    /// The caller must retain exclusive ownership of the descriptor's slot
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the descriptor does not match `destination`, or if the broker
    /// returns a mismatched or oversized response.
    pub fn receive_socket(
        &self,
        request: ReceiveSocketRequest,
        destination: &mut [u8],
        copy_received: bool,
    ) -> Result<core::result::Result<ReceiveSocketResponse, SocketError>, Channel::Error> {
        self.validate_socket_buffer(request.buffer, destination.len());
        match self.request_socket(SocketRequest::Receive(request))? {
            SocketResponse::Receive(response) => {
                if let ReceiveSocketResponse::Received(received) = response {
                    assert!(
                        received <= request.buffer.length,
                        "broker returned oversized socket receive"
                    );
                    if copy_received {
                        let received = received as usize;
                        self.shared_buffers
                            .read(request.buffer.slot_index, &mut destination[..received])
                            .expect("validated shared socket receive range must be accessible");
                    }
                }
                Ok(Ok(response))
            }
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected socket receive response: {response:?}"),
        }
    }

    /// Shuts down one or both directions of a broker socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn shutdown_socket(
        &self,
        handle: ObjectHandle,
        mode: ShutdownMode,
    ) -> Result<core::result::Result<(), SocketError>, Channel::Error> {
        match self.request_socket(SocketRequest::Shutdown(ShutdownSocketRequest {
            handle,
            mode,
        }))? {
            SocketResponse::Shutdown => Ok(Ok(())),
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected socket shutdown response: {response:?}"),
        }
    }

    fn validate_socket_buffer(&self, buffer: SharedBufferDescriptor, data_len: usize) {
        assert!(
            buffer.length <= MAX_SOCKET_TRANSFER_SIZE,
            "shared socket descriptor exceeds the transfer limit"
        );
        assert_eq!(
            data_len, buffer.length as usize,
            "shared socket data must match its descriptor"
        );
        self.shared_buffers
            .layout()
            .range(buffer.slot_index, data_len)
            .expect("shared socket descriptor must identify a valid slot range");
    }

    fn request_socket(&self, request: SocketRequest) -> Result<SocketResponse, Channel::Error> {
        match self.request(BrokerOperation::Socket(request))? {
            BrokerResult::Socket(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response @ (BrokerResult::ObjectClosed
            | BrokerResult::Readiness(_)
            | BrokerResult::Event(_)
            | BrokerResult::Pipe(_)) => {
                panic!("broker returned unexpected socket response: {response:?}");
            }
        }
    }
}
