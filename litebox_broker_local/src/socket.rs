// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::net::SocketAddrV4;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, SocketRequest, SocketResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferDescriptor;
use litebox_broker_protocol::socket::{
    AcceptSocketRequest, AcceptSocketResponse, AddressFamily, BindSocketRequest,
    ConnectSocketRequest, CreateSocketRequest, IpProtocol, ListenSocketRequest,
    MAX_SOCKET_TRANSFER_SIZE, MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags, ReceiveFromSocketRequest,
    ReceiveFromSocketResponse, ReceiveSocketRequest, ReceiveSocketResponse, SendFlags,
    SendSocketRequest, SendToSocketRequest, ShutdownMode, ShutdownSocketRequest,
    SocketConnectionStatus, SocketError, SocketStatusRequest, SocketStatusResponse, SocketType,
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

    /// Creates a broker-owned IPv4 UDP datagram socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_udp_socket(&self) -> Result<ObjectHandle, Channel::Error> {
        let response = self.request_socket(SocketRequest::Create(CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
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
        address: SocketAddrV4,
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
}

#[cfg(test)]
#[expect(
    clippy::items_after_test_module,
    reason = "the test module must access private adapter state while the production methods stay grouped"
)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::cell::RefCell;
    use core::convert::Infallible;
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerRequest, BrokerResponse,
    };
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_POOL_SIZE, SHARED_BUFFER_SLOT_SIZE, SharedBufferSlotIndex,
    };
    use litebox_broker_transport::channel::LocalSetupChannel;
    use litebox_broker_transport::shared_memory::{SharedMemory, SharedMemoryError};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[test]
    fn udp_operations_stage_complete_datagrams() {
        let handle = ObjectHandle(7);
        let channel = ScriptedChannel::new([
            BrokerResult::Socket(SocketResponse::Create(
                litebox_broker_protocol::socket::CreateSocketResponse { handle },
            )),
            BrokerResult::Socket(SocketResponse::SendTo(
                litebox_broker_protocol::socket::SendToSocketResponse { sent: 3 },
            )),
            BrokerResult::Socket(SocketResponse::ReceiveFrom(ReceiveFromSocketResponse {
                received: 2,
                datagram_length: 4,
                source_address: SocketAddrV4::new(core::net::Ipv4Addr::LOCALHOST, 49153),
            })),
        ]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let (local, ()) =
            BrokerLocal::negotiate(channel, |channel| Ok((channel, memory.clone(), ()))).unwrap();

        assert_eq!(local.create_udp_socket().unwrap(), handle);
        assert_eq!(
            local
                .send_to_socket(
                    handle,
                    descriptor(0, 3),
                    &[1, 2, 3],
                    SendFlags::NONE,
                    Some(SocketAddrV4::new(core::net::Ipv4Addr::LOCALHOST, 53)),
                )
                .unwrap(),
            Ok(3)
        );
        let mut staged = [0; 3];
        memory.read(0, &mut staged).unwrap();
        assert_eq!(staged, [1, 2, 3]);

        memory
            .write(SHARED_BUFFER_SLOT_SIZE as usize, &[4, 5])
            .unwrap();
        let mut received = [0; 2];
        assert_eq!(
            local
                .receive_from_socket(
                    handle,
                    descriptor(1, 2),
                    &mut received,
                    ReceiveFromFlags::PEEK,
                )
                .unwrap(),
            Ok(ReceiveFromSocketResponse {
                received: 2,
                datagram_length: 4,
                source_address: SocketAddrV4::new(core::net::Ipv4Addr::LOCALHOST, 49153),
            })
        );
        assert_eq!(received, [4, 5]);
        assert!(matches!(
            local.channel.sent_operations.borrow().as_slice(),
            [
                BrokerOperation::Socket(SocketRequest::Create(CreateSocketRequest {
                    socket_type: SocketType::Datagram,
                    protocol: IpProtocol::Udp,
                    ..
                })),
                BrokerOperation::Socket(SocketRequest::SendTo(_)),
                BrokerOperation::Socket(SocketRequest::ReceiveFrom(_)),
            ]
        ));
    }

    const fn descriptor(slot: u32, length: u32) -> SharedBufferDescriptor {
        SharedBufferDescriptor {
            slot_index: SharedBufferSlotIndex(slot),
            length,
        }
    }

    #[derive(Clone)]
    struct TestSharedMemory(Arc<Mutex<std::vec::Vec<u8>>>);

    impl TestSharedMemory {
        fn new(length: usize) -> Self {
            Self(Arc::new(Mutex::new(std::vec![0; length])))
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(
            &self,
            offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(
                memory
                    .get(offset..end)
                    .ok_or(SharedMemoryError::InvalidRange)?,
            );
            Ok(())
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?
                .copy_from_slice(source);
            Ok(())
        }
    }

    struct ScriptedChannel {
        results: RefCell<VecDeque<BrokerResult>>,
        sent_operations: RefCell<std::vec::Vec<BrokerOperation>>,
    }

    impl ScriptedChannel {
        fn new(results: impl IntoIterator<Item = BrokerResult>) -> Self {
            Self {
                results: RefCell::new(results.into_iter().collect()),
                sent_operations: RefCell::new(std::vec::Vec::new()),
            }
        }
    }

    impl LocalSetupChannel for ScriptedChannel {
        type Error = Infallible;

        fn send_handshake_request(
            &mut self,
            request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            assert_eq!(
                request.protocol_version,
                litebox_broker_protocol::BROKER_PROTOCOL_VERSION
            );
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            }))
        }
    }

    impl LocalCallChannel for ScriptedChannel {
        type Error = Infallible;

        fn call(
            &self,
            request: BrokerRequest,
        ) -> core::result::Result<BrokerResponse, Self::Error> {
            self.sent_operations.borrow_mut().push(request.operation);
            Ok(BrokerResponse {
                request_id: request.request_id,
                result: self
                    .results
                    .borrow_mut()
                    .pop_front()
                    .expect("response requires a scripted result"),
            })
        }
    }
}

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Binds a broker-owned socket to a local IPv4 address.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn bind_socket(
        &self,
        handle: ObjectHandle,
        address: SocketAddrV4,
    ) -> Result<core::result::Result<SocketAddrV4, SocketError>, Channel::Error> {
        match self.request_socket(SocketRequest::Bind(BindSocketRequest { handle, address }))? {
            SocketResponse::Bind(response) => Ok(Ok(response.local_address)),
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected socket bind response: {response:?}"),
        }
    }

    /// Makes a broker-owned TCP socket listen for incoming connections.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn listen_socket(
        &self,
        handle: ObjectHandle,
        backlog: u32,
    ) -> Result<core::result::Result<SocketAddrV4, SocketError>, Channel::Error> {
        match self.request_socket(SocketRequest::Listen(ListenSocketRequest {
            handle,
            backlog,
        }))? {
            SocketResponse::Listen(response) => Ok(Ok(response.local_address)),
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected socket listen response: {response:?}"),
        }
    }

    /// Accepts one pending connection from a broker-owned TCP listener.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn accept_socket(
        &self,
        handle: ObjectHandle,
    ) -> Result<core::result::Result<AcceptSocketResponse, SocketError>, Channel::Error> {
        match self.request_socket(SocketRequest::Accept(AcceptSocketRequest { handle }))? {
            SocketResponse::Accept(response) => Ok(Ok(response)),
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected socket accept response: {response:?}"),
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

    /// Sends one datagram from an operation-scoped shared-buffer lease.
    ///
    /// The destination is omitted only for a connected UDP socket.
    ///
    /// # Panics
    ///
    /// Panics if the descriptor does not match `data`, or if the broker
    /// returns a mismatched or non-atomic response.
    pub fn send_to_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        data: &[u8],
        flags: SendFlags,
        destination: Option<SocketAddrV4>,
    ) -> Result<core::result::Result<usize, SocketError>, Channel::Error> {
        self.validate_udp_buffer(buffer, data.len());
        self.shared_buffers
            .write(buffer.slot_index, data)
            .expect("validated shared UDP send range must be accessible");
        match self.request_socket(SocketRequest::SendTo(SendToSocketRequest {
            handle,
            buffer,
            flags,
            destination,
        }))? {
            SocketResponse::SendTo(response) => {
                let sent = response.sent as usize;
                assert_eq!(sent, data.len(), "broker returned partial UDP send");
                Ok(Ok(sent))
            }
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected UDP send response: {response:?}"),
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

    /// Receives one datagram into an operation-scoped shared-buffer lease.
    ///
    /// # Panics
    ///
    /// Panics if the descriptor does not match `destination`, or if the broker
    /// returns inconsistent datagram lengths.
    pub fn receive_from_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        destination: &mut [u8],
        flags: ReceiveFromFlags,
    ) -> Result<core::result::Result<ReceiveFromSocketResponse, SocketError>, Channel::Error> {
        self.validate_udp_buffer(buffer, destination.len());
        match self.request_socket(SocketRequest::ReceiveFrom(ReceiveFromSocketRequest {
            handle,
            buffer,
            flags,
        }))? {
            SocketResponse::ReceiveFrom(response) => {
                assert!(
                    response.received <= buffer.length,
                    "broker returned oversized UDP receive"
                );
                assert!(
                    response.received <= response.datagram_length,
                    "broker returned inconsistent UDP receive lengths"
                );
                assert!(
                    response.datagram_length <= MAX_UDP_DATAGRAM_SIZE,
                    "broker returned oversized UDP datagram length"
                );
                let received = response.received as usize;
                self.shared_buffers
                    .read(buffer.slot_index, &mut destination[..received])
                    .expect("validated shared UDP receive range must be accessible");
                Ok(Ok(response))
            }
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected UDP receive response: {response:?}"),
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

    fn validate_udp_buffer(&self, buffer: SharedBufferDescriptor, data_len: usize) {
        assert!(
            buffer.length <= MAX_UDP_DATAGRAM_SIZE,
            "shared UDP descriptor exceeds the datagram limit"
        );
        assert_eq!(
            data_len, buffer.length as usize,
            "shared UDP data must match its descriptor"
        );
        self.shared_buffers
            .layout()
            .range(buffer.slot_index, data_len)
            .expect("shared UDP descriptor must identify a valid slot range");
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
