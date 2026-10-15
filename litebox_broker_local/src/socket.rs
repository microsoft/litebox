// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::net::SocketAddrV4;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::FileOpenFlags;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, SocketRequest, SocketResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_protocol::socket::{
    AcceptSocketRequest, AcceptSocketResponse, AddressFamily, BindSocketRequest,
    CheckConnectSocketRequest, ConnectSocketRequest, CreateSocketRequest, GetSocketNameRequest,
    GetSocketOptionRequest, IpProtocol, ListenSocketRequest, MAX_SOCKET_TRANSFER_SIZE,
    MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags, ReceiveFromSocketRequest, ReceiveFromSocketResponse,
    ReceiveSocketRequest, ReceiveSocketResponse, SendFlags, SendSocketRequest, SendToSocketRequest,
    SetSocketErrorRequest, SetSocketOptionRequest, ShutdownMode, ShutdownSocketRequest,
    SocketConnectionStatus, SocketError, SocketOptionName, SocketOptionValue, SocketType,
    TakeSocketErrorRequest,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned IPv4 TCP stream socket with the status flags
    /// `flags`.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_tcp_socket(&self, flags: FileOpenFlags) -> Result<ObjectHandle, Channel::Error> {
        let response = self.request_socket(SocketRequest::Create(CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Stream,
            protocol: IpProtocol::Tcp,
            flags,
        }))?;
        let SocketResponse::Create(response) = response else {
            panic!("broker returned unexpected socket create response: {response:?}");
        };
        Ok(response.handle)
    }

    /// Creates a broker-owned IPv4 UDP datagram socket with the status flags
    /// `flags`.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_udp_socket(&self, flags: FileOpenFlags) -> Result<ObjectHandle, Channel::Error> {
        let response = self.request_socket(SocketRequest::Create(CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
            flags,
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
    use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse};
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_POOL_SIZE, SHARED_BUFFER_SLOT_SIZE, SharedBufferSlotIndex,
    };
    use litebox_broker_transport::shared_memory::{SharedMemory, SharedMemoryError};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use crate::test_support::test_broker_local;

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
        let local = test_broker_local(channel, memory.clone());

        assert_eq!(
            local.create_udp_socket(FileOpenFlags::NONE).unwrap(),
            handle
        );
        assert_eq!(
            local
                .send_to_socket(
                    handle,
                    sequence(0, 3),
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
                    sequence(1, 2),
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

    #[test]
    fn socket_options_use_typed_requests() {
        let handle = ObjectHandle(7);
        let timeout = Some(core::time::Duration::from_secs(3));
        let channel = ScriptedChannel::new([
            BrokerResult::Socket(SocketResponse::SetOption),
            BrokerResult::Socket(SocketResponse::GetOption(
                litebox_broker_protocol::socket::GetSocketOptionResponse {
                    value: SocketOptionValue::NoDelay(true),
                },
            )),
            BrokerResult::Socket(SocketResponse::GetOption(
                litebox_broker_protocol::socket::GetSocketOptionResponse {
                    value: SocketOptionValue::ReceiveTimeout(timeout),
                },
            )),
        ]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let local = test_broker_local(channel, memory);

        local
            .set_socket_option(handle, SocketOptionValue::NoDelay(true))
            .unwrap();
        assert_eq!(
            local
                .get_socket_option(handle, SocketOptionName::NoDelay)
                .unwrap(),
            SocketOptionValue::NoDelay(true)
        );
        assert_eq!(
            local
                .get_socket_option(handle, SocketOptionName::ReceiveTimeout)
                .unwrap(),
            SocketOptionValue::ReceiveTimeout(timeout)
        );
        assert_eq!(
            local.channel.sent_operations.borrow().as_slice(),
            [
                BrokerOperation::Socket(SocketRequest::SetOption(SetSocketOptionRequest {
                    handle,
                    value: SocketOptionValue::NoDelay(true),
                })),
                BrokerOperation::Socket(SocketRequest::GetOption(GetSocketOptionRequest {
                    handle,
                    name: SocketOptionName::NoDelay,
                })),
                BrokerOperation::Socket(SocketRequest::GetOption(GetSocketOptionRequest {
                    handle,
                    name: SocketOptionName::ReceiveTimeout,
                })),
            ]
        );
    }

    fn sequence(slot: u32, length: u32) -> SharedBufferSequence {
        SharedBufferSequence::new(&[SharedBufferSlotIndex(slot)], length).unwrap()
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

    /// Accepts one pending connection from a broker-owned TCP listener into a
    /// socket with the status flags `flags`.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn accept_socket(
        &self,
        handle: ObjectHandle,
        flags: FileOpenFlags,
    ) -> Result<core::result::Result<AcceptSocketResponse, SocketError>, Channel::Error> {
        match self.request_socket(SocketRequest::Accept(AcceptSocketRequest { handle, flags }))? {
            SocketResponse::Accept(response) => Ok(Ok(response)),
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected socket accept response: {response:?}"),
        }
    }

    /// Reports the progress of a broker-owned socket's connection attempt.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn check_connect_socket(
        &self,
        handle: ObjectHandle,
    ) -> Result<core::result::Result<SocketConnectionStatus, SocketError>, Channel::Error> {
        match self.request_socket(SocketRequest::CheckConnect(CheckConnectSocketRequest {
            handle,
        }))? {
            SocketResponse::CheckConnect(response) => Ok(Ok(response.status)),
            SocketResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected socket check-connect response: {response:?}")
            }
        }
    }

    /// Returns a broker-owned socket's local address, or if `peer` is set,
    /// its connected peer's address.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn get_socket_name(
        &self,
        handle: ObjectHandle,
        peer: bool,
    ) -> Result<Option<SocketAddrV4>, Channel::Error> {
        let response = self.request_socket(SocketRequest::GetName(GetSocketNameRequest {
            handle,
            peer,
        }))?;
        let SocketResponse::GetName(response) = response else {
            panic!("broker returned unexpected socket name response: {response:?}");
        };
        Ok(response.address)
    }

    /// Takes a broker-owned socket's oldest pending error.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn take_socket_error(
        &self,
        handle: ObjectHandle,
    ) -> Result<Option<SocketError>, Channel::Error> {
        let response =
            self.request_socket(SocketRequest::TakeError(TakeSocketErrorRequest { handle }))?;
        let SocketResponse::TakeError(response) = response else {
            panic!("broker returned unexpected socket take-error response: {response:?}");
        };
        Ok(response.error)
    }

    /// Makes `error` a broker-owned socket's oldest pending error.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn set_socket_error(
        &self,
        handle: ObjectHandle,
        error: SocketError,
    ) -> Result<(), Channel::Error> {
        let response = self.request_socket(SocketRequest::SetError(SetSocketErrorRequest {
            handle,
            error,
        }))?;
        let SocketResponse::SetError = response else {
            panic!("broker returned unexpected socket set-error response: {response:?}");
        };
        Ok(())
    }

    /// Sets one option of a broker-owned socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn set_socket_option(
        &self,
        handle: ObjectHandle,
        value: SocketOptionValue,
    ) -> Result<(), Channel::Error> {
        let response = self.request_socket(SocketRequest::SetOption(SetSocketOptionRequest {
            handle,
            value,
        }))?;
        assert_eq!(
            response,
            SocketResponse::SetOption,
            "broker returned unexpected socket option set response"
        );
        Ok(())
    }

    /// Reads one option of a broker-owned socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation or
    /// a value for a different option.
    pub fn get_socket_option(
        &self,
        handle: ObjectHandle,
        name: SocketOptionName,
    ) -> Result<SocketOptionValue, Channel::Error> {
        let response = self.request_socket(SocketRequest::GetOption(GetSocketOptionRequest {
            handle,
            name,
        }))?;
        let SocketResponse::GetOption(response) = response else {
            panic!("broker returned unexpected socket option get response: {response:?}");
        };
        assert_eq!(
            response.value.name(),
            name,
            "broker returned a mismatched socket option value"
        );
        Ok(response.value)
    }

    /// Sends bytes from an operation-scoped shared-buffer lease.
    ///
    /// The caller must retain exclusive ownership of the sequence's slots
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the sequence does not match `data`, or if the broker
    /// returns a mismatched or oversized response.
    pub fn send_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        data: &[u8],
        flags: SendFlags,
    ) -> Result<core::result::Result<usize, SocketError>, Channel::Error> {
        assert!(
            buffer.length() <= MAX_SOCKET_TRANSFER_SIZE,
            "shared socket sequence exceeds the transfer limit"
        );
        self.write_shared_buffer(buffer, data);
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
    /// Panics if the sequence does not match `data`, or if the broker
    /// returns a mismatched or non-atomic response.
    pub fn send_to_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        data: &[u8],
        flags: SendFlags,
        destination: Option<SocketAddrV4>,
    ) -> Result<core::result::Result<usize, SocketError>, Channel::Error> {
        assert!(
            buffer.length() <= MAX_UDP_DATAGRAM_SIZE,
            "shared UDP sequence exceeds the datagram limit"
        );
        self.write_shared_buffer(buffer, data);
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
    /// The caller must retain exclusive ownership of the sequence's slots
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the sequence does not match `destination`, or if the broker
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
                        received <= request.buffer.length(),
                        "broker returned oversized socket receive"
                    );
                    if copy_received {
                        let received = received as usize;
                        self.read_shared_buffer(request.buffer, &mut destination[..received]);
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
    /// Panics if the sequence does not match `destination`, or if the broker
    /// returns inconsistent datagram lengths.
    pub fn receive_from_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
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
                    response.received <= buffer.length(),
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
                self.read_shared_buffer(buffer, &mut destination[..received]);
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

    fn validate_socket_buffer(&self, buffer: SharedBufferSequence, data_len: usize) {
        assert!(
            buffer.length() <= MAX_SOCKET_TRANSFER_SIZE,
            "shared socket sequence exceeds the transfer limit"
        );
        assert_eq!(
            data_len,
            buffer.length() as usize,
            "shared data must match its buffer sequence"
        );
        let _ = buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges");
    }

    fn validate_udp_buffer(&self, buffer: SharedBufferSequence, data_len: usize) {
        assert!(
            buffer.length() <= MAX_UDP_DATAGRAM_SIZE,
            "shared UDP sequence exceeds the datagram limit"
        );
        assert_eq!(
            data_len,
            buffer.length() as usize,
            "shared data must match its buffer sequence"
        );
        let _ = buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges");
    }

    fn request_socket(&self, request: SocketRequest) -> Result<SocketResponse, Channel::Error> {
        match self.request(BrokerOperation::Socket(request))? {
            BrokerResult::Socket(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
                panic!("broker returned unexpected socket response: {response:?}");
            }
        }
    }
}
