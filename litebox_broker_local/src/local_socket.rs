// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{FileMode, FileOpenFlags, FileUser};
use litebox_broker_protocol::local_socket::{
    AcceptLocalSocketRequest, BindLocalSocketRequest, ConnectLocalSocketRequest,
    CreateLocalSocketPairResponse, CreateLocalSocketRequest, GetLocalSocketNameRequest,
    GetLocalSocketOptionsResponse, ListenLocalSocketRequest, LocalSocketError, LocalSocketName,
    LocalSocketOption, MAX_ENCODED_LOCAL_SOCKET_ADDRESS_SIZE, MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE,
    MAX_LOCAL_SOCKET_TRANSFER_SIZE, ReceiveLocalSocketRequest, ReceiveLocalSocketResponse,
    SendLocalSocketRequest, SetLocalSocketOptionRequest, ShutdownLocalSocketRequest,
};
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, LocalSocketRequest, LocalSocketResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_protocol::socket::{ShutdownMode, SocketType};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

type LocalSocketResult<T> = core::result::Result<T, LocalSocketError>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned local socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_local_socket(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<ObjectHandle, Channel::Error> {
        match self.request_local_socket(LocalSocketRequest::Create(CreateLocalSocketRequest {
            socket_type,
            flags,
        }))? {
            LocalSocketResponse::Create(response) => Ok(response.handle),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Creates a pair of connected broker-owned local sockets.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_local_socket_pair(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<CreateLocalSocketPairResponse, Channel::Error> {
        match self.request_local_socket(LocalSocketRequest::CreatePair(
            CreateLocalSocketRequest { socket_type, flags },
        ))? {
            LocalSocketResponse::CreatePair(response) => Ok(response),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Binds a local socket to an encoded address staged in `buffer`.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` does not match `address` or the broker returns a
    /// response for a different operation.
    pub fn bind_local_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        address: &[u8],
        user: FileUser,
        mode: FileMode,
    ) -> Result<LocalSocketResult<()>, Channel::Error> {
        self.stage_local_socket_buffer(buffer, address, MAX_ENCODED_LOCAL_SOCKET_ADDRESS_SIZE)?;
        match self.request_local_socket(LocalSocketRequest::Bind(BindLocalSocketRequest {
            handle,
            address: buffer,
            user,
            mode,
        }))? {
            LocalSocketResponse::Bind => Ok(Ok(())),
            LocalSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Makes a bound stream socket accept connections.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn listen_local_socket(
        &self,
        handle: ObjectHandle,
        backlog: u32,
    ) -> Result<LocalSocketResult<()>, Channel::Error> {
        match self.request_local_socket(LocalSocketRequest::Listen(ListenLocalSocketRequest {
            handle,
            backlog,
        }))? {
            LocalSocketResponse::Listen => Ok(Ok(())),
            LocalSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Connects a local socket to an encoded address staged in `buffer`.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` does not match `address` or the broker returns a
    /// response for a different operation.
    pub fn connect_local_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        address: &[u8],
        user: FileUser,
    ) -> Result<LocalSocketResult<()>, Channel::Error> {
        self.stage_local_socket_buffer(buffer, address, MAX_ENCODED_LOCAL_SOCKET_ADDRESS_SIZE)?;
        match self.request_local_socket(LocalSocketRequest::Connect(ConnectLocalSocketRequest {
            handle,
            address: buffer,
            user,
        }))? {
            LocalSocketResponse::Connect => Ok(Ok(())),
            LocalSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Accepts one pending connection from a listening local socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn accept_local_socket(
        &self,
        handle: ObjectHandle,
        flags: FileOpenFlags,
    ) -> Result<LocalSocketResult<ObjectHandle>, Channel::Error> {
        match self.request_local_socket(LocalSocketRequest::Accept(AcceptLocalSocketRequest {
            handle,
            flags,
        }))? {
            LocalSocketResponse::Accept(response) => Ok(Ok(response.handle)),
            LocalSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Sends `staged`, an encoded destination address of `address_length`
    /// bytes followed by the data, from a local socket.
    ///
    /// Returns the number of data bytes sent.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` does not match `staged`, `address_length` exceeds
    /// it, or the broker returns an invalid response.
    pub fn send_local_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        staged: &[u8],
        address_length: usize,
        user: FileUser,
    ) -> Result<LocalSocketResult<usize>, Channel::Error> {
        let data_length = staged
            .len()
            .checked_sub(address_length)
            .expect("staged send must hold its address");
        self.stage_local_socket_buffer(buffer, staged, MAX_LOCAL_SOCKET_TRANSFER_SIZE)?;
        match self.request_local_socket(LocalSocketRequest::Send(SendLocalSocketRequest {
            handle,
            buffer,
            address_length: u32::try_from(address_length)
                .expect("staged address fits the transfer limit"),
            user,
        }))? {
            LocalSocketResponse::Send(response) => {
                let sent = response.sent as usize;
                assert!(
                    sent <= data_length && (sent != 0 || data_length == 0),
                    "broker returned an invalid local socket send length"
                );
                Ok(Ok(sent))
            }
            LocalSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Receives data from a local socket into `destination` through
    /// `buffer`, which must hold `destination` plus an encoded name, as for a
    /// non-blocking socket if `nonblocking` is set.
    ///
    /// Returns the received lengths and the sender's name.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` is not `destination.len()` plus
    /// [`MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE`] bytes, or the broker returns an
    /// invalid response.
    pub fn receive_local_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        destination: &mut [u8],
        peek: bool,
        nonblocking: bool,
    ) -> Result<LocalSocketResult<(ReceiveLocalSocketResponse, LocalSocketName)>, Channel::Error>
    {
        let capacity = destination.len();
        self.validate_local_socket_buffer(
            buffer,
            capacity + MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE as usize,
            MAX_LOCAL_SOCKET_TRANSFER_SIZE,
        )?;
        match self.request_local_socket(LocalSocketRequest::Receive(ReceiveLocalSocketRequest {
            handle,
            buffer,
            capacity: u32::try_from(capacity).expect("validated capacity fits in u32"),
            peek,
            nonblocking,
        }))? {
            LocalSocketResponse::Receive(response) => {
                let received = response.received as usize;
                let source_length = response.source_length as usize;
                assert!(
                    received <= capacity
                        && received <= response.length as usize
                        && source_length <= MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE as usize,
                    "broker returned inconsistent local socket receive lengths"
                );
                let mut staged = Vec::new();
                staged
                    .try_reserve_exact(received + source_length)
                    .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
                staged.resize(received + source_length, 0);
                self.read_shared_buffer(buffer, &mut staged);
                let (data, source) = staged.split_at(received);
                destination[..received].copy_from_slice(data);
                let source = LocalSocketName::decode(source)
                    .expect("broker returned an invalid local socket source name");
                Ok(Ok((response, source)))
            }
            LocalSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Shuts down one or both directions of a local socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn shutdown_local_socket(
        &self,
        handle: ObjectHandle,
        mode: ShutdownMode,
    ) -> Result<LocalSocketResult<()>, Channel::Error> {
        match self.request_local_socket(LocalSocketRequest::Shutdown(
            ShutdownLocalSocketRequest { handle, mode },
        ))? {
            LocalSocketResponse::Shutdown => Ok(Ok(())),
            LocalSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Reads the name of a local socket, or of its peer if `peer` is set,
    /// through `buffer` of [`MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE`] bytes.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` has the wrong length or the broker returns an
    /// invalid response.
    pub fn local_socket_name(
        &self,
        handle: ObjectHandle,
        peer: bool,
        buffer: SharedBufferSequence,
    ) -> Result<LocalSocketResult<LocalSocketName>, Channel::Error> {
        self.validate_local_socket_buffer(
            buffer,
            MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE as usize,
            MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE,
        )?;
        match self.request_local_socket(LocalSocketRequest::GetName(GetLocalSocketNameRequest {
            handle,
            peer,
            buffer,
        }))? {
            LocalSocketResponse::GetName(response) => {
                let length = response.length as usize;
                assert!(
                    length <= MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE as usize,
                    "broker returned an oversized local socket name"
                );
                let mut encoded = [0; MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE as usize];
                self.read_shared_buffer(buffer, &mut encoded[..length]);
                Ok(Ok(LocalSocketName::decode(&encoded[..length])
                    .expect("broker returned an invalid local socket name")))
            }
            LocalSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Stores one option of a local socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn set_local_socket_option(
        &self,
        handle: ObjectHandle,
        option: LocalSocketOption,
    ) -> Result<(), Channel::Error> {
        match self.request_local_socket(LocalSocketRequest::SetOption(
            SetLocalSocketOptionRequest { handle, option },
        ))? {
            LocalSocketResponse::SetOption => Ok(()),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    /// Reads the type and stored options of a local socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn local_socket_options(
        &self,
        handle: ObjectHandle,
    ) -> Result<GetLocalSocketOptionsResponse, Channel::Error> {
        match self.request_local_socket(LocalSocketRequest::GetOptions(handle))? {
            LocalSocketResponse::GetOptions(response) => Ok(response),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }

    fn stage_local_socket_buffer(
        &self,
        buffer: SharedBufferSequence,
        data: &[u8],
        max_length: u32,
    ) -> Result<(), Channel::Error> {
        self.validate_local_socket_buffer(buffer, data.len(), max_length)?;
        self.write_shared_buffer(buffer, data);
        Ok(())
    }

    fn validate_local_socket_buffer(
        &self,
        buffer: SharedBufferSequence,
        expected_length: usize,
        max_length: u32,
    ) -> Result<(), Channel::Error> {
        if buffer.length() > max_length {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        assert_eq!(
            expected_length,
            buffer.length() as usize,
            "shared data must match its buffer sequence"
        );
        let _ = buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges");
        Ok(())
    }

    fn request_local_socket(
        &self,
        request: LocalSocketRequest,
    ) -> Result<LocalSocketResponse, Channel::Error> {
        match self.request(BrokerOperation::LocalSocket(request))? {
            BrokerResult::LocalSocket(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected local socket response: {response:?}"),
        }
    }
}
