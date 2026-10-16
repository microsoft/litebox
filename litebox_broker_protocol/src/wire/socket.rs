// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::net::{Ipv4Addr, SocketAddrV4};
use core::time::Duration;

use crate::message::{SocketRequest, SocketResponse};
use crate::socket::{
    AcceptSocketRequest, AcceptSocketResponse, AddressFamily, BindSocketRequest,
    BindSocketResponse, CheckConnectSocketRequest, ConnectSocketRequest, ConnectSocketResponse,
    CreateSocketRequest, CreateSocketResponse, GetSocketNameRequest, GetSocketNameResponse,
    GetSocketOptionRequest, GetSocketOptionResponse, IpProtocol, ListenSocketRequest,
    ListenSocketResponse, ReceiveFlags, ReceiveFromFlags, ReceiveFromSocketRequest,
    ReceiveFromSocketResponse, ReceiveSocketRequest, ReceiveSocketResponse, SendFlags,
    SendSocketRequest, SendSocketResponse, SendToSocketRequest, SendToSocketResponse,
    SetSocketErrorRequest, SetSocketOptionRequest, ShutdownMode, ShutdownSocketRequest,
    SocketConnectionStatus, SocketError, SocketOptionName, SocketOptionValue, SocketType,
    TakeSocketErrorRequest, TakeSocketErrorResponse,
};

use super::WireError;
use super::fs::decode_open_flags;
use super::primitive::{Decoder, Encoder};

const SOCKET_TAG_CREATE: u8 = 0;
const SOCKET_TAG_CONNECT: u8 = 1;
const SOCKET_TAG_BIND: u8 = 2;
const SOCKET_TAG_LISTEN: u8 = 3;
const SOCKET_TAG_ACCEPT: u8 = 4;
const SOCKET_TAG_SEND: u8 = 5;
const SOCKET_TAG_SEND_TO: u8 = 6;
const SOCKET_TAG_RECEIVE: u8 = 7;
const SOCKET_TAG_RECEIVE_FROM: u8 = 8;
const SOCKET_TAG_SHUTDOWN: u8 = 9;
const SOCKET_TAG_SET_OPTION: u8 = 10;
const SOCKET_TAG_GET_OPTION: u8 = 11;
const SOCKET_TAG_CHECK_CONNECT: u8 = 12;
const SOCKET_TAG_GET_NAME: u8 = 13;
const SOCKET_TAG_TAKE_ERROR: u8 = 14;
const SOCKET_TAG_SET_ERROR: u8 = 15;
const SOCKET_TAG_FAILED: u8 = 16;

const ADDRESS_FAMILY_TAG_IPV4: u8 = 0;

const TYPE_TAG_STREAM: u8 = 0;
const TYPE_TAG_DATAGRAM: u8 = 1;

const IP_PROTOCOL_TAG_TCP: u8 = 0;
const IP_PROTOCOL_TAG_UDP: u8 = 1;

const SHUTDOWN_TAG_READ: u8 = 0;
const SHUTDOWN_TAG_WRITE: u8 = 1;
const SHUTDOWN_TAG_BOTH: u8 = 2;
const SHUTDOWN_TAG_ABORT: u8 = 3;
const SHUTDOWN_TAG_STOP_LISTENING: u8 = 4;

const CONNECTION_STATUS_TAG_UNCONNECTED: u8 = 0;
const CONNECTION_STATUS_TAG_CONNECTING: u8 = 1;
const CONNECTION_STATUS_TAG_CONNECTED: u8 = 2;
const CONNECTION_STATUS_TAG_FAILED: u8 = 3;

const RECEIVE_RESPONSE_TAG_RECEIVED: u8 = 0;
const RECEIVE_RESPONSE_TAG_END_OF_STREAM: u8 = 1;

const OPTION_TAG_RECEIVE_TIMEOUT: u8 = 0;
const OPTION_TAG_SEND_TIMEOUT: u8 = 1;
const OPTION_TAG_LINGER: u8 = 2;
const OPTION_TAG_REUSE_ADDRESS: u8 = 3;
const OPTION_TAG_KEEP_ALIVE: u8 = 4;
const OPTION_TAG_BROADCAST: u8 = 5;
const OPTION_TAG_NO_DELAY: u8 = 6;

pub(super) fn encode_socket_request(encoder: &mut Encoder, request: SocketRequest) {
    match request {
        SocketRequest::Create(request) => {
            encoder.u8(SOCKET_TAG_CREATE);
            encoder.u8(match request.address_family {
                AddressFamily::Ipv4 => ADDRESS_FAMILY_TAG_IPV4,
            });
            encode_socket_type(encoder, request.socket_type);
            encoder.u8(match request.protocol {
                IpProtocol::Tcp => IP_PROTOCOL_TAG_TCP,
                IpProtocol::Udp => IP_PROTOCOL_TAG_UDP,
            });
            encoder.u16(request.flags.bits());
        }
        SocketRequest::Connect(request) => {
            encoder.u8(SOCKET_TAG_CONNECT);
            encoder.handle(request.handle);
            encode_address(encoder, request.address);
        }
        SocketRequest::Bind(request) => {
            encoder.u8(SOCKET_TAG_BIND);
            encoder.handle(request.handle);
            encode_address(encoder, request.address);
        }
        SocketRequest::Listen(request) => {
            encoder.u8(SOCKET_TAG_LISTEN);
            encoder.handle(request.handle);
            encoder.u32(request.backlog);
        }
        SocketRequest::Accept(request) => {
            encoder.u8(SOCKET_TAG_ACCEPT);
            encoder.handle(request.handle);
            encoder.u16(request.flags.bits());
        }
        SocketRequest::Send(request) => {
            encoder.u8(SOCKET_TAG_SEND);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.flags.0);
        }
        SocketRequest::SendTo(request) => {
            encoder.u8(SOCKET_TAG_SEND_TO);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.flags.0);
            encode_optional_address(encoder, request.destination);
        }
        SocketRequest::Receive(request) => {
            encoder.u8(SOCKET_TAG_RECEIVE);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.flags.0);
            encoder.u32(request.peek_offset);
            encoder.u32(request.peek_length);
        }
        SocketRequest::ReceiveFrom(request) => {
            encoder.u8(SOCKET_TAG_RECEIVE_FROM);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.flags.0);
        }
        SocketRequest::Shutdown(request) => {
            encoder.u8(SOCKET_TAG_SHUTDOWN);
            encoder.handle(request.handle);
            encode_shutdown_mode(encoder, request.mode);
        }
        SocketRequest::SetOption(request) => {
            encoder.u8(SOCKET_TAG_SET_OPTION);
            encoder.handle(request.handle);
            encode_option_value(encoder, request.value);
        }
        SocketRequest::GetOption(request) => {
            encoder.u8(SOCKET_TAG_GET_OPTION);
            encoder.handle(request.handle);
            encode_option_name(encoder, request.name);
        }
        SocketRequest::CheckConnect(request) => {
            encoder.u8(SOCKET_TAG_CHECK_CONNECT);
            encoder.handle(request.handle);
        }
        SocketRequest::GetName(request) => {
            encoder.u8(SOCKET_TAG_GET_NAME);
            encoder.handle(request.handle);
            encode_bool(encoder, request.peer);
        }
        SocketRequest::TakeError(request) => {
            encoder.u8(SOCKET_TAG_TAKE_ERROR);
            encoder.handle(request.handle);
        }
        SocketRequest::SetError(request) => {
            encoder.u8(SOCKET_TAG_SET_ERROR);
            encoder.handle(request.handle);
            encode_socket_error(encoder, request.error);
        }
    }
}

pub(super) fn decode_socket_request(decoder: &mut Decoder<'_>) -> Result<SocketRequest, WireError> {
    match decoder.u8()? {
        SOCKET_TAG_CREATE => Ok(SocketRequest::Create(CreateSocketRequest {
            address_family: match decoder.u8()? {
                ADDRESS_FAMILY_TAG_IPV4 => AddressFamily::Ipv4,
                _ => return Err(WireError::InvalidTag),
            },
            socket_type: decode_socket_type(decoder)?,
            protocol: match decoder.u8()? {
                IP_PROTOCOL_TAG_TCP => IpProtocol::Tcp,
                IP_PROTOCOL_TAG_UDP => IpProtocol::Udp,
                _ => return Err(WireError::InvalidTag),
            },
            flags: decode_open_flags(decoder)?,
        })),
        SOCKET_TAG_CONNECT => Ok(SocketRequest::Connect(ConnectSocketRequest {
            handle: decoder.handle()?,
            address: decode_address(decoder)?,
        })),
        SOCKET_TAG_BIND => Ok(SocketRequest::Bind(BindSocketRequest {
            handle: decoder.handle()?,
            address: decode_address(decoder)?,
        })),
        SOCKET_TAG_LISTEN => Ok(SocketRequest::Listen(ListenSocketRequest {
            handle: decoder.handle()?,
            backlog: decoder.u32()?,
        })),
        SOCKET_TAG_ACCEPT => Ok(SocketRequest::Accept(AcceptSocketRequest {
            handle: decoder.handle()?,
            flags: decode_open_flags(decoder)?,
        })),
        SOCKET_TAG_SEND => Ok(SocketRequest::Send(SendSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            flags: SendFlags(decoder.u32()?),
        })),
        SOCKET_TAG_SEND_TO => Ok(SocketRequest::SendTo(SendToSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            flags: SendFlags(decoder.u32()?),
            destination: decode_optional_address(decoder)?,
        })),
        SOCKET_TAG_RECEIVE => Ok(SocketRequest::Receive(ReceiveSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            flags: ReceiveFlags(decoder.u32()?),
            peek_offset: decoder.u32()?,
            peek_length: decoder.u32()?,
        })),
        SOCKET_TAG_RECEIVE_FROM => Ok(SocketRequest::ReceiveFrom(ReceiveFromSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            flags: ReceiveFromFlags(decoder.u32()?),
        })),
        SOCKET_TAG_SHUTDOWN => Ok(SocketRequest::Shutdown(ShutdownSocketRequest {
            handle: decoder.handle()?,
            mode: decode_shutdown_mode(decoder)?,
        })),
        SOCKET_TAG_SET_OPTION => Ok(SocketRequest::SetOption(SetSocketOptionRequest {
            handle: decoder.handle()?,
            value: decode_option_value(decoder)?,
        })),
        SOCKET_TAG_GET_OPTION => Ok(SocketRequest::GetOption(GetSocketOptionRequest {
            handle: decoder.handle()?,
            name: decode_option_name(decoder)?,
        })),
        SOCKET_TAG_CHECK_CONNECT => Ok(SocketRequest::CheckConnect(CheckConnectSocketRequest {
            handle: decoder.handle()?,
        })),
        SOCKET_TAG_GET_NAME => Ok(SocketRequest::GetName(GetSocketNameRequest {
            handle: decoder.handle()?,
            peer: decode_bool(decoder)?,
        })),
        SOCKET_TAG_TAKE_ERROR => Ok(SocketRequest::TakeError(TakeSocketErrorRequest {
            handle: decoder.handle()?,
        })),
        SOCKET_TAG_SET_ERROR => Ok(SocketRequest::SetError(SetSocketErrorRequest {
            handle: decoder.handle()?,
            error: decode_socket_error(decoder)?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_socket_response(encoder: &mut Encoder, response: SocketResponse) {
    match response {
        SocketResponse::Create(response) => {
            encoder.u8(SOCKET_TAG_CREATE);
            encoder.handle(response.handle);
        }
        SocketResponse::Connect(response) => {
            encoder.u8(SOCKET_TAG_CONNECT);
            encode_connection_status(encoder, response.status);
        }
        SocketResponse::Bind(response) => {
            encoder.u8(SOCKET_TAG_BIND);
            encode_address(encoder, response.local_address);
        }
        SocketResponse::Listen(response) => {
            encoder.u8(SOCKET_TAG_LISTEN);
            encode_address(encoder, response.local_address);
        }
        SocketResponse::Accept(response) => {
            encoder.u8(SOCKET_TAG_ACCEPT);
            encoder.handle(response.handle);
            encode_address(encoder, response.local_address);
            encode_address(encoder, response.remote_address);
        }
        SocketResponse::Send(response) => {
            encoder.u8(SOCKET_TAG_SEND);
            encoder.u32(response.sent);
        }
        SocketResponse::SendTo(response) => {
            encoder.u8(SOCKET_TAG_SEND_TO);
            encoder.u32(response.sent);
        }
        SocketResponse::Receive(response) => {
            encoder.u8(SOCKET_TAG_RECEIVE);
            match response {
                ReceiveSocketResponse::Received(received) => {
                    encoder.u8(RECEIVE_RESPONSE_TAG_RECEIVED);
                    encoder.u32(received);
                }
                ReceiveSocketResponse::EndOfStream => {
                    encoder.u8(RECEIVE_RESPONSE_TAG_END_OF_STREAM);
                }
            }
        }
        SocketResponse::ReceiveFrom(response) => {
            encoder.u8(SOCKET_TAG_RECEIVE_FROM);
            encoder.u32(response.received);
            encoder.u32(response.datagram_length);
            encode_address(encoder, response.source_address);
        }
        SocketResponse::Shutdown => encoder.u8(SOCKET_TAG_SHUTDOWN),
        SocketResponse::SetOption => encoder.u8(SOCKET_TAG_SET_OPTION),
        SocketResponse::GetOption(response) => {
            encoder.u8(SOCKET_TAG_GET_OPTION);
            encode_option_value(encoder, response.value);
        }
        SocketResponse::CheckConnect(response) => {
            encoder.u8(SOCKET_TAG_CHECK_CONNECT);
            encode_connection_status(encoder, response.status);
        }
        SocketResponse::GetName(response) => {
            encoder.u8(SOCKET_TAG_GET_NAME);
            encode_optional_address(encoder, response.address);
        }
        SocketResponse::TakeError(response) => {
            encoder.u8(SOCKET_TAG_TAKE_ERROR);
            encode_optional_socket_error(encoder, response.error);
        }
        SocketResponse::SetError => encoder.u8(SOCKET_TAG_SET_ERROR),
        SocketResponse::Failed(error) => {
            encoder.u8(SOCKET_TAG_FAILED);
            encode_socket_error(encoder, error);
        }
    }
}

pub(super) fn decode_socket_response(
    decoder: &mut Decoder<'_>,
) -> Result<SocketResponse, WireError> {
    match decoder.u8()? {
        SOCKET_TAG_CREATE => Ok(SocketResponse::Create(CreateSocketResponse {
            handle: decoder.handle()?,
        })),
        SOCKET_TAG_CONNECT => Ok(SocketResponse::Connect(ConnectSocketResponse {
            status: decode_connection_status(decoder)?,
        })),
        SOCKET_TAG_BIND => Ok(SocketResponse::Bind(BindSocketResponse {
            local_address: decode_address(decoder)?,
        })),
        SOCKET_TAG_LISTEN => Ok(SocketResponse::Listen(ListenSocketResponse {
            local_address: decode_address(decoder)?,
        })),
        SOCKET_TAG_ACCEPT => Ok(SocketResponse::Accept(AcceptSocketResponse {
            handle: decoder.handle()?,
            local_address: decode_address(decoder)?,
            remote_address: decode_address(decoder)?,
        })),
        SOCKET_TAG_SEND => Ok(SocketResponse::Send(SendSocketResponse {
            sent: decoder.u32()?,
        })),
        SOCKET_TAG_SEND_TO => Ok(SocketResponse::SendTo(SendToSocketResponse {
            sent: decoder.u32()?,
        })),
        SOCKET_TAG_RECEIVE => Ok(SocketResponse::Receive(match decoder.u8()? {
            RECEIVE_RESPONSE_TAG_RECEIVED => ReceiveSocketResponse::Received(decoder.u32()?),
            RECEIVE_RESPONSE_TAG_END_OF_STREAM => ReceiveSocketResponse::EndOfStream,
            _ => return Err(WireError::InvalidTag),
        })),
        SOCKET_TAG_RECEIVE_FROM => Ok(SocketResponse::ReceiveFrom(ReceiveFromSocketResponse {
            received: decoder.u32()?,
            datagram_length: decoder.u32()?,
            source_address: decode_address(decoder)?,
        })),
        SOCKET_TAG_SHUTDOWN => Ok(SocketResponse::Shutdown),
        SOCKET_TAG_SET_OPTION => Ok(SocketResponse::SetOption),
        SOCKET_TAG_GET_OPTION => Ok(SocketResponse::GetOption(GetSocketOptionResponse {
            value: decode_option_value(decoder)?,
        })),
        SOCKET_TAG_CHECK_CONNECT => Ok(SocketResponse::CheckConnect(ConnectSocketResponse {
            status: decode_connection_status(decoder)?,
        })),
        SOCKET_TAG_GET_NAME => Ok(SocketResponse::GetName(GetSocketNameResponse {
            address: decode_optional_address(decoder)?,
        })),
        SOCKET_TAG_TAKE_ERROR => Ok(SocketResponse::TakeError(TakeSocketErrorResponse {
            error: decode_optional_socket_error(decoder)?,
        })),
        SOCKET_TAG_SET_ERROR => Ok(SocketResponse::SetError),
        SOCKET_TAG_FAILED => Ok(SocketResponse::Failed(decode_socket_error(decoder)?)),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_socket_type(encoder: &mut Encoder, socket_type: SocketType) {
    encoder.u8(match socket_type {
        SocketType::Stream => TYPE_TAG_STREAM,
        SocketType::Datagram => TYPE_TAG_DATAGRAM,
    });
}

pub(super) fn decode_socket_type(decoder: &mut Decoder<'_>) -> Result<SocketType, WireError> {
    match decoder.u8()? {
        TYPE_TAG_STREAM => Ok(SocketType::Stream),
        TYPE_TAG_DATAGRAM => Ok(SocketType::Datagram),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_shutdown_mode(encoder: &mut Encoder, mode: ShutdownMode) {
    encoder.u8(match mode {
        ShutdownMode::Read => SHUTDOWN_TAG_READ,
        ShutdownMode::Write => SHUTDOWN_TAG_WRITE,
        ShutdownMode::Both => SHUTDOWN_TAG_BOTH,
        ShutdownMode::Abort => SHUTDOWN_TAG_ABORT,
        ShutdownMode::StopListening => SHUTDOWN_TAG_STOP_LISTENING,
    });
}

pub(super) fn decode_shutdown_mode(decoder: &mut Decoder<'_>) -> Result<ShutdownMode, WireError> {
    match decoder.u8()? {
        SHUTDOWN_TAG_READ => Ok(ShutdownMode::Read),
        SHUTDOWN_TAG_WRITE => Ok(ShutdownMode::Write),
        SHUTDOWN_TAG_BOTH => Ok(ShutdownMode::Both),
        SHUTDOWN_TAG_ABORT => Ok(ShutdownMode::Abort),
        SHUTDOWN_TAG_STOP_LISTENING => Ok(ShutdownMode::StopListening),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_bool(encoder: &mut Encoder, value: bool) {
    encoder.u8(u8::from(value));
}

pub(super) fn decode_bool(decoder: &mut Decoder<'_>) -> Result<bool, WireError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_duration(encoder: &mut Encoder, duration: Option<Duration>) {
    match duration {
        None => encoder.u8(0),
        Some(duration) => {
            encoder.u8(1);
            encoder.u64(duration.as_secs());
            encoder.u32(duration.subsec_nanos());
        }
    }
}

pub(super) fn decode_duration(decoder: &mut Decoder<'_>) -> Result<Option<Duration>, WireError> {
    if !decode_bool(decoder)? {
        return Ok(None);
    }
    let seconds = decoder.u64()?;
    let nanoseconds = decoder.u32()?;
    if nanoseconds >= 1_000_000_000 {
        return Err(WireError::InvalidTag);
    }
    Ok(Some(Duration::new(seconds, nanoseconds)))
}

pub(super) fn encode_option_name(encoder: &mut Encoder, name: SocketOptionName) {
    encoder.u8(match name {
        SocketOptionName::ReceiveTimeout => OPTION_TAG_RECEIVE_TIMEOUT,
        SocketOptionName::SendTimeout => OPTION_TAG_SEND_TIMEOUT,
        SocketOptionName::Linger => OPTION_TAG_LINGER,
        SocketOptionName::ReuseAddress => OPTION_TAG_REUSE_ADDRESS,
        SocketOptionName::KeepAlive => OPTION_TAG_KEEP_ALIVE,
        SocketOptionName::Broadcast => OPTION_TAG_BROADCAST,
        SocketOptionName::NoDelay => OPTION_TAG_NO_DELAY,
    });
}

pub(super) fn decode_option_name(decoder: &mut Decoder<'_>) -> Result<SocketOptionName, WireError> {
    Ok(match decoder.u8()? {
        OPTION_TAG_RECEIVE_TIMEOUT => SocketOptionName::ReceiveTimeout,
        OPTION_TAG_SEND_TIMEOUT => SocketOptionName::SendTimeout,
        OPTION_TAG_LINGER => SocketOptionName::Linger,
        OPTION_TAG_REUSE_ADDRESS => SocketOptionName::ReuseAddress,
        OPTION_TAG_KEEP_ALIVE => SocketOptionName::KeepAlive,
        OPTION_TAG_BROADCAST => SocketOptionName::Broadcast,
        OPTION_TAG_NO_DELAY => SocketOptionName::NoDelay,
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_option_value(encoder: &mut Encoder, value: SocketOptionValue) {
    encode_option_name(encoder, value.name());
    match value {
        SocketOptionValue::ReceiveTimeout(timeout)
        | SocketOptionValue::SendTimeout(timeout)
        | SocketOptionValue::Linger(timeout) => encode_duration(encoder, timeout),
        SocketOptionValue::ReuseAddress(value)
        | SocketOptionValue::KeepAlive(value)
        | SocketOptionValue::Broadcast(value)
        | SocketOptionValue::NoDelay(value) => encode_bool(encoder, value),
    }
}

pub(super) fn decode_option_value(
    decoder: &mut Decoder<'_>,
) -> Result<SocketOptionValue, WireError> {
    Ok(match decode_option_name(decoder)? {
        SocketOptionName::ReceiveTimeout => {
            SocketOptionValue::ReceiveTimeout(decode_duration(decoder)?)
        }
        SocketOptionName::SendTimeout => SocketOptionValue::SendTimeout(decode_duration(decoder)?),
        SocketOptionName::Linger => SocketOptionValue::Linger(decode_duration(decoder)?),
        SocketOptionName::ReuseAddress => SocketOptionValue::ReuseAddress(decode_bool(decoder)?),
        SocketOptionName::KeepAlive => SocketOptionValue::KeepAlive(decode_bool(decoder)?),
        SocketOptionName::Broadcast => SocketOptionValue::Broadcast(decode_bool(decoder)?),
        SocketOptionName::NoDelay => SocketOptionValue::NoDelay(decode_bool(decoder)?),
    })
}

fn encode_connection_status(encoder: &mut Encoder, status: SocketConnectionStatus) {
    match status {
        SocketConnectionStatus::Unconnected => encoder.u8(CONNECTION_STATUS_TAG_UNCONNECTED),
        SocketConnectionStatus::Connecting => encoder.u8(CONNECTION_STATUS_TAG_CONNECTING),
        SocketConnectionStatus::Connected => encoder.u8(CONNECTION_STATUS_TAG_CONNECTED),
        SocketConnectionStatus::Failed(error) => {
            encoder.u8(CONNECTION_STATUS_TAG_FAILED);
            encode_socket_error(encoder, error);
        }
    }
}

fn decode_connection_status(
    decoder: &mut Decoder<'_>,
) -> Result<SocketConnectionStatus, WireError> {
    match decoder.u8()? {
        CONNECTION_STATUS_TAG_UNCONNECTED => Ok(SocketConnectionStatus::Unconnected),
        CONNECTION_STATUS_TAG_CONNECTING => Ok(SocketConnectionStatus::Connecting),
        CONNECTION_STATUS_TAG_CONNECTED => Ok(SocketConnectionStatus::Connected),
        CONNECTION_STATUS_TAG_FAILED => Ok(SocketConnectionStatus::Failed(decode_socket_error(
            decoder,
        )?)),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_socket_error(encoder: &mut Encoder, error: SocketError) {
    encoder.u8(match error {
        SocketError::ConnectionRefused => 1,
        SocketError::ConnectionReset => 2,
        SocketError::ConnectionAborted => 3,
        SocketError::NetworkUnreachable => 4,
        SocketError::HostUnreachable => 5,
        SocketError::TimedOut => 6,
        SocketError::AddressInUse => 7,
        SocketError::AddressNotAvailable => 8,
        SocketError::PolicyDenied => 9,
        SocketError::Other => 10,
        SocketError::NotConnected => 11,
        SocketError::InvalidArgument => 12,
        SocketError::AlreadyConnected => 13,
        SocketError::AlreadyInProgress => 14,
        SocketError::Shutdown => 15,
        SocketError::DestinationAddressRequired => 16,
        SocketError::Listening => 17,
        SocketError::ResourceExhausted => 18,
        SocketError::UnsupportedOperation => 19,
    });
}

fn decode_socket_error(decoder: &mut Decoder<'_>) -> Result<SocketError, WireError> {
    match decoder.u8()? {
        1 => Ok(SocketError::ConnectionRefused),
        2 => Ok(SocketError::ConnectionReset),
        3 => Ok(SocketError::ConnectionAborted),
        4 => Ok(SocketError::NetworkUnreachable),
        5 => Ok(SocketError::HostUnreachable),
        6 => Ok(SocketError::TimedOut),
        7 => Ok(SocketError::AddressInUse),
        8 => Ok(SocketError::AddressNotAvailable),
        9 => Ok(SocketError::PolicyDenied),
        10 => Ok(SocketError::Other),
        11 => Ok(SocketError::NotConnected),
        12 => Ok(SocketError::InvalidArgument),
        13 => Ok(SocketError::AlreadyConnected),
        14 => Ok(SocketError::AlreadyInProgress),
        15 => Ok(SocketError::Shutdown),
        16 => Ok(SocketError::DestinationAddressRequired),
        17 => Ok(SocketError::Listening),
        18 => Ok(SocketError::ResourceExhausted),
        19 => Ok(SocketError::UnsupportedOperation),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_address(encoder: &mut Encoder, address: SocketAddrV4) {
    for octet in address.ip().octets() {
        encoder.u8(octet);
    }
    encoder.u16(address.port());
}

fn decode_address(decoder: &mut Decoder<'_>) -> Result<SocketAddrV4, WireError> {
    let mut octets = [0; 4];
    for octet in &mut octets {
        *octet = decoder.u8()?;
    }
    Ok(SocketAddrV4::new(Ipv4Addr::from(octets), decoder.u16()?))
}

fn encode_optional_address(encoder: &mut Encoder, address: Option<SocketAddrV4>) {
    encoder.u8(u8::from(address.is_some()));
    if let Some(address) = address {
        encode_address(encoder, address);
    }
}

fn decode_optional_address(decoder: &mut Decoder<'_>) -> Result<Option<SocketAddrV4>, WireError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => decode_address(decoder).map(Some),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_optional_socket_error(encoder: &mut Encoder, error: Option<SocketError>) {
    encoder.u8(u8::from(error.is_some()));
    if let Some(error) = error {
        encode_socket_error(encoder, error);
    }
}

fn decode_optional_socket_error(
    decoder: &mut Decoder<'_>,
) -> Result<Option<SocketError>, WireError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => decode_socket_error(decoder).map(Some),
        _ => Err(WireError::InvalidTag),
    }
}
