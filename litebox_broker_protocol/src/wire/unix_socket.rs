// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::time::Duration;

use super::WireError;
use super::fs::{
    decode_file_error, decode_mode, decode_open_flags, decode_user, encode_file_error, encode_user,
};
use super::primitive::{Decoder, Encoder};
use super::socket::{
    decode_shutdown_mode, decode_socket_type, encode_shutdown_mode, encode_socket_type,
};
use crate::message::{UnixSocketRequest, UnixSocketResponse};
use crate::unix_socket::{
    AcceptUnixSocketRequest, AcceptUnixSocketResponse, BindUnixSocketRequest,
    ConnectUnixSocketRequest, CreateUnixSocketPairResponse, CreateUnixSocketRequest,
    CreateUnixSocketResponse, GetUnixSocketNameRequest, GetUnixSocketNameResponse,
    GetUnixSocketOptionsResponse, ListenUnixSocketRequest, ReceiveUnixSocketRequest,
    ReceiveUnixSocketResponse, SendUnixSocketRequest, SendUnixSocketResponse,
    SetUnixSocketOptionRequest, ShutdownUnixSocketRequest, UnixSocketError, UnixSocketOption,
    UnixSocketOptions,
};

const TAG_CREATE: u8 = 0;
const TAG_CREATE_PAIR: u8 = 1;
const TAG_BIND: u8 = 2;
const TAG_LISTEN: u8 = 3;
const TAG_CONNECT: u8 = 4;
const TAG_ACCEPT: u8 = 5;
const TAG_SEND: u8 = 6;
const TAG_RECEIVE: u8 = 7;
const TAG_SHUTDOWN: u8 = 8;
const TAG_GET_NAME: u8 = 9;
const TAG_SET_OPTION: u8 = 10;
const TAG_GET_OPTIONS: u8 = 11;
const RESPONSE_TAG_FAILED: u8 = 12;

const OPTION_TAG_RECEIVE_TIMEOUT: u8 = 0;
const OPTION_TAG_SEND_TIMEOUT: u8 = 1;
const OPTION_TAG_LINGER: u8 = 2;
const OPTION_TAG_REUSE_ADDRESS: u8 = 3;
const OPTION_TAG_KEEP_ALIVE: u8 = 4;
const OPTION_TAG_BROADCAST: u8 = 5;

const ERROR_TAG_ADDRESS_IN_USE: u8 = 0;
const ERROR_TAG_CONNECTION_REFUSED: u8 = 1;
const ERROR_TAG_WRONG_TYPE: u8 = 2;
const ERROR_TAG_INVALID_ARGUMENT: u8 = 3;
const ERROR_TAG_ALREADY_CONNECTED: u8 = 4;
const ERROR_TAG_NOT_CONNECTED: u8 = 5;
const ERROR_TAG_UNSUPPORTED: u8 = 6;
const ERROR_TAG_MESSAGE_TOO_LARGE: u8 = 7;
const ERROR_TAG_BROKEN_PIPE: u8 = 8;
const ERROR_TAG_FILE: u8 = 9;
const ERROR_TAG_NOT_PERMITTED: u8 = 10;

pub(super) fn encode_unix_socket_request(encoder: &mut Encoder, request: UnixSocketRequest) {
    match request {
        UnixSocketRequest::Create(request) => {
            encoder.u8(TAG_CREATE);
            encode_create_request(encoder, request);
        }
        UnixSocketRequest::CreatePair(request) => {
            encoder.u8(TAG_CREATE_PAIR);
            encode_create_request(encoder, request);
        }
        UnixSocketRequest::Bind(request) => {
            encoder.u8(TAG_BIND);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.address);
            encode_user(encoder, request.user);
            encoder.u16(request.mode.bits());
        }
        UnixSocketRequest::Listen(request) => {
            encoder.u8(TAG_LISTEN);
            encoder.handle(request.handle);
            encoder.u32(request.backlog);
        }
        UnixSocketRequest::Connect(request) => {
            encoder.u8(TAG_CONNECT);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.address);
            encode_user(encoder, request.user);
        }
        UnixSocketRequest::Accept(request) => {
            encoder.u8(TAG_ACCEPT);
            encoder.handle(request.handle);
            encoder.u16(request.flags.bits());
        }
        UnixSocketRequest::Send(request) => {
            encoder.u8(TAG_SEND);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.address_length);
            encode_user(encoder, request.user);
        }
        UnixSocketRequest::Receive(request) => {
            encoder.u8(TAG_RECEIVE);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.capacity);
            encode_bool(encoder, request.peek);
            encode_bool(encoder, request.nonblocking);
        }
        UnixSocketRequest::Shutdown(request) => {
            encoder.u8(TAG_SHUTDOWN);
            encoder.handle(request.handle);
            encode_shutdown_mode(encoder, request.mode);
        }
        UnixSocketRequest::GetName(request) => {
            encoder.u8(TAG_GET_NAME);
            encoder.handle(request.handle);
            encode_bool(encoder, request.peer);
            encoder.shared_buffer_sequence(request.buffer);
        }
        UnixSocketRequest::SetOption(request) => {
            encoder.u8(TAG_SET_OPTION);
            encoder.handle(request.handle);
            encode_option(encoder, request.option);
        }
        UnixSocketRequest::GetOptions(handle) => {
            encoder.u8(TAG_GET_OPTIONS);
            encoder.handle(handle);
        }
    }
}

pub(super) fn decode_unix_socket_request(
    decoder: &mut Decoder<'_>,
) -> Result<UnixSocketRequest, WireError> {
    Ok(match decoder.u8()? {
        TAG_CREATE => UnixSocketRequest::Create(decode_create_request(decoder)?),
        TAG_CREATE_PAIR => UnixSocketRequest::CreatePair(decode_create_request(decoder)?),
        TAG_BIND => UnixSocketRequest::Bind(BindUnixSocketRequest {
            handle: decoder.handle()?,
            address: decoder.shared_buffer_sequence()?,
            user: decode_user(decoder)?,
            mode: decode_mode(decoder)?,
        }),
        TAG_LISTEN => UnixSocketRequest::Listen(ListenUnixSocketRequest {
            handle: decoder.handle()?,
            backlog: decoder.u32()?,
        }),
        TAG_CONNECT => UnixSocketRequest::Connect(ConnectUnixSocketRequest {
            handle: decoder.handle()?,
            address: decoder.shared_buffer_sequence()?,
            user: decode_user(decoder)?,
        }),
        TAG_ACCEPT => UnixSocketRequest::Accept(AcceptUnixSocketRequest {
            handle: decoder.handle()?,
            flags: decode_open_flags(decoder)?,
        }),
        TAG_SEND => UnixSocketRequest::Send(SendUnixSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            address_length: decoder.u32()?,
            user: decode_user(decoder)?,
        }),
        TAG_RECEIVE => UnixSocketRequest::Receive(ReceiveUnixSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            capacity: decoder.u32()?,
            peek: decode_bool(decoder)?,
            nonblocking: decode_bool(decoder)?,
        }),
        TAG_SHUTDOWN => UnixSocketRequest::Shutdown(ShutdownUnixSocketRequest {
            handle: decoder.handle()?,
            mode: decode_shutdown_mode(decoder)?,
        }),
        TAG_GET_NAME => UnixSocketRequest::GetName(GetUnixSocketNameRequest {
            handle: decoder.handle()?,
            peer: decode_bool(decoder)?,
            buffer: decoder.shared_buffer_sequence()?,
        }),
        TAG_SET_OPTION => UnixSocketRequest::SetOption(SetUnixSocketOptionRequest {
            handle: decoder.handle()?,
            option: decode_option(decoder)?,
        }),
        TAG_GET_OPTIONS => UnixSocketRequest::GetOptions(decoder.handle()?),
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_unix_socket_response(encoder: &mut Encoder, response: UnixSocketResponse) {
    match response {
        UnixSocketResponse::Create(response) => {
            encoder.u8(TAG_CREATE);
            encoder.handle(response.handle);
        }
        UnixSocketResponse::CreatePair(response) => {
            encoder.u8(TAG_CREATE_PAIR);
            encoder.handle(response.first);
            encoder.handle(response.second);
        }
        UnixSocketResponse::Bind => encoder.u8(TAG_BIND),
        UnixSocketResponse::Listen => encoder.u8(TAG_LISTEN),
        UnixSocketResponse::Connect => encoder.u8(TAG_CONNECT),
        UnixSocketResponse::Accept(response) => {
            encoder.u8(TAG_ACCEPT);
            encoder.handle(response.handle);
        }
        UnixSocketResponse::Send(response) => {
            encoder.u8(TAG_SEND);
            encoder.u32(response.sent);
        }
        UnixSocketResponse::Receive(response) => {
            encoder.u8(TAG_RECEIVE);
            encoder.u32(response.received);
            encoder.u32(response.length);
            encoder.u32(response.source_length);
        }
        UnixSocketResponse::Shutdown => encoder.u8(TAG_SHUTDOWN),
        UnixSocketResponse::GetName(response) => {
            encoder.u8(TAG_GET_NAME);
            encoder.u32(response.length);
        }
        UnixSocketResponse::SetOption => encoder.u8(TAG_SET_OPTION),
        UnixSocketResponse::GetOptions(response) => {
            encoder.u8(TAG_GET_OPTIONS);
            encode_socket_type(encoder, response.socket_type);
            encode_options(encoder, response.options);
        }
        UnixSocketResponse::Failed(error) => {
            encoder.u8(RESPONSE_TAG_FAILED);
            encode_error(encoder, error);
        }
    }
}

pub(super) fn decode_unix_socket_response(
    decoder: &mut Decoder<'_>,
) -> Result<UnixSocketResponse, WireError> {
    Ok(match decoder.u8()? {
        TAG_CREATE => UnixSocketResponse::Create(CreateUnixSocketResponse {
            handle: decoder.handle()?,
        }),
        TAG_CREATE_PAIR => UnixSocketResponse::CreatePair(CreateUnixSocketPairResponse {
            first: decoder.handle()?,
            second: decoder.handle()?,
        }),
        TAG_BIND => UnixSocketResponse::Bind,
        TAG_LISTEN => UnixSocketResponse::Listen,
        TAG_CONNECT => UnixSocketResponse::Connect,
        TAG_ACCEPT => UnixSocketResponse::Accept(AcceptUnixSocketResponse {
            handle: decoder.handle()?,
        }),
        TAG_SEND => UnixSocketResponse::Send(SendUnixSocketResponse {
            sent: decoder.u32()?,
        }),
        TAG_RECEIVE => UnixSocketResponse::Receive(ReceiveUnixSocketResponse {
            received: decoder.u32()?,
            length: decoder.u32()?,
            source_length: decoder.u32()?,
        }),
        TAG_SHUTDOWN => UnixSocketResponse::Shutdown,
        TAG_GET_NAME => UnixSocketResponse::GetName(GetUnixSocketNameResponse {
            length: decoder.u32()?,
        }),
        TAG_SET_OPTION => UnixSocketResponse::SetOption,
        TAG_GET_OPTIONS => UnixSocketResponse::GetOptions(GetUnixSocketOptionsResponse {
            socket_type: decode_socket_type(decoder)?,
            options: decode_options(decoder)?,
        }),
        RESPONSE_TAG_FAILED => UnixSocketResponse::Failed(decode_error(decoder)?),
        _ => return Err(WireError::InvalidTag),
    })
}

fn encode_create_request(encoder: &mut Encoder, request: CreateUnixSocketRequest) {
    encode_socket_type(encoder, request.socket_type);
    encoder.u16(request.flags.bits());
}

fn decode_create_request(decoder: &mut Decoder<'_>) -> Result<CreateUnixSocketRequest, WireError> {
    Ok(CreateUnixSocketRequest {
        socket_type: decode_socket_type(decoder)?,
        flags: decode_open_flags(decoder)?,
    })
}

fn encode_bool(encoder: &mut Encoder, value: bool) {
    encoder.u8(u8::from(value));
}

fn decode_bool(decoder: &mut Decoder<'_>) -> Result<bool, WireError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_duration(encoder: &mut Encoder, duration: Option<Duration>) {
    match duration {
        None => encoder.u8(0),
        Some(duration) => {
            encoder.u8(1);
            encoder.u64(duration.as_secs());
            encoder.u32(duration.subsec_nanos());
        }
    }
}

fn decode_duration(decoder: &mut Decoder<'_>) -> Result<Option<Duration>, WireError> {
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

fn encode_option(encoder: &mut Encoder, option: UnixSocketOption) {
    match option {
        UnixSocketOption::ReceiveTimeout(timeout) => {
            encoder.u8(OPTION_TAG_RECEIVE_TIMEOUT);
            encode_duration(encoder, timeout);
        }
        UnixSocketOption::SendTimeout(timeout) => {
            encoder.u8(OPTION_TAG_SEND_TIMEOUT);
            encode_duration(encoder, timeout);
        }
        UnixSocketOption::Linger(timeout) => {
            encoder.u8(OPTION_TAG_LINGER);
            encode_duration(encoder, timeout);
        }
        UnixSocketOption::ReuseAddress(value) => {
            encoder.u8(OPTION_TAG_REUSE_ADDRESS);
            encode_bool(encoder, value);
        }
        UnixSocketOption::KeepAlive(value) => {
            encoder.u8(OPTION_TAG_KEEP_ALIVE);
            encode_bool(encoder, value);
        }
        UnixSocketOption::Broadcast(value) => {
            encoder.u8(OPTION_TAG_BROADCAST);
            encode_bool(encoder, value);
        }
    }
}

fn decode_option(decoder: &mut Decoder<'_>) -> Result<UnixSocketOption, WireError> {
    Ok(match decoder.u8()? {
        OPTION_TAG_RECEIVE_TIMEOUT => UnixSocketOption::ReceiveTimeout(decode_duration(decoder)?),
        OPTION_TAG_SEND_TIMEOUT => UnixSocketOption::SendTimeout(decode_duration(decoder)?),
        OPTION_TAG_LINGER => UnixSocketOption::Linger(decode_duration(decoder)?),
        OPTION_TAG_REUSE_ADDRESS => UnixSocketOption::ReuseAddress(decode_bool(decoder)?),
        OPTION_TAG_KEEP_ALIVE => UnixSocketOption::KeepAlive(decode_bool(decoder)?),
        OPTION_TAG_BROADCAST => UnixSocketOption::Broadcast(decode_bool(decoder)?),
        _ => return Err(WireError::InvalidTag),
    })
}

fn encode_options(encoder: &mut Encoder, options: UnixSocketOptions) {
    encode_duration(encoder, options.receive_timeout);
    encode_duration(encoder, options.send_timeout);
    encode_duration(encoder, options.linger);
    encode_bool(encoder, options.reuse_address);
    encode_bool(encoder, options.keep_alive);
    encode_bool(encoder, options.broadcast);
}

fn decode_options(decoder: &mut Decoder<'_>) -> Result<UnixSocketOptions, WireError> {
    Ok(UnixSocketOptions {
        receive_timeout: decode_duration(decoder)?,
        send_timeout: decode_duration(decoder)?,
        linger: decode_duration(decoder)?,
        reuse_address: decode_bool(decoder)?,
        keep_alive: decode_bool(decoder)?,
        broadcast: decode_bool(decoder)?,
    })
}

fn encode_error(encoder: &mut Encoder, error: UnixSocketError) {
    match error {
        UnixSocketError::AddressInUse => encoder.u8(ERROR_TAG_ADDRESS_IN_USE),
        UnixSocketError::ConnectionRefused => encoder.u8(ERROR_TAG_CONNECTION_REFUSED),
        UnixSocketError::WrongType => encoder.u8(ERROR_TAG_WRONG_TYPE),
        UnixSocketError::InvalidArgument => encoder.u8(ERROR_TAG_INVALID_ARGUMENT),
        UnixSocketError::AlreadyConnected => encoder.u8(ERROR_TAG_ALREADY_CONNECTED),
        UnixSocketError::NotConnected => encoder.u8(ERROR_TAG_NOT_CONNECTED),
        UnixSocketError::Unsupported => encoder.u8(ERROR_TAG_UNSUPPORTED),
        UnixSocketError::MessageTooLarge => encoder.u8(ERROR_TAG_MESSAGE_TOO_LARGE),
        UnixSocketError::BrokenPipe => encoder.u8(ERROR_TAG_BROKEN_PIPE),
        UnixSocketError::NotPermitted => encoder.u8(ERROR_TAG_NOT_PERMITTED),
        UnixSocketError::File(error) => {
            encoder.u8(ERROR_TAG_FILE);
            encode_file_error(encoder, error);
        }
    }
}

fn decode_error(decoder: &mut Decoder<'_>) -> Result<UnixSocketError, WireError> {
    Ok(match decoder.u8()? {
        ERROR_TAG_ADDRESS_IN_USE => UnixSocketError::AddressInUse,
        ERROR_TAG_CONNECTION_REFUSED => UnixSocketError::ConnectionRefused,
        ERROR_TAG_WRONG_TYPE => UnixSocketError::WrongType,
        ERROR_TAG_INVALID_ARGUMENT => UnixSocketError::InvalidArgument,
        ERROR_TAG_ALREADY_CONNECTED => UnixSocketError::AlreadyConnected,
        ERROR_TAG_NOT_CONNECTED => UnixSocketError::NotConnected,
        ERROR_TAG_UNSUPPORTED => UnixSocketError::Unsupported,
        ERROR_TAG_MESSAGE_TOO_LARGE => UnixSocketError::MessageTooLarge,
        ERROR_TAG_BROKEN_PIPE => UnixSocketError::BrokenPipe,
        ERROR_TAG_NOT_PERMITTED => UnixSocketError::NotPermitted,
        ERROR_TAG_FILE => UnixSocketError::File(decode_file_error(decoder)?),
        _ => return Err(WireError::InvalidTag),
    })
}
