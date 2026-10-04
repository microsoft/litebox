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
use crate::local_socket::{
    AcceptLocalSocketRequest, AcceptLocalSocketResponse, BindLocalSocketRequest,
    ConnectLocalSocketRequest, CreateLocalSocketPairResponse, CreateLocalSocketRequest,
    CreateLocalSocketResponse, GetLocalSocketNameRequest, GetLocalSocketNameResponse,
    GetLocalSocketOptionsResponse, ListenLocalSocketRequest, LocalSocketError, LocalSocketOption,
    LocalSocketOptions, ReceiveLocalSocketRequest, ReceiveLocalSocketResponse,
    SendLocalSocketRequest, SendLocalSocketResponse, SetLocalSocketOptionRequest,
    ShutdownLocalSocketRequest,
};
use crate::message::{LocalSocketRequest, LocalSocketResponse};

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

pub(super) fn encode_local_socket_request(encoder: &mut Encoder, request: LocalSocketRequest) {
    match request {
        LocalSocketRequest::Create(request) => {
            encoder.u8(TAG_CREATE);
            encode_create_request(encoder, request);
        }
        LocalSocketRequest::CreatePair(request) => {
            encoder.u8(TAG_CREATE_PAIR);
            encode_create_request(encoder, request);
        }
        LocalSocketRequest::Bind(request) => {
            encoder.u8(TAG_BIND);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.address);
            encode_user(encoder, request.user);
            encoder.u16(request.mode.bits());
        }
        LocalSocketRequest::Listen(request) => {
            encoder.u8(TAG_LISTEN);
            encoder.handle(request.handle);
            encoder.u32(request.backlog);
        }
        LocalSocketRequest::Connect(request) => {
            encoder.u8(TAG_CONNECT);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.address);
            encode_user(encoder, request.user);
        }
        LocalSocketRequest::Accept(request) => {
            encoder.u8(TAG_ACCEPT);
            encoder.handle(request.handle);
            encoder.u16(request.flags.bits());
        }
        LocalSocketRequest::Send(request) => {
            encoder.u8(TAG_SEND);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.address_length);
            encode_user(encoder, request.user);
        }
        LocalSocketRequest::Receive(request) => {
            encoder.u8(TAG_RECEIVE);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.capacity);
            encode_bool(encoder, request.peek);
            encode_bool(encoder, request.nonblocking);
        }
        LocalSocketRequest::Shutdown(request) => {
            encoder.u8(TAG_SHUTDOWN);
            encoder.handle(request.handle);
            encode_shutdown_mode(encoder, request.mode);
        }
        LocalSocketRequest::GetName(request) => {
            encoder.u8(TAG_GET_NAME);
            encoder.handle(request.handle);
            encode_bool(encoder, request.peer);
            encoder.shared_buffer_sequence(request.buffer);
        }
        LocalSocketRequest::SetOption(request) => {
            encoder.u8(TAG_SET_OPTION);
            encoder.handle(request.handle);
            encode_option(encoder, request.option);
        }
        LocalSocketRequest::GetOptions(handle) => {
            encoder.u8(TAG_GET_OPTIONS);
            encoder.handle(handle);
        }
    }
}

pub(super) fn decode_local_socket_request(
    decoder: &mut Decoder<'_>,
) -> Result<LocalSocketRequest, WireError> {
    Ok(match decoder.u8()? {
        TAG_CREATE => LocalSocketRequest::Create(decode_create_request(decoder)?),
        TAG_CREATE_PAIR => LocalSocketRequest::CreatePair(decode_create_request(decoder)?),
        TAG_BIND => LocalSocketRequest::Bind(BindLocalSocketRequest {
            handle: decoder.handle()?,
            address: decoder.shared_buffer_sequence()?,
            user: decode_user(decoder)?,
            mode: decode_mode(decoder)?,
        }),
        TAG_LISTEN => LocalSocketRequest::Listen(ListenLocalSocketRequest {
            handle: decoder.handle()?,
            backlog: decoder.u32()?,
        }),
        TAG_CONNECT => LocalSocketRequest::Connect(ConnectLocalSocketRequest {
            handle: decoder.handle()?,
            address: decoder.shared_buffer_sequence()?,
            user: decode_user(decoder)?,
        }),
        TAG_ACCEPT => LocalSocketRequest::Accept(AcceptLocalSocketRequest {
            handle: decoder.handle()?,
            flags: decode_open_flags(decoder)?,
        }),
        TAG_SEND => LocalSocketRequest::Send(SendLocalSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            address_length: decoder.u32()?,
            user: decode_user(decoder)?,
        }),
        TAG_RECEIVE => LocalSocketRequest::Receive(ReceiveLocalSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            capacity: decoder.u32()?,
            peek: decode_bool(decoder)?,
            nonblocking: decode_bool(decoder)?,
        }),
        TAG_SHUTDOWN => LocalSocketRequest::Shutdown(ShutdownLocalSocketRequest {
            handle: decoder.handle()?,
            mode: decode_shutdown_mode(decoder)?,
        }),
        TAG_GET_NAME => LocalSocketRequest::GetName(GetLocalSocketNameRequest {
            handle: decoder.handle()?,
            peer: decode_bool(decoder)?,
            buffer: decoder.shared_buffer_sequence()?,
        }),
        TAG_SET_OPTION => LocalSocketRequest::SetOption(SetLocalSocketOptionRequest {
            handle: decoder.handle()?,
            option: decode_option(decoder)?,
        }),
        TAG_GET_OPTIONS => LocalSocketRequest::GetOptions(decoder.handle()?),
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_local_socket_response(encoder: &mut Encoder, response: LocalSocketResponse) {
    match response {
        LocalSocketResponse::Create(response) => {
            encoder.u8(TAG_CREATE);
            encoder.handle(response.handle);
        }
        LocalSocketResponse::CreatePair(response) => {
            encoder.u8(TAG_CREATE_PAIR);
            encoder.handle(response.first);
            encoder.handle(response.second);
        }
        LocalSocketResponse::Bind => encoder.u8(TAG_BIND),
        LocalSocketResponse::Listen => encoder.u8(TAG_LISTEN),
        LocalSocketResponse::Connect => encoder.u8(TAG_CONNECT),
        LocalSocketResponse::Accept(response) => {
            encoder.u8(TAG_ACCEPT);
            encoder.handle(response.handle);
        }
        LocalSocketResponse::Send(response) => {
            encoder.u8(TAG_SEND);
            encoder.u32(response.sent);
        }
        LocalSocketResponse::Receive(response) => {
            encoder.u8(TAG_RECEIVE);
            encoder.u32(response.received);
            encoder.u32(response.length);
            encoder.u32(response.source_length);
        }
        LocalSocketResponse::Shutdown => encoder.u8(TAG_SHUTDOWN),
        LocalSocketResponse::GetName(response) => {
            encoder.u8(TAG_GET_NAME);
            encoder.u32(response.length);
        }
        LocalSocketResponse::SetOption => encoder.u8(TAG_SET_OPTION),
        LocalSocketResponse::GetOptions(response) => {
            encoder.u8(TAG_GET_OPTIONS);
            encode_socket_type(encoder, response.socket_type);
            encode_options(encoder, response.options);
        }
        LocalSocketResponse::Failed(error) => {
            encoder.u8(RESPONSE_TAG_FAILED);
            encode_error(encoder, error);
        }
    }
}

pub(super) fn decode_local_socket_response(
    decoder: &mut Decoder<'_>,
) -> Result<LocalSocketResponse, WireError> {
    Ok(match decoder.u8()? {
        TAG_CREATE => LocalSocketResponse::Create(CreateLocalSocketResponse {
            handle: decoder.handle()?,
        }),
        TAG_CREATE_PAIR => LocalSocketResponse::CreatePair(CreateLocalSocketPairResponse {
            first: decoder.handle()?,
            second: decoder.handle()?,
        }),
        TAG_BIND => LocalSocketResponse::Bind,
        TAG_LISTEN => LocalSocketResponse::Listen,
        TAG_CONNECT => LocalSocketResponse::Connect,
        TAG_ACCEPT => LocalSocketResponse::Accept(AcceptLocalSocketResponse {
            handle: decoder.handle()?,
        }),
        TAG_SEND => LocalSocketResponse::Send(SendLocalSocketResponse {
            sent: decoder.u32()?,
        }),
        TAG_RECEIVE => LocalSocketResponse::Receive(ReceiveLocalSocketResponse {
            received: decoder.u32()?,
            length: decoder.u32()?,
            source_length: decoder.u32()?,
        }),
        TAG_SHUTDOWN => LocalSocketResponse::Shutdown,
        TAG_GET_NAME => LocalSocketResponse::GetName(GetLocalSocketNameResponse {
            length: decoder.u32()?,
        }),
        TAG_SET_OPTION => LocalSocketResponse::SetOption,
        TAG_GET_OPTIONS => LocalSocketResponse::GetOptions(GetLocalSocketOptionsResponse {
            socket_type: decode_socket_type(decoder)?,
            options: decode_options(decoder)?,
        }),
        RESPONSE_TAG_FAILED => LocalSocketResponse::Failed(decode_error(decoder)?),
        _ => return Err(WireError::InvalidTag),
    })
}

fn encode_create_request(encoder: &mut Encoder, request: CreateLocalSocketRequest) {
    encode_socket_type(encoder, request.socket_type);
    encoder.u16(request.flags.bits());
}

fn decode_create_request(decoder: &mut Decoder<'_>) -> Result<CreateLocalSocketRequest, WireError> {
    Ok(CreateLocalSocketRequest {
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

fn encode_option(encoder: &mut Encoder, option: LocalSocketOption) {
    match option {
        LocalSocketOption::ReceiveTimeout(timeout) => {
            encoder.u8(OPTION_TAG_RECEIVE_TIMEOUT);
            encode_duration(encoder, timeout);
        }
        LocalSocketOption::SendTimeout(timeout) => {
            encoder.u8(OPTION_TAG_SEND_TIMEOUT);
            encode_duration(encoder, timeout);
        }
        LocalSocketOption::Linger(timeout) => {
            encoder.u8(OPTION_TAG_LINGER);
            encode_duration(encoder, timeout);
        }
        LocalSocketOption::ReuseAddress(value) => {
            encoder.u8(OPTION_TAG_REUSE_ADDRESS);
            encode_bool(encoder, value);
        }
        LocalSocketOption::KeepAlive(value) => {
            encoder.u8(OPTION_TAG_KEEP_ALIVE);
            encode_bool(encoder, value);
        }
        LocalSocketOption::Broadcast(value) => {
            encoder.u8(OPTION_TAG_BROADCAST);
            encode_bool(encoder, value);
        }
    }
}

fn decode_option(decoder: &mut Decoder<'_>) -> Result<LocalSocketOption, WireError> {
    Ok(match decoder.u8()? {
        OPTION_TAG_RECEIVE_TIMEOUT => LocalSocketOption::ReceiveTimeout(decode_duration(decoder)?),
        OPTION_TAG_SEND_TIMEOUT => LocalSocketOption::SendTimeout(decode_duration(decoder)?),
        OPTION_TAG_LINGER => LocalSocketOption::Linger(decode_duration(decoder)?),
        OPTION_TAG_REUSE_ADDRESS => LocalSocketOption::ReuseAddress(decode_bool(decoder)?),
        OPTION_TAG_KEEP_ALIVE => LocalSocketOption::KeepAlive(decode_bool(decoder)?),
        OPTION_TAG_BROADCAST => LocalSocketOption::Broadcast(decode_bool(decoder)?),
        _ => return Err(WireError::InvalidTag),
    })
}

fn encode_options(encoder: &mut Encoder, options: LocalSocketOptions) {
    encode_duration(encoder, options.receive_timeout);
    encode_duration(encoder, options.send_timeout);
    encode_duration(encoder, options.linger);
    encode_bool(encoder, options.reuse_address);
    encode_bool(encoder, options.keep_alive);
    encode_bool(encoder, options.broadcast);
}

fn decode_options(decoder: &mut Decoder<'_>) -> Result<LocalSocketOptions, WireError> {
    Ok(LocalSocketOptions {
        receive_timeout: decode_duration(decoder)?,
        send_timeout: decode_duration(decoder)?,
        linger: decode_duration(decoder)?,
        reuse_address: decode_bool(decoder)?,
        keep_alive: decode_bool(decoder)?,
        broadcast: decode_bool(decoder)?,
    })
}

fn encode_error(encoder: &mut Encoder, error: LocalSocketError) {
    match error {
        LocalSocketError::AddressInUse => encoder.u8(ERROR_TAG_ADDRESS_IN_USE),
        LocalSocketError::ConnectionRefused => encoder.u8(ERROR_TAG_CONNECTION_REFUSED),
        LocalSocketError::WrongType => encoder.u8(ERROR_TAG_WRONG_TYPE),
        LocalSocketError::InvalidArgument => encoder.u8(ERROR_TAG_INVALID_ARGUMENT),
        LocalSocketError::AlreadyConnected => encoder.u8(ERROR_TAG_ALREADY_CONNECTED),
        LocalSocketError::NotConnected => encoder.u8(ERROR_TAG_NOT_CONNECTED),
        LocalSocketError::Unsupported => encoder.u8(ERROR_TAG_UNSUPPORTED),
        LocalSocketError::MessageTooLarge => encoder.u8(ERROR_TAG_MESSAGE_TOO_LARGE),
        LocalSocketError::BrokenPipe => encoder.u8(ERROR_TAG_BROKEN_PIPE),
        LocalSocketError::NotPermitted => encoder.u8(ERROR_TAG_NOT_PERMITTED),
        LocalSocketError::File(error) => {
            encoder.u8(ERROR_TAG_FILE);
            encode_file_error(encoder, error);
        }
    }
}

fn decode_error(decoder: &mut Decoder<'_>) -> Result<LocalSocketError, WireError> {
    Ok(match decoder.u8()? {
        ERROR_TAG_ADDRESS_IN_USE => LocalSocketError::AddressInUse,
        ERROR_TAG_CONNECTION_REFUSED => LocalSocketError::ConnectionRefused,
        ERROR_TAG_WRONG_TYPE => LocalSocketError::WrongType,
        ERROR_TAG_INVALID_ARGUMENT => LocalSocketError::InvalidArgument,
        ERROR_TAG_ALREADY_CONNECTED => LocalSocketError::AlreadyConnected,
        ERROR_TAG_NOT_CONNECTED => LocalSocketError::NotConnected,
        ERROR_TAG_UNSUPPORTED => LocalSocketError::Unsupported,
        ERROR_TAG_MESSAGE_TOO_LARGE => LocalSocketError::MessageTooLarge,
        ERROR_TAG_BROKEN_PIPE => LocalSocketError::BrokenPipe,
        ERROR_TAG_NOT_PERMITTED => LocalSocketError::NotPermitted,
        ERROR_TAG_FILE => LocalSocketError::File(decode_file_error(decoder)?),
        _ => return Err(WireError::InvalidTag),
    })
}
