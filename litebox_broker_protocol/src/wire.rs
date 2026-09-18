// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable byte codec for broker request/response control-channel messages.
//!
//! The wire codec mirrors the protocol DTO hierarchy:
//! - this module owns public encode/decode entry points and top-level broker
//!   envelope tags;
//! - object-family modules such as `event` own their operation and nested value
//!   tags;
//! - `primitive` owns shared scalar/value encoders.
//!
//! New object families should add a top-level broker message tag and a private
//! family codec module instead of adding flat helpers here. Existing payloads
//! are positional, so update both endpoints and their codec tests together.

use alloc::vec::Vec;
use thiserror::Error;

use crate::error::ErrorCode;
use crate::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
    BrokerRequest, BrokerResponse, BrokerResult, ReadinessNotification,
};
use crate::process::ProcessStartupDescriptor;
use crate::readiness::ReadinessFlags;

use primitive::{Decoder, Encoder};

mod event;
mod fs;
mod pipe;
mod primitive;
mod process;
mod process_group;
mod readiness_queue;
mod signal;
mod socket;
mod thread;
mod timer;
mod unix_socket;

const REQUEST_TAG_NEGOTIATE: u8 = 0;
const REQUEST_TAG_EVENT: u8 = 1;
const REQUEST_TAG_CLOSE_OBJECT: u8 = 2;
const REQUEST_TAG_PIPE: u8 = 3;
const REQUEST_TAG_CHECK_READINESS: u8 = 4;
const REQUEST_TAG_SOCKET: u8 = 5;
const REQUEST_TAG_FILL_RANDOM: u8 = 6;
const REQUEST_TAG_FILE: u8 = 7;
const REQUEST_TAG_THREAD: u8 = 8;
const REQUEST_TAG_PROCESS: u8 = 9;
const REQUEST_TAG_TIMER: u8 = 10;
const REQUEST_TAG_GET_STATUS_FLAGS: u8 = 11;
const REQUEST_TAG_SET_STATUS_FLAGS: u8 = 12;
const REQUEST_TAG_SIGNAL: u8 = 13;
const REQUEST_TAG_PROCESS_GROUP: u8 = 14;
const REQUEST_TAG_UNIX_SOCKET: u8 = 15;
const REQUEST_TAG_READINESS_QUEUE: u8 = 16;

// Paired request and successful-response tags intentionally share values.
const RESPONSE_TAG_NEGOTIATED: u8 = 0;
const RESPONSE_TAG_EVENT: u8 = 1;
const RESPONSE_TAG_OBJECT_CLOSED: u8 = 2;
const RESPONSE_TAG_PIPE: u8 = 3;
const RESPONSE_TAG_READINESS: u8 = 4;
const RESPONSE_TAG_SOCKET: u8 = 5;
const RESPONSE_TAG_RANDOM_FILLED: u8 = 6;
const RESPONSE_TAG_FILE: u8 = 7;
const RESPONSE_TAG_THREAD: u8 = 8;
const RESPONSE_TAG_PROCESS: u8 = 9;
const RESPONSE_TAG_TIMER: u8 = 10;
const RESPONSE_TAG_STATUS_FLAGS: u8 = 11;
const RESPONSE_TAG_STATUS_FLAGS_SET: u8 = 12;
const RESPONSE_TAG_SIGNAL: u8 = 13;
const RESPONSE_TAG_PROCESS_GROUP: u8 = 14;
const RESPONSE_TAG_UNIX_SOCKET: u8 = 15;
const RESPONSE_TAG_READINESS_QUEUE: u8 = 16;

// Reserve the top of the tag space for responses without paired requests.
const RESPONSE_TAG_ERROR: u8 = 253;
const RESPONSE_TAG_HANDSHAKE_ERROR: u8 = 254;
const RESPONSE_TAG_VERSION_MISMATCH: u8 = 255;

const NOTIFICATION_TAG_READINESS: u8 = 0;

/// Maximum byte length of any encoded active request or response.
pub const MAX_ENCODED_ACTIVE_MESSAGE_SIZE: usize = 99;

/// Maximum byte length of any encoded broker notification.
pub const MAX_ENCODED_NOTIFICATION_SIZE: usize = 13;

/// Error produced while encoding or decoding a broker wire message.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    #[error("truncated broker wire frame")]
    TruncatedFrame,
    #[error("trailing broker wire bytes")]
    TrailingBytes,
    #[error("invalid broker wire tag")]
    InvalidTag,
    #[error("broker wire message is not valid in this protocol phase")]
    WrongMessagePhase,
    #[error("broker wire offset overflow")]
    OffsetOverflow,
}

/// Encodes a broker handshake request body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_handshake_request(request: BrokerHandshakeRequest) -> Vec<u8> {
    let mut encoder = Encoder::default();
    encoder.u8(REQUEST_TAG_NEGOTIATE);
    encoder.protocol_version(request.protocol_version);
    encoder.finish()
}

/// Decodes a broker handshake request body.
pub fn decode_handshake_request(frame: &[u8]) -> Result<BrokerHandshakeRequest, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let request = match tag {
        REQUEST_TAG_NEGOTIATE => BrokerHandshakeRequest {
            protocol_version: decoder.protocol_version()?,
        },
        REQUEST_TAG_EVENT
        | REQUEST_TAG_CLOSE_OBJECT
        | REQUEST_TAG_PIPE
        | REQUEST_TAG_CHECK_READINESS
        | REQUEST_TAG_SOCKET
        | REQUEST_TAG_FILL_RANDOM
        | REQUEST_TAG_FILE
        | REQUEST_TAG_THREAD
        | REQUEST_TAG_PROCESS
        | REQUEST_TAG_TIMER
        | REQUEST_TAG_GET_STATUS_FLAGS
        | REQUEST_TAG_SET_STATUS_FLAGS
        | REQUEST_TAG_SIGNAL
        | REQUEST_TAG_PROCESS_GROUP
        | REQUEST_TAG_UNIX_SOCKET
        | REQUEST_TAG_READINESS_QUEUE => {
            return Err(WireError::WrongMessagePhase);
        }
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(request)
}

/// Encodes a broker request body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_request(request: BrokerRequest) -> Vec<u8> {
    let mut encoder = Encoder::default();
    let BrokerRequest {
        request_id,
        operation,
    } = request;
    match operation {
        BrokerOperation::Thread(request) => {
            encoder.u8(REQUEST_TAG_THREAD);
            encoder.request_id(request_id);
            thread::encode_thread_request(&mut encoder, request);
        }
        BrokerOperation::CloseObject(handle) => {
            encoder.u8(REQUEST_TAG_CLOSE_OBJECT);
            encoder.request_id(request_id);
            encoder.handle(handle);
        }
        BrokerOperation::CheckReadiness(handle) => {
            encoder.u8(REQUEST_TAG_CHECK_READINESS);
            encoder.request_id(request_id);
            encoder.handle(handle);
        }
        BrokerOperation::GetStatusFlags(handle) => {
            encoder.u8(REQUEST_TAG_GET_STATUS_FLAGS);
            encoder.request_id(request_id);
            encoder.handle(handle);
        }
        BrokerOperation::SetStatusFlags(request) => {
            encoder.u8(REQUEST_TAG_SET_STATUS_FLAGS);
            encoder.request_id(request_id);
            fs::encode_set_status_flags_request(&mut encoder, request);
        }
        BrokerOperation::Event(request) => {
            encoder.u8(REQUEST_TAG_EVENT);
            encoder.request_id(request_id);
            event::encode_event_request(&mut encoder, request);
        }
        BrokerOperation::Pipe(request) => {
            encoder.u8(REQUEST_TAG_PIPE);
            encoder.request_id(request_id);
            pipe::encode_pipe_request(&mut encoder, request);
        }
        BrokerOperation::Socket(request) => {
            encoder.u8(REQUEST_TAG_SOCKET);
            encoder.request_id(request_id);
            socket::encode_socket_request(&mut encoder, request);
        }
        BrokerOperation::FillRandom(buffer) => {
            encoder.u8(REQUEST_TAG_FILL_RANDOM);
            encoder.request_id(request_id);
            encoder.shared_buffer_sequence(buffer);
        }
        BrokerOperation::File(request) => {
            encoder.u8(REQUEST_TAG_FILE);
            encoder.request_id(request_id);
            fs::encode_fs_request(&mut encoder, request);
        }
        BrokerOperation::Process(request) => {
            encoder.u8(REQUEST_TAG_PROCESS);
            encoder.request_id(request_id);
            process::encode_process_request(&mut encoder, request);
        }
        BrokerOperation::ProcessGroup(request) => {
            encoder.u8(REQUEST_TAG_PROCESS_GROUP);
            encoder.request_id(request_id);
            process_group::encode_process_group_request(&mut encoder, request);
        }
        BrokerOperation::Timer(request) => {
            encoder.u8(REQUEST_TAG_TIMER);
            encoder.request_id(request_id);
            timer::encode_timer_request(&mut encoder, request);
        }
        BrokerOperation::Signal(request) => {
            encoder.u8(REQUEST_TAG_SIGNAL);
            encoder.request_id(request_id);
            signal::encode_signal_request(&mut encoder, request);
        }
        BrokerOperation::UnixSocket(request) => {
            encoder.u8(REQUEST_TAG_UNIX_SOCKET);
            encoder.request_id(request_id);
            unix_socket::encode_unix_socket_request(&mut encoder, request);
        }
        BrokerOperation::ReadinessQueue(request) => {
            encoder.u8(REQUEST_TAG_READINESS_QUEUE);
            encoder.request_id(request_id);
            readiness_queue::encode_readiness_queue_request(&mut encoder, request);
        }
    }
    encoder.finish()
}

/// Decodes a broker request body.
pub fn decode_request(frame: &[u8]) -> Result<BrokerRequest, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    match tag {
        REQUEST_TAG_NEGOTIATE => return Err(WireError::WrongMessagePhase),
        REQUEST_TAG_CLOSE_OBJECT
        | REQUEST_TAG_CHECK_READINESS
        | REQUEST_TAG_EVENT
        | REQUEST_TAG_PIPE
        | REQUEST_TAG_SOCKET
        | REQUEST_TAG_FILL_RANDOM
        | REQUEST_TAG_FILE
        | REQUEST_TAG_THREAD
        | REQUEST_TAG_PROCESS
        | REQUEST_TAG_TIMER
        | REQUEST_TAG_GET_STATUS_FLAGS
        | REQUEST_TAG_SET_STATUS_FLAGS
        | REQUEST_TAG_SIGNAL
        | REQUEST_TAG_PROCESS_GROUP
        | REQUEST_TAG_UNIX_SOCKET
        | REQUEST_TAG_READINESS_QUEUE => {}
        _ => return Err(WireError::InvalidTag),
    }
    let request_id = decoder.request_id()?;
    let operation = match tag {
        REQUEST_TAG_THREAD => BrokerOperation::Thread(thread::decode_thread_request(&mut decoder)?),
        REQUEST_TAG_CLOSE_OBJECT => BrokerOperation::CloseObject(decoder.handle()?),
        REQUEST_TAG_CHECK_READINESS => BrokerOperation::CheckReadiness(decoder.handle()?),
        REQUEST_TAG_GET_STATUS_FLAGS => BrokerOperation::GetStatusFlags(decoder.handle()?),
        REQUEST_TAG_SET_STATUS_FLAGS => {
            BrokerOperation::SetStatusFlags(fs::decode_set_status_flags_request(&mut decoder)?)
        }
        REQUEST_TAG_EVENT => BrokerOperation::Event(event::decode_event_request(&mut decoder)?),
        REQUEST_TAG_PIPE => BrokerOperation::Pipe(pipe::decode_pipe_request(&mut decoder)?),
        REQUEST_TAG_SOCKET => BrokerOperation::Socket(socket::decode_socket_request(&mut decoder)?),
        REQUEST_TAG_FILL_RANDOM => BrokerOperation::FillRandom(decoder.shared_buffer_sequence()?),
        REQUEST_TAG_FILE => BrokerOperation::File(fs::decode_fs_request(&mut decoder)?),
        REQUEST_TAG_PROCESS => {
            BrokerOperation::Process(process::decode_process_request(&mut decoder)?)
        }
        REQUEST_TAG_PROCESS_GROUP => BrokerOperation::ProcessGroup(
            process_group::decode_process_group_request(&mut decoder)?,
        ),
        REQUEST_TAG_TIMER => BrokerOperation::Timer(timer::decode_timer_request(&mut decoder)?),
        REQUEST_TAG_SIGNAL => BrokerOperation::Signal(signal::decode_signal_request(&mut decoder)?),
        REQUEST_TAG_UNIX_SOCKET => {
            BrokerOperation::UnixSocket(unix_socket::decode_unix_socket_request(&mut decoder)?)
        }
        REQUEST_TAG_READINESS_QUEUE => BrokerOperation::ReadinessQueue(
            readiness_queue::decode_readiness_queue_request(&mut decoder)?,
        ),
        _ => unreachable!("active request tag was validated"),
    };
    decoder.finish()?;
    Ok(BrokerRequest {
        request_id,
        operation,
    })
}

/// Encodes a broker handshake response body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_handshake_response(response: BrokerHandshakeResponse) -> Vec<u8> {
    let mut encoder = Encoder::default();
    match response {
        BrokerHandshakeResponse::Negotiated {
            broker_protocol_version,
            process_id,
            initial_thread_id,
            startup,
        } => {
            encoder.u8(RESPONSE_TAG_NEGOTIATED);
            encoder.protocol_version(broker_protocol_version);
            encoder.process_id(process_id);
            encoder.thread_id(initial_thread_id);
            match startup {
                Some(ProcessStartupDescriptor { buffer }) => {
                    encoder.u8(1);
                    encoder.shared_buffer_sequence(buffer);
                }
                None => encoder.u8(0),
            }
        }
        BrokerHandshakeResponse::VersionMismatch {
            broker_protocol_version,
        } => {
            encoder.u8(RESPONSE_TAG_VERSION_MISMATCH);
            encoder.protocol_version(broker_protocol_version);
        }
        BrokerHandshakeResponse::Error(error) => {
            encoder.u8(RESPONSE_TAG_HANDSHAKE_ERROR);
            encode_error_code(&mut encoder, error);
        }
    }
    encoder.finish()
}

/// Decodes a broker handshake response body.
pub fn decode_handshake_response(frame: &[u8]) -> Result<BrokerHandshakeResponse, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let response = match tag {
        RESPONSE_TAG_NEGOTIATED => BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: decoder.protocol_version()?,
            process_id: decoder.process_id()?,
            initial_thread_id: decoder.thread_id()?,
            startup: match decoder.u8()? {
                0 => None,
                1 => Some(ProcessStartupDescriptor {
                    buffer: decoder.shared_buffer_sequence()?,
                }),
                _ => return Err(WireError::InvalidTag),
            },
        },
        RESPONSE_TAG_EVENT
        | RESPONSE_TAG_OBJECT_CLOSED
        | RESPONSE_TAG_PIPE
        | RESPONSE_TAG_READINESS
        | RESPONSE_TAG_ERROR
        | RESPONSE_TAG_SOCKET
        | RESPONSE_TAG_RANDOM_FILLED
        | RESPONSE_TAG_FILE
        | RESPONSE_TAG_THREAD
        | RESPONSE_TAG_PROCESS
        | RESPONSE_TAG_TIMER
        | RESPONSE_TAG_STATUS_FLAGS
        | RESPONSE_TAG_STATUS_FLAGS_SET
        | RESPONSE_TAG_SIGNAL
        | RESPONSE_TAG_PROCESS_GROUP
        | RESPONSE_TAG_UNIX_SOCKET
        | RESPONSE_TAG_READINESS_QUEUE => {
            return Err(WireError::WrongMessagePhase);
        }
        RESPONSE_TAG_VERSION_MISMATCH => BrokerHandshakeResponse::VersionMismatch {
            broker_protocol_version: decoder.protocol_version()?,
        },
        RESPONSE_TAG_HANDSHAKE_ERROR => {
            BrokerHandshakeResponse::Error(decode_error_code(&mut decoder)?)
        }
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(response)
}

/// Encodes a broker response body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_response(response: BrokerResponse) -> Vec<u8> {
    let mut encoder = Encoder::default();
    let BrokerResponse { request_id, result } = response;
    match result {
        BrokerResult::Thread(response) => {
            encoder.u8(RESPONSE_TAG_THREAD);
            encoder.request_id(request_id);
            thread::encode_thread_response(&mut encoder, response);
        }
        BrokerResult::ObjectClosed => {
            encoder.u8(RESPONSE_TAG_OBJECT_CLOSED);
            encoder.request_id(request_id);
        }
        BrokerResult::Readiness(readiness) => {
            encoder.u8(RESPONSE_TAG_READINESS);
            encoder.request_id(request_id);
            encoder.u32(readiness.0);
        }
        BrokerResult::StatusFlags(status) => {
            encoder.u8(RESPONSE_TAG_STATUS_FLAGS);
            encoder.request_id(request_id);
            fs::encode_status_flags(&mut encoder, status);
        }
        BrokerResult::StatusFlagsSet => {
            encoder.u8(RESPONSE_TAG_STATUS_FLAGS_SET);
            encoder.request_id(request_id);
        }
        BrokerResult::Event(response) => {
            encoder.u8(RESPONSE_TAG_EVENT);
            encoder.request_id(request_id);
            event::encode_event_response(&mut encoder, response);
        }
        BrokerResult::Pipe(response) => {
            encoder.u8(RESPONSE_TAG_PIPE);
            encoder.request_id(request_id);
            pipe::encode_pipe_response(&mut encoder, response);
        }
        BrokerResult::Socket(response) => {
            encoder.u8(RESPONSE_TAG_SOCKET);
            encoder.request_id(request_id);
            socket::encode_socket_response(&mut encoder, response);
        }
        BrokerResult::RandomFilled => {
            encoder.u8(RESPONSE_TAG_RANDOM_FILLED);
            encoder.request_id(request_id);
        }
        BrokerResult::File(response) => {
            encoder.u8(RESPONSE_TAG_FILE);
            encoder.request_id(request_id);
            fs::encode_fs_response(&mut encoder, response);
        }
        BrokerResult::Process(response) => {
            encoder.u8(RESPONSE_TAG_PROCESS);
            encoder.request_id(request_id);
            process::encode_process_response(&mut encoder, response);
        }
        BrokerResult::ProcessGroup(response) => {
            encoder.u8(RESPONSE_TAG_PROCESS_GROUP);
            encoder.request_id(request_id);
            process_group::encode_process_group_response(&mut encoder, response);
        }
        BrokerResult::Timer(response) => {
            encoder.u8(RESPONSE_TAG_TIMER);
            encoder.request_id(request_id);
            timer::encode_timer_response(&mut encoder, response);
        }
        BrokerResult::Signal(response) => {
            encoder.u8(RESPONSE_TAG_SIGNAL);
            encoder.request_id(request_id);
            signal::encode_signal_response(&mut encoder, response);
        }
        BrokerResult::UnixSocket(response) => {
            encoder.u8(RESPONSE_TAG_UNIX_SOCKET);
            encoder.request_id(request_id);
            unix_socket::encode_unix_socket_response(&mut encoder, response);
        }
        BrokerResult::ReadinessQueue(response) => {
            encoder.u8(RESPONSE_TAG_READINESS_QUEUE);
            encoder.request_id(request_id);
            readiness_queue::encode_readiness_queue_response(&mut encoder, response);
        }
        BrokerResult::Error(error) => {
            encoder.u8(RESPONSE_TAG_ERROR);
            encoder.request_id(request_id);
            encode_error_code(&mut encoder, error);
        }
    }
    encoder.finish()
}

/// Decodes a broker response body.
pub fn decode_response(frame: &[u8]) -> Result<BrokerResponse, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    match tag {
        RESPONSE_TAG_NEGOTIATED | RESPONSE_TAG_HANDSHAKE_ERROR | RESPONSE_TAG_VERSION_MISMATCH => {
            return Err(WireError::WrongMessagePhase);
        }
        RESPONSE_TAG_EVENT
        | RESPONSE_TAG_OBJECT_CLOSED
        | RESPONSE_TAG_PIPE
        | RESPONSE_TAG_READINESS
        | RESPONSE_TAG_ERROR
        | RESPONSE_TAG_SOCKET
        | RESPONSE_TAG_RANDOM_FILLED
        | RESPONSE_TAG_FILE
        | RESPONSE_TAG_THREAD
        | RESPONSE_TAG_PROCESS
        | RESPONSE_TAG_TIMER
        | RESPONSE_TAG_STATUS_FLAGS
        | RESPONSE_TAG_STATUS_FLAGS_SET
        | RESPONSE_TAG_SIGNAL
        | RESPONSE_TAG_PROCESS_GROUP
        | RESPONSE_TAG_UNIX_SOCKET
        | RESPONSE_TAG_READINESS_QUEUE => {}
        _ => return Err(WireError::InvalidTag),
    }
    let request_id = decoder.request_id()?;
    let result = match tag {
        RESPONSE_TAG_EVENT => BrokerResult::Event(event::decode_event_response(&mut decoder)?),
        RESPONSE_TAG_PIPE => BrokerResult::Pipe(pipe::decode_pipe_response(&mut decoder)?),
        RESPONSE_TAG_SOCKET => BrokerResult::Socket(socket::decode_socket_response(&mut decoder)?),
        RESPONSE_TAG_ERROR => BrokerResult::Error(decode_error_code(&mut decoder)?),
        RESPONSE_TAG_THREAD => BrokerResult::Thread(thread::decode_thread_response(&mut decoder)?),
        RESPONSE_TAG_OBJECT_CLOSED => BrokerResult::ObjectClosed,
        RESPONSE_TAG_READINESS => BrokerResult::Readiness(ReadinessFlags(decoder.u32()?)),
        RESPONSE_TAG_STATUS_FLAGS => {
            BrokerResult::StatusFlags(fs::decode_status_flags(&mut decoder)?)
        }
        RESPONSE_TAG_STATUS_FLAGS_SET => BrokerResult::StatusFlagsSet,
        RESPONSE_TAG_RANDOM_FILLED => BrokerResult::RandomFilled,
        RESPONSE_TAG_FILE => BrokerResult::File(fs::decode_fs_response(&mut decoder)?),
        RESPONSE_TAG_PROCESS => {
            BrokerResult::Process(process::decode_process_response(&mut decoder)?)
        }
        RESPONSE_TAG_PROCESS_GROUP => {
            BrokerResult::ProcessGroup(process_group::decode_process_group_response(&mut decoder)?)
        }
        RESPONSE_TAG_TIMER => BrokerResult::Timer(timer::decode_timer_response(&mut decoder)?),
        RESPONSE_TAG_SIGNAL => BrokerResult::Signal(signal::decode_signal_response(&mut decoder)?),
        RESPONSE_TAG_UNIX_SOCKET => {
            BrokerResult::UnixSocket(unix_socket::decode_unix_socket_response(&mut decoder)?)
        }
        RESPONSE_TAG_READINESS_QUEUE => BrokerResult::ReadinessQueue(
            readiness_queue::decode_readiness_queue_response(&mut decoder)?,
        ),
        _ => unreachable!("active response tag was validated"),
    };
    decoder.finish()?;
    Ok(BrokerResponse { request_id, result })
}

fn encode_error_code(encoder: &mut Encoder, error: ErrorCode) {
    encoder.u16(match error {
        ErrorCode::UnsupportedVersion => 1,
        ErrorCode::MalformedRequest => 2,
        ErrorCode::ProtocolState => 3,
        ErrorCode::UnsupportedOperation => 4,
        ErrorCode::Internal => 5,
        ErrorCode::PolicyDenied => 6,
        ErrorCode::UnknownObject => 7,
        ErrorCode::InvalidRights => 8,
        ErrorCode::ResourceExhausted => 9,
        ErrorCode::WouldBlock => 10,
        ErrorCode::PeerClosed => 11,
        ErrorCode::OutOfMemory => 12,
        ErrorCode::NonBlockingWouldBlock => 13,
    });
}

fn decode_error_code(decoder: &mut Decoder<'_>) -> Result<ErrorCode, WireError> {
    match decoder.u16()? {
        1 => Ok(ErrorCode::UnsupportedVersion),
        2 => Ok(ErrorCode::MalformedRequest),
        3 => Ok(ErrorCode::ProtocolState),
        4 => Ok(ErrorCode::UnsupportedOperation),
        5 => Ok(ErrorCode::Internal),
        6 => Ok(ErrorCode::PolicyDenied),
        7 => Ok(ErrorCode::UnknownObject),
        8 => Ok(ErrorCode::InvalidRights),
        9 => Ok(ErrorCode::ResourceExhausted),
        10 => Ok(ErrorCode::WouldBlock),
        11 => Ok(ErrorCode::PeerClosed),
        12 => Ok(ErrorCode::OutOfMemory),
        13 => Ok(ErrorCode::NonBlockingWouldBlock),
        _ => Err(WireError::InvalidTag),
    }
}

/// Encodes a broker notification body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_notification(notification: BrokerNotification) -> Vec<u8> {
    let mut encoder = Encoder::default();
    match notification {
        BrokerNotification::Readiness(notification) => {
            encoder.u8(NOTIFICATION_TAG_READINESS);
            encoder.handle(notification.handle);
            encoder.u32(notification.readiness.0);
        }
    }
    encoder.finish()
}

/// Decodes a broker notification body.
pub fn decode_notification(frame: &[u8]) -> Result<BrokerNotification, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let notification = match tag {
        NOTIFICATION_TAG_READINESS => BrokerNotification::Readiness(ReadinessNotification {
            handle: decoder.handle()?,
            readiness: ReadinessFlags(decoder.u32()?),
        }),
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(notification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{
        AddEventRequest, AddEventResponse, ConsumeEventRequest, CreateEventRequest,
        CreateEventResponse, EventConsumeMode, EventConsumption,
    };
    use crate::fs::{
        ChmodFileRequest, ChownFileRequest, FileAccessMode, FileError, FileMode, FileNodeInfo,
        FileOpenFlags, FileSeekWhence, FileStatus, FileStatusFlags, FileType, FileUser,
        HandleFileStatusRequest, IsTerminalFileRequest, MkdirFileRequest, OpenFileRequest,
        OpenFileResponse, PathFileStatusRequest, ReadDirectoryRequest, ReadDirectoryResponse,
        ReadFileRequest, ReadFileResponse, RmdirFileRequest, SeekFileRequest, SeekFileResponse,
        SetStatusFlagsRequest, TruncateFileRequest, UnlinkFileRequest, WriteFileRequest,
        WriteFileResponse,
    };
    use crate::message::{
        EventRequest, EventResponse, FileRequest, FileResponse, PipeRequest, PipeResponse,
        ProcessGroupRequest, ProcessGroupResponse, ProcessRequest, ProcessResponse,
        ReadinessQueueRequest, ReadinessQueueResponse, SignalRequest, SignalResponse,
        SocketRequest, SocketResponse, ThreadRequest, ThreadResponse, TimerRequest, TimerResponse,
        UnixSocketRequest, UnixSocketResponse,
    };
    use crate::pipe::{
        CreatePipeRequest, CreatePipeResponse, ReadPipeRequest, ReadPipeResponse, WritePipeRequest,
        WritePipeResponse,
    };
    use crate::process::{
        ChildExit, ChildSelector, DuplicateObjectsToChildRequest, ExitChildProcessRequest,
        ProcessExitStatus, ProcessIdentity, ProcessInfo, StartChildProcessRequest, ThreadInfo,
        WriteChildMemoryRequest,
    };
    use crate::process_group::{ProcessGroupMembership, SetProcessGroupRequest};
    use crate::readiness_queue::{
        AddReadinessQueueEntryRequest, CreateReadinessQueueResponse,
        ModifyReadinessQueueEntryRequest, ReadinessQueueEntryFlags, ReadinessQueueError,
        ReadinessQueueInterest, RemoveReadinessQueueEntryRequest, TakeReadyRequest,
        TakeReadyResponse,
    };
    use crate::shared_buffer::{
        MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence,
        SharedBufferSlotIndex,
    };
    use crate::signal::{
        OpenSignalsResponse, PendingSignal, SendSignalRequest, SignalEvent, SignalTarget,
        TakeSignalRequest,
    };
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
    use crate::timer::{
        CreateTimerRequest, CreateTimerResponse, GetTimerRequest, GetTimerResponse,
        ReadTimerRequest, ReadTimerResponse, SetTimerRequest, SetTimerResponse, TimerSpec,
    };
    use crate::unix_socket::{
        AcceptUnixSocketRequest, AcceptUnixSocketResponse, BindUnixSocketRequest,
        ConnectUnixSocketRequest, CreateUnixSocketPairResponse, CreateUnixSocketRequest,
        CreateUnixSocketResponse, GetUnixSocketNameRequest, GetUnixSocketNameResponse,
        GetUnixSocketOptionRequest, GetUnixSocketOptionResponse, ListenUnixSocketRequest,
        ReceiveUnixSocketRequest, ReceiveUnixSocketResponse, SendUnixSocketRequest,
        SendUnixSocketResponse, SetUnixSocketOptionRequest, ShutdownUnixSocketRequest,
        UnixSocketError,
    };
    use crate::{
        ObjectHandle, ProcessGroupId, ProcessId, ProtocolVersion, RequestId, SessionId, ThreadId,
    };
    use core::net::{Ipv4Addr, SocketAddrV4};
    use core::num::NonZeroU64;

    const TEST_REQUEST_ID: RequestId = RequestId(0x0102_0304_0506_0708);

    fn process_id(id: u32) -> ProcessId {
        ProcessId(id)
    }

    fn thread_id(id: u32) -> ThreadId {
        ThreadId(id)
    }

    fn sequence(slot_index: u32, length: u32) -> SharedBufferSequence {
        SharedBufferSequence::new(&[SharedBufferSlotIndex(slot_index)], length).unwrap()
    }

    #[test]
    fn successful_response_tags_match_request_tags() {
        assert_eq!(
            [
                RESPONSE_TAG_NEGOTIATED,
                RESPONSE_TAG_EVENT,
                RESPONSE_TAG_OBJECT_CLOSED,
                RESPONSE_TAG_PIPE,
                RESPONSE_TAG_READINESS,
                RESPONSE_TAG_SOCKET,
                RESPONSE_TAG_RANDOM_FILLED,
                RESPONSE_TAG_FILE,
                RESPONSE_TAG_THREAD,
                RESPONSE_TAG_PROCESS,
                RESPONSE_TAG_TIMER,
                RESPONSE_TAG_STATUS_FLAGS,
                RESPONSE_TAG_STATUS_FLAGS_SET,
                RESPONSE_TAG_SIGNAL,
                RESPONSE_TAG_PROCESS_GROUP,
                RESPONSE_TAG_UNIX_SOCKET,
                RESPONSE_TAG_READINESS_QUEUE,
            ],
            [
                REQUEST_TAG_NEGOTIATE,
                REQUEST_TAG_EVENT,
                REQUEST_TAG_CLOSE_OBJECT,
                REQUEST_TAG_PIPE,
                REQUEST_TAG_CHECK_READINESS,
                REQUEST_TAG_SOCKET,
                REQUEST_TAG_FILL_RANDOM,
                REQUEST_TAG_FILE,
                REQUEST_TAG_THREAD,
                REQUEST_TAG_PROCESS,
                REQUEST_TAG_TIMER,
                REQUEST_TAG_GET_STATUS_FLAGS,
                REQUEST_TAG_SET_STATUS_FLAGS,
                REQUEST_TAG_SIGNAL,
                REQUEST_TAG_PROCESS_GROUP,
                REQUEST_TAG_UNIX_SOCKET,
                REQUEST_TAG_READINESS_QUEUE,
            ]
        );
        // Top-level tags are consecutive.
        assert_eq!(REQUEST_TAG_READINESS_QUEUE, 16);
        assert_eq!(
            [
                RESPONSE_TAG_ERROR,
                RESPONSE_TAG_HANDSHAKE_ERROR,
                RESPONSE_TAG_VERSION_MISMATCH,
            ],
            [253, 254, 255]
        );
    }

    #[test]
    fn handshake_request_codec_round_trips_all_variants() {
        let requests = [BrokerHandshakeRequest {
            protocol_version: ProtocolVersion(1),
        }];

        for request in requests {
            assert_eq!(
                decode_handshake_request(&encode_handshake_request(request.clone())).unwrap(),
                request
            );
        }
    }

    #[test]
    fn request_codec_round_trips_all_variants() {
        let handle = ObjectHandle(13);
        // The wire bound covers encodable requests before operation-specific
        // transfer limits are validated.
        let largest_slots: [SharedBufferSlotIndex; MAX_SHARED_BUFFER_SEQUENCE_SLOTS] =
            core::array::from_fn(|index| {
                SharedBufferSlotIndex(u32::try_from(2 * index + 1).unwrap())
            });
        let largest_sequence = SharedBufferSequence::new(
            &largest_slots,
            u32::try_from(MAX_SHARED_BUFFER_SEQUENCE_SLOTS).unwrap() * SHARED_BUFFER_SLOT_SIZE,
        )
        .unwrap();
        let operations = [
            BrokerOperation::Thread(ThreadRequest::Exit(thread_id(17))),
            BrokerOperation::CloseObject(handle),
            BrokerOperation::CheckReadiness(handle),
            BrokerOperation::GetStatusFlags(handle),
            BrokerOperation::SetStatusFlags(SetStatusFlagsRequest {
                handle,
                mask: FileOpenFlags::STATUS,
                flags: FileOpenFlags::APPEND,
            }),
            BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
                flags: FileOpenFlags::NONE,
            })),
            BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 7,
                flags: FileOpenFlags::NONBLOCKING,
            })),
            BrokerOperation::Event(EventRequest::Add(AddEventRequest { handle, value: 3 })),
            BrokerOperation::Event(EventRequest::Consume(ConsumeEventRequest {
                handle,
                mode: EventConsumeMode::All,
            })),
            BrokerOperation::Event(EventRequest::Consume(ConsumeEventRequest {
                handle,
                mode: EventConsumeMode::One,
            })),
            BrokerOperation::Timer(TimerRequest::Create(CreateTimerRequest {
                flags: FileOpenFlags::NONE,
            })),
            BrokerOperation::Timer(TimerRequest::Create(CreateTimerRequest {
                flags: FileOpenFlags::NONBLOCKING,
            })),
            BrokerOperation::Timer(TimerRequest::Set(SetTimerRequest {
                handle,
                spec: TimerSpec {
                    value_ns: u64::MAX,
                    interval_ns: 1,
                },
            })),
            BrokerOperation::Timer(TimerRequest::Get(GetTimerRequest { handle })),
            BrokerOperation::Timer(TimerRequest::Read(ReadTimerRequest { handle })),
            BrokerOperation::ReadinessQueue(ReadinessQueueRequest::Create),
            BrokerOperation::ReadinessQueue(ReadinessQueueRequest::Add(
                AddReadinessQueueEntryRequest {
                    queue: handle,
                    target: ObjectHandle(u64::MAX),
                    key: u64::MAX,
                    interest: ReadinessQueueInterest {
                        readiness: ReadinessFlags(u32::MAX),
                        flags: ReadinessQueueEntryFlags::all(),
                        token: u64::MAX,
                    },
                },
            )),
            BrokerOperation::ReadinessQueue(ReadinessQueueRequest::Modify(
                ModifyReadinessQueueEntryRequest {
                    queue: handle,
                    target: ObjectHandle(7),
                    key: 0,
                    interest: ReadinessQueueInterest::default(),
                },
            )),
            BrokerOperation::ReadinessQueue(ReadinessQueueRequest::Remove(
                RemoveReadinessQueueEntryRequest {
                    queue: handle,
                    target: ObjectHandle(7),
                    key: 3,
                },
            )),
            BrokerOperation::ReadinessQueue(ReadinessQueueRequest::TakeReady(TakeReadyRequest {
                queue: handle,
                buffer: sequence(4, 48),
            })),
            BrokerOperation::Signal(SignalRequest::Open),
            BrokerOperation::Signal(SignalRequest::Send(SendSignalRequest {
                target: SignalTarget::Process(process_id(u32::MAX)),
                signal: 9,
            })),
            BrokerOperation::Signal(SignalRequest::Send(SendSignalRequest {
                target: SignalTarget::ProcessGroup(ProcessGroupId(7)),
                signal: 0,
            })),
            BrokerOperation::Signal(SignalRequest::Send(SendSignalRequest {
                target: SignalTarget::All,
                signal: 64,
            })),
            BrokerOperation::ProcessGroup(ProcessGroupRequest::Set(SetProcessGroupRequest {
                process_id: process_id(3),
                process_group: ProcessGroupId(u32::MAX),
            })),
            BrokerOperation::ProcessGroup(ProcessGroupRequest::CreateSession(process_id(5))),
            BrokerOperation::Signal(SignalRequest::Take(TakeSignalRequest { handle })),
            BrokerOperation::Pipe(PipeRequest::Create(CreatePipeRequest {
                capacity: 4096,
                atomic_write_size: 512,
                flags: FileOpenFlags::STATUS,
            })),
            BrokerOperation::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle,
                buffer: sequence(2, 32),
            })),
            BrokerOperation::Pipe(PipeRequest::Write(WritePipeRequest {
                handle,
                buffer: sequence(15, 3),
            })),
            BrokerOperation::FillRandom(sequence(7, 256)),
            BrokerOperation::File(FileRequest::Open(OpenFileRequest {
                path: sequence(1, 7),
                user: FileUser { user: 2, group: 3 },
                access: FileAccessMode::ReadWrite,
                flags: FileOpenFlags::CREATE | FileOpenFlags::EXCLUSIVE | FileOpenFlags::NO_FOLLOW,
                mode: FileMode::from_bits(0o640).unwrap(),
            })),
            BrokerOperation::File(FileRequest::Read(ReadFileRequest {
                handle,
                buffer: largest_sequence,
                offset: Some(u64::MAX),
            })),
            BrokerOperation::File(FileRequest::Read(ReadFileRequest {
                handle,
                buffer: SharedBufferSequence::new(&[SharedBufferSlotIndex(2)], 32).unwrap(),
                offset: None,
            })),
            BrokerOperation::File(FileRequest::Write(WriteFileRequest {
                handle,
                buffer: SharedBufferSequence::new(&[SharedBufferSlotIndex(3)], 17).unwrap(),
                offset: Some(11),
            })),
            BrokerOperation::File(FileRequest::Seek(SeekFileRequest {
                handle,
                offset: -19,
                whence: FileSeekWhence::RelativeToCurrentOffset,
            })),
            BrokerOperation::File(FileRequest::Truncate(TruncateFileRequest {
                handle,
                length: 4096,
                reset_offset: true,
            })),
            BrokerOperation::File(FileRequest::ReadDirectory(ReadDirectoryRequest {
                handle,
                buffer: sequence(4, 256),
                start_index: 19,
            })),
            BrokerOperation::File(FileRequest::PathStatus(PathFileStatusRequest {
                path: sequence(5, 9),
                user: FileUser { user: 2, group: 3 },
            })),
            BrokerOperation::File(FileRequest::HandleStatus(HandleFileStatusRequest {
                handle,
            })),
            BrokerOperation::File(FileRequest::IsTerminal(IsTerminalFileRequest { handle })),
            BrokerOperation::File(FileRequest::Chmod(ChmodFileRequest {
                path: sequence(6, 9),
                user: FileUser { user: 2, group: 3 },
                mode: FileMode::from_bits(0o755).unwrap(),
            })),
            BrokerOperation::File(FileRequest::Chown(ChownFileRequest {
                path: sequence(7, 9),
                acting_user: FileUser { user: 0, group: 0 },
                user: Some(2),
                group: None,
            })),
            BrokerOperation::File(FileRequest::Unlink(UnlinkFileRequest {
                path: sequence(8, 9),
                user: FileUser { user: 2, group: 3 },
            })),
            BrokerOperation::File(FileRequest::Mkdir(MkdirFileRequest {
                path: sequence(9, 9),
                user: FileUser { user: 2, group: 3 },
                mode: FileMode::from_bits(0o750).unwrap(),
            })),
            BrokerOperation::File(FileRequest::Rmdir(RmdirFileRequest {
                path: sequence(10, 9),
                user: FileUser { user: 2, group: 3 },
            })),
            BrokerOperation::Socket(SocketRequest::Create(CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
                flags: FileOpenFlags::NONE,
            })),
            BrokerOperation::Socket(SocketRequest::Create(CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Datagram,
                protocol: IpProtocol::Udp,
                flags: FileOpenFlags::NONBLOCKING,
            })),
            BrokerOperation::Socket(SocketRequest::Bind(BindSocketRequest {
                handle,
                address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            })),
            BrokerOperation::Socket(SocketRequest::Listen(ListenSocketRequest {
                handle,
                backlog: 4096,
            })),
            BrokerOperation::Socket(SocketRequest::Accept(AcceptSocketRequest {
                handle,
                flags: FileOpenFlags::NONBLOCKING,
            })),
            BrokerOperation::Socket(SocketRequest::Connect(ConnectSocketRequest {
                handle,
                address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443),
            })),
            BrokerOperation::Socket(SocketRequest::Send(SendSocketRequest {
                handle,
                buffer: sequence(15, 3),
                flags: SendFlags::NONE,
            })),
            BrokerOperation::Socket(SocketRequest::SendTo(SendToSocketRequest {
                handle,
                buffer: sequence(15, 3),
                flags: SendFlags::NONE,
                destination: Some(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 53)),
            })),
            BrokerOperation::Socket(SocketRequest::SendTo(SendToSocketRequest {
                handle,
                buffer: largest_sequence,
                flags: SendFlags::NONE,
                destination: Some(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 53)),
            })),
            BrokerOperation::Socket(SocketRequest::SendTo(SendToSocketRequest {
                handle,
                buffer: sequence(15, 0),
                flags: SendFlags::NONE,
                destination: None,
            })),
            BrokerOperation::Socket(SocketRequest::Receive(ReceiveSocketRequest {
                handle,
                buffer: sequence(15, 3),
                flags: ReceiveFlags::PEEK,
                peek_offset: 2,
                peek_length: 5,
            })),
            BrokerOperation::Socket(SocketRequest::Receive(ReceiveSocketRequest {
                handle,
                buffer: largest_sequence,
                flags: ReceiveFlags::PEEK,
                peek_offset: u32::MAX,
                peek_length: u32::MAX,
            })),
            BrokerOperation::Socket(SocketRequest::ReceiveFrom(ReceiveFromSocketRequest {
                handle,
                buffer: sequence(15, 3),
                flags: ReceiveFromFlags::PEEK,
            })),
            BrokerOperation::Socket(SocketRequest::Shutdown(ShutdownSocketRequest {
                handle,
                mode: ShutdownMode::Read,
            })),
            BrokerOperation::Socket(SocketRequest::Shutdown(ShutdownSocketRequest {
                handle,
                mode: ShutdownMode::Write,
            })),
            BrokerOperation::Socket(SocketRequest::Shutdown(ShutdownSocketRequest {
                handle,
                mode: ShutdownMode::Both,
            })),
            BrokerOperation::Socket(SocketRequest::Shutdown(ShutdownSocketRequest {
                handle,
                mode: ShutdownMode::Abort,
            })),
            BrokerOperation::Socket(SocketRequest::Shutdown(ShutdownSocketRequest {
                handle,
                mode: ShutdownMode::StopListening,
            })),
            BrokerOperation::Socket(SocketRequest::SetOption(SetSocketOptionRequest {
                handle,
                value: SocketOptionValue::NoDelay(true),
            })),
            BrokerOperation::Socket(SocketRequest::SetOption(SetSocketOptionRequest {
                handle,
                value: SocketOptionValue::KeepAlive(false),
            })),
            BrokerOperation::Socket(SocketRequest::SetOption(SetSocketOptionRequest {
                handle,
                value: SocketOptionValue::ReceiveTimeout(Some(core::time::Duration::new(3, 4))),
            })),
            BrokerOperation::Socket(SocketRequest::SetOption(SetSocketOptionRequest {
                handle,
                value: SocketOptionValue::Linger(None),
            })),
            BrokerOperation::Socket(SocketRequest::GetOption(GetSocketOptionRequest {
                handle,
                name: SocketOptionName::NoDelay,
            })),
            BrokerOperation::Socket(SocketRequest::GetOption(GetSocketOptionRequest {
                handle,
                name: SocketOptionName::SendTimeout,
            })),
            BrokerOperation::Socket(SocketRequest::CheckConnect(CheckConnectSocketRequest {
                handle,
            })),
            BrokerOperation::Socket(SocketRequest::GetName(GetSocketNameRequest {
                handle,
                peer: false,
            })),
            BrokerOperation::Socket(SocketRequest::GetName(GetSocketNameRequest {
                handle,
                peer: true,
            })),
            BrokerOperation::Socket(SocketRequest::TakeError(TakeSocketErrorRequest { handle })),
            BrokerOperation::Socket(SocketRequest::SetError(SetSocketErrorRequest {
                handle,
                error: SocketError::ConnectionReset,
            })),
            BrokerOperation::Thread(ThreadRequest::Create),
            BrokerOperation::Thread(ThreadRequest::Exit(thread_id(u32::MAX))),
            BrokerOperation::Process(ProcessRequest::AllocateChild),
            BrokerOperation::Process(ProcessRequest::DuplicateObjectsToChild(
                DuplicateObjectsToChildRequest {
                    child_process_id: process_id(u32::MAX),
                    handles: largest_sequence,
                },
            )),
            BrokerOperation::Process(ProcessRequest::WriteChildMemory(WriteChildMemoryRequest {
                child_process_id: process_id(u32::MAX),
                offset: u64::MAX,
                data: largest_sequence,
            })),
            BrokerOperation::Process(ProcessRequest::StartChild(StartChildProcessRequest {
                child_process_id: process_id(u32::MAX),
                startup: ProcessStartupDescriptor {
                    buffer: largest_sequence,
                },
            })),
            BrokerOperation::Process(ProcessRequest::ExitChild(ExitChildProcessRequest {
                child_process_id: process_id(u32::MAX),
                exit_status: ProcessExitStatus::Exited { code: u32::MAX },
            })),
            BrokerOperation::Process(ProcessRequest::ExitChild(ExitChildProcessRequest {
                child_process_id: process_id(1),
                exit_status: ProcessExitStatus::Signaled { signal: 9 },
            })),
            BrokerOperation::Process(ProcessRequest::ExitChild(ExitChildProcessRequest {
                child_process_id: process_id(1),
                exit_status: ProcessExitStatus::Unknown,
            })),
            BrokerOperation::Process(ProcessRequest::CancelChild(process_id(u32::MAX))),
            BrokerOperation::Process(ProcessRequest::ReportExitStatus(
                ProcessExitStatus::Exited { code: u32::MAX },
            )),
            BrokerOperation::Process(ProcessRequest::ReportExitStatus(
                ProcessExitStatus::Signaled { signal: 6 },
            )),
            BrokerOperation::Process(ProcessRequest::ReportExitStatus(ProcessExitStatus::Unknown)),
            BrokerOperation::Process(ProcessRequest::SetChildExitRetention(false)),
            BrokerOperation::Process(ProcessRequest::SetChildExitRetention(true)),
            BrokerOperation::Process(ProcessRequest::SetOrphanAdoption(false)),
            BrokerOperation::Process(ProcessRequest::SetOrphanAdoption(true)),
            BrokerOperation::Process(ProcessRequest::CollectChildExit(ChildSelector::Any)),
            BrokerOperation::Process(ProcessRequest::CollectChildExit(ChildSelector::Process(
                process_id(u32::MAX),
            ))),
            BrokerOperation::Process(ProcessRequest::CollectChildExit(
                ChildSelector::ProcessGroup(ProcessGroupId(7)),
            )),
            BrokerOperation::Process(ProcessRequest::GetInfo(process_id(u32::MAX))),
            BrokerOperation::Process(ProcessRequest::GetThreadInfo(thread_id(u32::MAX))),
            BrokerOperation::UnixSocket(UnixSocketRequest::Create(CreateUnixSocketRequest {
                socket_type: SocketType::Stream,
                flags: FileOpenFlags::NONBLOCKING,
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::CreatePair(CreateUnixSocketRequest {
                socket_type: SocketType::Datagram,
                flags: FileOpenFlags::NONE,
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::Bind(BindUnixSocketRequest {
                handle,
                address: largest_sequence,
                user: FileUser {
                    user: 1000,
                    group: u16::MAX,
                },
                mode: FileMode::from_bits(0o755).unwrap(),
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::Listen(ListenUnixSocketRequest {
                handle,
                backlog: u32::MAX,
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::Connect(ConnectUnixSocketRequest {
                handle,
                address: largest_sequence,
                user: FileUser { user: 0, group: 0 },
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::Accept(AcceptUnixSocketRequest {
                handle,
                flags: FileOpenFlags::NONBLOCKING,
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::Send(SendUnixSocketRequest {
                handle,
                buffer: largest_sequence,
                address_length: u32::MAX,
                user: FileUser { user: 1, group: 2 },
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::Receive(ReceiveUnixSocketRequest {
                handle,
                buffer: largest_sequence,
                capacity: u32::MAX,
                peek: true,
                source: true,
                nonblocking: true,
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::Shutdown(ShutdownUnixSocketRequest {
                handle,
                mode: ShutdownMode::Both,
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::GetName(GetUnixSocketNameRequest {
                handle,
                peer: true,
                buffer: largest_sequence,
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::SetOption(SetUnixSocketOptionRequest {
                handle,
                value: SocketOptionValue::ReceiveTimeout(Some(core::time::Duration::new(
                    u64::MAX,
                    999_999_999,
                ))),
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::SetOption(SetUnixSocketOptionRequest {
                handle,
                value: SocketOptionValue::Linger(None),
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::SetOption(SetUnixSocketOptionRequest {
                handle,
                value: SocketOptionValue::Broadcast(true),
            })),
            BrokerOperation::UnixSocket(UnixSocketRequest::GetOption(GetUnixSocketOptionRequest {
                handle,
                name: SocketOptionName::SendTimeout,
            })),
        ];
        let mut maximum_encoded_size = 0;

        for operation in operations {
            let request = BrokerRequest {
                request_id: TEST_REQUEST_ID,
                operation,
            };
            let encoded = encode_request(request.clone());
            maximum_encoded_size = maximum_encoded_size.max(encoded.len());
            assert!(encoded.len() <= MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
            assert_eq!(decode_request(&encoded).unwrap(), request);
            // Every active tag must be reported as a phase violation during
            // the handshake, not as an unknown tag: only the former is turned
            // into a clean protocol-violation shutdown by the transport.
            assert_eq!(
                decode_handshake_request(&encoded),
                Err(WireError::WrongMessagePhase)
            );
        }
        assert_eq!(maximum_encoded_size, MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
    }

    #[test]
    fn flag_bits_round_trip_unmasked() {
        // The codec carries flags verbatim so the core can reject unsupported
        // bits; masking them here would hide them from that check, and a
        // dropped field would make an unsupported flag look like none at all.
        let handle = ObjectHandle(13);
        let buffer = sequence(15, 3);
        let unsupported = 0x8000_0001;
        for operation in [
            BrokerOperation::Socket(SocketRequest::Send(SendSocketRequest {
                handle,
                buffer,
                flags: SendFlags(unsupported),
            })),
            BrokerOperation::Socket(SocketRequest::Receive(ReceiveSocketRequest {
                handle,
                buffer,
                flags: ReceiveFlags(unsupported),
                peek_offset: 0,
                peek_length: 0,
            })),
            BrokerOperation::Socket(SocketRequest::ReceiveFrom(ReceiveFromSocketRequest {
                handle,
                buffer,
                flags: ReceiveFromFlags(unsupported),
            })),
        ] {
            let request = BrokerRequest {
                request_id: TEST_REQUEST_ID,
                operation,
            };
            assert_eq!(
                decode_request(&encode_request(request.clone())).unwrap(),
                request
            );
        }

        assert!(SendFlags(unsupported).has_unsupported_bits());
        assert!(ReceiveFlags(unsupported).has_unsupported_bits());
        // No send flag exists yet, so every bit is unsupported there.
        assert!(SendFlags(ReceiveFlags::PEEK.0).has_unsupported_bits());
        assert!(!SendFlags::NONE.has_unsupported_bits());
        assert!(!ReceiveFlags::PEEK.has_unsupported_bits());
        assert!(ReceiveFlags::PEEK.contains(ReceiveFlags::PEEK));
        assert!(!ReceiveFlags::NONE.contains(ReceiveFlags::PEEK));
        assert!(ReceiveFromFlags(unsupported).has_unsupported_bits());
        assert!(!ReceiveFromFlags::PEEK.has_unsupported_bits());
        assert!(ReceiveFromFlags::PEEK.contains(ReceiveFromFlags::PEEK));
    }

    #[test]
    fn socket_error_codec_round_trips_all_variants() {
        for error in [
            SocketError::ConnectionRefused,
            SocketError::ConnectionReset,
            SocketError::ConnectionAborted,
            SocketError::NetworkUnreachable,
            SocketError::HostUnreachable,
            SocketError::TimedOut,
            SocketError::AddressInUse,
            SocketError::AddressNotAvailable,
            SocketError::PolicyDenied,
            SocketError::Other,
            SocketError::NotConnected,
            SocketError::InvalidArgument,
            SocketError::AlreadyConnected,
            SocketError::AlreadyInProgress,
            SocketError::Shutdown,
            SocketError::DestinationAddressRequired,
            SocketError::Listening,
            SocketError::ResourceExhausted,
            SocketError::UnsupportedOperation,
        ] {
            for socket_response in [
                SocketResponse::Failed(error),
                SocketResponse::Connect(ConnectSocketResponse {
                    status: SocketConnectionStatus::Failed(error),
                }),
                SocketResponse::TakeError(TakeSocketErrorResponse { error: Some(error) }),
            ] {
                let response = BrokerResponse {
                    request_id: TEST_REQUEST_ID,
                    result: BrokerResult::Socket(socket_response),
                };
                assert_eq!(
                    decode_response(&encode_response(response.clone())).unwrap(),
                    response
                );
            }
        }
    }

    #[test]
    fn file_error_wire_values_are_stable_and_round_trip() {
        for (error, raw) in [
            (FileError::AccessNotAllowed, 1),
            (FileError::NoWritePermissions, 2),
            (FileError::ReadOnlyFs, 3),
            (FileError::AlreadyExists, 4),
            (FileError::Io, 5),
            (FileError::NoSuchFileOrDirectory, 6),
            (FileError::NoSearchPermissions, 7),
            (FileError::InvalidPathname, 8),
            (FileError::MissingComponent, 9),
            (FileError::ComponentNotDirectory, 10),
            (FileError::NotFile, 11),
            (FileError::NotForReading, 12),
            (FileError::NotForWriting, 13),
            (FileError::InvalidOffset, 14),
            (FileError::NonSeekable, 15),
            (FileError::IsDirectory, 16),
            (FileError::IsTerminalDevice, 17),
            (FileError::NotOwner, 18),
            (FileError::NotDirectory, 19),
            (FileError::Busy, 20),
            (FileError::NotEmpty, 21),
            (FileError::PathOnly, 22),
        ] {
            let response = BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result: BrokerResult::File(FileResponse::Failed(error)),
            };
            let encoded = encode_response(response.clone());
            assert_eq!(encoded.last(), Some(&raw));
            assert_eq!(decode_response(&encoded).unwrap(), response);
        }
    }

    #[test]
    fn request_codec_round_trips_identifier_bounds() {
        for request_id in [RequestId(0), RequestId(u64::MAX)] {
            let request = BrokerRequest {
                request_id,
                operation: BrokerOperation::CloseObject(ObjectHandle(13)),
            };
            assert_eq!(
                decode_request(&encode_request(request.clone())).unwrap(),
                request
            );
        }
        for thread_id in [ThreadId(0), ThreadId(u32::MAX)] {
            let request = BrokerRequest {
                request_id: TEST_REQUEST_ID,
                operation: BrokerOperation::Thread(ThreadRequest::Exit(thread_id)),
            };
            assert_eq!(
                decode_request(&encode_request(request.clone())).unwrap(),
                request
            );
        }
    }

    #[test]
    fn handshake_response_codec_round_trips_all_variants() {
        let responses = [
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: ProtocolVersion(1),
                process_id: process_id(1),
                initial_thread_id: thread_id(2),
                startup: None,
            },
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: ProtocolVersion(1),
                process_id: process_id(7),
                initial_thread_id: thread_id(8),
                startup: Some(ProcessStartupDescriptor {
                    buffer: sequence(0, 37),
                }),
            },
            BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version: ProtocolVersion(1),
            },
            BrokerHandshakeResponse::Error(ErrorCode::PolicyDenied),
            BrokerHandshakeResponse::Error(ErrorCode::Internal),
        ];

        for response in responses {
            assert_eq!(
                decode_handshake_response(&encode_handshake_response(response.clone())).unwrap(),
                response
            );
        }
    }

    #[test]
    fn response_codec_round_trips_all_variants() {
        let handle = ObjectHandle(13);
        let results = [
            BrokerResult::Thread(ThreadResponse::Create(thread_id(17))),
            BrokerResult::Thread(ThreadResponse::Exit),
            BrokerResult::ObjectClosed,
            BrokerResult::Readiness(ReadinessFlags::READ),
            BrokerResult::Readiness(ReadinessFlags::WRITE),
            BrokerResult::StatusFlags(FileStatusFlags {
                access: FileAccessMode::WriteOnly,
                flags: FileOpenFlags::NONBLOCKING | FileOpenFlags::APPEND,
            }),
            BrokerResult::StatusFlags(FileStatusFlags {
                access: FileAccessMode::ReadOnly,
                flags: FileOpenFlags::PATH,
            }),
            BrokerResult::StatusFlagsSet,
            BrokerResult::Event(EventResponse::Create(CreateEventResponse { handle })),
            BrokerResult::Event(EventResponse::Add(AddEventResponse {
                readiness: ReadinessFlags::READ | ReadinessFlags::WRITE,
            })),
            BrokerResult::Event(EventResponse::Consume(EventConsumption {
                value: 3,
                readiness: ReadinessFlags::WRITE,
            })),
            BrokerResult::Timer(TimerResponse::Create(CreateTimerResponse { handle })),
            BrokerResult::Timer(TimerResponse::Set(SetTimerResponse {
                previous: TimerSpec {
                    value_ns: 5,
                    interval_ns: u64::MAX,
                },
            })),
            BrokerResult::Timer(TimerResponse::Get(GetTimerResponse {
                current: TimerSpec::default(),
            })),
            BrokerResult::Timer(TimerResponse::Read(ReadTimerResponse {
                expirations: u64::MAX,
            })),
            BrokerResult::UnixSocket(UnixSocketResponse::Create(CreateUnixSocketResponse {
                handle,
            })),
            BrokerResult::UnixSocket(UnixSocketResponse::CreatePair(
                CreateUnixSocketPairResponse {
                    first: handle,
                    second: ObjectHandle(u64::MAX),
                },
            )),
            BrokerResult::UnixSocket(UnixSocketResponse::Bind),
            BrokerResult::UnixSocket(UnixSocketResponse::Listen),
            BrokerResult::UnixSocket(UnixSocketResponse::Connect),
            BrokerResult::UnixSocket(UnixSocketResponse::Accept(AcceptUnixSocketResponse {
                handle,
            })),
            BrokerResult::UnixSocket(UnixSocketResponse::Send(SendUnixSocketResponse {
                sent: u32::MAX,
            })),
            BrokerResult::UnixSocket(UnixSocketResponse::Receive(ReceiveUnixSocketResponse {
                received: 1,
                length: u32::MAX,
                source_length: 109,
            })),
            BrokerResult::UnixSocket(UnixSocketResponse::Shutdown),
            BrokerResult::UnixSocket(UnixSocketResponse::GetName(GetUnixSocketNameResponse {
                length: 3,
            })),
            BrokerResult::UnixSocket(UnixSocketResponse::SetOption),
            BrokerResult::UnixSocket(UnixSocketResponse::GetOption(GetUnixSocketOptionResponse {
                value: SocketOptionValue::ReceiveTimeout(Some(core::time::Duration::new(
                    u64::MAX,
                    1,
                ))),
            })),
            BrokerResult::UnixSocket(UnixSocketResponse::GetOption(GetUnixSocketOptionResponse {
                value: SocketOptionValue::KeepAlive(false),
            })),
            BrokerResult::UnixSocket(UnixSocketResponse::Failed(UnixSocketError::AddressInUse)),
            BrokerResult::UnixSocket(UnixSocketResponse::Failed(UnixSocketError::NotPermitted)),
            BrokerResult::UnixSocket(UnixSocketResponse::Failed(UnixSocketError::ConnectionReset)),
            BrokerResult::UnixSocket(UnixSocketResponse::Failed(UnixSocketError::File(
                FileError::NoSuchFileOrDirectory,
            ))),
            BrokerResult::ReadinessQueue(ReadinessQueueResponse::Create(
                CreateReadinessQueueResponse { handle },
            )),
            BrokerResult::ReadinessQueue(ReadinessQueueResponse::Add),
            BrokerResult::ReadinessQueue(ReadinessQueueResponse::Modify),
            BrokerResult::ReadinessQueue(ReadinessQueueResponse::Remove),
            BrokerResult::ReadinessQueue(ReadinessQueueResponse::TakeReady(TakeReadyResponse {
                count: u32::MAX,
            })),
            BrokerResult::ReadinessQueue(ReadinessQueueResponse::Failed(
                ReadinessQueueError::AlreadyRegistered,
            )),
            BrokerResult::ReadinessQueue(ReadinessQueueResponse::Failed(
                ReadinessQueueError::NotRegistered,
            )),
            BrokerResult::Signal(SignalResponse::Open(OpenSignalsResponse { handle })),
            BrokerResult::Signal(SignalResponse::Sent),
            BrokerResult::Signal(SignalResponse::Take(SignalEvent::Signal(PendingSignal {
                signal: 64,
                sender: process_id(u32::MAX),
            }))),
            BrokerResult::Signal(SignalResponse::Take(SignalEvent::ChildExited(ChildExit {
                process_id: process_id(u32::MAX),
                exit_status: ProcessExitStatus::Signaled { signal: 9 },
            }))),
            BrokerResult::Signal(SignalResponse::Take(SignalEvent::ChildRemoved)),
            BrokerResult::ProcessGroup(ProcessGroupResponse::Set),
            BrokerResult::ProcessGroup(ProcessGroupResponse::CreateSession),
            BrokerResult::Pipe(PipeResponse::Create(CreatePipeResponse {
                read_handle: handle,
                write_handle: ObjectHandle(14),
            })),
            BrokerResult::Pipe(PipeResponse::Read(ReadPipeResponse { read: 3 })),
            BrokerResult::Pipe(PipeResponse::Write(WritePipeResponse { written: 3 })),
            BrokerResult::Socket(SocketResponse::Create(CreateSocketResponse { handle })),
            BrokerResult::Socket(SocketResponse::Bind(BindSocketResponse {
                local_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152),
            })),
            BrokerResult::Socket(SocketResponse::Listen(ListenSocketResponse {
                local_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152),
            })),
            BrokerResult::Socket(SocketResponse::Accept(AcceptSocketResponse {
                handle,
                local_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152),
                remote_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            })),
            BrokerResult::Socket(SocketResponse::CheckConnect(ConnectSocketResponse {
                status: SocketConnectionStatus::Unconnected,
            })),
            BrokerResult::Socket(SocketResponse::Connect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connecting,
            })),
            BrokerResult::Socket(SocketResponse::Connect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connected,
            })),
            BrokerResult::Socket(SocketResponse::Connect(ConnectSocketResponse {
                status: SocketConnectionStatus::Failed(SocketError::ConnectionRefused),
            })),
            BrokerResult::Socket(SocketResponse::Send(SendSocketResponse { sent: 3 })),
            BrokerResult::Socket(SocketResponse::SendTo(SendToSocketResponse { sent: 3 })),
            BrokerResult::Socket(SocketResponse::Receive(ReceiveSocketResponse::Received(3))),
            BrokerResult::Socket(SocketResponse::Receive(ReceiveSocketResponse::Received(0))),
            BrokerResult::Socket(SocketResponse::Receive(ReceiveSocketResponse::EndOfStream)),
            BrokerResult::Socket(SocketResponse::ReceiveFrom(ReceiveFromSocketResponse {
                received: 3,
                datagram_length: 7,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            })),
            BrokerResult::Socket(SocketResponse::ReceiveFrom(ReceiveFromSocketResponse {
                received: 0,
                datagram_length: 0,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            })),
            BrokerResult::Socket(SocketResponse::Shutdown),
            BrokerResult::Socket(SocketResponse::SetOption),
            BrokerResult::Socket(SocketResponse::GetOption(GetSocketOptionResponse {
                value: SocketOptionValue::NoDelay(true),
            })),
            BrokerResult::Socket(SocketResponse::GetOption(GetSocketOptionResponse {
                value: SocketOptionValue::SendTimeout(Some(core::time::Duration::new(5, 6))),
            })),
            BrokerResult::Socket(SocketResponse::CheckConnect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connecting,
            })),
            BrokerResult::Socket(SocketResponse::CheckConnect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connected,
            })),
            BrokerResult::Socket(SocketResponse::GetName(GetSocketNameResponse {
                address: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152)),
            })),
            BrokerResult::Socket(SocketResponse::GetName(GetSocketNameResponse {
                address: None,
            })),
            BrokerResult::Socket(SocketResponse::TakeError(TakeSocketErrorResponse {
                error: Some(SocketError::ConnectionReset),
            })),
            BrokerResult::Socket(SocketResponse::TakeError(TakeSocketErrorResponse {
                error: None,
            })),
            BrokerResult::Socket(SocketResponse::SetError),
            BrokerResult::Socket(SocketResponse::Failed(SocketError::ConnectionReset)),
            BrokerResult::RandomFilled,
            BrokerResult::File(FileResponse::Open(OpenFileResponse { handle })),
            BrokerResult::File(FileResponse::Read(ReadFileResponse { read: 11 })),
            BrokerResult::File(FileResponse::Write(WriteFileResponse { written: 17 })),
            BrokerResult::File(FileResponse::Seek(SeekFileResponse { offset: 19 })),
            BrokerResult::File(FileResponse::Truncate),
            BrokerResult::File(FileResponse::ReadDirectory(ReadDirectoryResponse {
                length: 23,
                next_index: Some(29),
            })),
            BrokerResult::File(FileResponse::PathStatus(FileStatus {
                file_type: FileType::CharacterDevice,
                mode: FileMode::from_bits(0o620).unwrap(),
                size: u64::MAX,
                owner: FileUser {
                    user: u16::MAX,
                    group: u16::MAX,
                },
                node_info: FileNodeInfo {
                    dev: u64::MAX,
                    ino: u64::MAX,
                    rdev: Some(NonZeroU64::MAX),
                },
                blksize: u64::MAX,
            })),
            BrokerResult::File(FileResponse::HandleStatus(FileStatus {
                file_type: FileType::CharacterDevice,
                mode: FileMode::from_bits(0o620).unwrap(),
                size: u64::MAX,
                owner: FileUser {
                    user: u16::MAX,
                    group: u16::MAX,
                },
                node_info: FileNodeInfo {
                    dev: u64::MAX,
                    ino: u64::MAX,
                    rdev: Some(NonZeroU64::MAX),
                },
                blksize: u64::MAX,
            })),
            BrokerResult::File(FileResponse::IsTerminal(false)),
            BrokerResult::File(FileResponse::IsTerminal(true)),
            BrokerResult::File(FileResponse::Chmod),
            BrokerResult::File(FileResponse::Chown),
            BrokerResult::File(FileResponse::Unlink),
            BrokerResult::File(FileResponse::Mkdir),
            BrokerResult::File(FileResponse::Rmdir),
            BrokerResult::File(FileResponse::Failed(FileError::Io)),
            BrokerResult::Process(ProcessResponse::AllocateChild(ProcessIdentity {
                process_id: process_id(19),
                initial_thread_id: thread_id(21),
            })),
            BrokerResult::Process(ProcessResponse::DuplicateObjectsToChild),
            BrokerResult::Process(ProcessResponse::WriteChildMemory),
            BrokerResult::Process(ProcessResponse::StartChild),
            BrokerResult::Process(ProcessResponse::ExitChild),
            BrokerResult::Process(ProcessResponse::CancelChild),
            BrokerResult::Process(ProcessResponse::ReportExitStatus),
            BrokerResult::Process(ProcessResponse::SetChildExitRetention),
            BrokerResult::Process(ProcessResponse::SetOrphanAdoption),
            BrokerResult::Process(ProcessResponse::CollectChildExit(ChildExit {
                process_id: process_id(u32::MAX),
                exit_status: ProcessExitStatus::Exited { code: u32::MAX },
            })),
            BrokerResult::Process(ProcessResponse::CollectChildExit(ChildExit {
                process_id: process_id(1),
                exit_status: ProcessExitStatus::Signaled { signal: 11 },
            })),
            BrokerResult::Process(ProcessResponse::CollectChildExit(ChildExit {
                process_id: process_id(1),
                exit_status: ProcessExitStatus::Unknown,
            })),
            BrokerResult::Process(ProcessResponse::GetInfo(ProcessInfo {
                creator: None,
                parent: None,
                membership: ProcessGroupMembership {
                    process_group: ProcessGroupId(1),
                    session: SessionId(1),
                },
            })),
            BrokerResult::Process(ProcessResponse::GetInfo(ProcessInfo {
                creator: Some(process_id(u32::MAX)),
                parent: Some(process_id(1)),
                membership: ProcessGroupMembership {
                    process_group: ProcessGroupId(u32::MAX),
                    session: SessionId(3),
                },
            })),
            BrokerResult::Process(ProcessResponse::GetThreadInfo(ThreadInfo {
                process_id: process_id(1),
                initial: false,
            })),
            BrokerResult::Process(ProcessResponse::GetThreadInfo(ThreadInfo {
                process_id: process_id(u32::MAX),
                initial: true,
            })),
            BrokerResult::Error(ErrorCode::PolicyDenied),
            BrokerResult::Error(ErrorCode::WouldBlock),
            BrokerResult::Error(ErrorCode::NonBlockingWouldBlock),
            BrokerResult::Error(ErrorCode::PeerClosed),
            BrokerResult::Error(ErrorCode::OutOfMemory),
            BrokerResult::Error(ErrorCode::Internal),
        ];
        let mut maximum_encoded_size = 0;

        for result in results {
            let response = BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result,
            };
            let encoded = encode_response(response.clone());
            maximum_encoded_size = maximum_encoded_size.max(encoded.len());
            assert!(encoded.len() <= MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
            assert_eq!(decode_response(&encoded).unwrap(), response);
            assert_eq!(
                decode_handshake_response(&encoded),
                Err(WireError::WrongMessagePhase)
            );
        }
        assert_eq!(maximum_encoded_size, 58);
    }

    #[test]
    fn response_codec_round_trips_identifier_bounds() {
        for request_id in [RequestId(0), RequestId(u64::MAX)] {
            let response = BrokerResponse {
                request_id,
                result: BrokerResult::ObjectClosed,
            };
            assert_eq!(
                decode_response(&encode_response(response.clone())).unwrap(),
                response
            );
        }
        for thread_id in [ThreadId(0), ThreadId(u32::MAX)] {
            let response = BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result: BrokerResult::Thread(ThreadResponse::Create(thread_id)),
            };
            assert_eq!(
                decode_response(&encode_response(response.clone())).unwrap(),
                response
            );
        }
        for process_id in [ProcessId(0), ProcessId(u32::MAX)] {
            let response = BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result: BrokerResult::Process(ProcessResponse::AllocateChild(ProcessIdentity {
                    process_id,
                    initial_thread_id: ThreadId(0),
                })),
            };
            assert_eq!(
                decode_response(&encode_response(response.clone())).unwrap(),
                response
            );
        }
    }

    #[test]
    fn notification_codec_round_trips_all_variants() {
        let handle = ObjectHandle(13);
        let notifications = [BrokerNotification::Readiness(ReadinessNotification {
            handle,
            readiness: ReadinessFlags::READ | ReadinessFlags::HANGUP,
        })];
        let mut maximum_encoded_size = 0;

        for notification in notifications {
            let encoded = encode_notification(notification.clone());
            maximum_encoded_size = maximum_encoded_size.max(encoded.len());
            assert!(encoded.len() <= MAX_ENCODED_NOTIFICATION_SIZE);
            assert_eq!(decode_notification(&encoded).unwrap(), notification);
        }
        assert_eq!(maximum_encoded_size, MAX_ENCODED_NOTIFICATION_SIZE);
    }

    #[test]
    fn decode_rejects_malformed_handshake_request_frames() {
        assert_eq!(
            decode_handshake_request(&[0xff, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_handshake_request(&[0, 1]),
            Err(WireError::TruncatedFrame)
        );
        assert_eq!(
            decode_handshake_request(&encode_request(BrokerRequest {
                request_id: TEST_REQUEST_ID,
                operation: BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                    initial_count: 0,
                    flags: FileOpenFlags::NONE,
                })),
            })),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_handshake_request(&encode_request(BrokerRequest {
                request_id: TEST_REQUEST_ID,
                operation: BrokerOperation::CloseObject(ObjectHandle(13)),
            })),
            Err(WireError::WrongMessagePhase)
        );
        let mut frame = encode_handshake_request(BrokerHandshakeRequest {
            protocol_version: ProtocolVersion(1),
        });
        frame.push(0xff);
        assert_eq!(
            decode_handshake_request(&frame),
            Err(WireError::TrailingBytes)
        );
    }

    #[test]
    fn decode_rejects_malformed_request_frames() {
        assert_eq!(decode_request(&[0xff, 1, 2, 3]), Err(WireError::InvalidTag));
        assert_eq!(
            decode_request(&encode_handshake_request(BrokerHandshakeRequest {
                protocol_version: ProtocolVersion(1),
            })),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_request(&[REQUEST_TAG_EVENT, 0, 0, 0, 0, 0, 0, 0]),
            Err(WireError::TruncatedFrame)
        );
        let mut unknown_consume_mode = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Event(EventRequest::Consume(ConsumeEventRequest {
                handle: ObjectHandle(13),
                mode: EventConsumeMode::All,
            })),
        });
        *unknown_consume_mode.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_request(&unknown_consume_mode),
            Err(WireError::InvalidTag)
        );
        let mut unknown_timer_request = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Timer(TimerRequest::Create(CreateTimerRequest::default())),
        });
        unknown_timer_request[9] = 0xff;
        assert_eq!(
            decode_request(&unknown_timer_request),
            Err(WireError::InvalidTag)
        );
        let truncated_timer_set = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Timer(TimerRequest::Set(SetTimerRequest {
                handle: ObjectHandle(13),
                spec: TimerSpec::default(),
            })),
        });
        assert_eq!(
            decode_request(&truncated_timer_set[..truncated_timer_set.len() - 1]),
            Err(WireError::TruncatedFrame)
        );
        let mut unknown_signal_request = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Signal(SignalRequest::Open),
        });
        unknown_signal_request[9] = 0xff;
        assert_eq!(
            decode_request(&unknown_signal_request),
            Err(WireError::InvalidTag)
        );
        let mut unknown_readiness_queue_request = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::ReadinessQueue(ReadinessQueueRequest::Create),
        });
        unknown_readiness_queue_request[9] = 0xff;
        assert_eq!(
            decode_request(&unknown_readiness_queue_request),
            Err(WireError::InvalidTag)
        );
        let mut unknown_readiness_queue_flags = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::ReadinessQueue(ReadinessQueueRequest::Add(
                AddReadinessQueueEntryRequest {
                    queue: ObjectHandle(1),
                    target: ObjectHandle(2),
                    key: 3,
                    interest: ReadinessQueueInterest::default(),
                },
            )),
        });
        // Tag, request ID, family tag, two handles, key, and readiness
        // precede the entry flags.
        unknown_readiness_queue_flags[38] = 1 << 7;
        assert_eq!(
            decode_request(&unknown_readiness_queue_flags),
            Err(WireError::InvalidTag)
        );
        let truncated_signal_send = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Signal(SignalRequest::Send(SendSignalRequest {
                target: SignalTarget::Process(process_id(1)),
                signal: 10,
            })),
        });
        assert_eq!(
            decode_request(&truncated_signal_send[..truncated_signal_send.len() - 1]),
            Err(WireError::TruncatedFrame)
        );
        let mut unknown_signal_target = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Signal(SignalRequest::Send(SendSignalRequest {
                target: SignalTarget::All,
                signal: 10,
            })),
        });
        unknown_signal_target[10] = 0xff;
        assert_eq!(
            decode_request(&unknown_signal_target),
            Err(WireError::InvalidTag)
        );
        let mut unknown_process_group_request = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::ProcessGroup(ProcessGroupRequest::CreateSession(
                process_id(1),
            )),
        });
        unknown_process_group_request[9] = 0xff;
        assert_eq!(
            decode_request(&unknown_process_group_request),
            Err(WireError::InvalidTag)
        );
        let truncated_process_group_set = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::ProcessGroup(ProcessGroupRequest::Set(
                SetProcessGroupRequest {
                    process_id: process_id(1),
                    process_group: ProcessGroupId(2),
                },
            )),
        });
        assert_eq!(
            decode_request(&truncated_process_group_set[..truncated_process_group_set.len() - 1]),
            Err(WireError::TruncatedFrame)
        );
        let mut unknown_status_flag = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::SetStatusFlags(SetStatusFlagsRequest {
                handle: ObjectHandle(13),
                mask: FileOpenFlags::NONBLOCKING,
                flags: FileOpenFlags::NONE,
            }),
        });
        *unknown_status_flag.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_request(&unknown_status_flag),
            Err(WireError::InvalidTag)
        );
        let mut unknown_thread_request = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Thread(ThreadRequest::Create),
        });
        unknown_thread_request[9] = 0xff;
        assert_eq!(
            decode_request(&unknown_thread_request),
            Err(WireError::InvalidTag)
        );
        let mut unknown_process_request = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Process(ProcessRequest::AllocateChild),
        });
        unknown_process_request[9] = 0xff;
        assert_eq!(
            decode_request(&unknown_process_request),
            Err(WireError::InvalidTag)
        );
        let mut unknown_exit_status = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Process(ProcessRequest::ExitChild(
                ExitChildProcessRequest {
                    child_process_id: process_id(1),
                    exit_status: ProcessExitStatus::Unknown,
                },
            )),
        });
        unknown_exit_status[14] = 0xff;
        assert_eq!(
            decode_request(&unknown_exit_status),
            Err(WireError::InvalidTag)
        );
        let mut invalid_child_exit_retention = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Process(ProcessRequest::SetChildExitRetention(true)),
        });
        invalid_child_exit_retention[10] = 2;
        assert_eq!(
            decode_request(&invalid_child_exit_retention),
            Err(WireError::InvalidTag)
        );
        let mut invalid_orphan_adoption = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Process(ProcessRequest::SetOrphanAdoption(true)),
        });
        invalid_orphan_adoption[10] = 2;
        assert_eq!(
            decode_request(&invalid_orphan_adoption),
            Err(WireError::InvalidTag)
        );
        let mut unknown_child_selector = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Process(ProcessRequest::CollectChildExit(
                ChildSelector::Any,
            )),
        });
        unknown_child_selector[10] = 0xff;
        assert_eq!(
            decode_request(&unknown_child_selector),
            Err(WireError::InvalidTag)
        );
        let mut frame = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
                flags: FileOpenFlags::NONE,
            })),
        });
        frame.push(0xff);
        assert_eq!(decode_request(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_malformed_fs_request_frames() {
        let open = BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::File(FileRequest::Open(OpenFileRequest {
                path: sequence(1, 9),
                user: FileUser { user: 2, group: 3 },
                access: FileAccessMode::ReadOnly,
                flags: FileOpenFlags::CREATE,
                mode: FileMode::from_bits(0o640).unwrap(),
            })),
        };

        let mut unknown_operation = Vec::from([REQUEST_TAG_FILE]);
        unknown_operation.extend_from_slice(&TEST_REQUEST_ID.0.to_le_bytes());
        unknown_operation.push(0xff);
        assert_eq!(
            decode_request(&unknown_operation),
            Err(WireError::InvalidTag)
        );

        let open = encode_request(open);
        let mut unknown_access = open.clone();
        unknown_access[23] = 0xff;
        assert_eq!(decode_request(&unknown_access), Err(WireError::InvalidTag));
        let mut unsupported_flags = open.clone();
        unsupported_flags[24..26].copy_from_slice(&(1u16 << 15).to_le_bytes());
        assert_eq!(
            decode_request(&unsupported_flags),
            Err(WireError::InvalidTag)
        );
        let mut unsupported_mode = open.clone();
        unsupported_mode[26..28].copy_from_slice(&0o10000u16.to_le_bytes());
        assert_eq!(
            decode_request(&unsupported_mode),
            Err(WireError::InvalidTag)
        );
        let mut invalid_reset_offset = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::File(FileRequest::Truncate(TruncateFileRequest {
                handle: ObjectHandle(13),
                length: 17,
                reset_offset: false,
            })),
        });
        *invalid_reset_offset.last_mut().unwrap() = 2;
        assert_eq!(
            decode_request(&invalid_reset_offset),
            Err(WireError::InvalidTag)
        );

        let mut invalid_whence = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::File(FileRequest::Seek(SeekFileRequest {
                handle: ObjectHandle(13),
                offset: 0,
                whence: FileSeekWhence::RelativeToBeginning,
            })),
        });
        *invalid_whence.last_mut().unwrap() = 0xff;
        assert_eq!(decode_request(&invalid_whence), Err(WireError::InvalidTag));

        let chown = BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::File(FileRequest::Chown(ChownFileRequest {
                path: sequence(1, 9),
                acting_user: FileUser { user: 0, group: 0 },
                user: Some(2),
                group: None,
            })),
        };
        let mut invalid_user = encode_request(chown);
        let user_tag = invalid_user.len() - 4;
        invalid_user[user_tag] = 2;
        assert_eq!(decode_request(&invalid_user), Err(WireError::InvalidTag));
    }

    #[test]
    fn decode_rejects_malformed_fs_response_frames() {
        let status = BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::File(FileResponse::PathStatus(FileStatus {
                file_type: FileType::RegularFile,
                mode: FileMode::from_bits(0o640).unwrap(),
                size: 17,
                owner: FileUser { user: 2, group: 3 },
                node_info: FileNodeInfo {
                    dev: 5,
                    ino: 7,
                    rdev: None,
                },
                blksize: 4096,
            })),
        };
        let status = encode_response(status);
        let mut unknown_file_type = status.clone();
        unknown_file_type[10] = 0xff;
        assert_eq!(
            decode_response(&unknown_file_type),
            Err(WireError::InvalidTag)
        );
        let mut unsupported_mode = status.clone();
        unsupported_mode[11..13].copy_from_slice(&0o10000u16.to_le_bytes());
        assert_eq!(
            decode_response(&unsupported_mode),
            Err(WireError::InvalidTag)
        );
        let mut invalid_next_index = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::File(FileResponse::ReadDirectory(ReadDirectoryResponse {
                length: 17,
                next_index: None,
            })),
        });
        *invalid_next_index.last_mut().unwrap() = 2;
        assert_eq!(
            decode_response(&invalid_next_index),
            Err(WireError::InvalidTag)
        );
        let mut invalid_is_terminal = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::File(FileResponse::IsTerminal(true)),
        });
        *invalid_is_terminal.last_mut().unwrap() = 2;
        assert_eq!(
            decode_response(&invalid_is_terminal),
            Err(WireError::InvalidTag)
        );

        let mut invalid_error = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::File(FileResponse::Failed(FileError::Io)),
        });
        *invalid_error.last_mut().unwrap() = 0xff;
        assert_eq!(decode_response(&invalid_error), Err(WireError::InvalidTag));
    }

    #[test]
    fn decode_rejects_malformed_socket_request_frames() {
        let mut unknown_operation = Vec::from([REQUEST_TAG_SOCKET]);
        unknown_operation.extend_from_slice(&TEST_REQUEST_ID.0.to_le_bytes());
        unknown_operation.push(0xff);
        assert_eq!(
            decode_request(&unknown_operation),
            Err(WireError::InvalidTag)
        );

        // A socket envelope carrying no family tag at all.
        assert_eq!(
            decode_request(&unknown_operation[..unknown_operation.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        // Address family, type, and protocol precede the two-byte status flags
        // at the end of a create frame, so each unknown tag, and unknown flag
        // bits, are rejected on their own.
        let create = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Socket(SocketRequest::Create(CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
                flags: FileOpenFlags::NONE,
            })),
        });
        for offset in [1, 3, 4, 5] {
            let mut frame = create.clone();
            let index = frame.len() - offset;
            frame[index] = 0xff;
            assert_eq!(decode_request(&frame), Err(WireError::InvalidTag));
        }
        assert_eq!(
            decode_request(&create[..create.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let set_option = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Socket(SocketRequest::SetOption(SetSocketOptionRequest {
                handle: ObjectHandle(13),
                value: SocketOptionValue::NoDelay(true),
            })),
        });
        for offset in 1..=2 {
            let mut frame = set_option.clone();
            let index = frame.len() - offset;
            frame[index] = 0xff;
            assert_eq!(decode_request(&frame), Err(WireError::InvalidTag));
        }

        let mut unknown_shutdown_mode = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Socket(SocketRequest::Shutdown(ShutdownSocketRequest {
                handle: ObjectHandle(9),
                mode: ShutdownMode::Both,
            })),
        });
        *unknown_shutdown_mode.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_request(&unknown_shutdown_mode),
            Err(WireError::InvalidTag)
        );

        let connect = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Socket(SocketRequest::Connect(ConnectSocketRequest {
                handle: ObjectHandle(9),
                address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443),
            })),
        });
        assert_eq!(
            decode_request(&connect[..connect.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let mut unknown_send_to_destination = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Socket(SocketRequest::SendTo(SendToSocketRequest {
                handle: ObjectHandle(9),
                buffer: sequence(1, 0),
                flags: SendFlags::NONE,
                destination: None,
            })),
        });
        *unknown_send_to_destination.last_mut().unwrap() = 2;
        assert_eq!(
            decode_request(&unknown_send_to_destination),
            Err(WireError::InvalidTag)
        );

        let mut trailing = connect;
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(WireError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_malformed_socket_response_frames() {
        let mut unknown_response = Vec::from([RESPONSE_TAG_SOCKET]);
        unknown_response.extend_from_slice(&TEST_REQUEST_ID.0.to_le_bytes());
        unknown_response.push(0xff);
        assert_eq!(
            decode_response(&unknown_response),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_response(&unknown_response[..unknown_response.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let mut unknown_connect_status = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::Connect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connecting,
            })),
        });
        *unknown_connect_status.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_response(&unknown_connect_status),
            Err(WireError::InvalidTag)
        );

        let mut unknown_optional_error = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::TakeError(TakeSocketErrorResponse {
                error: None,
            })),
        });
        *unknown_optional_error.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_response(&unknown_optional_error),
            Err(WireError::InvalidTag)
        );

        let get_option = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::GetOption(GetSocketOptionResponse {
                value: SocketOptionValue::KeepAlive(true),
            })),
        });
        for offset in 1..=2 {
            let mut frame = get_option.clone();
            let index = frame.len() - offset;
            frame[index] = 0xff;
            assert_eq!(decode_response(&frame), Err(WireError::InvalidTag));
        }

        let socket_error = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::Failed(SocketError::TimedOut)),
        });
        for raw in [0, 20, u8::MAX] {
            let mut unknown_socket_error = socket_error.clone();
            *unknown_socket_error.last_mut().unwrap() = raw;
            assert_eq!(
                decode_response(&unknown_socket_error),
                Err(WireError::InvalidTag)
            );
        }
        assert_eq!(
            decode_response(&socket_error[..socket_error.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let failed_connection = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::Connect(ConnectSocketResponse {
                status: SocketConnectionStatus::Failed(SocketError::ConnectionRefused),
            })),
        });
        assert_eq!(
            decode_response(&failed_connection[..failed_connection.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let received = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::Receive(ReceiveSocketResponse::Received(
                4096,
            ))),
        });
        assert_eq!(
            decode_response(&received[..received.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let mut unknown_receive_result = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::Receive(
                ReceiveSocketResponse::EndOfStream,
            )),
        });
        *unknown_receive_result.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_response(&unknown_receive_result),
            Err(WireError::InvalidTag)
        );
    }

    #[test]
    fn decode_rejects_malformed_handshake_response_frames() {
        assert_eq!(
            decode_handshake_response(&[0xfb, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_handshake_response(&[0, 1]),
            Err(WireError::TruncatedFrame)
        );
        assert_eq!(
            decode_handshake_response(&[254, 0xff, 0xff]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_handshake_response(&encode_response(BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result: BrokerResult::Event(EventResponse::Create(CreateEventResponse {
                    handle: ObjectHandle(13),
                })),
            })),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_handshake_response(&encode_response(BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result: BrokerResult::ObjectClosed,
            })),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_handshake_response(&encode_response(BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result: BrokerResult::Error(ErrorCode::WouldBlock),
            })),
            Err(WireError::WrongMessagePhase)
        );

        let negotiated = BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: ProtocolVersion(1),
            process_id: process_id(1),
            initial_thread_id: thread_id(2),
            startup: None,
        };
        let mut invalid_startup = encode_handshake_response(negotiated.clone());
        *invalid_startup.last_mut().unwrap() = 2;
        assert_eq!(
            decode_handshake_response(&invalid_startup),
            Err(WireError::InvalidTag)
        );

        let mut frame = encode_handshake_response(negotiated);
        frame.push(0xff);
        assert_eq!(
            decode_handshake_response(&frame),
            Err(WireError::TrailingBytes)
        );
    }

    #[test]
    fn decode_rejects_malformed_response_frames() {
        assert_eq!(
            decode_response(&[0xfb, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        for response in [
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: ProtocolVersion(1),
                process_id: process_id(1),
                initial_thread_id: thread_id(2),
                startup: None,
            },
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: ProtocolVersion(1),
                process_id: process_id(2),
                initial_thread_id: thread_id(3),
                startup: Some(ProcessStartupDescriptor {
                    buffer: sequence(0, 5),
                }),
            },
            BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version: ProtocolVersion(1),
            },
            BrokerHandshakeResponse::Error(ErrorCode::PolicyDenied),
        ] {
            assert_eq!(
                decode_response(&encode_handshake_response(response)),
                Err(WireError::WrongMessagePhase)
            );
        }
        assert_eq!(
            decode_response(&[RESPONSE_TAG_READINESS, 0xff]),
            Err(WireError::TruncatedFrame)
        );
        let mut invalid_error = Vec::from([RESPONSE_TAG_ERROR]);
        invalid_error.extend_from_slice(&TEST_REQUEST_ID.0.to_le_bytes());
        invalid_error.extend_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(decode_response(&invalid_error), Err(WireError::InvalidTag));

        let truncated = [RESPONSE_TAG_EVENT, 2, 2, 0];
        assert_eq!(decode_response(&truncated), Err(WireError::TruncatedFrame));

        let mut unknown_thread_response = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Thread(ThreadResponse::Create(thread_id(1))),
        });
        unknown_thread_response[9] = 0xff;
        assert_eq!(
            decode_response(&unknown_thread_response),
            Err(WireError::InvalidTag)
        );
        let mut unknown_process_response = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Process(ProcessResponse::StartChild),
        });
        unknown_process_response[9] = 0xff;
        assert_eq!(
            decode_response(&unknown_process_response),
            Err(WireError::InvalidTag)
        );

        let mut invalid_exit_status = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Process(ProcessResponse::CollectChildExit(ChildExit {
                process_id: process_id(1),
                exit_status: ProcessExitStatus::Unknown,
            })),
        });
        invalid_exit_status[14] = 0xff;
        assert_eq!(
            decode_response(&invalid_exit_status),
            Err(WireError::InvalidTag)
        );
        let mut invalid_creator = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Process(ProcessResponse::GetInfo(ProcessInfo {
                creator: None,
                parent: None,
                membership: ProcessGroupMembership {
                    process_group: ProcessGroupId(1),
                    session: SessionId(1),
                },
            })),
        });
        invalid_creator[10] = 2;
        assert_eq!(
            decode_response(&invalid_creator),
            Err(WireError::InvalidTag)
        );

        let mut unknown_timer_response = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Timer(TimerResponse::Read(ReadTimerResponse { expirations: 1 })),
        });
        unknown_timer_response[9] = 0xff;
        assert_eq!(
            decode_response(&unknown_timer_response),
            Err(WireError::InvalidTag)
        );

        let mut unknown_readiness_queue_error = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::ReadinessQueue(ReadinessQueueResponse::Failed(
                ReadinessQueueError::NotRegistered,
            )),
        });
        unknown_readiness_queue_error[10] = 0xff;
        assert_eq!(
            decode_response(&unknown_readiness_queue_error),
            Err(WireError::InvalidTag)
        );

        let mut unknown_signal_response = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Signal(SignalResponse::Sent),
        });
        unknown_signal_response[9] = 0xff;
        assert_eq!(
            decode_response(&unknown_signal_response),
            Err(WireError::InvalidTag)
        );
        let mut unknown_signal_event = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Signal(SignalResponse::Take(SignalEvent::Signal(
                PendingSignal {
                    signal: 1,
                    sender: process_id(1),
                },
            ))),
        });
        unknown_signal_event[10] = 0xff;
        assert_eq!(
            decode_response(&unknown_signal_event),
            Err(WireError::InvalidTag)
        );

        let mut frame = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Event(EventResponse::Add(AddEventResponse {
                readiness: ReadinessFlags::READ | ReadinessFlags::WRITE,
            })),
        });
        frame.push(0xff);
        assert_eq!(decode_response(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_malformed_notification_frames() {
        assert_eq!(
            decode_notification(&[0xff, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_notification(&[NOTIFICATION_TAG_READINESS]),
            Err(WireError::TruncatedFrame)
        );

        let mut truncated =
            encode_notification(BrokerNotification::Readiness(ReadinessNotification {
                handle: ObjectHandle(13),
                readiness: ReadinessFlags::READ,
            }));
        truncated.pop();
        assert_eq!(
            decode_notification(&truncated),
            Err(WireError::TruncatedFrame)
        );

        let mut trailing =
            encode_notification(BrokerNotification::Readiness(ReadinessNotification {
                handle: ObjectHandle(13),
                readiness: ReadinessFlags::READ,
            }));
        trailing.push(0xff);
        assert_eq!(
            decode_notification(&trailing),
            Err(WireError::TrailingBytes)
        );
    }

    #[test]
    fn event_create_request_wire_shape_is_pinned() {
        assert_eq!(
            encode_request(BrokerRequest {
                request_id: RequestId(13),
                operation: BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                    initial_count: 7,
                    flags: FileOpenFlags::NONBLOCKING,
                })),
            }),
            [1, 13, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 32, 0]
        );
    }

    #[test]
    fn fs_open_request_wire_shape_is_pinned() {
        assert_eq!(
            encode_request(BrokerRequest {
                request_id: RequestId(13),
                operation: BrokerOperation::File(FileRequest::Open(OpenFileRequest {
                    path: sequence(2, 3),
                    user: FileUser { user: 5, group: 7 },
                    access: FileAccessMode::ReadWrite,
                    flags: FileOpenFlags::CREATE
                        | FileOpenFlags::EXCLUSIVE
                        | FileOpenFlags::NO_FOLLOW,
                    mode: FileMode::from_bits(0o640).unwrap(),
                })),
            }),
            [
                7, 13, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 3, 0, 0, 0, 5, 0, 7, 0, 2, 137, 0,
                160, 1,
            ]
        );
    }

    #[test]
    fn socket_connect_request_wire_shape_is_pinned() {
        assert_eq!(
            encode_request(BrokerRequest {
                request_id: RequestId(13),
                operation: BrokerOperation::Socket(SocketRequest::Connect(ConnectSocketRequest {
                    handle: ObjectHandle(9),
                    address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443),
                })),
            }),
            [
                5, 13, 0, 0, 0, 0, 0, 0, 0, 1, 9, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 7, 187, 1
            ]
        );
    }

    #[test]
    fn socket_accept_request_wire_shape_is_pinned() {
        assert_eq!(
            encode_request(BrokerRequest {
                request_id: RequestId(13),
                operation: BrokerOperation::Socket(SocketRequest::Accept(AcceptSocketRequest {
                    handle: ObjectHandle(9),
                    flags: FileOpenFlags::NONBLOCKING,
                })),
            }),
            [5, 13, 0, 0, 0, 0, 0, 0, 0, 4, 9, 0, 0, 0, 0, 0, 0, 0, 32, 0]
        );
    }

    #[test]
    fn socket_send_to_request_wire_shape_is_pinned() {
        assert_eq!(
            encode_request(BrokerRequest {
                request_id: RequestId(13),
                operation: BrokerOperation::Socket(SocketRequest::SendTo(SendToSocketRequest {
                    handle: ObjectHandle(9),
                    buffer: sequence(2, 3),
                    flags: SendFlags::NONE,
                    destination: Some(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 53,)),
                })),
            }),
            [
                5, 13, 0, 0, 0, 0, 0, 0, 0, 6, 9, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 3, 0, 0, 0,
                0, 0, 0, 0, 1, 203, 0, 113, 7, 53, 0
            ]
        );
    }

    #[test]
    fn socket_failure_response_wire_shape_is_pinned() {
        assert_eq!(
            encode_response(BrokerResponse {
                request_id: RequestId(13),
                result: BrokerResult::Socket(SocketResponse::Failed(SocketError::ConnectionReset,)),
            }),
            [5, 13, 0, 0, 0, 0, 0, 0, 0, 16, 2]
        );
    }

    #[test]
    fn socket_accept_response_wire_shape_is_pinned() {
        assert_eq!(
            encode_response(BrokerResponse {
                request_id: RequestId(13),
                result: BrokerResult::Socket(SocketResponse::Accept(AcceptSocketResponse {
                    handle: ObjectHandle(9),
                    local_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152),
                    remote_address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443),
                })),
            }),
            [
                5, 13, 0, 0, 0, 0, 0, 0, 0, 4, 9, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 0, 192, 203,
                0, 113, 7, 187, 1,
            ]
        );
    }

    #[test]
    fn event_add_response_wire_shape_is_pinned() {
        assert_eq!(
            encode_response(BrokerResponse {
                request_id: RequestId(13),
                result: BrokerResult::Event(EventResponse::Add(AddEventResponse {
                    readiness: ReadinessFlags::READ,
                })),
            }),
            [1, 13, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0]
        );
    }

    #[test]
    fn readiness_notification_wire_shape_is_pinned() {
        assert_eq!(
            encode_notification(BrokerNotification::Readiness(ReadinessNotification {
                handle: ObjectHandle(13),
                readiness: ReadinessFlags::READ | ReadinessFlags::HANGUP,
            })),
            [0, 13, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0]
        );
    }
}
