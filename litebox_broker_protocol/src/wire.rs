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
//! are positional; changing fields is an ABI change, so prefer a new operation
//! tag or explicit negotiated-version gate for payload evolution.

use alloc::vec::Vec;
use thiserror::Error;

use crate::error::ErrorCode;
use crate::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
    BrokerRequest, BrokerResponse, BrokerResult, ReadinessNotification,
};
use crate::readiness::ReadinessFlags;

use primitive::{Decoder, Encoder};

mod event;
mod fs;
mod pipe;
mod primitive;
mod socket;
mod stdio;

const REQUEST_TAG_NEGOTIATE: u8 = 0;
const REQUEST_TAG_EVENT: u8 = 1;
const REQUEST_TAG_CLOSE_OBJECT: u8 = 2;
const REQUEST_TAG_PIPE: u8 = 3;
const REQUEST_TAG_CHECK_READINESS: u8 = 4;
const REQUEST_TAG_SOCKET: u8 = 5;
const REQUEST_TAG_FILL_RANDOM: u8 = 6;
const REQUEST_TAG_STDIO: u8 = 7;
const REQUEST_TAG_FILESYSTEM: u8 = 8;

// Paired request and successful-response tags intentionally share values.
const RESPONSE_TAG_NEGOTIATED: u8 = 0;
const RESPONSE_TAG_EVENT: u8 = 1;
const RESPONSE_TAG_OBJECT_CLOSED: u8 = 2;
const RESPONSE_TAG_PIPE: u8 = 3;
const RESPONSE_TAG_READINESS: u8 = 4;
const RESPONSE_TAG_SOCKET: u8 = 5;
const RESPONSE_TAG_RANDOM_FILLED: u8 = 6;
const RESPONSE_TAG_STDIO: u8 = 7;
const RESPONSE_TAG_FILESYSTEM: u8 = 8;

// Reserve the top of the tag space for responses without paired requests.
const RESPONSE_TAG_ERROR: u8 = 253;
const RESPONSE_TAG_HANDSHAKE_ERROR: u8 = 254;
const RESPONSE_TAG_VERSION_MISMATCH: u8 = 255;

const NOTIFICATION_TAG_READINESS: u8 = 0;

/// Maximum byte length of any encoded active request or response.
pub const MAX_ENCODED_ACTIVE_MESSAGE_SIZE: usize = 60;

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
        | REQUEST_TAG_STDIO
        | REQUEST_TAG_FILESYSTEM => {
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
            encoder.shared_buffer_descriptor(buffer);
        }
        BrokerOperation::Stdio(request) => {
            encoder.u8(REQUEST_TAG_STDIO);
            encoder.request_id(request_id);
            stdio::encode_stdio_request(&mut encoder, request);
        }
        BrokerOperation::Filesystem(request) => {
            encoder.u8(REQUEST_TAG_FILESYSTEM);
            encoder.request_id(request_id);
            fs::encode_fs_request(&mut encoder, request);
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
        | REQUEST_TAG_STDIO
        | REQUEST_TAG_FILESYSTEM => {}
        _ => return Err(WireError::InvalidTag),
    }
    let request_id = decoder.request_id()?;
    let operation = match tag {
        REQUEST_TAG_CLOSE_OBJECT => BrokerOperation::CloseObject(decoder.handle()?),
        REQUEST_TAG_CHECK_READINESS => BrokerOperation::CheckReadiness(decoder.handle()?),
        REQUEST_TAG_EVENT => BrokerOperation::Event(event::decode_event_request(&mut decoder)?),
        REQUEST_TAG_PIPE => BrokerOperation::Pipe(pipe::decode_pipe_request(&mut decoder)?),
        REQUEST_TAG_SOCKET => BrokerOperation::Socket(socket::decode_socket_request(&mut decoder)?),
        REQUEST_TAG_FILL_RANDOM => BrokerOperation::FillRandom(decoder.shared_buffer_descriptor()?),
        REQUEST_TAG_STDIO => BrokerOperation::Stdio(stdio::decode_stdio_request(&mut decoder)?),
        REQUEST_TAG_FILESYSTEM => BrokerOperation::Filesystem(fs::decode_fs_request(&mut decoder)?),
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
        } => {
            encoder.u8(RESPONSE_TAG_NEGOTIATED);
            encoder.protocol_version(broker_protocol_version);
        }
        BrokerHandshakeResponse::VersionMismatch {
            broker_protocol_version,
        } => {
            encoder.u8(RESPONSE_TAG_VERSION_MISMATCH);
            encoder.protocol_version(broker_protocol_version);
        }
        BrokerHandshakeResponse::Error(error) => {
            encoder.u8(RESPONSE_TAG_HANDSHAKE_ERROR);
            encoder.u16(error.as_raw());
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
        },
        RESPONSE_TAG_EVENT
        | RESPONSE_TAG_OBJECT_CLOSED
        | RESPONSE_TAG_PIPE
        | RESPONSE_TAG_READINESS
        | RESPONSE_TAG_ERROR
        | RESPONSE_TAG_SOCKET
        | RESPONSE_TAG_RANDOM_FILLED
        | RESPONSE_TAG_STDIO
        | RESPONSE_TAG_FILESYSTEM => {
            return Err(WireError::WrongMessagePhase);
        }
        RESPONSE_TAG_VERSION_MISMATCH => BrokerHandshakeResponse::VersionMismatch {
            broker_protocol_version: decoder.protocol_version()?,
        },
        RESPONSE_TAG_HANDSHAKE_ERROR => {
            let error = ErrorCode::from_raw(decoder.u16()?).ok_or(WireError::InvalidTag)?;
            BrokerHandshakeResponse::Error(error)
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
        BrokerResult::ObjectClosed => {
            encoder.u8(RESPONSE_TAG_OBJECT_CLOSED);
            encoder.request_id(request_id);
        }
        BrokerResult::Readiness(readiness) => {
            encoder.u8(RESPONSE_TAG_READINESS);
            encoder.request_id(request_id);
            encoder.u32(readiness.0);
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
        BrokerResult::Stdio(response) => {
            encoder.u8(RESPONSE_TAG_STDIO);
            encoder.request_id(request_id);
            stdio::encode_stdio_response(&mut encoder, response);
        }
        BrokerResult::Filesystem(response) => {
            encoder.u8(RESPONSE_TAG_FILESYSTEM);
            encoder.request_id(request_id);
            fs::encode_fs_response(&mut encoder, response);
        }
        BrokerResult::Error(error) => {
            encoder.u8(RESPONSE_TAG_ERROR);
            encoder.request_id(request_id);
            encoder.u16(error.as_raw());
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
        | RESPONSE_TAG_STDIO
        | RESPONSE_TAG_FILESYSTEM => {}
        _ => return Err(WireError::InvalidTag),
    }
    let request_id = decoder.request_id()?;
    let result = match tag {
        RESPONSE_TAG_EVENT => BrokerResult::Event(event::decode_event_response(&mut decoder)?),
        RESPONSE_TAG_PIPE => BrokerResult::Pipe(pipe::decode_pipe_response(&mut decoder)?),
        RESPONSE_TAG_SOCKET => BrokerResult::Socket(socket::decode_socket_response(&mut decoder)?),
        RESPONSE_TAG_ERROR => {
            let error = ErrorCode::from_raw(decoder.u16()?).ok_or(WireError::InvalidTag)?;
            BrokerResult::Error(error)
        }
        RESPONSE_TAG_OBJECT_CLOSED => BrokerResult::ObjectClosed,
        RESPONSE_TAG_READINESS => BrokerResult::Readiness(ReadinessFlags(decoder.u32()?)),
        RESPONSE_TAG_RANDOM_FILLED => BrokerResult::RandomFilled,
        RESPONSE_TAG_STDIO => BrokerResult::Stdio(stdio::decode_stdio_response(&mut decoder)?),
        RESPONSE_TAG_FILESYSTEM => BrokerResult::Filesystem(fs::decode_fs_response(&mut decoder)?),
        _ => unreachable!("active response tag was validated"),
    };
    decoder.finish()?;
    Ok(BrokerResponse { request_id, result })
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
        ChmodFileRequest, ChownFileRequest, FilesystemError, FilesystemFileStatus,
        FilesystemFileType, FilesystemNamespace, FilesystemNodeInfo, FilesystemSeekWhence,
        FilesystemUser, HandleFileStatusRequest, MkdirFileRequest, OpenFileRequest,
        OpenFileResponse, PathFileStatusRequest, ReadDirectoryRequest, ReadDirectoryResponse,
        ReadFileRequest, ReadFileResponse, RmdirFileRequest, SeekFileRequest, SeekFileResponse,
        TruncateFileRequest, UnlinkFileRequest, WriteFileRequest, WriteFileResponse,
    };
    use crate::message::{
        EventRequest, EventResponse, FilesystemRequest, FilesystemResponse, PipeRequest,
        PipeResponse, SocketRequest, SocketResponse, StdioRequest, StdioResponse,
    };
    use crate::pipe::{
        CreatePipeRequest, CreatePipeResponse, ReadPipeRequest, ReadPipeResponse, WritePipeRequest,
        WritePipeResponse,
    };
    use crate::shared_buffer::{SharedBufferDescriptor, SharedBufferSlotIndex};
    use crate::socket::{
        AcceptSocketRequest, AcceptSocketResponse, AddressFamily, BindSocketRequest,
        BindSocketResponse, ConnectSocketRequest, ConnectSocketResponse, CreateSocketRequest,
        CreateSocketResponse, GetTcpOptionRequest, GetTcpOptionResponse, IpProtocol,
        ListenSocketRequest, ListenSocketResponse, ReceiveFlags, ReceiveFromFlags,
        ReceiveFromSocketRequest, ReceiveFromSocketResponse, ReceiveSocketRequest,
        ReceiveSocketResponse, SendFlags, SendSocketRequest, SendSocketResponse,
        SendToSocketRequest, SendToSocketResponse, SetTcpOptionRequest, ShutdownMode,
        ShutdownSocketRequest, SocketConnectionStatus, SocketError, SocketStatusRequest,
        SocketStatusResponse, SocketType, TcpOptionName, TcpOptionValue,
    };
    use crate::stdio::{
        IsTerminalStdioRequest, IsTerminalStdioResponse, ReadStdioRequest, ReadStdioResponse,
        StdioOutputStream, StdioStream, WriteStdioRequest, WriteStdioResponse,
    };
    use crate::{ObjectHandle, ProtocolVersion, RequestId};
    use core::net::{Ipv4Addr, SocketAddrV4};

    const TEST_REQUEST_ID: RequestId = RequestId(0x0102_0304_0506_0708);

    const fn socket_status(status: SocketConnectionStatus) -> SocketStatusResponse {
        SocketStatusResponse {
            status,
            local_address: None,
            pending_error: None,
        }
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
                RESPONSE_TAG_STDIO,
                RESPONSE_TAG_FILESYSTEM,
            ],
            [
                REQUEST_TAG_NEGOTIATE,
                REQUEST_TAG_EVENT,
                REQUEST_TAG_CLOSE_OBJECT,
                REQUEST_TAG_PIPE,
                REQUEST_TAG_CHECK_READINESS,
                REQUEST_TAG_SOCKET,
                REQUEST_TAG_FILL_RANDOM,
                REQUEST_TAG_STDIO,
                REQUEST_TAG_FILESYSTEM,
            ]
        );
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
        let operations = [
            BrokerOperation::CloseObject(handle),
            BrokerOperation::CheckReadiness(handle),
            BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
            BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 7,
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
            BrokerOperation::Pipe(PipeRequest::Create(CreatePipeRequest {
                capacity: 4096,
                atomic_write_size: 512,
            })),
            BrokerOperation::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(2),
                    length: 32,
                },
            })),
            BrokerOperation::Pipe(PipeRequest::Write(WritePipeRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(15),
                    length: 3,
                },
            })),
            BrokerOperation::FillRandom(SharedBufferDescriptor {
                slot_index: SharedBufferSlotIndex(7),
                length: 256,
            }),
            BrokerOperation::Stdio(StdioRequest::Read(ReadStdioRequest {
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(4),
                    length: 31,
                },
            })),
            BrokerOperation::Stdio(StdioRequest::Write(WriteStdioRequest {
                stream: StdioOutputStream::Stdout,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(6),
                    length: 17,
                },
            })),
            BrokerOperation::Stdio(StdioRequest::Write(WriteStdioRequest {
                stream: StdioOutputStream::Stderr,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(5),
                    length: 23,
                },
            })),
            BrokerOperation::Stdio(StdioRequest::IsTerminal(IsTerminalStdioRequest {
                stream: StdioStream::Stdin,
            })),
            BrokerOperation::Stdio(StdioRequest::IsTerminal(IsTerminalStdioRequest {
                stream: StdioStream::Stdout,
            })),
            BrokerOperation::Stdio(StdioRequest::IsTerminal(IsTerminalStdioRequest {
                stream: StdioStream::Stderr,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Open(OpenFileRequest {
                namespace: FilesystemNamespace::Guest,
                path: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(1),
                    length: 7,
                },
                user: FilesystemUser { user: 2, group: 3 },
                flags: 0x1234,
                mode: 0o640,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Read(ReadFileRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(2),
                    length: 32,
                },
                offset: None,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Read(ReadFileRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(2),
                    length: 32,
                },
                offset: Some(u64::MAX),
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Write(WriteFileRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(3),
                    length: 17,
                },
                offset: Some(11),
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Seek(SeekFileRequest {
                handle,
                offset: -19,
                whence: FilesystemSeekWhence::Current,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Truncate(TruncateFileRequest {
                handle,
                length: 4096,
                reset_offset: true,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::ReadDirectory(ReadDirectoryRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(4),
                    length: 256,
                },
                start_index: 19,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::PathStatus(PathFileStatusRequest {
                namespace: FilesystemNamespace::WindowsRegistry,
                path: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(5),
                    length: 9,
                },
                user: FilesystemUser { user: 2, group: 3 },
            })),
            BrokerOperation::Filesystem(FilesystemRequest::HandleStatus(HandleFileStatusRequest {
                handle,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Chmod(ChmodFileRequest {
                namespace: FilesystemNamespace::Guest,
                path: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(6),
                    length: 9,
                },
                user: FilesystemUser { user: 2, group: 3 },
                mode: 0o755,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Chown(ChownFileRequest {
                namespace: FilesystemNamespace::Guest,
                path: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(7),
                    length: 9,
                },
                acting_user: FilesystemUser { user: 0, group: 0 },
                user: Some(2),
                group: None,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Unlink(UnlinkFileRequest {
                namespace: FilesystemNamespace::Guest,
                path: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(8),
                    length: 9,
                },
                user: FilesystemUser { user: 2, group: 3 },
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Mkdir(MkdirFileRequest {
                namespace: FilesystemNamespace::Guest,
                path: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(9),
                    length: 9,
                },
                user: FilesystemUser { user: 2, group: 3 },
                mode: 0o750,
            })),
            BrokerOperation::Filesystem(FilesystemRequest::Rmdir(RmdirFileRequest {
                namespace: FilesystemNamespace::Guest,
                path: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(10),
                    length: 9,
                },
                user: FilesystemUser { user: 2, group: 3 },
            })),
            BrokerOperation::Socket(SocketRequest::Create(CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            })),
            BrokerOperation::Socket(SocketRequest::Create(CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Datagram,
                protocol: IpProtocol::Udp,
            })),
            BrokerOperation::Socket(SocketRequest::Bind(BindSocketRequest {
                handle,
                address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            })),
            BrokerOperation::Socket(SocketRequest::Listen(ListenSocketRequest {
                handle,
                backlog: 4096,
            })),
            BrokerOperation::Socket(SocketRequest::Accept(AcceptSocketRequest { handle })),
            BrokerOperation::Socket(SocketRequest::Connect(ConnectSocketRequest {
                handle,
                address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443),
            })),
            BrokerOperation::Socket(SocketRequest::Send(SendSocketRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(15),
                    length: 3,
                },
                flags: SendFlags::NONE,
            })),
            BrokerOperation::Socket(SocketRequest::SendTo(SendToSocketRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(15),
                    length: 3,
                },
                flags: SendFlags::NONE,
                destination: Some(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 53)),
            })),
            BrokerOperation::Socket(SocketRequest::SendTo(SendToSocketRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(15),
                    length: 0,
                },
                flags: SendFlags::NONE,
                destination: None,
            })),
            BrokerOperation::Socket(SocketRequest::Receive(ReceiveSocketRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(15),
                    length: 3,
                },
                flags: ReceiveFlags::PEEK,
                peek_offset: 2,
                peek_length: 5,
            })),
            BrokerOperation::Socket(SocketRequest::ReceiveFrom(ReceiveFromSocketRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(15),
                    length: 3,
                },
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
            BrokerOperation::Socket(SocketRequest::SetTcpOption(SetTcpOptionRequest {
                handle,
                value: TcpOptionValue::NoDelay(true),
            })),
            BrokerOperation::Socket(SocketRequest::SetTcpOption(SetTcpOptionRequest {
                handle,
                value: TcpOptionValue::KeepAlive(false),
            })),
            BrokerOperation::Socket(SocketRequest::GetTcpOption(GetTcpOptionRequest {
                handle,
                name: TcpOptionName::NoDelay,
            })),
            BrokerOperation::Socket(SocketRequest::GetTcpOption(GetTcpOptionRequest {
                handle,
                name: TcpOptionName::KeepAlive,
            })),
            BrokerOperation::Socket(SocketRequest::Status(SocketStatusRequest { handle })),
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
        assert!(maximum_encoded_size <= MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
    }

    #[test]
    fn flag_bits_round_trip_unmasked() {
        // The codec carries flags verbatim so the core can reject unsupported
        // bits; masking them here would hide them from that check, and a
        // dropped field would make an unsupported flag look like none at all.
        let handle = ObjectHandle(13);
        let buffer = SharedBufferDescriptor {
            slot_index: SharedBufferSlotIndex(15),
            length: 3,
        };
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
        ] {
            for socket_response in [
                SocketResponse::Failed(error),
                SocketResponse::Connect(ConnectSocketResponse {
                    status: SocketConnectionStatus::Failed(error),
                }),
                SocketResponse::Status(socket_status(SocketConnectionStatus::Failed(error))),
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
    }

    #[test]
    fn handshake_response_codec_round_trips_all_variants() {
        let responses = [
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: ProtocolVersion(1),
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
            BrokerResult::ObjectClosed,
            BrokerResult::Readiness(ReadinessFlags::READ),
            BrokerResult::Readiness(ReadinessFlags::WRITE),
            BrokerResult::Event(EventResponse::Create(CreateEventResponse { handle })),
            BrokerResult::Event(EventResponse::Add(AddEventResponse {
                readiness: ReadinessFlags::READ | ReadinessFlags::WRITE,
            })),
            BrokerResult::Event(EventResponse::Consume(EventConsumption {
                value: 3,
                readiness: ReadinessFlags::WRITE,
            })),
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
            BrokerResult::Socket(SocketResponse::Status(socket_status(
                SocketConnectionStatus::Unconnected,
            ))),
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
            BrokerResult::Socket(SocketResponse::SetTcpOption),
            BrokerResult::Socket(SocketResponse::GetTcpOption(GetTcpOptionResponse {
                value: TcpOptionValue::NoDelay(true),
            })),
            BrokerResult::Socket(SocketResponse::GetTcpOption(GetTcpOptionResponse {
                value: TcpOptionValue::KeepAlive(false),
            })),
            BrokerResult::Socket(SocketResponse::Status(socket_status(
                SocketConnectionStatus::Connecting,
            ))),
            BrokerResult::Socket(SocketResponse::Status(socket_status(
                SocketConnectionStatus::Connected,
            ))),
            BrokerResult::Socket(SocketResponse::Status(SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152)),
                pending_error: Some(SocketError::ConnectionReset),
            })),
            BrokerResult::Socket(SocketResponse::Status(socket_status(
                SocketConnectionStatus::Failed(SocketError::TimedOut),
            ))),
            BrokerResult::Socket(SocketResponse::Failed(SocketError::ConnectionReset)),
            BrokerResult::RandomFilled,
            BrokerResult::Stdio(StdioResponse::Read(ReadStdioResponse { read: 11 })),
            BrokerResult::Stdio(StdioResponse::Write(WriteStdioResponse { written: 17 })),
            BrokerResult::Stdio(StdioResponse::IsTerminal(IsTerminalStdioResponse {
                is_terminal: false,
            })),
            BrokerResult::Stdio(StdioResponse::IsTerminal(IsTerminalStdioResponse {
                is_terminal: true,
            })),
            BrokerResult::Filesystem(FilesystemResponse::Open(OpenFileResponse { handle })),
            BrokerResult::Filesystem(FilesystemResponse::Read(ReadFileResponse { read: 11 })),
            BrokerResult::Filesystem(FilesystemResponse::Write(WriteFileResponse { written: 17 })),
            BrokerResult::Filesystem(FilesystemResponse::Seek(SeekFileResponse { offset: 19 })),
            BrokerResult::Filesystem(FilesystemResponse::Truncate),
            BrokerResult::Filesystem(FilesystemResponse::ReadDirectory(ReadDirectoryResponse {
                length: 23,
                next_index: Some(29),
            })),
            BrokerResult::Filesystem(FilesystemResponse::Status(FilesystemFileStatus {
                file_type: FilesystemFileType::CharacterDevice,
                mode: 0o620,
                size: u64::MAX,
                owner: FilesystemUser {
                    user: u16::MAX,
                    group: u16::MAX,
                },
                node_info: FilesystemNodeInfo {
                    dev: u64::MAX,
                    ino: u64::MAX,
                    rdev: Some(u64::MAX),
                },
                block_size: u64::MAX,
            })),
            BrokerResult::Filesystem(FilesystemResponse::Chmod),
            BrokerResult::Filesystem(FilesystemResponse::Chown),
            BrokerResult::Filesystem(FilesystemResponse::Unlink),
            BrokerResult::Filesystem(FilesystemResponse::Mkdir),
            BrokerResult::Filesystem(FilesystemResponse::Rmdir),
            BrokerResult::Filesystem(FilesystemResponse::Failed(FilesystemError::Io)),
            BrokerResult::Error(ErrorCode::PolicyDenied),
            BrokerResult::Error(ErrorCode::WouldBlock),
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
        assert_eq!(maximum_encoded_size, MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
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
        let mut frame = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
        });
        frame.push(0xff);
        assert_eq!(decode_request(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_malformed_stdio_request_frames() {
        let request = BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Stdio(StdioRequest::Write(WriteStdioRequest {
                stream: StdioOutputStream::Stdout,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(1),
                    length: 9,
                },
            })),
        };

        let mut unknown_operation = encode_request(request.clone());
        unknown_operation[9] = 0xff;
        assert_eq!(
            decode_request(&unknown_operation),
            Err(WireError::InvalidTag)
        );

        let mut unknown_stream = encode_request(request.clone());
        unknown_stream[10] = 0xff;
        assert_eq!(decode_request(&unknown_stream), Err(WireError::InvalidTag));

        let frame = encode_request(request);
        assert_eq!(
            decode_request(&frame[..frame.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let read = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Stdio(StdioRequest::Read(ReadStdioRequest {
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(1),
                    length: 9,
                },
            })),
        });
        assert_eq!(
            decode_request(&read[..read.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let terminal = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Stdio(StdioRequest::IsTerminal(IsTerminalStdioRequest {
                stream: StdioStream::Stdin,
            })),
        });
        let mut unknown_terminal_stream = terminal.clone();
        *unknown_terminal_stream.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_request(&unknown_terminal_stream),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_request(&terminal[..terminal.len() - 1]),
            Err(WireError::TruncatedFrame)
        );
    }

    #[test]
    fn decode_rejects_malformed_stdio_response_frames() {
        let response = BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Stdio(StdioResponse::Write(WriteStdioResponse { written: 9 })),
        };

        let mut unknown_operation = encode_response(response.clone());
        unknown_operation[9] = 0xff;
        assert_eq!(
            decode_response(&unknown_operation),
            Err(WireError::InvalidTag)
        );

        let frame = encode_response(response);
        assert_eq!(
            decode_response(&frame[..frame.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let read = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Stdio(StdioResponse::Read(ReadStdioResponse { read: 9 })),
        });
        assert_eq!(
            decode_response(&read[..read.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let terminal = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Stdio(StdioResponse::IsTerminal(IsTerminalStdioResponse {
                is_terminal: true,
            })),
        });
        let mut unknown_terminal_value = terminal.clone();
        *unknown_terminal_value.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_response(&unknown_terminal_value),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_response(&terminal[..terminal.len() - 1]),
            Err(WireError::TruncatedFrame)
        );
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

        // Address family, type, and protocol are the last three bytes of a
        // create frame, so each unknown tag is rejected on its own.
        let create = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Socket(SocketRequest::Create(CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            })),
        });
        for offset in 1..=3 {
            let mut frame = create.clone();
            let index = frame.len() - offset;
            frame[index] = 0xff;
            assert_eq!(decode_request(&frame), Err(WireError::InvalidTag));
        }
        assert_eq!(
            decode_request(&create[..create.len() - 1]),
            Err(WireError::TruncatedFrame)
        );

        let set_tcp_option = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Socket(SocketRequest::SetTcpOption(SetTcpOptionRequest {
                handle: ObjectHandle(13),
                value: TcpOptionValue::NoDelay(true),
            })),
        });
        for offset in 1..=2 {
            let mut frame = set_tcp_option.clone();
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
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(1),
                    length: 0,
                },
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

        let mut unknown_status = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::Status(SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: None,
                pending_error: None,
            })),
        });
        *unknown_status.last_mut().unwrap() = 0xff;
        assert_eq!(decode_response(&unknown_status), Err(WireError::InvalidTag));

        let get_tcp_option = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::GetTcpOption(GetTcpOptionResponse {
                value: TcpOptionValue::KeepAlive(true),
            })),
        });
        for offset in 1..=2 {
            let mut frame = get_tcp_option.clone();
            let index = frame.len() - offset;
            frame[index] = 0xff;
            assert_eq!(decode_response(&frame), Err(WireError::InvalidTag));
        }

        let socket_error = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Socket(SocketResponse::Failed(SocketError::TimedOut)),
        });
        for raw in [0, 13, u8::MAX] {
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
            decode_handshake_response(&[0xfc, 1, 2, 3]),
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

        let mut frame = encode_handshake_response(BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: ProtocolVersion(1),
        });
        frame.push(0xff);
        assert_eq!(
            decode_handshake_response(&frame),
            Err(WireError::TrailingBytes)
        );
    }

    #[test]
    fn decode_rejects_malformed_response_frames() {
        assert_eq!(
            decode_response(&[0xfc, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        for response in [
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: ProtocolVersion(1),
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
                })),
            }),
            [1, 13, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]
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
                })),
            }),
            [5, 13, 0, 0, 0, 0, 0, 0, 0, 9, 9, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn socket_send_to_request_wire_shape_is_pinned() {
        assert_eq!(
            encode_request(BrokerRequest {
                request_id: RequestId(13),
                operation: BrokerOperation::Socket(SocketRequest::SendTo(SendToSocketRequest {
                    handle: ObjectHandle(9),
                    buffer: SharedBufferDescriptor {
                        slot_index: SharedBufferSlotIndex(2),
                        length: 3,
                    },
                    flags: SendFlags::NONE,
                    destination: Some(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 53,)),
                })),
            }),
            [
                5, 13, 0, 0, 0, 0, 0, 0, 0, 10, 9, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0,
                0, 0, 0, 1, 203, 0, 113, 7, 53, 0
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
            [5, 13, 0, 0, 0, 0, 0, 0, 0, 6, 2]
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
                5, 13, 0, 0, 0, 0, 0, 0, 0, 9, 9, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 0, 192, 203,
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
