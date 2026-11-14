// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Descriptions of broker-owned objects.
//!
//! The broker reads a description from the object itself, so a process given a
//! reference by another process learns what the object is from the broker, not
//! from the other process.

use thiserror::Error;

use crate::ObjectHandle;
use crate::event::EventConsumeMode;
use crate::socket::SocketType;
use crate::timer::TimerTimeBase;

/// Encoded size in bytes of one [`ReceivedReference`] in a shared buffer.
pub const RECEIVED_REFERENCE_SIZE: u32 = 16;

// Every tag is nonzero, so a zeroed record never decodes and a zero detail or
// attribute byte means the kind has none. Detail and attribute tags are
// interpreted per kind.
const KIND_FILE: u8 = 1;
const KIND_PIPE: u8 = 2;
const KIND_UNIX_SOCKET: u8 = 3;
const KIND_SOCKET: u8 = 4;
const KIND_VSOCK_SOCKET: u8 = 5;
const KIND_EVENT: u8 = 6;
const KIND_TIMER: u8 = 7;
const KIND_READINESS_QUEUE: u8 = 8;

const PIPE_END_READ: u8 = 1;
const PIPE_END_WRITE: u8 = 2;

const SOCKET_TYPE_STREAM: u8 = 1;
const SOCKET_TYPE_DATAGRAM: u8 = 2;
const SOCKET_TYPE_SEQ_PACKET: u8 = 3;

const EVENT_CONSUME_ALL: u8 = 1;
const EVENT_CONSUME_ONE: u8 = 2;

const TIMER_TIME_BASE_MONOTONIC: u8 = 1;
const TIMER_TIME_BASE_WALL: u8 = 2;

/// The kind of a broker-owned object, with the attributes fixed when it was
/// created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectDescription {
    /// A file.
    File,
    /// One end of a pipe.
    Pipe {
        /// Which end.
        end: PipeEnd,
    },
    /// A Unix socket.
    UnixSocket {
        /// The socket's type.
        socket_type: SocketType,
    },
    /// A network socket.
    Socket {
        /// The socket's type.
        socket_type: SocketType,
    },
    /// A vsock socket.
    VsockSocket {
        /// The socket's type.
        socket_type: SocketType,
    },
    /// An event.
    Event {
        /// How consuming the event removes credits.
        consume: EventConsumeMode,
    },
    /// A timer.
    Timer {
        /// The timer's time base.
        time_base: TimerTimeBase,
    },
    /// A readiness queue.
    ReadinessQueue,
}

/// One end of a pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeEnd {
    /// The end that reads.
    Read,
    /// The end that writes.
    Write,
}

impl ObjectDescription {
    /// Returns the kind, detail, and attribute bytes of this description.
    fn encode(self) -> [u8; 3] {
        match self {
            Self::File => [KIND_FILE, 0, 0],
            Self::Pipe { end } => {
                let end = match end {
                    PipeEnd::Read => PIPE_END_READ,
                    PipeEnd::Write => PIPE_END_WRITE,
                };
                [KIND_PIPE, end, 0]
            }
            Self::UnixSocket { socket_type } => {
                [KIND_UNIX_SOCKET, encode_socket_type(socket_type), 0]
            }
            Self::Socket { socket_type } => [KIND_SOCKET, encode_socket_type(socket_type), 0],
            Self::VsockSocket { socket_type } => {
                [KIND_VSOCK_SOCKET, encode_socket_type(socket_type), 0]
            }
            Self::Event { consume } => {
                let consume = match consume {
                    EventConsumeMode::All => EVENT_CONSUME_ALL,
                    EventConsumeMode::One => EVENT_CONSUME_ONE,
                };
                [KIND_EVENT, 0, consume]
            }
            Self::Timer { time_base } => {
                let time_base = match time_base {
                    TimerTimeBase::Monotonic => TIMER_TIME_BASE_MONOTONIC,
                    TimerTimeBase::Wall => TIMER_TIME_BASE_WALL,
                };
                [KIND_TIMER, 0, time_base]
            }
            Self::ReadinessQueue => [KIND_READINESS_QUEUE, 0, 0],
        }
    }

    /// Decodes the description that `kind`, `detail`, and `attribute` name,
    /// ignoring bytes the kind does not use.
    fn decode([kind, detail, attribute]: [u8; 3]) -> Option<Self> {
        Some(match kind {
            KIND_FILE => Self::File,
            KIND_PIPE => Self::Pipe {
                end: match detail {
                    PIPE_END_READ => PipeEnd::Read,
                    PIPE_END_WRITE => PipeEnd::Write,
                    _ => return None,
                },
            },
            KIND_UNIX_SOCKET => Self::UnixSocket {
                socket_type: decode_socket_type(detail)?,
            },
            KIND_SOCKET => Self::Socket {
                socket_type: decode_socket_type(detail)?,
            },
            KIND_VSOCK_SOCKET => Self::VsockSocket {
                socket_type: decode_socket_type(detail)?,
            },
            KIND_EVENT => Self::Event {
                consume: match attribute {
                    EVENT_CONSUME_ALL => EventConsumeMode::All,
                    EVENT_CONSUME_ONE => EventConsumeMode::One,
                    _ => return None,
                },
            },
            KIND_TIMER => Self::Timer {
                time_base: match attribute {
                    TIMER_TIME_BASE_MONOTONIC => TimerTimeBase::Monotonic,
                    TIMER_TIME_BASE_WALL => TimerTimeBase::Wall,
                    _ => return None,
                },
            },
            KIND_READINESS_QUEUE => Self::ReadinessQueue,
            _ => return None,
        })
    }
}

fn encode_socket_type(socket_type: SocketType) -> u8 {
    match socket_type {
        SocketType::Stream => SOCKET_TYPE_STREAM,
        SocketType::Datagram => SOCKET_TYPE_DATAGRAM,
        SocketType::SeqPacket => SOCKET_TYPE_SEQ_PACKET,
    }
}

fn decode_socket_type(detail: u8) -> Option<SocketType> {
    match detail {
        SOCKET_TYPE_STREAM => Some(SocketType::Stream),
        SOCKET_TYPE_DATAGRAM => Some(SocketType::Datagram),
        SOCKET_TYPE_SEQ_PACKET => Some(SocketType::SeqPacket),
        _ => None,
    }
}

/// A reference the broker installed in a process's handle table, with the
/// description of its object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedReference {
    /// The installed handle.
    pub handle: ObjectHandle,
    /// The description of the handle's object.
    pub description: ObjectDescription,
}

impl ReceivedReference {
    /// Returns this reference's encoding in a shared buffer: the handle in
    /// little-endian order, the description's kind, detail, and attribute
    /// bytes, and five reserved zero bytes.
    #[must_use]
    pub fn encode(self) -> [u8; RECEIVED_REFERENCE_SIZE as usize] {
        let mut bytes = [0; RECEIVED_REFERENCE_SIZE as usize];
        bytes[..8].copy_from_slice(&self.handle.0.to_le_bytes());
        bytes[8..11].copy_from_slice(&self.description.encode());
        bytes
    }

    /// Decodes a reference from its encoding by [`Self::encode`].
    pub fn decode(
        bytes: &[u8; RECEIVED_REFERENCE_SIZE as usize],
    ) -> Result<Self, InvalidReceivedReference> {
        let mut handle = [0; 8];
        handle.copy_from_slice(&bytes[..8]);
        let reference = Self {
            handle: ObjectHandle(u64::from_le_bytes(handle)),
            description: ObjectDescription::decode([bytes[8], bytes[9], bytes[10]])
                .ok_or(InvalidReceivedReference)?,
        };
        // Bytes the description does not use, and the reserved bytes, must be
        // zero.
        if reference.encode() != *bytes {
            return Err(InvalidReceivedReference);
        }
        Ok(reference)
    }
}

/// Failure to decode a [`ReceivedReference`] from a shared buffer.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("invalid received reference")]
pub struct InvalidReceivedReference;

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE: ObjectHandle = ObjectHandle(0x0102_0304_0506_0708);

    #[test]
    fn received_references_round_trip() {
        let mut descriptions = alloc::vec![
            ObjectDescription::File,
            ObjectDescription::Pipe { end: PipeEnd::Read },
            ObjectDescription::Pipe {
                end: PipeEnd::Write
            },
            ObjectDescription::Event {
                consume: EventConsumeMode::All,
            },
            ObjectDescription::Event {
                consume: EventConsumeMode::One,
            },
            ObjectDescription::Timer {
                time_base: TimerTimeBase::Monotonic,
            },
            ObjectDescription::Timer {
                time_base: TimerTimeBase::Wall,
            },
            ObjectDescription::ReadinessQueue,
        ];
        for socket_type in [
            SocketType::Stream,
            SocketType::Datagram,
            SocketType::SeqPacket,
        ] {
            descriptions.extend([
                ObjectDescription::UnixSocket { socket_type },
                ObjectDescription::Socket { socket_type },
                ObjectDescription::VsockSocket { socket_type },
            ]);
        }

        for description in descriptions {
            let reference = ReceivedReference {
                handle: HANDLE,
                description,
            };
            let bytes = reference.encode();
            assert_eq!(bytes[..8], HANDLE.0.to_le_bytes());
            assert_eq!(bytes[11..], [0; 5]);
            assert_eq!(ReceivedReference::decode(&bytes), Ok(reference));
        }
    }

    #[test]
    fn received_references_with_invalid_bytes_are_rejected() {
        let record = |kind, detail, attribute| {
            let mut bytes = [0; RECEIVED_REFERENCE_SIZE as usize];
            bytes[..8].copy_from_slice(&HANDLE.0.to_le_bytes());
            bytes[8..11].copy_from_slice(&[kind, detail, attribute]);
            bytes
        };
        let mut reserved = record(KIND_FILE, 0, 0);
        reserved[15] = 1;

        for bytes in [
            [0; RECEIVED_REFERENCE_SIZE as usize],
            // Unknown kinds.
            record(0, 0, 0),
            record(KIND_READINESS_QUEUE + 1, 0, 0),
            // Missing or unknown details and attributes.
            record(KIND_PIPE, 0, 0),
            record(KIND_PIPE, PIPE_END_WRITE + 1, 0),
            record(KIND_UNIX_SOCKET, 0, 0),
            record(KIND_SOCKET, SOCKET_TYPE_SEQ_PACKET + 1, 0),
            record(KIND_VSOCK_SOCKET, 0xff, 0),
            record(KIND_EVENT, 0, 0),
            record(KIND_EVENT, 0, EVENT_CONSUME_ONE + 1),
            record(KIND_TIMER, 0, 0),
            record(KIND_TIMER, 0, TIMER_TIME_BASE_WALL + 1),
            // Bytes the kind does not use.
            record(KIND_FILE, 1, 0),
            record(KIND_PIPE, PIPE_END_READ, 1),
            record(KIND_EVENT, 1, EVENT_CONSUME_ALL),
            record(KIND_READINESS_QUEUE, 0, 1),
            reserved,
        ] {
            assert_eq!(
                ReceivedReference::decode(&bytes),
                Err(InvalidReceivedReference),
                "{bytes:?}"
            );
        }
    }
}
