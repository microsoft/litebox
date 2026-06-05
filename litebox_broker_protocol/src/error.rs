// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;

/// ABI-neutral broker error category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The requested protocol version is unsupported.
    UnsupportedVersion,
    /// The request is structurally invalid.
    MalformedRequest,
    /// The request is validly encoded but violates the connection state machine.
    ProtocolState,
    /// The request is unsupported by this broker protocol implementation.
    UnsupportedOperation,
    /// Broker hit an internal condition or an error category this protocol cannot represent.
    Internal,
    /// Policy denied the operation.
    PolicyDenied,
    /// The referenced object does not exist.
    UnknownObject,
    /// The referenced object generation is stale.
    StaleHandle,
    /// The referenced object type does not match the operation.
    WrongObjectType,
    /// The caller lacks the required broker rights.
    InvalidRights,
    /// Broker-side resource exhaustion.
    ResourceExhausted,
    /// The operation would block in the current event state.
    WouldBlock,
    /// Error code emitted by a newer broker and not understood by this local peer.
    ///
    /// This variant is reserved for raw codes not assigned by this protocol
    /// version.
    Unknown(u16),
}

impl ErrorCode {
    /// Raw error values are part of the broker wire ABI; do not renumber
    /// assigned values.
    ///
    /// Values `0` and `1` remain unassigned so null/default-looking values never
    /// represent concrete broker errors.
    ///
    /// Converts a raw protocol error code to an error category.
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            2 => Self::UnsupportedVersion,
            3 => Self::MalformedRequest,
            10 => Self::ProtocolState,
            11 => Self::UnsupportedOperation,
            12 => Self::Internal,
            4 => Self::PolicyDenied,
            5 => Self::UnknownObject,
            6 => Self::StaleHandle,
            7 => Self::WrongObjectType,
            8 => Self::InvalidRights,
            9 => Self::ResourceExhausted,
            13 => Self::WouldBlock,
            raw => Self::Unknown(raw),
        }
    }

    /// Returns the raw protocol error code.
    pub const fn as_raw(self) -> u16 {
        match self {
            Self::UnsupportedVersion => 2,
            Self::MalformedRequest => 3,
            Self::ProtocolState => 10,
            Self::UnsupportedOperation => 11,
            Self::Internal => 12,
            Self::PolicyDenied => 4,
            Self::UnknownObject => 5,
            Self::StaleHandle => 6,
            Self::WrongObjectType => 7,
            Self::InvalidRights => 8,
            Self::ResourceExhausted => 9,
            Self::WouldBlock => 13,
            Self::Unknown(raw) => raw,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => f.write_str("unsupported broker protocol version"),
            Self::MalformedRequest => f.write_str("malformed broker request"),
            Self::ProtocolState => f.write_str("broker protocol state violation"),
            Self::UnsupportedOperation => f.write_str("unsupported broker operation"),
            Self::Internal => f.write_str("internal broker error"),
            Self::PolicyDenied => f.write_str("broker policy denied the operation"),
            Self::UnknownObject => f.write_str("unknown broker object"),
            Self::StaleHandle => f.write_str("stale broker handle"),
            Self::WrongObjectType => f.write_str("wrong broker object type"),
            Self::InvalidRights => f.write_str("invalid broker rights"),
            Self::ResourceExhausted => f.write_str("broker resource exhausted"),
            Self::WouldBlock => f.write_str("broker operation would block"),
            Self::Unknown(raw) => write!(f, "unknown broker error code {raw}"),
        }
    }
}

impl core::error::Error for ErrorCode {}
