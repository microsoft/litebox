// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use thiserror::Error;

/// ABI-neutral broker error category.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    #[error("unsupported broker protocol version")]
    UnsupportedVersion,
    #[error("malformed broker request")]
    MalformedRequest,
    #[error("broker protocol state violation")]
    ProtocolState,
    #[error("unsupported broker operation")]
    UnsupportedOperation,
    #[error("internal broker error")]
    Internal,
    #[error("broker policy denied the operation")]
    PolicyDenied,
    #[error("unknown broker object")]
    UnknownObject,
    #[error("invalid broker rights")]
    InvalidRights,
    #[error("broker resource exhausted")]
    ResourceExhausted,
    #[error("broker operation would block")]
    WouldBlock,
    /// Error code emitted by a newer broker and not understood by this local peer.
    ///
    /// This variant is reserved for raw codes not assigned by this protocol
    /// version.
    #[error("unknown broker error code {0}")]
    Unknown(u16),
}

impl ErrorCode {
    /// Raw error values are part of the broker wire ABI; do not renumber
    /// assigned values.
    ///
    /// Values `0`, `1`, `6`, and `7` remain unassigned so null/default-looking
    /// values never represent concrete broker errors and retired values are not reused.
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
            Self::InvalidRights => 8,
            Self::ResourceExhausted => 9,
            Self::WouldBlock => 13,
            Self::Unknown(raw) => raw,
        }
    }
}
