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
    /// Raw error values are part of the broker wire ABI.
    ///
    /// Value `0` is unassigned so null/default-looking values never represent
    /// concrete broker errors.
    ///
    /// Converts a raw protocol error code to an error category.
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            1 => Self::UnsupportedVersion,
            2 => Self::MalformedRequest,
            3 => Self::ProtocolState,
            4 => Self::UnsupportedOperation,
            5 => Self::Internal,
            6 => Self::PolicyDenied,
            7 => Self::UnknownObject,
            8 => Self::InvalidRights,
            9 => Self::ResourceExhausted,
            10 => Self::WouldBlock,
            raw => Self::Unknown(raw),
        }
    }

    /// Returns the raw protocol error code.
    pub const fn as_raw(self) -> u16 {
        match self {
            Self::UnsupportedVersion => 1,
            Self::MalformedRequest => 2,
            Self::ProtocolState => 3,
            Self::UnsupportedOperation => 4,
            Self::Internal => 5,
            Self::PolicyDenied => 6,
            Self::UnknownObject => 7,
            Self::InvalidRights => 8,
            Self::ResourceExhausted => 9,
            Self::WouldBlock => 10,
            Self::Unknown(raw) => raw,
        }
    }
}
