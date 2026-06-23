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
}

impl ErrorCode {
    /// Raw error values are part of the broker wire ABI.
    ///
    /// Value `0` is unassigned so null/default-looking values never represent
    /// concrete broker errors.
    ///
    /// Converts a raw protocol error code to an error category.
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::UnsupportedVersion),
            2 => Some(Self::MalformedRequest),
            3 => Some(Self::ProtocolState),
            4 => Some(Self::UnsupportedOperation),
            5 => Some(Self::Internal),
            6 => Some(Self::PolicyDenied),
            7 => Some(Self::UnknownObject),
            8 => Some(Self::InvalidRights),
            9 => Some(Self::ResourceExhausted),
            10 => Some(Self::WouldBlock),
            _ => None,
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
        }
    }
}
