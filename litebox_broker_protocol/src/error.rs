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
    #[error("broker object peer is closed")]
    PeerClosed,
    #[error("broker memory allocation failed")]
    OutOfMemory,
}
