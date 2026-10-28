// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Task request errors and their ttrpc status codes.

use containerd_shim::protos::ttrpc::{self, Code};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    InvalidArgument,
    NotFound,
    AlreadyExists,
    FailedPrecondition,
    Unimplemented,
    DeadlineExceeded,
    /// The caller went away.
    Cancelled,
    Internal,
}

/// A failed request. Messages never quote guest values such as arguments or environment entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Error {
    pub(crate) kind: Kind,
    pub(crate) message: String,
}

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub(crate) fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(Kind::InvalidArgument, message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(Kind::NotFound, message)
    }

    pub(crate) fn precondition(message: impl Into<String>) -> Self {
        Self::new(Kind::FailedPrecondition, message)
    }

    pub(crate) fn unimplemented(message: impl Into<String>) -> Self {
        Self::new(Kind::Unimplemented, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(Kind::Internal, message)
    }

    /// Wraps a host failure while doing `what`.
    pub(crate) fn io(what: &str, error: &dyn std::fmt::Display) -> Self {
        Self::internal(format!("{what}: {error}"))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl From<Error> for ttrpc::Error {
    fn from(error: Error) -> Self {
        let code = match error.kind {
            Kind::InvalidArgument => Code::INVALID_ARGUMENT,
            Kind::NotFound => Code::NOT_FOUND,
            Kind::AlreadyExists => Code::ALREADY_EXISTS,
            Kind::FailedPrecondition => Code::FAILED_PRECONDITION,
            Kind::Unimplemented => Code::UNIMPLEMENTED,
            Kind::DeadlineExceeded => Code::DEADLINE_EXCEEDED,
            Kind::Cancelled => Code::CANCELLED,
            Kind::Internal => Code::INTERNAL,
        };
        ttrpc::Error::RpcStatus(ttrpc::get_status(code, error.message))
    }
}
