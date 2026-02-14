// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Error types for VSM operations.

use litebox_common_linux::errno::Errno;
use thiserror::Error;

/// Errors for module signature verification.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("signature not found in module")]
    SignatureNotFound,
    #[error("invalid signature format")]
    InvalidSignature,
    #[error("invalid certificate")]
    InvalidCertificate,
    #[error("signature authentication failed")]
    AuthenticationFailed,
    #[error("failed to parse signature data")]
    ParseFailed,
    #[error("unsupported signature algorithm")]
    Unsupported,
}

impl From<VerificationError> for Errno {
    fn from(e: VerificationError) -> Self {
        match e {
            VerificationError::AuthenticationFailed => Errno::EKEYREJECTED,
            VerificationError::SignatureNotFound => Errno::ENODATA,
            VerificationError::Unsupported => Errno::ENOPKG,
            VerificationError::InvalidCertificate => Errno::ENOKEY,
            VerificationError::InvalidSignature | VerificationError::ParseFailed => Errno::ELIBBAD,
        }
    }
}
