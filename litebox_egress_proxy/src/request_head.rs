// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Raw request-head validation before HTTP framing normalization.

use std::io;

use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::headers::validate_raw_request_framing;
use crate::limits::{MAX_HEADER_FIELDS, MAX_REQUEST_HEADER_BYTES, REQUEST_HEADER_READ_TIMEOUT};

/// A complete, raw-validated request prefix, including bytes read ahead.
pub(crate) struct ValidatedRequestPrefix(Bytes);

impl ValidatedRequestPrefix {
    pub(crate) fn into_bytes(self) -> Bytes {
        self.0
    }
}

/// Reason the first request head could not be accepted.
#[derive(Debug, Error)]
pub(crate) enum RequestHeadError {
    #[error("client closed before sending a complete request head")]
    Closed,
    #[error("request head exceeded the read timeout")]
    TimedOut,
    #[error("request head exceeded a configured limit")]
    TooLarge,
    #[error("request head is malformed or framing-ambiguous")]
    Malformed,
    #[error("request-head read failed: {0}")]
    Io(#[from] io::Error),
}

impl RequestHeadError {
    /// A complete HTTP rejection for errors caused by client input.
    pub(crate) fn response(&self) -> Option<&'static [u8]> {
        match self {
            Self::Closed | Self::Io(_) => None,
            Self::TimedOut => Some(
                b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
            Self::TooLarge => Some(
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
            Self::Malformed => Some(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
        }
    }
}

/// Reads and validates exactly the first raw HTTP/1 request head.
pub(crate) async fn read_validated_request_prefix<S>(
    stream: &mut S,
) -> Result<ValidatedRequestPrefix, RequestHeadError>
where
    S: AsyncRead + Unpin,
{
    timeout(REQUEST_HEADER_READ_TIMEOUT, read_request_prefix(stream))
        .await
        .map_err(|_| RequestHeadError::TimedOut)?
}

async fn read_request_prefix<S>(stream: &mut S) -> Result<ValidatedRequestPrefix, RequestHeadError>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];

    loop {
        if prefix.len() == MAX_REQUEST_HEADER_BYTES {
            return Err(RequestHeadError::TooLarge);
        }
        let remaining = MAX_REQUEST_HEADER_BYTES - prefix.len();
        let read_capacity = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..read_capacity]).await?;
        if read == 0 {
            return Err(RequestHeadError::Closed);
        }
        prefix.extend_from_slice(&chunk[..read]);

        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_FIELDS];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(&prefix) {
            Ok(httparse::Status::Partial) => {}
            Ok(httparse::Status::Complete(_)) => {
                let method = request.method.ok_or(RequestHeadError::Malformed)?;
                let target = request.path.ok_or(RequestHeadError::Malformed)?;
                let version = request.version.ok_or(RequestHeadError::Malformed)?;
                if target.as_bytes().contains(&b'#') {
                    return Err(RequestHeadError::Malformed);
                }
                validate_raw_request_framing(method, version, request.headers)
                    .map_err(|_| RequestHeadError::Malformed)?;
                return Ok(ValidatedRequestPrefix(Bytes::from(prefix)));
            }
            Err(httparse::Error::TooManyHeaders) => return Err(RequestHeadError::TooLarge),
            Err(_) => return Err(RequestHeadError::Malformed),
        }
    }
}
