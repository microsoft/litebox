// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CONNECT request framing validation.

use hyper::header;
use hyper::header::HeaderMap;
use thiserror::Error;

/// Reason a CONNECT request was rejected as framing-ambiguous.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FramingError {
    /// More than one `Host` header was present.
    #[error("message carries more than one Host header")]
    DuplicateHost,
    /// A CONNECT request carried body framing.
    #[error("CONNECT request carries a body")]
    BodyOnConnect,
}

/// Validates request framing before `hyper` normalizes the raw header list.
pub(crate) fn validate_raw_request_framing(
    method: &str,
    _version: u8,
    headers: &[httparse::Header<'_>],
) -> Result<(), FramingError> {
    if raw_header_count(headers, b"host") > 1 {
        return Err(FramingError::DuplicateHost);
    }
    if method == "CONNECT"
        && (raw_header_count(headers, b"transfer-encoding") != 0
            || raw_header_count(headers, b"content-length") != 0)
    {
        return Err(FramingError::BodyOnConnect);
    }
    Ok(())
}

/// Validates that a parsed CONNECT request is unambiguously bodyless.
pub fn validate_connect_framing(headers: &HeaderMap) -> Result<(), FramingError> {
    if headers.contains_key(header::TRANSFER_ENCODING)
        || headers.contains_key(header::CONTENT_LENGTH)
    {
        return Err(FramingError::BodyOnConnect);
    }
    if headers.get_all(header::HOST).iter().count() > 1 {
        return Err(FramingError::DuplicateHost);
    }
    Ok(())
}

fn raw_header_count(headers: &[httparse::Header<'_>], name: &[u8]) -> usize {
    headers
        .iter()
        .filter(|header| header.name.as_bytes().eq_ignore_ascii_case(name))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::{HeaderName, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn connect_requests_must_be_bodyless() {
        assert!(validate_connect_framing(&headers(&[("host", "example.com:443")])).is_ok());
        assert_eq!(
            validate_connect_framing(&headers(&[("content-length", "0")])),
            Err(FramingError::BodyOnConnect)
        );
        assert_eq!(
            validate_connect_framing(&headers(&[("transfer-encoding", "chunked")])),
            Err(FramingError::BodyOnConnect)
        );
    }

    #[test]
    fn duplicate_host_is_rejected() {
        assert_eq!(
            validate_connect_framing(&headers(&[
                ("host", "example.com:443"),
                ("host", "example.com:443"),
            ])),
            Err(FramingError::DuplicateHost)
        );
    }
}
