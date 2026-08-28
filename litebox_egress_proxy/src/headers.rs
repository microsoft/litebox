// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Header handling: framing validation and hop-by-hop removal.
//!
//! `hyper` already rejects most malformed HTTP/1 messages while parsing, such
//! as obsolete line folding and whitespace before a header colon. The checks
//! here are applied on top of that, so that framing ambiguity is rejected by
//! this proxy's own rules rather than by whatever a particular parser version
//! happens to tolerate.

use hyper::header::{HeaderMap, HeaderName};
use hyper::{Version, header};
use thiserror::Error;

/// Headers that never travel beyond a single hop.
const HOP_BY_HOP_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Reason a message was rejected as malformed or framing-ambiguous.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FramingError {
    /// The message carried both `Content-Length` and `Transfer-Encoding`.
    #[error("message carries both Content-Length and Transfer-Encoding")]
    ConflictingLength,
    /// The message carried conflicting `Content-Length` values.
    #[error("message carries conflicting Content-Length values")]
    ConflictingContentLength,
    /// A `Content-Length` value was not a single decimal number.
    #[error("Content-Length is not a decimal number")]
    InvalidContentLength,
    /// A transfer coding other than a single `chunked` was requested.
    #[error("unsupported transfer coding")]
    UnsupportedTransferCoding,
    /// `Transfer-Encoding` was used on an HTTP/1.0 message.
    #[error("Transfer-Encoding is not valid for HTTP/1.0")]
    TransferEncodingOnHttp10,
    /// A header value was not valid ASCII text.
    #[error("header value is not valid ASCII")]
    NonAsciiHeaderValue,
    /// More than one `Host` header was present.
    #[error("message carries more than one Host header")]
    DuplicateHost,
    /// A CONNECT request carried a body.
    #[error("CONNECT request carries a body")]
    BodyOnConnect,
}

/// Validates the framing headers of a client request.
///
/// Returns an error for every form that could be framed differently by this
/// proxy and by an upstream server.
pub fn validate_request_framing(headers: &HeaderMap, version: Version) -> Result<(), FramingError> {
    validate_message_framing(headers, version)?;

    if headers.get_all(header::HOST).iter().count() > 1 {
        return Err(FramingError::DuplicateHost);
    }

    Ok(())
}

/// Validates request framing before `hyper` normalizes the raw header list.
pub(crate) fn validate_raw_request_framing(
    method: &str,
    version: u8,
    headers: &[httparse::Header<'_>],
) -> Result<(), FramingError> {
    let transfer_encoding = raw_header_values(headers, b"transfer-encoding");
    let content_length = raw_header_values(headers, b"content-length");

    if method == "CONNECT" && (!transfer_encoding.is_empty() || !content_length.is_empty()) {
        return Err(FramingError::BodyOnConnect);
    }
    if raw_header_values(headers, b"host").len() > 1 {
        return Err(FramingError::DuplicateHost);
    }
    if !transfer_encoding.is_empty() && !content_length.is_empty() {
        return Err(FramingError::ConflictingLength);
    }

    if !transfer_encoding.is_empty() {
        if version == 0 {
            return Err(FramingError::TransferEncodingOnHttp10);
        }
        validate_raw_chunked_only(&transfer_encoding)?;
    }
    if !content_length.is_empty() {
        validate_raw_single_content_length(&content_length)?;
    }

    Ok(())
}

/// Validates the framing headers of an upstream response.
pub fn validate_response_framing(
    headers: &HeaderMap,
    version: Version,
) -> Result<(), FramingError> {
    validate_message_framing(headers, version)
}

/// Validates framing shared by requests and responses.
fn validate_message_framing(headers: &HeaderMap, version: Version) -> Result<(), FramingError> {
    let has_transfer_encoding = headers.contains_key(header::TRANSFER_ENCODING);
    let has_content_length = headers.contains_key(header::CONTENT_LENGTH);

    if has_transfer_encoding && has_content_length {
        return Err(FramingError::ConflictingLength);
    }

    if has_transfer_encoding {
        if version == Version::HTTP_10 {
            return Err(FramingError::TransferEncodingOnHttp10);
        }
        validate_chunked_only(headers)?;
    }

    if has_content_length {
        validate_single_content_length(headers)?;
    }

    Ok(())
}

/// Validates that a CONNECT request carries no body framing at all.
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

/// Rejects anything but exactly one `chunked` transfer coding.
fn validate_chunked_only(headers: &HeaderMap) -> Result<(), FramingError> {
    let mut codings = 0_usize;
    for value in headers.get_all(header::TRANSFER_ENCODING) {
        let text = value
            .to_str()
            .map_err(|_| FramingError::NonAsciiHeaderValue)?;
        for coding in text.split(',') {
            let coding = coding.trim();
            if coding.is_empty() {
                return Err(FramingError::UnsupportedTransferCoding);
            }
            if !coding.eq_ignore_ascii_case("chunked") {
                return Err(FramingError::UnsupportedTransferCoding);
            }
            codings += 1;
        }
    }
    if codings == 1 {
        Ok(())
    } else {
        Err(FramingError::UnsupportedTransferCoding)
    }
}

/// Rejects duplicate or conflicting `Content-Length` values.
fn validate_single_content_length(headers: &HeaderMap) -> Result<(), FramingError> {
    let mut seen: Option<u64> = None;
    for value in headers.get_all(header::CONTENT_LENGTH) {
        let text = value
            .to_str()
            .map_err(|_| FramingError::NonAsciiHeaderValue)?;
        for entry in text.split(',') {
            let entry = entry.trim();
            if entry.is_empty() || !entry.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(FramingError::InvalidContentLength);
            }
            let length: u64 = entry
                .parse()
                .map_err(|_| FramingError::InvalidContentLength)?;
            if seen.is_some() {
                return Err(FramingError::ConflictingContentLength);
            }
            seen = Some(length);
        }
    }
    Ok(())
}

fn raw_header_values<'a>(headers: &'a [httparse::Header<'a>], name: &[u8]) -> Vec<&'a [u8]> {
    headers
        .iter()
        .filter(|header| header.name.as_bytes().eq_ignore_ascii_case(name))
        .map(|header| header.value)
        .collect()
}

fn validate_raw_chunked_only(values: &[&[u8]]) -> Result<(), FramingError> {
    let mut codings = 0_usize;
    for value in values {
        let text = core::str::from_utf8(value).map_err(|_| FramingError::NonAsciiHeaderValue)?;
        for coding in text.split(',') {
            let coding = coding.trim();
            if coding.is_empty() || !coding.eq_ignore_ascii_case("chunked") {
                return Err(FramingError::UnsupportedTransferCoding);
            }
            codings += 1;
        }
    }
    if codings == 1 {
        Ok(())
    } else {
        Err(FramingError::UnsupportedTransferCoding)
    }
}

fn validate_raw_single_content_length(values: &[&[u8]]) -> Result<(), FramingError> {
    let mut seen = false;
    for value in values {
        let text = core::str::from_utf8(value).map_err(|_| FramingError::NonAsciiHeaderValue)?;
        for entry in text.split(',') {
            let entry = entry.trim();
            if entry.is_empty() || !entry.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(FramingError::InvalidContentLength);
            }
            let _: u64 = entry
                .parse()
                .map_err(|_| FramingError::InvalidContentLength)?;
            if seen {
                return Err(FramingError::ConflictingContentLength);
            }
            seen = true;
        }
    }
    Ok(())
}

/// Removes hop-by-hop headers, including every header named by `Connection`.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let mut connection_named: Vec<HeaderName> = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                connection_named.push(name);
            }
        }
    }

    for name in connection_named {
        headers.remove(&name);
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
}

/// Removes the framing headers so that the outgoing message is framed from the
/// forwarded body itself rather than from a claimed length.
pub fn remove_framing_headers(headers: &mut HeaderMap) {
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::TRANSFER_ENCODING);
}

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::HeaderValue;

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
    fn accepts_well_framed_requests() {
        assert!(
            validate_request_framing(&headers(&[("content-length", "12")]), Version::HTTP_11)
                .is_ok()
        );
        assert!(
            validate_request_framing(
                &headers(&[("transfer-encoding", "chunked")]),
                Version::HTTP_11
            )
            .is_ok()
        );
        assert!(validate_request_framing(&HeaderMap::new(), Version::HTTP_10).is_ok());
    }

    #[test]
    fn rejects_framing_ambiguity() {
        assert_eq!(
            validate_request_framing(
                &headers(&[("content-length", "1"), ("transfer-encoding", "chunked")]),
                Version::HTTP_11
            ),
            Err(FramingError::ConflictingLength)
        );
        assert_eq!(
            validate_request_framing(
                &headers(&[("content-length", "1"), ("content-length", "2")]),
                Version::HTTP_11
            ),
            Err(FramingError::ConflictingContentLength)
        );
        assert_eq!(
            validate_request_framing(
                &headers(&[("content-length", "1"), ("content-length", "1")]),
                Version::HTTP_11
            ),
            Err(FramingError::ConflictingContentLength)
        );
        assert_eq!(
            validate_request_framing(&headers(&[("content-length", "1, 2")]), Version::HTTP_11),
            Err(FramingError::ConflictingContentLength)
        );
        assert_eq!(
            validate_request_framing(&headers(&[("content-length", "abc")]), Version::HTTP_11),
            Err(FramingError::InvalidContentLength)
        );
        assert_eq!(
            validate_request_framing(
                &headers(&[("transfer-encoding", "gzip, chunked")]),
                Version::HTTP_11
            ),
            Err(FramingError::UnsupportedTransferCoding)
        );
        assert_eq!(
            validate_request_framing(
                &headers(&[
                    ("transfer-encoding", "chunked"),
                    ("transfer-encoding", "chunked")
                ]),
                Version::HTTP_11
            ),
            Err(FramingError::UnsupportedTransferCoding)
        );
        assert_eq!(
            validate_request_framing(
                &headers(&[("transfer-encoding", "chunked")]),
                Version::HTTP_10
            ),
            Err(FramingError::TransferEncodingOnHttp10)
        );
        assert_eq!(
            validate_request_framing(
                &headers(&[("host", "a.example"), ("host", "b.example")]),
                Version::HTTP_11
            ),
            Err(FramingError::DuplicateHost)
        );
    }

    #[test]
    fn response_framing_is_validated_without_request_headers() {
        assert!(
            validate_response_framing(&headers(&[("content-length", "12")]), Version::HTTP_11)
                .is_ok()
        );
        assert_eq!(
            validate_response_framing(
                &headers(&[("content-length", "1"), ("transfer-encoding", "chunked")]),
                Version::HTTP_11
            ),
            Err(FramingError::ConflictingLength)
        );
    }

    #[test]
    fn connect_requests_carry_no_body() {
        assert!(validate_connect_framing(&headers(&[("host", "a.example:443")])).is_ok());
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
    fn hop_by_hop_headers_are_removed() {
        let mut map = headers(&[
            ("connection", "keep-alive, X-Custom"),
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
            ("x-custom", "secret"),
            ("te", "trailers"),
            ("upgrade", "websocket"),
            ("x-kept", "value"),
        ]);

        strip_hop_by_hop(&mut map);

        assert_eq!(map.len(), 1);
        assert_eq!(map.get("x-kept").unwrap(), "value");
    }
}
