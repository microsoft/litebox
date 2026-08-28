// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hop-by-hop HTTP header handling.

use hyper::HeaderMap;
use hyper::header::{self, HeaderName};

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

#[derive(Debug)]
pub(crate) struct InvalidConnectionHeader;

/// Removes hop-by-hop headers, including headers named by `Connection`.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) -> Result<(), InvalidConnectionHeader> {
    let mut connection_named = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        let text = value.to_str().map_err(|_| InvalidConnectionHeader)?;
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(InvalidConnectionHeader);
            }
            connection_named.push(
                HeaderName::from_bytes(token.as_bytes()).map_err(|_| InvalidConnectionHeader)?,
            );
        }
    }

    for name in connection_named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
    Ok(())
}

/// Lets Hyper regenerate framing from the parsed streaming body.
pub(crate) fn remove_framing_headers(headers: &mut HeaderMap) {
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::TRANSFER_ENCODING);
}

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::HeaderValue;

    #[test]
    fn strips_hop_by_hop_and_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-secret", HeaderValue::from_static("value"));
        headers.insert("x-kept", HeaderValue::from_static("value"));

        strip_hop_by_hop(&mut headers).unwrap();

        assert_eq!(headers.len(), 1);
        assert_eq!(headers["x-kept"], "value");
    }
}
