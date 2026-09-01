// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Headers forwarded across an HTTP proxy hop.

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

/// Removes hop-by-hop headers and lets Hyper regenerate message framing.
pub(crate) fn prepare_for_forwarding(headers: &mut HeaderMap) -> bool {
    let mut connection_named = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        let Ok(text) = value.to_str() else {
            return false;
        };
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return false;
            }
            let Ok(name) = HeaderName::from_bytes(token.as_bytes()) else {
                return false;
            };
            connection_named.push(name);
        }
    }

    for name in connection_named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
    headers.remove(header::CONTENT_LENGTH);
    true
}
