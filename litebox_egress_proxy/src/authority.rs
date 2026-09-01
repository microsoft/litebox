// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Request authority canonicalization.
//!
//! Every request authority reaching the policy check goes through
//! [`parse_authority`], which shares [`Hostname`] canonicalization with the
//! policy parser. Ambiguous or reinterpretable forms are rejected before a URI
//! can be split differently by the proxy and by an upstream server.

use core::fmt;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use thiserror::Error;

use crate::policy::{Hostname, parse_port};

/// Default destination port of a plain `http` request target.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// Indicates that a request authority is invalid.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("invalid request authority")]
pub struct AuthorityError;

/// A canonical request authority: an exact hostname and an effective
/// destination port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestAuthority {
    host: Hostname,
    port: u16,
}

impl RequestAuthority {
    /// Returns the canonical hostname.
    pub fn host(&self) -> &Hostname {
        &self.host
    }

    /// Returns the effective destination port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Renders the canonical `Host` header value for this authority.
    ///
    /// The port is omitted when it is the default `http` port, matching what
    /// an origin server expects from a direct client.
    pub fn host_header_value(&self) -> String {
        if self.port == DEFAULT_HTTP_PORT {
            self.host.as_str().to_owned()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for RequestAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.host, self.port)
    }
}

/// Parses a request authority into canonical form.
///
/// `default_port` supplies the effective port when the authority carries none.
/// Passing [`None`] requires an explicit port, which is what CONNECT
/// authority-form targets must use.
///
/// Bytes that could make the proxy and an upstream server disagree about where
/// the authority ends -- control bytes, ASCII whitespace, percent-encoding,
/// `@`, and URI delimiters -- are rejected before any further interpretation.
pub fn parse_authority(
    raw: &str,
    default_port: Option<u16>,
) -> Result<RequestAuthority, AuthorityError> {
    if raw.is_empty() || !raw.is_ascii() {
        return Err(AuthorityError);
    }

    for byte in raw.bytes() {
        match byte {
            // Everything up to and including SPACE, plus DEL.
            0x00..=0x20 | 0x7f | b'%' | b'@' | b'[' | b']' | b'/' | b'\\' | b'?' | b'#' => {
                return Err(AuthorityError);
            }
            _ => {}
        }
    }

    let (host_part, port_part) = match raw.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (raw, None),
    };

    let port = match port_part {
        Some(port) if port.contains(':') => return Err(AuthorityError),
        Some(port) => parse_port(port).ok_or(AuthorityError)?,
        None => default_port
            .filter(|port| *port != 0)
            .ok_or(AuthorityError)?,
    };

    // The hostname parser rejects IP literals and numeric forms, keeping
    // addresses out of hostname policy entirely.
    let host = Hostname::parse(host_part).map_err(|_| AuthorityError)?;
    Ok(RequestAuthority { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::string::ToString;

    fn authority(raw: &str, default_port: Option<u16>) -> RequestAuthority {
        parse_authority(raw, default_port).unwrap()
    }

    #[test]
    fn canonicalizes_host_and_port() {
        let parsed = authority("Example.COM.:8080", None);
        assert_eq!(parsed.host().as_str(), "example.com");
        assert_eq!(parsed.port(), 8080);
        assert_eq!(parsed.to_string(), "example.com:8080");
    }

    #[test]
    fn applies_default_port_only_when_provided() {
        assert_eq!(authority("example.com", Some(DEFAULT_HTTP_PORT)).port(), 80);
        assert_eq!(parse_authority("example.com", None), Err(AuthorityError));
        assert_eq!(parse_authority("example.com", Some(0)), Err(AuthorityError));
    }

    #[test]
    fn rejects_reinterpretable_authorities() {
        for raw in [
            "",
            "exa\u{fe}mple.com:80",
            "example.com\r\n:80",
            "example.com :80",
            "exam%70le.com:80",
            "user@example.com:80",
            "example.com:80/evil.com",
            "example.com:80#frag",
            "[2001:db8::1]:443",
            "example.com:80:443",
        ] {
            assert_eq!(parse_authority(raw, None), Err(AuthorityError), "{raw:?}");
        }
    }

    #[test]
    fn rejects_ip_and_invalid_ports() {
        for raw in ["192.0.2.10:443", "example.com:0", "example.com:http"] {
            assert_eq!(parse_authority(raw, None), Err(AuthorityError), "{raw}");
        }
    }
}
