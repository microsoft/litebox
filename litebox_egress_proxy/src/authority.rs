// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Request authority canonicalization.
//!
//! Every request authority reaching the policy check goes through
//! [`parse_authority`], which shares [`Hostname`] canonicalization with the
//! policy parser. Ambiguous or reinterpretable forms are rejected before a URI
//! can be split differently by the proxy and by an upstream server.

use core::fmt;

use thiserror::Error;

use crate::policy::{Hostname, HostnameError, PortRangeError, parse_port};

/// Default destination port of a plain `http` request target.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// Reason an authority was rejected.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AuthorityError {
    /// The authority was empty.
    #[error("authority is empty")]
    Empty,
    /// The authority contained non-ASCII bytes.
    #[error("authority is not ASCII")]
    NotAscii,
    /// The authority contained a control byte or ASCII whitespace.
    #[error("authority contains a control byte or whitespace")]
    ControlOrWhitespace,
    /// The authority contained a percent sign; percent-decoding could change
    /// how the authority is interpreted.
    #[error("authority contains percent-encoding")]
    PercentEncoding,
    /// The authority contained `@`, i.e. userinfo, which is never accepted.
    #[error("authority contains userinfo")]
    UserInfo,
    /// The authority contained a delimiter that would let the authority be
    /// re-split into a different URI.
    #[error("authority contains a URI delimiter")]
    Delimiter,
    /// The authority contained an IP literal, including bracketed IPv6.
    #[error("authority is an IP literal")]
    IpLiteral,
    /// The authority contained more than one colon.
    #[error("authority contains more than one port separator")]
    AmbiguousPort,
    /// The request form requires an explicit port and none was present.
    #[error("authority is missing an explicit port")]
    MissingPort,
    /// The port was not a valid destination port.
    #[error("invalid port: {0}")]
    Port(#[from] PortRangeError),
    /// The host part was not a valid hostname.
    #[error("invalid hostname: {0}")]
    Hostname(#[from] HostnameError),
}

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
    if raw.is_empty() {
        return Err(AuthorityError::Empty);
    }
    if !raw.is_ascii() {
        return Err(AuthorityError::NotAscii);
    }

    for byte in raw.bytes() {
        match byte {
            // Everything up to and including SPACE, plus DEL.
            0x00..=0x20 | 0x7f => return Err(AuthorityError::ControlOrWhitespace),
            b'%' => return Err(AuthorityError::PercentEncoding),
            b'@' => return Err(AuthorityError::UserInfo),
            b'[' | b']' => return Err(AuthorityError::IpLiteral),
            b'/' | b'\\' | b'?' | b'#' => return Err(AuthorityError::Delimiter),
            _ => {}
        }
    }

    let (host_part, port_part) = match raw.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (raw, None),
    };

    let port = match port_part {
        Some(port) if port.contains(':') => return Err(AuthorityError::AmbiguousPort),
        Some(port) => parse_port(port)?,
        None => default_port.ok_or(AuthorityError::MissingPort)?,
    };

    // The hostname parser rejects IP literals and numeric forms, keeping
    // addresses out of hostname policy entirely.
    let host = Hostname::parse(host_part)?;
    Ok(RequestAuthority { host, port })
}

/// Returns whether a `Host` header identifies the same canonical host and
/// effective port as the request target.
///
/// `default_port` must be the default that applies to the request form: the
/// `http` default for absolute-form requests, and [`None`] for CONNECT, where
/// the header has to state the port explicitly to be unambiguous.
pub fn host_header_matches(
    raw_header: &str,
    target: &RequestAuthority,
    default_port: Option<u16>,
) -> bool {
    parse_authority(raw_header, default_port).is_ok_and(|header| &header == target)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            parse_authority("example.com", None),
            Err(AuthorityError::MissingPort)
        );
    }

    #[test]
    fn rejects_reinterpretable_authorities() {
        assert_eq!(parse_authority("", None), Err(AuthorityError::Empty));
        assert_eq!(
            parse_authority("exa\u{fe}mple.com:80", None),
            Err(AuthorityError::NotAscii)
        );
        assert_eq!(
            parse_authority("example.com\r\n:80", None),
            Err(AuthorityError::ControlOrWhitespace)
        );
        assert_eq!(
            parse_authority("example.com :80", None),
            Err(AuthorityError::ControlOrWhitespace)
        );
        assert_eq!(
            parse_authority("exam%70le.com:80", None),
            Err(AuthorityError::PercentEncoding)
        );
        assert_eq!(
            parse_authority("user@example.com:80", None),
            Err(AuthorityError::UserInfo)
        );
        assert_eq!(
            parse_authority("example.com:80/evil.com", None),
            Err(AuthorityError::Delimiter)
        );
        assert_eq!(
            parse_authority("example.com:80#frag", None),
            Err(AuthorityError::Delimiter)
        );
        assert_eq!(
            parse_authority("[2001:db8::1]:443", None),
            Err(AuthorityError::IpLiteral)
        );
        assert_eq!(
            parse_authority("example.com:80:443", None),
            Err(AuthorityError::AmbiguousPort)
        );
    }

    #[test]
    fn rejects_ip_and_invalid_ports() {
        assert!(matches!(
            parse_authority("192.0.2.10:443", None),
            Err(AuthorityError::Hostname(HostnameError::NumericForm))
        ));
        assert!(matches!(
            parse_authority("example.com:0", None),
            Err(AuthorityError::Port(PortRangeError::ZeroPort))
        ));
        assert!(matches!(
            parse_authority("example.com:http", None),
            Err(AuthorityError::Port(PortRangeError::NotANumber))
        ));
    }

    #[test]
    fn host_header_comparison() {
        let target = authority("example.com:8080", None);
        assert!(host_header_matches("Example.com:8080", &target, None));
        assert!(!host_header_matches("other.example:8080", &target, None));
        assert!(!host_header_matches("example.com", &target, None));
        assert!(!host_header_matches("example.com:80", &target, None));

        let default_target = authority("example.com", Some(DEFAULT_HTTP_PORT));
        assert!(host_header_matches(
            "example.com",
            &default_target,
            Some(DEFAULT_HTTP_PORT)
        ));
        assert!(host_header_matches(
            "example.com:80",
            &default_target,
            Some(DEFAULT_HTTP_PORT)
        ));
        assert!(!host_header_matches(
            "example.com:8080",
            &default_target,
            Some(DEFAULT_HTTP_PORT)
        ));
    }
}
