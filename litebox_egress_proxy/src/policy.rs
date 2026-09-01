// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Exact hostname and destination-port policy.

use core::fmt;
use core::ops::RangeInclusive;

use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;
use thiserror::Error;

const MAX_HOSTNAME_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;

/// Indicates that a hostname is invalid.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("invalid hostname")]
pub struct HostnameError;

/// A canonical DNS hostname.
///
/// Canonicalization lowercases the name and removes at most one trailing dot.
/// IP literals and legacy numeric IPv4 forms are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Parses and canonicalizes a hostname.
    pub fn parse(input: &str) -> Result<Self, HostnameError> {
        if input.is_empty() || !input.is_ascii() {
            return Err(HostnameError);
        }

        let trimmed = input.strip_suffix('.').unwrap_or(input);
        if trimmed.is_empty() || trimmed.len() > MAX_HOSTNAME_BYTES {
            return Err(HostnameError);
        }

        let canonical = trimmed.to_ascii_lowercase();
        for label in canonical.split('.') {
            if label.is_empty()
                || label.len() > MAX_LABEL_BYTES
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
            {
                return Err(HostnameError);
            }
        }

        if is_ipv4_numeric_form(&canonical) {
            return Err(HostnameError);
        }

        Ok(Self(canonical))
    }

    /// Returns the canonical hostname.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Returns whether `host` is an IPv4 address in the historical `inet_aton`
/// grammar.
fn is_ipv4_numeric_form(host: &str) -> bool {
    let mut values = [0_u64; 4];
    let mut count = 0;

    for component in host.split('.') {
        if count == values.len() {
            return false;
        }
        let Some(value) = parse_ipv4_component(component) else {
            return false;
        };
        values[count] = value;
        count += 1;
    }

    match count {
        1 => u32::try_from(values[0]).is_ok(),
        2 => u8::try_from(values[0]).is_ok() && values[1] <= 0x00ff_ffff,
        3 => {
            u8::try_from(values[0]).is_ok()
                && u8::try_from(values[1]).is_ok()
                && u16::try_from(values[2]).is_ok()
        }
        4 => values.iter().all(|value| u8::try_from(*value).is_ok()),
        _ => false,
    }
}

fn parse_ipv4_component(component: &str) -> Option<u64> {
    let (digits, radix) = if let Some(hex) = component.strip_prefix("0x") {
        (hex, 16)
    } else if component.len() > 1 && component.starts_with('0') {
        (component, 8)
    } else {
        (component, 10)
    };

    if digits.is_empty() {
        None
    } else {
        u64::from_str_radix(digits, radix).ok()
    }
}

pub(crate) fn parse_port(input: &str) -> Option<u16> {
    if input.is_empty() || input.len() > 5 || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    input.parse().ok().filter(|port| *port != 0)
}

/// Indicates that a hostname policy rule is invalid.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("invalid hostname policy rule")]
pub struct PolicyError;

/// An immutable, default-deny hostname and destination-port policy.
#[derive(Clone, Debug)]
pub struct HostPolicy {
    entries: HashMap<Hostname, Vec<RangeInclusive<u16>>>,
}

impl HostPolicy {
    /// Parses `HOST:PORT[-PORT]` rules into a policy.
    pub fn from_rules<S>(rules: impl IntoIterator<Item = S>) -> Result<Self, PolicyError>
    where
        S: AsRef<str>,
    {
        let mut entries: HashMap<Hostname, Vec<RangeInclusive<u16>>> = HashMap::new();
        for rule in rules {
            let (host, ports) = parse_rule(rule.as_ref())?;
            entries.entry(host).or_default().push(ports);
        }
        Ok(Self { entries })
    }

    /// Returns whether the exact canonical hostname and port are allowed.
    pub fn allows(&self, host: &Hostname, port: u16) -> bool {
        self.entries
            .get(host)
            .is_some_and(|ranges| ranges.iter().any(|range| range.contains(&port)))
    }
}

fn parse_rule(input: &str) -> Result<(Hostname, RangeInclusive<u16>), PolicyError> {
    let (host, ports) = input.split_once(':').ok_or(PolicyError)?;
    let host = Hostname::parse(host).map_err(|_| PolicyError)?;

    let (start, end) = if let Some((start, end)) = ports.split_once('-') {
        (
            parse_port(start).ok_or(PolicyError)?,
            parse_port(end).ok_or(PolicyError)?,
        )
    } else {
        let port = parse_port(ports).ok_or(PolicyError)?;
        (port, port)
    };
    if start > end {
        return Err(PolicyError);
    }

    Ok((host, start..=end))
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::format;

    #[test]
    fn hostname_is_canonicalized() {
        assert_eq!(
            Hostname::parse("Example.COM.").unwrap().as_str(),
            "example.com"
        );
        assert_eq!(
            Hostname::parse("a-b.example").unwrap().as_str(),
            "a-b.example"
        );
    }

    #[test]
    fn hostname_rejects_invalid_forms() {
        for hostname in [
            "",
            ".",
            "a..b",
            "a.b..",
            "exämple.com",
            "-a.example",
            "a-.example",
            "a_b.example",
            "a b.example",
            "host:80",
            "192.0.2.1",
            "12345",
            "[::1]",
            "127.1",
            "0177.0.0.1",
            "0x7f000001",
            "0x7f.0x0.0x0.0x1",
            "127.0.0.0x1",
            "4294967295",
        ] {
            assert!(Hostname::parse(hostname).is_err(), "{hostname:?}");
        }

        for hostname in [
            "service.123",
            "0xservice",
            "09",
            "1.2.3.09",
            "08.1",
            "4294967296",
            "1.2.3.4.5",
        ] {
            assert!(Hostname::parse(hostname).is_ok(), "{hostname}");
        }
    }

    #[test]
    fn hostname_enforces_length_bounds() {
        let long_label = "a".repeat(64);
        assert!(Hostname::parse(&format!("{long_label}.example")).is_err());

        let long_name = format!("{}.example", "a".repeat(250));
        assert!(Hostname::parse(&long_name).is_err());

        let at_limit = format!(
            "{label}.{label}.{label}.{tail}",
            label = "a".repeat(63),
            tail = "a".repeat(61)
        );
        assert_eq!(at_limit.len(), 253);
        assert!(Hostname::parse(&at_limit).is_ok());
    }

    #[test]
    fn policy_parses_rules_and_denies_by_default() {
        let policy =
            HostPolicy::from_rules(["a.example:80", "a.example:81-90", "A.EXAMPLE:8000-8100"])
                .unwrap();
        let host = Hostname::parse("a.example").unwrap();

        assert!(policy.allows(&host, 80));
        assert!(policy.allows(&host, 90));
        assert!(policy.allows(&host, 8100));
        assert!(!policy.allows(&host, 91));
        assert!(!policy.allows(&host, 443));
        assert!(!policy.allows(&Hostname::parse("b.example").unwrap(), 80));
    }

    #[test]
    fn policy_rejects_invalid_rules() {
        for rule in [
            "",
            "example.com",
            ":443",
            "example.com:",
            "example.com:+80",
            "example.com:8o",
            "example.com:0",
            "example.com:65536",
            "example.com:90-80",
            "example.com:80:443",
            "192.0.2.1:443",
        ] {
            assert!(HostPolicy::from_rules([rule]).is_err(), "{rule:?}");
        }
    }
}
