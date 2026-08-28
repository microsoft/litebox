// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed, immutable hostname and destination-port policy.
//!
//! The policy is parsed once, before any listener is announced, and is never
//! mutated afterwards. Only canonical values reach the request path: a
//! [`Hostname`] is always lowercase, dot-normalised and syntactically valid,
//! and a [`PortRange`] never spans a reserved DNS port.

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeMap;

use thiserror::Error;

use crate::limits::MAX_HOST_RULES;

/// Maximum total length of a canonical DNS name, in bytes.
const MAX_HOSTNAME_BYTES: usize = 253;

/// Maximum length of a single DNS label, in bytes.
const MAX_LABEL_BYTES: usize = 63;

/// Well-known DNS ports that a proxy rule may never authorize.
///
/// Port 53 is plain DNS and port 853 is DNS-over-TLS. Both remain reserved for
/// the configured resolver path, so that a proxy rule can never be used to
/// reach an arbitrary resolver.
pub const RESERVED_DNS_PORTS: [u16; 2] = [53, 853];

/// Reason a hostname was rejected.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum HostnameError {
    /// The name, or the name after removing one trailing dot, was empty.
    #[error("hostname is empty")]
    Empty,
    /// The name contained non-ASCII bytes. Internationalized names must be
    /// supplied in A-label (punycode) form.
    #[error("hostname is not ASCII")]
    NotAscii,
    /// The canonical name was longer than 253 bytes.
    #[error("hostname is longer than {MAX_HOSTNAME_BYTES} bytes")]
    TooLong,
    /// A label was empty or longer than 63 bytes.
    #[error("hostname label is empty or longer than {MAX_LABEL_BYTES} bytes")]
    LabelLength,
    /// A label contained something other than an ASCII letter, digit or
    /// hyphen.
    #[error("hostname label contains an unsupported character")]
    LabelCharacter,
    /// A label started or ended with a hyphen.
    #[error("hostname label starts or ends with a hyphen")]
    LabelHyphen,
    /// The name was an IP literal or otherwise numeric. Addresses belong to
    /// the direct IP/CIDR policy, never to the hostname policy.
    #[error("hostname is an IP literal or numeric form")]
    NumericForm,
    /// The name was `localhost` or one of its descendants.
    #[error("`localhost` and its descendants are not proxy hostnames")]
    Localhost,
}

/// A canonical, exact DNS hostname that a proxy rule or request may name.
///
/// Canonicalization lowercases the name and removes at most one trailing dot.
/// The same constructor is used for policy rules and for request authorities,
/// so a request can only ever match a rule byte-for-byte after
/// canonicalization.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Parses and canonicalizes `input`.
    pub fn parse(input: &str) -> Result<Self, HostnameError> {
        if input.is_empty() {
            return Err(HostnameError::Empty);
        }
        if !input.is_ascii() {
            return Err(HostnameError::NotAscii);
        }

        // Accept and remove exactly one trailing dot; a second trailing dot
        // leaves an empty label and is rejected below.
        let trimmed = input.strip_suffix('.').unwrap_or(input);
        if trimmed.is_empty() {
            return Err(HostnameError::Empty);
        }
        if trimmed.len() > MAX_HOSTNAME_BYTES {
            return Err(HostnameError::TooLong);
        }

        let canonical = trimmed.to_ascii_lowercase();
        let mut last_label = "";
        for label in canonical.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL_BYTES {
                return Err(HostnameError::LabelLength);
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(HostnameError::LabelCharacter);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(HostnameError::LabelHyphen);
            }
            last_label = label;
        }

        // An all-digit rightmost label covers dotted-quad IPv4 literals and
        // every other numeric-looking form. IPv6 literals and their brackets
        // are already rejected by the label character check.
        if last_label.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(HostnameError::NumericForm);
        }

        if canonical == "localhost" || canonical.ends_with(".localhost") {
            return Err(HostnameError::Localhost);
        }

        Ok(Self(canonical))
    }

    /// Returns the canonical name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Hostname {
    type Err = HostnameError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// Reason a port range was rejected.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PortRangeError {
    /// The range was empty or contained a non-digit.
    #[error("port is not a decimal number in 1..=65535")]
    NotANumber,
    /// Port zero is never a destination.
    #[error("port 0 is not a valid destination port")]
    ZeroPort,
    /// The range end was smaller than its start.
    #[error("port range end is smaller than its start")]
    Inverted,
    /// The range contained port 53 or port 853.
    #[error("port range contains reserved DNS port 53 or 853")]
    ReservedDnsPort,
}

/// An inclusive range of destination ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Creates an inclusive range, rejecting port zero, inverted ranges, and
    /// any range containing a reserved DNS port.
    pub fn new(start: u16, end: u16) -> Result<Self, PortRangeError> {
        if start == 0 || end == 0 {
            return Err(PortRangeError::ZeroPort);
        }
        if start > end {
            return Err(PortRangeError::Inverted);
        }
        if RESERVED_DNS_PORTS
            .iter()
            .any(|reserved| (start..=end).contains(reserved))
        {
            return Err(PortRangeError::ReservedDnsPort);
        }
        Ok(Self { start, end })
    }

    /// Returns the first port of the range.
    pub fn start(self) -> u16 {
        self.start
    }

    /// Returns the last port of the range.
    pub fn end(self) -> u16 {
        self.end
    }

    /// Returns whether `port` is inside the range.
    pub fn contains(self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(formatter, "{}", self.start)
        } else {
            write!(formatter, "{}-{}", self.start, self.end)
        }
    }
}

impl FromStr for PortRange {
    type Err = PortRangeError;

    /// Parses `PORT` or `PORT-PORT`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Some((start, end)) = input.split_once('-') {
            Self::new(parse_port(start)?, parse_port(end)?)
        } else {
            let port = parse_port(input)?;
            Self::new(port, port)
        }
    }
}

/// Parses a strict decimal port number.
///
/// Unlike [`u16::from_str`] this rejects a leading sign and any surrounding
/// whitespace, so that no two textual forms map to one port.
pub(crate) fn parse_port(input: &str) -> Result<u16, PortRangeError> {
    if input.is_empty() || input.len() > 5 || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PortRangeError::NotANumber);
    }
    let port: u16 = input.parse().map_err(|_| PortRangeError::NotANumber)?;
    if port == 0 {
        return Err(PortRangeError::ZeroPort);
    }
    Ok(port)
}

/// Reason a `HOST:PORT[-PORT]` rule was rejected.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum HostRuleError {
    /// The rule did not have the `HOST:PORT[-PORT]` shape.
    #[error("rule is not of the form HOST:PORT[-PORT]")]
    Shape,
    /// The hostname part was invalid.
    #[error("invalid hostname: {0}")]
    Hostname(#[from] HostnameError),
    /// The port part was invalid.
    #[error("invalid port range: {0}")]
    PortRange(#[from] PortRangeError),
}

/// One `HOST:PORT[-PORT]` policy rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRule {
    /// Canonical hostname the rule authorizes.
    pub host: Hostname,
    /// Destination ports the rule authorizes.
    pub ports: PortRange,
}

impl FromStr for HostRule {
    type Err = HostRuleError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (host, ports) = input.split_once(':').ok_or(HostRuleError::Shape)?;
        if host.is_empty() || ports.is_empty() {
            return Err(HostRuleError::Shape);
        }
        Ok(Self {
            host: Hostname::parse(host)?,
            ports: ports.parse()?,
        })
    }
}

/// Reason a set of rules could not become a policy.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// More than [`MAX_HOST_RULES`] distinct canonical hostnames were given.
    #[error("policy contains more than {MAX_HOST_RULES} canonical hostnames")]
    TooManyHosts,
    /// Merging overlapping ranges produced a range spanning a reserved DNS
    /// port. This cannot happen for validated inputs and is checked anyway so
    /// that the reserved-port invariant holds for the stored ranges.
    #[error("merged port range is invalid: {0}")]
    MergedRange(#[from] PortRangeError),
}

/// The immutable proxy policy: exact hostnames mapped to allowed destination
/// port ranges.
///
/// The policy default is deny: a hostname without a rule, or a port outside
/// every range of a rule, is never authorized.
#[derive(Clone, Debug, Default)]
pub struct HostPolicy {
    entries: BTreeMap<Hostname, Vec<PortRange>>,
}

impl HostPolicy {
    /// Builds a policy from rules, merging overlapping and adjacent ranges of
    /// the same canonical hostname.
    ///
    /// Merging is deterministic: ranges are sorted and folded in ascending
    /// order, so the same rule set always yields the same policy regardless of
    /// argument order.
    pub fn from_rules(rules: impl IntoIterator<Item = HostRule>) -> Result<Self, PolicyError> {
        let mut entries: BTreeMap<Hostname, Vec<PortRange>> = BTreeMap::new();
        for rule in rules {
            entries.entry(rule.host).or_default().push(rule.ports);
        }
        if entries.len() > MAX_HOST_RULES {
            return Err(PolicyError::TooManyHosts);
        }
        for ranges in entries.values_mut() {
            *ranges = merge_ranges(ranges)?;
        }
        Ok(Self { entries })
    }

    /// Returns whether the exact canonical `host` is authorized for `port`.
    pub fn allows(&self, host: &Hostname, port: u16) -> bool {
        self.entries
            .get(host)
            .is_some_and(|ranges| ranges.iter().any(|range| range.contains(port)))
    }

    /// Returns the canonical hostnames of the policy, in a stable order.
    pub fn hostnames(&self) -> impl ExactSizeIterator<Item = &Hostname> {
        self.entries.keys()
    }

    /// Returns the merged port ranges authorized for `host`.
    pub fn port_ranges(&self, host: &Hostname) -> &[PortRange] {
        self.entries.get(host).map_or(&[], Vec::as_slice)
    }

    /// Returns the number of canonical hostnames in the policy.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the policy authorizes nothing at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Sorts and folds overlapping or adjacent ranges.
fn merge_ranges(ranges: &[PortRange]) -> Result<Vec<PortRange>, PortRangeError> {
    let mut sorted = ranges.to_vec();
    sorted.sort_unstable();

    let mut merged: Vec<PortRange> = Vec::with_capacity(sorted.len());
    for range in sorted {
        match merged.last_mut() {
            // `saturating_add` keeps adjacency well-defined at 65535.
            Some(previous) if range.start() <= previous.end().saturating_add(1) => {
                let end = previous.end().max(range.end());
                // Re-validate: a merged range must still exclude reserved DNS
                // ports.
                *previous = PortRange::new(previous.start(), end)?;
            }
            _ => merged.push(range),
        }
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(Hostname::parse(""), Err(HostnameError::Empty));
        assert_eq!(Hostname::parse("."), Err(HostnameError::Empty));
        assert_eq!(Hostname::parse("a..b"), Err(HostnameError::LabelLength));
        assert_eq!(Hostname::parse("a.b.."), Err(HostnameError::LabelLength));
        assert_eq!(Hostname::parse("exämple.com"), Err(HostnameError::NotAscii));
        assert_eq!(
            Hostname::parse("-a.example"),
            Err(HostnameError::LabelHyphen)
        );
        assert_eq!(
            Hostname::parse("a-.example"),
            Err(HostnameError::LabelHyphen)
        );
        assert_eq!(
            Hostname::parse("a_b.example"),
            Err(HostnameError::LabelCharacter)
        );
        assert_eq!(
            Hostname::parse("a b.example"),
            Err(HostnameError::LabelCharacter)
        );
        assert_eq!(
            Hostname::parse("host:80"),
            Err(HostnameError::LabelCharacter)
        );
        assert_eq!(
            Hostname::parse("192.0.2.1"),
            Err(HostnameError::NumericForm)
        );
        assert_eq!(Hostname::parse("12345"), Err(HostnameError::NumericForm));
        assert_eq!(Hostname::parse("[::1]"), Err(HostnameError::LabelCharacter));
        assert_eq!(Hostname::parse("localhost"), Err(HostnameError::Localhost));
        assert_eq!(Hostname::parse("LOCALHOST."), Err(HostnameError::Localhost));
        assert_eq!(
            Hostname::parse("a.localhost"),
            Err(HostnameError::Localhost)
        );
    }

    #[test]
    fn hostname_enforces_length_bounds() {
        let long_label = "a".repeat(64);
        assert_eq!(
            Hostname::parse(&format!("{long_label}.example")),
            Err(HostnameError::LabelLength)
        );

        let long_name = format!("{}.example", "a".repeat(250));
        assert_eq!(Hostname::parse(&long_name), Err(HostnameError::TooLong));

        let at_limit = format!(
            "{label}.{label}.{label}.{tail}",
            label = "a".repeat(63),
            tail = "a".repeat(61)
        );
        assert_eq!(at_limit.len(), 253);
        assert!(Hostname::parse(&at_limit).is_ok());
    }

    #[test]
    fn port_ranges_reject_reserved_dns_ports() {
        assert_eq!(
            "53".parse::<PortRange>(),
            Err(PortRangeError::ReservedDnsPort)
        );
        assert_eq!(
            "853".parse::<PortRange>(),
            Err(PortRangeError::ReservedDnsPort)
        );
        assert_eq!(
            "50-60".parse::<PortRange>(),
            Err(PortRangeError::ReservedDnsPort)
        );
        assert_eq!(
            "1-65535".parse::<PortRange>(),
            Err(PortRangeError::ReservedDnsPort)
        );
        assert!("54-852".parse::<PortRange>().is_ok());
    }

    #[test]
    fn port_ranges_reject_malformed_input() {
        assert_eq!("".parse::<PortRange>(), Err(PortRangeError::NotANumber));
        assert_eq!("+80".parse::<PortRange>(), Err(PortRangeError::NotANumber));
        assert_eq!("8o".parse::<PortRange>(), Err(PortRangeError::NotANumber));
        assert_eq!(
            "65536".parse::<PortRange>(),
            Err(PortRangeError::NotANumber)
        );
        assert_eq!("0".parse::<PortRange>(), Err(PortRangeError::ZeroPort));
        assert_eq!("90-80".parse::<PortRange>(), Err(PortRangeError::Inverted));
    }

    #[test]
    fn host_rule_parsing() {
        let rule: HostRule = "Example.com:443".parse().unwrap();
        assert_eq!(rule.host.as_str(), "example.com");
        assert!(rule.ports.contains(443));

        assert_eq!("example.com".parse::<HostRule>(), Err(HostRuleError::Shape));
        assert_eq!(":443".parse::<HostRule>(), Err(HostRuleError::Shape));
        assert_eq!(
            "example.com:".parse::<HostRule>(),
            Err(HostRuleError::Shape)
        );
        assert!(matches!(
            "example.com:80:443".parse::<HostRule>(),
            Err(HostRuleError::PortRange(_))
        ));
        assert!(matches!(
            "192.0.2.1:443".parse::<HostRule>(),
            Err(HostRuleError::Hostname(_))
        ));
    }

    #[test]
    fn policy_merges_and_denies_by_default() {
        let rules = ["a.example:80", "a.example:81-90", "A.EXAMPLE:8000-8100"]
            .into_iter()
            .map(|rule| rule.parse::<HostRule>().unwrap());
        let policy = HostPolicy::from_rules(rules).unwrap();

        let host = Hostname::parse("a.example").unwrap();
        assert_eq!(policy.len(), 1);
        assert_eq!(policy.port_ranges(&host).len(), 2);
        assert!(policy.allows(&host, 80));
        assert!(policy.allows(&host, 90));
        assert!(policy.allows(&host, 8100));
        assert!(!policy.allows(&host, 91));
        assert!(!policy.allows(&host, 443));

        let other = Hostname::parse("b.example").unwrap();
        assert!(!policy.allows(&other, 80));
        assert!(policy.port_ranges(&other).is_empty());
    }

    #[test]
    fn policy_merge_never_spans_a_reserved_port() {
        let rules = ["a.example:40-52", "a.example:54-60"]
            .into_iter()
            .map(|rule| rule.parse::<HostRule>().unwrap());
        let policy = HostPolicy::from_rules(rules).unwrap();
        let host = Hostname::parse("a.example").unwrap();

        assert_eq!(policy.port_ranges(&host).len(), 2);
        assert!(!policy.allows(&host, 53));
    }

    #[test]
    fn policy_rejects_too_many_hosts() {
        let rules = (0..=MAX_HOST_RULES)
            .map(|index| format!("h{index}.example:443").parse::<HostRule>().unwrap());
        assert!(matches!(
            HostPolicy::from_rules(rules),
            Err(PolicyError::TooManyHosts)
        ));
    }
}
