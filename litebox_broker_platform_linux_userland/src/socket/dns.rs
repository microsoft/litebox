// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

use litebox_broker_core::socket::{
    BROKER_DNS_IPV4_ADDRESS, PlatformSocketDestination, host_socket_destination,
    is_internal_socket_address, normalize_socket_destination,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::socket::{SocketError, SocketOutcome};

pub(super) const MAX_DNS_A_RECORDS: usize = 64;
const MAX_DNS_QUERY_SIZE: usize = 1232;
const DNS_HEADER_SIZE: usize = 12;
const DNS_TTL_SECONDS: u32 = 300;
const SYNTHETIC_NETWORK: [u8; 3] = [198, 51, 100];

/// One exact static IPv4 DNS record exposed by the broker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsARecord {
    name: String,
    address: Ipv4Addr,
}

impl DnsARecord {
    /// Returns the canonical record name without a trailing dot.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the pinned native IPv4 address.
    #[must_use]
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }
}

/// Error returned when parsing a static DNS A record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsARecordParseError(&'static str);

impl fmt::Display for DnsARecordParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for DnsARecordParseError {}

impl FromStr for DnsARecord {
    type Err = DnsARecordParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, address) = value
            .split_once('=')
            .ok_or(DnsARecordParseError("DNS record must use NAME=IP syntax"))?;
        let name = canonical_dns_name(name)?;
        let address = address
            .parse()
            .map_err(|_| DnsARecordParseError("DNS record address must be IPv4"))?;
        Ok(Self { name, address })
    }
}

struct DnsMapping {
    name: String,
    native_address: Ipv4Addr,
    synthetic_address: Ipv4Addr,
}

pub(super) struct DnsMappings {
    records: Vec<DnsMapping>,
}

impl DnsMappings {
    pub(super) fn new(records: &[DnsARecord]) -> IoResult<Self> {
        if records.len() > MAX_DNS_A_RECORDS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "too many static DNS records",
            ));
        }

        let mut mappings = Vec::new();
        mappings
            .try_reserve_exact(records.len())
            .map_err(|_| Error::new(ErrorKind::OutOfMemory, "DNS mapping allocation failed"))?;
        for (index, record) in records.iter().enumerate() {
            if mappings
                .iter()
                .any(|mapping: &DnsMapping| mapping.name == record.name)
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "duplicate static DNS record name",
                ));
            }
            if mappings
                .iter()
                .any(|mapping| mapping.native_address == record.address)
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "duplicate static DNS destination",
                ));
            }
            if !is_valid_native_address(record.address) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "invalid static DNS destination",
                ));
            }
            let host = u8::try_from(index + 1).expect("DNS record limit fits in one octet");
            let mut name = String::new();
            name.try_reserve_exact(record.name.len())
                .map_err(|_| Error::new(ErrorKind::OutOfMemory, "DNS name allocation failed"))?;
            name.push_str(&record.name);
            mappings.push(DnsMapping {
                name,
                native_address: record.address,
                synthetic_address: Ipv4Addr::new(
                    SYNTHETIC_NETWORK[0],
                    SYNTHETIC_NETWORK[1],
                    SYNTHETIC_NETWORK[2],
                    host,
                ),
            });
        }
        Ok(Self { records: mappings })
    }

    pub(super) fn route_destination(
        &self,
        destination: SocketAddrV4,
    ) -> SocketOutcome<PlatformSocketDestination> {
        if !self.is_enabled() {
            return SocketOutcome::Completed(PlatformSocketDestination::standard(destination));
        }
        if *destination.ip() == BROKER_DNS_IPV4_ADDRESS {
            return if destination.port() == 53 {
                SocketOutcome::Completed(PlatformSocketDestination::BrokerDns(destination))
            } else {
                SocketOutcome::Failed(SocketError::ConnectionRefused)
            };
        }

        if is_synthetic_address(*destination.ip()) {
            let Some(mapping) = self
                .records
                .iter()
                .find(|mapping| mapping.synthetic_address == *destination.ip())
            else {
                return SocketOutcome::Failed(SocketError::ConnectionRefused);
            };
            let policy_address = SocketAddrV4::new(mapping.native_address, destination.port());
            return SocketOutcome::Completed(PlatformSocketDestination::External {
                guest_address: destination,
                policy_address,
                host_address: host_socket_destination(policy_address),
            });
        }
        SocketOutcome::Completed(PlatformSocketDestination::standard(destination))
    }

    pub(super) fn is_enabled(&self) -> bool {
        !self.records.is_empty()
    }

    pub(super) fn response(&self, query: &[u8]) -> BrokerResult<Option<Vec<u8>>> {
        if query.len() < DNS_HEADER_SIZE || query.len() > MAX_DNS_QUERY_SIZE {
            return Ok(None);
        }
        let request_flags = read_u16(query, 2);
        if request_flags & 0xf800 != 0
            || read_u16(query, 4) != 1
            || read_u16(query, 6) != 0
            || read_u16(query, 8) != 0
        {
            return Ok(None);
        }
        let Some(question) = parse_question_name(query)? else {
            return Ok(None);
        };
        let question_end = question
            .name_end
            .checked_add(4)
            .ok_or(BrokerError::Internal)?;
        if question_end > query.len() {
            return Ok(None);
        }
        let question_type = read_u16(query, question.name_end);
        let question_class = read_u16(query, question.name_end + 2);
        let (response_code, answer) = if question_class == 1 {
            match question
                .lookup_name
                .as_deref()
                .and_then(|name| self.records.iter().find(|mapping| mapping.name == name))
            {
                Some(mapping) => (0, (question_type == 1).then_some(mapping.synthetic_address)),
                None => (3, None),
            }
        } else {
            (4, None)
        };

        let answer_size = if answer.is_some() { 16 } else { 0 };
        let mut response = Vec::new();
        response
            .try_reserve_exact(question_end + answer_size)
            .map_err(|_| BrokerError::OutOfMemory)?;
        response.extend_from_slice(&query[..2]);
        append_u16(
            &mut response,
            0x8400 | (request_flags & 0x0100) | response_code,
        );
        append_u16(&mut response, 1);
        append_u16(&mut response, u16::from(answer.is_some()));
        append_u16(&mut response, 0);
        append_u16(&mut response, 0);
        response.extend_from_slice(&query[DNS_HEADER_SIZE..question_end]);
        if let Some(address) = answer {
            append_u16(&mut response, 0xc00c);
            append_u16(&mut response, 1);
            append_u16(&mut response, 1);
            response.extend_from_slice(&DNS_TTL_SECONDS.to_be_bytes());
            append_u16(&mut response, 4);
            response.extend_from_slice(&address.octets());
        }
        Ok(Some(response))
    }
}

fn canonical_dns_name(name: &str) -> Result<String, DnsARecordParseError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err(DnsARecordParseError("invalid DNS record name"));
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(DnsARecordParseError("invalid DNS record name"));
        }
    }
    let canonical = name.to_ascii_lowercase();
    if canonical == "localhost"
        || canonical == "litebox"
        || canonical.ends_with(".localhost")
        || is_numeric_looking_name(&canonical)
    {
        return Err(DnsARecordParseError("DNS record name bypasses broker DNS"));
    }
    Ok(canonical)
}

fn is_numeric_looking_name(name: &str) -> bool {
    name.split('.').all(|component| {
        !component.is_empty()
            && (component.bytes().all(|byte| byte.is_ascii_digit())
                || component.strip_prefix("0x").is_some_and(|hex| {
                    !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                }))
    })
}

struct ParsedQuestion {
    lookup_name: Option<String>,
    name_end: usize,
}

fn parse_question_name(query: &[u8]) -> BrokerResult<Option<ParsedQuestion>> {
    let mut offset = DNS_HEADER_SIZE;
    let mut expanded_length = 0usize;
    let mut label_count = 0usize;
    let mut lookup_name_valid = true;
    loop {
        let Some(length) = query.get(offset).copied().map(usize::from) else {
            return Ok(None);
        };
        let Some(next_offset) = offset.checked_add(1) else {
            return Ok(None);
        };
        offset = next_offset;
        if length == 0 {
            break;
        }
        if length > 63 {
            return Ok(None);
        }
        let Some(end) = offset.checked_add(length) else {
            return Ok(None);
        };
        let Some(label) = query.get(offset..end) else {
            return Ok(None);
        };
        lookup_name_valid &= label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            && label.first() != Some(&b'-')
            && label.last() != Some(&b'-');
        let Some(length) = expanded_length.checked_add(length + usize::from(label_count != 0))
        else {
            return Ok(None);
        };
        expanded_length = length;
        if expanded_length > 253 {
            return Ok(None);
        }
        label_count += 1;
        offset = end;
    }
    if label_count == 0 {
        return Ok(None);
    }
    let lookup_name = if lookup_name_valid {
        let mut name = String::new();
        name.try_reserve_exact(expanded_length)
            .map_err(|_| BrokerError::OutOfMemory)?;
        let mut label_offset = DNS_HEADER_SIZE;
        for label_index in 0..label_count {
            let length = usize::from(query[label_offset]);
            label_offset += 1;
            if label_index != 0 {
                name.push('.');
            }
            for byte in &query[label_offset..label_offset + length] {
                name.push(char::from(byte.to_ascii_lowercase()));
            }
            label_offset += length;
        }
        Some(name)
    } else {
        None
    };
    Ok(Some(ParsedQuestion {
        lookup_name,
        name_end: offset,
    }))
}

fn is_valid_native_address(address: Ipv4Addr) -> bool {
    let destination = SocketAddrV4::new(address, 1);
    normalize_socket_destination(destination) == Ok(destination)
        && !is_internal_socket_address(destination)
        && address != BROKER_DNS_IPV4_ADDRESS
        && !is_synthetic_address(address)
}

fn is_synthetic_address(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[..3] == SYNTHETIC_NETWORK
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn append_u16(data: &mut Vec<u8>, value: u16) {
    data.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(value: &str) -> DnsARecord {
        value.parse().unwrap()
    }

    fn query(name: &str, question_type: u16) -> Vec<u8> {
        let labels = name.split('.').map(str::as_bytes).collect::<Vec<_>>();
        raw_query(&labels, question_type, 1)
    }

    fn raw_query(labels: &[&[u8]], question_type: u16, question_class: u16) -> Vec<u8> {
        let mut query = Vec::from([
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        for label in labels {
            query.push(u8::try_from(label.len()).unwrap());
            query.extend_from_slice(label);
        }
        query.push(0);
        append_u16(&mut query, question_type);
        append_u16(&mut query, question_class);
        query
    }

    #[test]
    fn static_record_parser_canonicalizes_and_validates_names() {
        let record = record("Service.Example.=203.0.113.7");
        assert_eq!(record.name(), "service.example");
        assert_eq!(record.address(), Ipv4Addr::new(203, 0, 113, 7));

        for invalid in [
            "missing-address",
            "=203.0.113.7",
            "-service.example=203.0.113.7",
            "service..example=203.0.113.7",
            "service.example=not-an-address",
            "localhost=203.0.113.7",
            "LOCALHOST.=203.0.113.7",
            "child.localhost=203.0.113.7",
            "litebox=203.0.113.7",
            "127.1=203.0.113.7",
            "0177.1=203.0.113.7",
            "0x7f.1=203.0.113.7",
            "2130706433=203.0.113.7",
        ] {
            assert!(invalid.parse::<DnsARecord>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn empty_mappings_preserve_standard_provider_routing() {
        let mappings = DnsMappings::new(&[]).unwrap();
        for destination in [
            SocketAddrV4::new(BROKER_DNS_IPV4_ADDRESS, 53),
            SocketAddrV4::new(BROKER_DNS_IPV4_ADDRESS, 80),
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 443),
        ] {
            assert_eq!(
                mappings.route_destination(destination),
                SocketOutcome::Completed(PlatformSocketDestination::standard(destination))
            );
        }
        assert!(!mappings.is_enabled());
    }

    #[test]
    fn mappings_pin_names_and_fail_closed_for_unassigned_synthetic_addresses() {
        let mappings = DnsMappings::new(&[record("service.example=203.0.113.7")]).unwrap();
        let synthetic = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 443);
        assert_eq!(
            mappings.route_destination(synthetic),
            SocketOutcome::Completed(PlatformSocketDestination::External {
                guest_address: synthetic,
                policy_address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443),
                host_address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443),
            })
        );
        assert_eq!(
            mappings.route_destination(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 64), 443,)),
            SocketOutcome::Failed(SocketError::ConnectionRefused)
        );
        assert_eq!(
            mappings.route_destination(SocketAddrV4::new(BROKER_DNS_IPV4_ADDRESS, 53)),
            SocketOutcome::Completed(PlatformSocketDestination::BrokerDns(SocketAddrV4::new(
                BROKER_DNS_IPV4_ADDRESS,
                53
            )))
        );
    }

    #[test]
    fn mappings_reject_duplicates_reserved_destinations_and_excess_records() {
        assert!(
            DnsMappings::new(&[
                record("service.example=203.0.113.7"),
                record("SERVICE.EXAMPLE=203.0.113.8"),
            ])
            .is_err()
        );
        assert!(
            DnsMappings::new(&[
                record("first.example=203.0.113.7"),
                record("second.example=203.0.113.7"),
            ])
            .is_err()
        );
        assert!(DnsMappings::new(&[record("service.example=127.0.0.1")]).is_err());
        assert!(DnsMappings::new(&[record("service.example=198.51.100.8")]).is_err());

        let records = (0..=MAX_DNS_A_RECORDS)
            .map(|index| record(&format!("service-{index}.example=203.0.113.{}", index + 1)))
            .collect::<Vec<_>>();
        assert!(DnsMappings::new(&records).is_err());
    }

    #[test]
    fn mappings_assign_the_full_synthetic_range_through_dot_64() {
        let records = (0..MAX_DNS_A_RECORDS)
            .map(|index| record(&format!("service-{index}.example=203.0.113.{}", index + 1)))
            .collect::<Vec<_>>();
        let mappings = DnsMappings::new(&records).unwrap();
        let guest = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 64), 443);

        assert_eq!(
            mappings.route_destination(guest),
            SocketOutcome::Completed(PlatformSocketDestination::External {
                guest_address: guest,
                policy_address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 64), 443),
                host_address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 64), 443),
            })
        );
        let response = mappings
            .response(&query("service-63.example", 1))
            .unwrap()
            .unwrap();
        assert_eq!(
            &response[response.len() - 4..],
            &Ipv4Addr::new(198, 51, 100, 64).octets()
        );
    }

    #[test]
    fn dns_responder_returns_synthetic_a_and_empty_aaaa_answers() {
        let mappings = DnsMappings::new(&[record("service.example=203.0.113.7")]).unwrap();
        let mixed_case_query = query("SeRvIcE.ExAmPlE", 1);
        let a_response = mappings.response(&mixed_case_query).unwrap().unwrap();
        assert_eq!(read_u16(&a_response, 0), 0x1234);
        assert_eq!(read_u16(&a_response, 2), 0x8500);
        assert_eq!(read_u16(&a_response, 6), 1);
        assert_eq!(
            &a_response[a_response.len() - 4..],
            &Ipv4Addr::new(198, 51, 100, 1).octets()
        );
        assert_eq!(
            &a_response[DNS_HEADER_SIZE..mixed_case_query.len()],
            &mixed_case_query[DNS_HEADER_SIZE..]
        );

        let aaaa_response = mappings
            .response(&query("service.example", 28))
            .unwrap()
            .unwrap();
        assert_eq!(read_u16(&aaaa_response, 2) & 0x000f, 0);
        assert_eq!(read_u16(&aaaa_response, 6), 0);

        let unknown_response = mappings
            .response(&query("unknown.example", 1))
            .unwrap()
            .unwrap();
        assert_eq!(read_u16(&unknown_response, 2) & 0x000f, 3);
        assert_eq!(read_u16(&unknown_response, 6), 0);

        let unsupported_class = mappings
            .response(&raw_query(&[b"unknown", b"example"], 1, 3))
            .unwrap()
            .unwrap();
        assert_eq!(read_u16(&unsupported_class, 2) & 0x000f, 4);
    }

    #[test]
    fn dns_responder_drops_malformed_or_oversized_queries() {
        let mappings = DnsMappings::new(&[]).unwrap();
        let mut compressed = query("service.example", 1);
        compressed[DNS_HEADER_SIZE] = 0xc0;
        assert_eq!(mappings.response(&compressed).unwrap(), None);
        assert_eq!(
            mappings.response(&vec![0; MAX_DNS_QUERY_SIZE + 1]).unwrap(),
            None
        );
        let mut root = Vec::from([
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        append_u16(&mut root, 1);
        append_u16(&mut root, 1);
        assert_eq!(mappings.response(&root).unwrap(), None);
    }

    #[test]
    fn dns_responder_answers_well_formed_unmatchable_names_with_nxdomain() {
        let mappings = DnsMappings::new(&[record("service.example=203.0.113.7")]).unwrap();
        for labels in [
            &[&b"_service"[..], &b"example"[..]][..],
            &[&b"\xff"[..]][..],
            &[&b"service.example"[..]][..],
        ] {
            let response = mappings
                .response(&raw_query(labels, 1, 1))
                .unwrap()
                .unwrap();
            assert_eq!(read_u16(&response, 2) & 0x000f, 3);
            assert_eq!(read_u16(&response, 6), 0);
        }
    }
}
