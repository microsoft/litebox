// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! DNS query tracking for hostname-based network policy enforcement.
//!
//! Intercepts DNS queries (UDP port 53) from the guest, forwards them to the
//! host resolver, and records `IP → hostname` mappings from the responses.
//! This allows the network policy to match connections by hostname rather than
//! only by raw IP address.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use simple_dns::{Packet, PacketFlag, QTYPE, ResourceRecord, rdata::RData};
use tracing::{debug, trace, warn};

/// Maximum number of IP → hostname mappings to retain.
const MAX_ENTRIES: usize = 4096;

/// Default TTL for entries when the DNS response has no TTL or TTL is 0.
const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// A single cached DNS resolution: hostname + expiry.
#[derive(Debug, Clone)]
struct DnsEntry {
    hostname: String,
    expires: Instant,
}

/// Tracks DNS query/response pairs to build an IP → hostname reverse map.
///
/// The broker intercepts DNS packets (UDP port 53) passing through the network
/// proxy. When a DNS response contains A records, the resolved IPs are stored
/// with the queried hostname. Later, when the guest opens a TCP/UDP connection,
/// the policy engine can look up the destination IP to find the original
/// hostname.
pub struct DnsTracker {
    /// IP → hostname + expiry.
    ip_to_hostname: HashMap<Ipv4Addr, DnsEntry>,
    /// Pending queries: transaction ID → queried hostname.
    pending_queries: HashMap<u16, String>,
}

impl DnsTracker {
    /// Create a new empty DNS tracker.
    pub fn new() -> Self {
        Self {
            ip_to_hostname: HashMap::new(),
            pending_queries: HashMap::new(),
        }
    }

    /// Look up the hostname that resolved to `ip`, if any.
    ///
    /// Returns `None` if no DNS query for this IP was observed, or if the
    /// cached entry has expired.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&str> {
        let entry = self.ip_to_hostname.get(&ip)?;
        if Instant::now() > entry.expires {
            return None;
        }
        Some(&entry.hostname)
    }

    /// Process an outbound DNS query packet from the guest.
    ///
    /// Extracts the queried hostname and stores it keyed by the DNS
    /// transaction ID so we can correlate it with the response.
    ///
    /// Returns `true` if the packet was recognized as a DNS query.
    pub fn process_query(&mut self, payload: &[u8]) -> bool {
        let packet = match Packet::parse(payload) {
            Ok(p) => p,
            Err(e) => {
                trace!("DNS parse error (query): {e}");
                return false;
            }
        };

        // Must be a query (QR=0).
        if packet.has_flags(PacketFlag::RESPONSE) {
            return false;
        }

        let id = packet.id();
        for question in packet.questions.iter() {
            let qname = question.qname.to_string();
            // Only track A/AAAA queries.
            if question.qtype == QTYPE::TYPE(simple_dns::TYPE::A)
                || question.qtype == QTYPE::TYPE(simple_dns::TYPE::AAAA)
            {
                // Strip trailing dot if present.
                let hostname = qname.strip_suffix('.').unwrap_or(&qname).to_lowercase();
                debug!("DNS query: id={id} hostname={hostname}");
                self.pending_queries.insert(id, hostname);
                return true;
            }
        }
        false
    }

    /// Process an inbound DNS response packet from the host resolver.
    ///
    /// Extracts A record answers and maps the resolved IPs to the hostname
    /// from the original query.
    ///
    /// Returns `Some((hostname, ips))` if the packet was recognized as a DNS
    /// response with A records, `None` otherwise.
    pub fn process_response(&mut self, payload: &[u8]) -> Option<(String, Vec<Ipv4Addr>)> {
        let packet = match Packet::parse(payload) {
            Ok(p) => p,
            Err(e) => {
                trace!("DNS parse error (response): {e}");
                return None;
            }
        };

        // Must be a response (QR=1).
        if !packet.has_flags(PacketFlag::RESPONSE) {
            return None;
        }

        let id = packet.id();
        let hostname = match self.pending_queries.remove(&id) {
            Some(h) => h,
            None => {
                // No matching query — may be an unsolicited response or we
                // missed the query. Try extracting hostname from the question
                // section as a fallback.
                packet
                    .questions
                    .first()
                    .map(|q| {
                        let name = q.qname.to_string();
                        name.strip_suffix('.').unwrap_or(&name).to_lowercase()
                    })
                    .unwrap_or_default()
            }
        };

        if hostname.is_empty() {
            return None;
        }

        let now = Instant::now();
        let mut resolved_ips = Vec::new();

        for answer in packet.answers.iter() {
            let ResourceRecord { rdata, ttl, .. } = answer;
            if let RData::A(a) = rdata {
                let ip = Ipv4Addr::from(a.address.to_be_bytes());
                let ttl_duration = if *ttl == 0 {
                    DEFAULT_TTL
                } else {
                    Duration::from_secs(u64::from(*ttl))
                };

                debug!("DNS response: {hostname} → {ip} (TTL {ttl}s)");
                self.insert(ip, hostname.clone(), now + ttl_duration);
                resolved_ips.push(ip);
            }
        }

        if resolved_ips.is_empty() {
            None
        } else {
            Some((hostname, resolved_ips))
        }
    }

    /// Insert a hostname mapping, evicting oldest entries if at capacity.
    fn insert(&mut self, ip: Ipv4Addr, hostname: String, expires: Instant) {
        // Evict expired entries first.
        let now = Instant::now();
        self.ip_to_hostname.retain(|_, e| e.expires > now);

        // If still at capacity, remove the entry expiring soonest.
        if self.ip_to_hostname.len() >= MAX_ENTRIES
            && let Some((&oldest_ip, _)) = self.ip_to_hostname.iter().min_by_key(|(_, e)| e.expires)
        {
            self.ip_to_hostname.remove(&oldest_ip);
        }

        // GC stale pending queries (older than 30s).
        if self.pending_queries.len() > 256 {
            // Can't easily track age without extra state; just clear all.
            warn!("pending DNS query table overflow, clearing");
            self.pending_queries.clear();
        }

        self.ip_to_hostname
            .insert(ip, DnsEntry { hostname, expires });
    }
}

impl Default for DnsTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for an A record.
    fn build_dns_query(id: u16, hostname: &str) -> Vec<u8> {
        use simple_dns::{Name, Question};

        let mut packet = Packet::new_query(id);
        let name = Name::new_unchecked(hostname);
        packet.questions.push(Question::new(
            name,
            QTYPE::TYPE(simple_dns::TYPE::A),
            simple_dns::QCLASS::CLASS(simple_dns::CLASS::IN),
            false,
        ));
        packet.build_bytes_vec().unwrap()
    }

    /// Build a minimal DNS response packet with A records.
    fn build_dns_response(id: u16, hostname: &str, ips: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
        use simple_dns::{Name, Question};

        let mut packet = Packet::new_reply(id);
        let name = Name::new_unchecked(hostname);
        packet.questions.push(Question::new(
            name.clone(),
            QTYPE::TYPE(simple_dns::TYPE::A),
            simple_dns::QCLASS::CLASS(simple_dns::CLASS::IN),
            false,
        ));
        for ip in ips {
            let a_record = simple_dns::rdata::A {
                address: (*ip).into(),
            };
            packet.answers.push(ResourceRecord::new(
                name.clone(),
                simple_dns::CLASS::IN,
                ttl,
                RData::A(a_record),
            ));
        }
        packet.build_bytes_vec().unwrap()
    }

    #[test]
    fn query_response_tracking() {
        let mut tracker = DnsTracker::new();

        let query = build_dns_query(42, "api.github.com");
        assert!(tracker.process_query(&query));

        let ip = Ipv4Addr::new(140, 82, 121, 6);
        let response = build_dns_response(42, "api.github.com", &[ip], 300);
        let result = tracker.process_response(&response);
        assert!(result.is_some());
        let (hostname, ips) = result.unwrap();
        assert_eq!(hostname, "api.github.com");
        assert_eq!(ips, vec![ip]);

        assert_eq!(tracker.lookup(ip), Some("api.github.com"));
        assert_eq!(tracker.lookup(Ipv4Addr::new(1, 2, 3, 4)), None);
    }

    #[test]
    fn multiple_a_records() {
        let mut tracker = DnsTracker::new();

        let query = build_dns_query(1, "example.com");
        tracker.process_query(&query);

        let ips = [
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(93, 184, 216, 35),
        ];
        let response = build_dns_response(1, "example.com", &ips, 600);
        tracker.process_response(&response);

        assert_eq!(tracker.lookup(ips[0]), Some("example.com"));
        assert_eq!(tracker.lookup(ips[1]), Some("example.com"));
    }

    #[test]
    fn unknown_ip_returns_none() {
        let tracker = DnsTracker::new();
        assert_eq!(tracker.lookup(Ipv4Addr::new(10, 0, 0, 1)), None);
    }

    #[test]
    fn non_dns_packet_rejected() {
        let mut tracker = DnsTracker::new();
        assert!(!tracker.process_query(&[0, 1, 2, 3]));
        assert!(tracker.process_response(&[0, 1, 2, 3]).is_none());
    }
}
