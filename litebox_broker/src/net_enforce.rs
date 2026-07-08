// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-global network policy enforcement.
//!
//! This module is the live home of the network side of sandbox policy. The
//! filesystem side is enforced in [`crate::nine_p::server`] via
//! [`crate::policy::GlobPolicy`]; the network side is enforced here and
//! consulted from the broker-held inet connect path
//! (`cwfd::state_service::handle_inet_tcp_conn_connect`).
//!
//! A [`NetEnforcer`] bundles the three pieces of shared state the two network
//! handler sites need:
//!
//! - the loaded [`SandboxPolicy`] (may be absent — then enforcement is a no-op),
//! - the structured [`AuditLog`] (may be absent — then no events are emitted),
//! - a bounded IP→hostname reverse map built by intercepting guest DNS
//!   responses at the broker's virtual resolver.
//!
//! The reverse map is what makes *hostname*-based policies work: the guest
//! looks up `api.github.com`, the broker forwards the query and records every
//! returned address as belonging to `api.github.com`, so a later
//! `connect(140.82.121.6:443)` can be matched against an
//! `allow_connect: ["api.github.com:443"]` rule.
//!
//! Historically this lived in the (since-removed) smoltcp network proxy; it was
//! lost when inet resources moved to the broker-held model and is re-homed here.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use crate::audit::AuditLog;
use crate::sandbox_policy::{Decision, SandboxPolicy};

/// Upper bound on the number of IP→hostname entries retained. DNS answers are
/// cheap to relearn, so on overflow the oldest entries are evicted FIFO.
const DNS_REVERSE_MAX: usize = 8192;

/// DNS resource-record type codes we care about.
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;

/// Bounded IP→hostname reverse map built from intercepted DNS responses.
#[derive(Default)]
struct DnsReverseMap {
    map: HashMap<IpAddr, String>,
    /// Insertion order of *new* keys, for FIFO eviction once `map` exceeds
    /// [`DNS_REVERSE_MAX`]. Updating an existing key does not re-order it.
    order: VecDeque<IpAddr>,
}

impl DnsReverseMap {
    fn insert(&mut self, ip: IpAddr, hostname: String) {
        if self.map.insert(ip, hostname).is_none() {
            self.order.push_back(ip);
            while self.order.len() > DNS_REVERSE_MAX {
                if let Some(evicted) = self.order.pop_front() {
                    self.map.remove(&evicted);
                }
            }
        }
    }

    fn get(&self, ip: &IpAddr) -> Option<String> {
        self.map.get(ip).cloned()
    }
}

/// Broker-global network enforcement context: policy + audit + DNS reverse map.
///
/// Cheap to clone as `Arc<NetEnforcer>`; shared by the registry, every
/// broker-held UDP datagram socket (for DNS recording), and the TCP connect
/// handler (for enforcement).
pub struct NetEnforcer {
    policy: Option<Arc<SandboxPolicy>>,
    audit: Option<AuditLog>,
    dns_reverse: Mutex<DnsReverseMap>,
}

impl NetEnforcer {
    /// Create an enforcer. With `policy = None`, [`NetEnforcer::allow_connect`]
    /// permits everything and emits nothing (enforcement disabled).
    pub fn new(policy: Option<Arc<SandboxPolicy>>, audit: Option<AuditLog>) -> Arc<Self> {
        Arc::new(Self {
            policy,
            audit,
            dns_reverse: Mutex::new(DnsReverseMap::default()),
        })
    }

    /// A disabled enforcer (no policy, no audit). Used by
    /// [`crate::state_registry::BrokerStateRegistry::new`] and tests.
    pub fn disabled() -> Arc<Self> {
        Self::new(None, None)
    }

    /// Parse a DNS response datagram and record every returned address as
    /// belonging to the queried hostname, then emit a `dns_resolved` audit
    /// event. Malformed or answer-less responses are ignored.
    pub fn record_dns_response(&self, response: &[u8]) {
        let Some((hostname, ips)) = parse_dns_response(response) else {
            return;
        };
        if ips.is_empty() {
            return;
        }
        {
            let mut map = self.dns_reverse.lock().expect("dns_reverse poisoned");
            for ip in &ips {
                map.insert(*ip, hostname.clone());
            }
        }
        if let Some(audit) = &self.audit {
            audit.dns_resolved(&hostname, &ips);
        }
    }

    /// Decide whether an outbound TCP connection to `ip:port` is permitted,
    /// emitting the matching `tcp_allowed` / `tcp_denied` audit event.
    ///
    /// Returns `true` when the connection may proceed. When no policy is
    /// loaded, always returns `true` and emits nothing.
    pub fn allow_connect(&self, ip: IpAddr, port: u16) -> bool {
        let Some(policy) = &self.policy else {
            return true;
        };
        let hostname = self
            .dns_reverse
            .lock()
            .expect("dns_reverse poisoned")
            .get(&ip);
        match policy.check_connect(ip, port, hostname.as_deref()) {
            Decision::Allow => {
                if let Some(audit) = &self.audit {
                    audit.tcp_allowed(hostname.as_deref(), ip, port);
                }
                true
            }
            Decision::Deny => {
                if let Some(audit) = &self.audit {
                    audit.tcp_denied(hostname.as_deref(), ip, port);
                }
                false
            }
        }
    }
}

impl std::fmt::Debug for NetEnforcer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetEnforcer")
            .field("policy_loaded", &self.policy.is_some())
            .field("audit_enabled", &self.audit.is_some())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Minimal DNS response parser (RFC 1035). Dependency-free by design.
// ---------------------------------------------------------------------------
/// Parse a DNS message, returning the queried hostname and every A/AAAA
/// address in the answer section. Returns `None` on malformed input.
///
/// All returned addresses are attributed to the *question* name (what the
/// guest asked for), which is what policy allowlists reference — even when the
/// answer chain passes through CNAMEs to CDN-owned record names.
fn parse_dns_response(buf: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    // Header is 12 bytes: ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if qdcount < 1 {
        return None;
    }

    // Question section: read the first QNAME, then skip QTYPE+QCLASS (4 bytes).
    let (qname, mut off) = read_qname(buf, 12)?;
    off += 4;
    // Skip any additional questions (rare; almost always exactly one).
    for _ in 1..qdcount {
        off = skip_name(buf, off)?.checked_add(4)?;
    }

    // Answer section.
    let mut ips = Vec::new();
    for _ in 0..ancount {
        off = skip_name(buf, off)?;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) then RDATA.
        let rtype = u16::from_be_bytes([*buf.get(off)?, *buf.get(off + 1)?]);
        let rdlength = usize::from(u16::from_be_bytes([*buf.get(off + 8)?, *buf.get(off + 9)?]));
        let rdata_start = off + 10;
        let rdata = buf.get(rdata_start..rdata_start.checked_add(rdlength)?)?;
        match rtype {
            DNS_TYPE_A if rdlength == 4 => {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            DNS_TYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        off = rdata_start + rdlength;
    }
    Some((qname, ips))
}

/// Read an uncompressed domain name (the question's QNAME) starting at `off`,
/// returning the dotted name and the offset just past its terminating zero.
///
/// Question names are never compressed, so a compression pointer here is
/// treated as malformed.
fn read_qname(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *buf.get(off)?;
        if len == 0 {
            return Some((labels.join("."), off + 1));
        }
        if len & 0xC0 != 0 {
            // Compression pointer or reserved bits — unexpected in a question.
            return None;
        }
        let start = off + 1;
        let end = start.checked_add(usize::from(len))?;
        let label = buf.get(start..end)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        off = end;
    }
}

/// Advance past a (possibly compressed) domain name, returning the offset of
/// the first byte after it.
fn skip_name(buf: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *buf.get(off)?;
        if len & 0xC0 == 0xC0 {
            // Two-byte compression pointer terminates the name in-place.
            return off.checked_add(2);
        }
        if len == 0 {
            return off.checked_add(1);
        }
        off = off.checked_add(1 + usize::from(len))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS response: one question for `name`, followed by one
    /// A record per address, all attributed (via the question) to `name`.
    fn build_response(name: &str, addrs: &[Ipv4Addr]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]); // ID
        buf.extend_from_slice(&[0x81, 0x80]); // flags: response, recursion
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&(addrs.len() as u16).to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        let qname_start = buf.len();
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root
        buf.extend_from_slice(&DNS_TYPE_A.to_be_bytes()); // QTYPE
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        for addr in addrs {
            // NAME as a compression pointer back to the question name.
            let ptr = 0xC000 | (qname_start as u16);
            buf.extend_from_slice(&ptr.to_be_bytes());
            buf.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
            buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            buf.extend_from_slice(&300u32.to_be_bytes()); // TTL
            buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            buf.extend_from_slice(&addr.octets());
        }
        buf
    }

    #[test]
    fn parses_single_a_record() {
        let resp = build_response("api.github.com", &[Ipv4Addr::new(140, 82, 121, 6)]);
        let (name, ips) = parse_dns_response(&resp).expect("parse");
        assert_eq!(name, "api.github.com");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(140, 82, 121, 6))]);
    }

    #[test]
    fn parses_multiple_a_records_to_same_name() {
        let addrs = [
            Ipv4Addr::new(104, 16, 20, 35),
            Ipv4Addr::new(104, 16, 21, 35),
        ];
        let resp = build_response("registry.npmjs.org", &addrs);
        let (name, ips) = parse_dns_response(&resp).expect("parse");
        assert_eq!(name, "registry.npmjs.org");
        assert_eq!(
            ips,
            addrs.iter().map(|a| IpAddr::V4(*a)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ignores_answerless_response() {
        let resp = build_response("nxdomain.example", &[]);
        let (name, ips) = parse_dns_response(&resp).expect("parse");
        assert_eq!(name, "nxdomain.example");
        assert!(ips.is_empty());
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(parse_dns_response(&[0u8; 4]).is_none());
    }

    #[test]
    fn record_then_allow_connect_matches_hostname() {
        let policy = SandboxPolicy::from_json(
            r#"{ "network": { "deny_all": true, "allow_connect": ["api.github.com:443"] } }"#,
        )
        .unwrap();
        let enforcer = NetEnforcer::new(Some(Arc::new(policy)), None);
        let allowed_ip = Ipv4Addr::new(140, 82, 121, 6);
        enforcer.record_dns_response(&build_response("api.github.com", &[allowed_ip]));

        // Learned IP for an allowlisted hostname → allowed.
        assert!(enforcer.allow_connect(IpAddr::V4(allowed_ip), 443));
        // Same IP, wrong port → denied.
        assert!(!enforcer.allow_connect(IpAddr::V4(allowed_ip), 80));
        // Unknown IP (no DNS mapping) under deny_all → denied.
        assert!(!enforcer.allow_connect(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443));
    }

    #[test]
    fn loopback_allowed_under_deny_all() {
        // Loopback is intra-sandbox and exempt from the egress allowlist, even
        // with an empty `allow_connect` under `deny_all`. VS Code Remote-SSH's
        // SOCKS port-forward relies on the in-sandbox sshd reaching the
        // server's `127.0.0.1:<ephemeral-port>`.
        let policy =
            SandboxPolicy::from_json(r#"{ "network": { "deny_all": true, "allow_connect": [] } }"#)
                .unwrap();
        let enforcer = NetEnforcer::new(Some(Arc::new(policy)), None);
        // Any port on 127.0.0.0/8 and ::1 is allowed.
        assert!(enforcer.allow_connect(IpAddr::V4(Ipv4Addr::LOCALHOST), 40539));
        assert!(enforcer.allow_connect(IpAddr::V4(Ipv4Addr::new(127, 7, 7, 7)), 8080));
        assert!(enforcer.allow_connect("::1".parse().unwrap(), 40539));
        // A non-loopback address is still denied under deny_all.
        assert!(!enforcer.allow_connect(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 40539));
    }

    #[test]
    fn disabled_enforcer_allows_everything() {
        let enforcer = NetEnforcer::disabled();
        assert!(enforcer.allow_connect(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443));
    }

    #[test]
    fn emits_audit_events_for_dns_and_connect() {
        use std::io::Read as _;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "litebox-net-enforce-{}-{nanos}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let audit = AuditLog::open(&path).unwrap();
        let policy = SandboxPolicy::from_json(
            r#"{ "network": { "deny_all": true, "allow_connect": ["api.github.com:443"] } }"#,
        )
        .unwrap();
        let enforcer = NetEnforcer::new(Some(Arc::new(policy)), Some(audit));

        let ip = Ipv4Addr::new(140, 82, 121, 6);
        enforcer.record_dns_response(&build_response("api.github.com", &[ip]));
        assert!(enforcer.allow_connect(IpAddr::V4(ip), 443));
        assert!(!enforcer.allow_connect(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443));

        let mut contents = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(contents.contains(r#""event":"dns_resolved""#), "{contents}");
        assert!(contents.contains(r#""event":"tcp_allowed""#), "{contents}");
        assert!(contents.contains(r#""event":"tcp_denied""#), "{contents}");
        assert!(contents.contains("api.github.com"), "{contents}");
    }

    #[test]
    fn reverse_map_evicts_oldest_when_full() {
        let mut map = DnsReverseMap::default();
        for i in 0..(DNS_REVERSE_MAX + 10) {
            let ip = IpAddr::V4(Ipv4Addr::from(i as u32));
            map.insert(ip, format!("host{i}"));
        }
        assert!(map.map.len() <= DNS_REVERSE_MAX);
        // The very first inserted entries should have been evicted.
        assert!(map.get(&IpAddr::V4(Ipv4Addr::from(0u32))).is_none());
        // A recent entry should still be present.
        let recent = IpAddr::V4(Ipv4Addr::from((DNS_REVERSE_MAX + 5) as u32));
        assert_eq!(
            map.get(&recent),
            Some(format!("host{}", DNS_REVERSE_MAX + 5))
        );
    }
}
