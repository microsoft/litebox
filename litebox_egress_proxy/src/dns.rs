// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Controlled DNS resolution and immutable startup pinning.
//!
//! Every allowed hostname is resolved exactly once, before the listener is
//! announced ready, and the resulting addresses are pinned for the lifetime of
//! the process. Request handling never performs a lookup, so an upstream
//! connection can only target an address that was validated at startup.

use core::future::Future;
use core::pin::Pin;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
    ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RData};
use ipnet::Ipv4Net;
use thiserror::Error;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::limits::{
    DNS_ATTEMPT_TIMEOUT, DNS_QUERY_TIMEOUT, MAX_CONCURRENT_STARTUP_RESOLUTIONS,
    MAX_PINNED_ADDRESSES_PER_HOST, MAX_RESOLVED_DESTINATION_RULES, MAX_UDP_DNS_RESPONSE_BYTES,
};
use crate::policy::{HostPolicy, Hostname};

/// A future returned by a [`HostResolver`].
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<Ipv4Addr>, ResolveError>> + Send + 'a>>;

/// Resolves policy hostnames to upstream IPv4 addresses.
///
/// # Contract
///
/// Implementations return DNS data only. [`PinnedTable::resolve`] applies the
/// destination policy before retaining any address, keeping target safety in
/// one path for production and injected resolvers.
pub trait HostResolver: Send + Sync + 'static {
    /// Resolves one canonical hostname.
    ///
    /// Returning an empty vector is a protocol error; implementations should
    /// return [`ResolveError::NoAddresses`] instead.
    fn resolve(&self, host: Hostname) -> ResolveFuture<'_>;
}

/// Reason a hostname could not be resolved into pinned addresses.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ResolveError {
    /// The canonical name could not be expressed as a DNS name.
    #[error("hostname is not a valid DNS name: {0}")]
    InvalidName(String),
    /// The configured DNS server did not answer successfully.
    #[error("DNS query failed: {0}")]
    Query(String),
    /// The answer contained no IPv4 address.
    #[error("DNS answer contained no IPv4 address")]
    NoAddresses,
    /// The answer contained an address that is not a permitted upstream
    /// target.
    #[error("DNS answer contained non-global address {0}")]
    UnsafeAddress(Ipv4Addr),
}

/// Reason startup pinning failed.
#[derive(Clone, Debug, Error)]
pub enum PinError {
    /// One hostname failed to resolve.
    #[error("failed to resolve `{host}`: {source}")]
    Host {
        /// The hostname that failed.
        host: Hostname,
        /// The underlying resolution failure.
        source: ResolveError,
    },
    /// One hostname exceeded the per-name DNS timeout.
    #[error("timed out resolving `{host}`")]
    Timeout {
        /// The hostname that timed out.
        host: Hostname,
    },
    /// A resolution task could not be run to completion.
    #[error("resolution task failed: {0}")]
    Task(String),
}

/// Returns whether `address` is a public proxy destination.
///
/// Only globally routable unicast addresses are permitted. This is a
/// proxy-specific safety rule: hostname policy must never be able to reach the
/// host's own networks, link-local metadata services, or any special-purpose
/// range.
pub fn is_public_proxy_target(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();

    // 0.0.0.0/8 "this network", including the unspecified address.
    if a == 0 {
        return false;
    }
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
    if address.is_private() {
        return false;
    }
    // 100.64.0.0/10 shared address space (carrier-grade NAT).
    if a == 100 && (64..128).contains(&b) {
        return false;
    }
    // 127.0.0.0/8 loopback.
    if address.is_loopback() {
        return false;
    }
    // 169.254.0.0/16 link-local.
    if address.is_link_local() {
        return false;
    }
    // 192.0.0.0/24 IETF protocol assignments.
    if a == 192 && b == 0 && c == 0 {
        return false;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 documentation.
    if (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
    {
        return false;
    }
    // 198.18.0.0/15 benchmarking.
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, 255.255.255.255 broadcast.
    if address.is_multicast() || a >= 240 {
        return false;
    }
    true
}

/// Returns whether an explicitly configured DNS server is externally usable.
///
/// Private and link-local unicast addresses are accepted because the trusted
/// operator selects this endpoint directly. Resolved proxy targets use the
/// stricter [`TargetPolicy`] instead.
pub fn is_permitted_dns_server_ipv4(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    first != 0 && !address.is_loopback() && !address.is_multicast() && first < 240
}

/// The immutable envelope for addresses learned from DNS.
///
/// Public destinations are accepted by default. Additional canonical CIDRs
/// permit private services through the proxy without granting the guest direct
/// access to those ranges. Unspecified, loopback, multicast, broadcast, and
/// reserved addresses remain hard-denied even if an additional CIDR covers
/// them.
#[derive(Clone, Debug, Default)]
pub struct TargetPolicy {
    additional: Vec<Ipv4Net>,
}

/// Reason a resolved-destination policy was rejected.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TargetPolicyError {
    /// More than the fixed number of additional CIDRs was supplied.
    #[error(
        "resolved-destination policy contains more than {MAX_RESOLVED_DESTINATION_RULES} CIDRs"
    )]
    TooManyCidrs,
}

impl TargetPolicy {
    /// Creates a target policy from additional canonical IPv4 CIDRs.
    pub fn new(mut additional: Vec<Ipv4Net>) -> Result<Self, TargetPolicyError> {
        if additional.len() > MAX_RESOLVED_DESTINATION_RULES {
            return Err(TargetPolicyError::TooManyCidrs);
        }
        additional.sort_unstable();
        additional.dedup();
        Ok(Self { additional })
    }

    /// Returns a policy that permits public destinations only.
    pub fn public_only() -> Self {
        Self::default()
    }

    /// Returns whether a resolved address may be pinned.
    pub fn allows(&self, address: Ipv4Addr) -> bool {
        if !is_permitted_dns_server_ipv4(address) {
            return false;
        }
        is_public_proxy_target(address)
            || self
                .additional
                .iter()
                .any(|network| network.contains(&address))
    }
}

/// The production resolver: a stub resolver bound to one configured server.
///
/// The resolver never consults the host's resolver configuration or hosts
/// file, sends queries only to the configured server, and falls back from UDP
/// to TCP when a response is truncated or a UDP exchange fails.
pub struct ConfiguredDnsResolver {
    resolver: Resolver<TokioRuntimeProvider>,
}

impl ConfiguredDnsResolver {
    /// Builds a resolver that queries only `server`.
    pub fn new(server: SocketAddrV4) -> Result<Self, ResolveError> {
        let mut udp = ConnectionConfig::udp();
        udp.port = server.port();
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = server.port();

        let name_server = NameServerConfig::new(IpAddr::V4(*server.ip()), true, vec![udp, tcp]);
        let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);

        // `ResolverOpts` is `#[non_exhaustive]`, so the defaults have to be
        // adjusted field by field rather than through a struct literal.
        #[allow(clippy::field_reassign_with_default)]
        let mut options = ResolverOpts::default();
        // Query fully qualified names only; there is no search list and no
        // host-configured domain.
        options.ndots = 0;
        options.timeout = DNS_ATTEMPT_TIMEOUT;
        options.attempts = 1;
        options.try_tcp_on_error = true;
        options.edns0 = true;
        options.edns_payload_len = MAX_UDP_DNS_RESPONSE_BYTES;
        options.ip_strategy = LookupIpStrategy::Ipv4Only;
        options.use_hosts_file = ResolveHosts::Never;
        options.num_concurrent_reqs = 1;
        options.preserve_intermediates = false;
        // Pinning happens once; a cache would only add state that must not
        // influence later behaviour.
        options.cache_size = 0;

        let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(options)
            .build()
            .map_err(|error| ResolveError::Query(error.to_string()))?;
        Ok(Self { resolver })
    }
}

impl HostResolver for ConfiguredDnsResolver {
    fn resolve(&self, host: Hostname) -> ResolveFuture<'_> {
        Box::pin(async move {
            // The trailing dot makes the query fully qualified, so no search
            // list can ever be appended.
            let name = Name::from_ascii(format!("{host}."))
                .map_err(|error| ResolveError::InvalidName(error.to_string()))?;

            let lookup = self
                .resolver
                .ipv4_lookup(name)
                .await
                .map_err(|error| ResolveError::Query(error.to_string()))?;

            let mut addresses: Vec<Ipv4Addr> = Vec::new();
            for record in lookup.answers() {
                // CNAME chains are followed by the resolver itself; only the
                // terminal A records matter here.
                let RData::A(address) = &record.data else {
                    continue;
                };
                let address = address.0;
                if addresses.len() < MAX_PINNED_ADDRESSES_PER_HOST && !addresses.contains(&address)
                {
                    addresses.push(address);
                }
            }

            if addresses.is_empty() {
                return Err(ResolveError::NoAddresses);
            }
            Ok(addresses)
        })
    }
}

/// The immutable startup resolution table.
///
/// Addresses are stored in the order the resolver returned them, which is also
/// the order in which upstream connection attempts are made.
#[derive(Clone, Debug, Default)]
pub struct PinnedTable {
    entries: HashMap<Hostname, Vec<Ipv4Addr>>,
}

impl PinnedTable {
    /// Resolves every hostname of `policy` and pins the results.
    ///
    /// At most [`MAX_CONCURRENT_STARTUP_RESOLUTIONS`] lookups run at a time,
    /// and each lookup is bounded by [`DNS_QUERY_TIMEOUT`]. A single failure
    /// fails the whole table: startup must fail closed.
    pub async fn resolve(
        policy: &HostPolicy,
        targets: &TargetPolicy,
        resolver: Arc<dyn HostResolver>,
    ) -> Result<Self, PinError> {
        let mut pending = policy.hostnames().cloned().collect::<Vec<_>>().into_iter();
        let mut tasks: JoinSet<(Hostname, Result<Vec<Ipv4Addr>, PinError>)> = JoinSet::new();
        let mut entries = HashMap::with_capacity(policy.len());

        loop {
            while tasks.len() < MAX_CONCURRENT_STARTUP_RESOLUTIONS {
                let Some(host) = pending.next() else {
                    break;
                };
                let resolver = Arc::clone(&resolver);
                tasks.spawn(async move {
                    let outcome =
                        match timeout(DNS_QUERY_TIMEOUT, resolver.resolve(host.clone())).await {
                            Ok(Ok(addresses)) => Ok(addresses),
                            Ok(Err(source)) => Err(PinError::Host {
                                host: host.clone(),
                                source,
                            }),
                            Err(_elapsed) => Err(PinError::Timeout { host: host.clone() }),
                        };
                    (host, outcome)
                });
            }

            let Some(joined) = tasks.join_next().await else {
                break;
            };
            let (host, outcome) = joined.map_err(|error| PinError::Task(error.to_string()))?;
            let mut addresses = outcome?;
            if addresses.is_empty() {
                return Err(PinError::Host {
                    host,
                    source: ResolveError::NoAddresses,
                });
            }
            for address in &addresses {
                if !targets.allows(*address) {
                    // Defence in depth: a resolver that violates its contract
                    // must not be able to pin an unsafe address.
                    return Err(PinError::Host {
                        host,
                        source: ResolveError::UnsafeAddress(*address),
                    });
                }
            }
            addresses.truncate(MAX_PINNED_ADDRESSES_PER_HOST);
            entries.insert(host, addresses);
        }

        Ok(Self { entries })
    }

    /// Returns the pinned addresses for `host`, in startup order.
    ///
    /// An unknown hostname yields an empty slice; the policy check has already
    /// rejected such a request before this point.
    pub fn addresses(&self, host: &Hostname) -> &[Ipv4Addr] {
        self.entries.get(host).map_or(&[], Vec::as_slice)
    }

    /// Returns the number of pinned hostnames.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether nothing is pinned.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::HostRule;

    struct StaticResolver {
        answers: HashMap<String, Result<Vec<Ipv4Addr>, ResolveError>>,
    }

    impl HostResolver for StaticResolver {
        fn resolve(&self, host: Hostname) -> ResolveFuture<'_> {
            let answer = self
                .answers
                .get(host.as_str())
                .cloned()
                .unwrap_or(Err(ResolveError::NoAddresses));
            Box::pin(async move { answer })
        }
    }

    fn policy(rules: &[&str]) -> HostPolicy {
        HostPolicy::from_rules(
            rules
                .iter()
                .map(|rule| rule.parse::<HostRule>().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn global_unicast_addresses_are_permitted() {
        assert!(is_public_proxy_target(Ipv4Addr::new(93, 184, 216, 34)));
        assert!(is_public_proxy_target(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_public_proxy_target(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn special_purpose_addresses_are_rejected() {
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(192, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            assert!(
                !is_public_proxy_target(address),
                "{address} must not be a permitted upstream target"
            );
        }
    }

    #[test]
    fn pins_every_policy_hostname() {
        let resolver = StaticResolver {
            answers: [
                (
                    "a.example".to_owned(),
                    Ok(vec![
                        Ipv4Addr::new(93, 184, 216, 34),
                        Ipv4Addr::new(1, 1, 1, 1),
                    ]),
                ),
                ("b.example".to_owned(), Ok(vec![Ipv4Addr::new(8, 8, 4, 4)])),
            ]
            .into_iter()
            .collect(),
        };

        let policy = policy(&["a.example:80", "b.example:443"]);
        let table = runtime()
            .block_on(PinnedTable::resolve(
                &policy,
                &TargetPolicy::public_only(),
                Arc::new(resolver),
            ))
            .unwrap();

        assert_eq!(table.len(), 2);
        assert_eq!(
            table.addresses(&Hostname::parse("a.example").unwrap()),
            [Ipv4Addr::new(93, 184, 216, 34), Ipv4Addr::new(1, 1, 1, 1)]
        );
        assert!(
            table
                .addresses(&Hostname::parse("c.example").unwrap())
                .is_empty()
        );
    }

    #[test]
    fn unresolved_hostname_fails_startup() {
        let resolver = StaticResolver {
            answers: HashMap::new(),
        };
        let policy = policy(&["a.example:80"]);
        let error = runtime()
            .block_on(PinnedTable::resolve(
                &policy,
                &TargetPolicy::public_only(),
                Arc::new(resolver),
            ))
            .unwrap_err();
        assert!(matches!(
            error,
            PinError::Host {
                source: ResolveError::NoAddresses,
                ..
            }
        ));
    }

    #[test]
    fn unsafe_address_fails_startup() {
        let resolver = StaticResolver {
            answers: [("a.example".to_owned(), Ok(vec![Ipv4Addr::LOCALHOST]))]
                .into_iter()
                .collect(),
        };
        let policy = policy(&["a.example:80"]);
        let error = runtime()
            .block_on(PinnedTable::resolve(
                &policy,
                &TargetPolicy::public_only(),
                Arc::new(resolver),
            ))
            .unwrap_err();
        assert!(matches!(
            error,
            PinError::Host {
                source: ResolveError::UnsafeAddress(_),
                ..
            }
        ));
    }

    #[test]
    fn pinned_addresses_are_bounded_per_host() {
        let many = (1..=40)
            .map(|index| Ipv4Addr::new(93, 184, 216, index))
            .collect::<Vec<_>>();
        let resolver = StaticResolver {
            answers: [("a.example".to_owned(), Ok(many))].into_iter().collect(),
        };
        let policy = policy(&["a.example:80"]);
        let table = runtime()
            .block_on(PinnedTable::resolve(
                &policy,
                &TargetPolicy::public_only(),
                Arc::new(resolver),
            ))
            .unwrap();
        assert_eq!(
            table
                .addresses(&Hostname::parse("a.example").unwrap())
                .len(),
            MAX_PINNED_ADDRESSES_PER_HOST
        );
    }

    #[test]
    fn additional_target_cidr_allows_private_but_not_loopback() {
        let targets = TargetPolicy::new(vec!["10.0.0.0/8".parse().unwrap()]).unwrap();
        assert!(targets.allows(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!targets.allows(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn additional_target_cidrs_are_bounded() {
        let networks = (0..=MAX_RESOLVED_DESTINATION_RULES)
            .map(|index| format!("10.{index}.0.0/16").parse().unwrap())
            .collect();
        assert_eq!(
            TargetPolicy::new(networks).unwrap_err(),
            TargetPolicyError::TooManyCidrs
        );
    }
}
