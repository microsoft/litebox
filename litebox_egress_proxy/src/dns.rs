// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! On-demand hostname resolution through one configured DNS server.
//!
//! The resolver never consults host resolver configuration or a hosts file.
//! Request handling invokes it only after the exact hostname and port have
//! passed policy authorization.

use core::future::Future;
use core::pin::Pin;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
    ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RData};
use thiserror::Error;

use crate::limits::{DNS_ATTEMPT_TIMEOUT, MAX_RESOLVED_ADDRESSES, MAX_UDP_DNS_RESPONSE_BYTES};
use crate::policy::Hostname;

/// A future returned by a [`HostResolver`].
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<Ipv4Addr>, ResolveError>> + Send + 'a>>;

/// Resolves a canonical hostname to upstream IPv4 addresses.
pub trait HostResolver: Send + Sync + 'static {
    /// Resolves one canonical hostname.
    fn resolve(&self, host: Hostname) -> ResolveFuture<'_>;
}

/// Reason a hostname could not be resolved.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ResolveError {
    /// The canonical hostname could not be expressed as a DNS name.
    #[error("hostname is not a valid DNS name: {0}")]
    InvalidName(String),
    /// The configured DNS server did not answer successfully.
    #[error("DNS query failed: {0}")]
    Query(String),
    /// The answer contained no IPv4 address.
    #[error("DNS answer contained no IPv4 address")]
    NoAddresses,
}

/// A stub resolver bound to one operator-selected DNS server.
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

        #[allow(clippy::field_reassign_with_default)]
        let mut options = ResolverOpts::default();
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
            let name = Name::from_ascii(format!("{host}."))
                .map_err(|error| ResolveError::InvalidName(error.to_string()))?;
            let lookup = self
                .resolver
                .ipv4_lookup(name)
                .await
                .map_err(|error| ResolveError::Query(error.to_string()))?;

            let mut addresses = Vec::new();
            for record in lookup.answers() {
                let RData::A(address) = &record.data else {
                    continue;
                };
                let address = address.0;
                if addresses.len() < MAX_RESOLVED_ADDRESSES && !addresses.contains(&address) {
                    addresses.push(address);
                }
            }

            if addresses.is_empty() {
                Err(ResolveError::NoAddresses)
            } else {
                Ok(addresses)
            }
        })
    }
}
