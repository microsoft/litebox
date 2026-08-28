// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A standalone, hostname-filtering HTTP and HTTPS egress proxy for LiteBox
//! sandboxes.
//!
//! # Model
//!
//! The proxy is a separate trusted process. It authorizes each request against
//! an immutable, exact-hostname policy and connects only to addresses that were
//! resolved through one explicitly configured DNS server before the listener
//! was announced as ready. It never consults the host resolver configuration,
//! never re-resolves a hostname, and never grants direct access to a resolved
//! address: a hostname rule authorizes an endpoint reached through this proxy
//! and nothing else.
//!
//! Two request forms are supported:
//!
//! * plain HTTP/1 forward-proxy requests with an absolute-form `http` target,
//!   which are rewritten to origin form and relayed over a dedicated upstream
//!   connection per request, and
//! * `CONNECT` tunnels, which relay bytes to an allowed hostname and port
//!   without inspecting or terminating TLS.
//!
//! Each plain HTTP client connection carries exactly one request. This keeps
//! raw request framing validation authoritative without duplicating a
//! streaming HTTP parser, while upstream connections are already dedicated per
//! request. A successful `CONNECT` instead upgrades that one request into its
//! bounded tunnel.
//!
//! Everything else -- protocol upgrades, `https` absolute URIs, IP-literal
//! authorities, ambiguous framing, and any hostname or port that policy does
//! not name -- is rejected.
//!
//! # Executable contract
//!
//! ```text
//! litebox_egress_proxy --listen 127.0.0.1:0 --dns-server IPV4[:PORT] \
//!     --allow-host HOST:PORT[-PORT] ...
//! litebox_egress_proxy --listener-fd FD --dns-server IPV4[:PORT] \
//!     --allow-host HOST:PORT[-PORT] ...
//! ```
//!
//! After the listener is acquired, every policy hostname is resolved, and all
//! startup validation has passed, exactly one line is written to standard
//! output:
//!
//! ```text
//! READY 127.0.0.1:PORT
//! ```
//!
//! Diagnostics go to standard error only, and no readiness line is written on
//! failure. Startup as a whole is bounded by [`limits::STARTUP_BUDGET`].
//!
//! # Testing
//!
//! [`dns::HostResolver`] and [`upstream::UpstreamConnector`] are injected
//! abstractions, so the request path can be driven hermetically over loopback.
//! The shared pinning path applies the same destination policy to production
//! and injected DNS answers.

pub mod authority;
pub mod config;
pub mod dns;
pub mod headers;
pub mod limits;
pub mod listener;
pub mod policy;
pub mod proxy;
pub mod stream;
pub mod upstream;

mod request_head;

use std::io::{self, Write};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;

use thiserror::Error;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::config::ProxyConfig;
use crate::dns::{ConfiguredDnsResolver, PinError, PinnedTable, ResolveError};
use crate::limits::STARTUP_BUDGET;
use crate::listener::ListenerError;
use crate::proxy::ProxyState;
use crate::upstream::TcpUpstreamConnector;

/// Reason the proxy could not start.
#[derive(Debug, Error)]
pub enum StartupError {
    /// The listener could not be acquired or validated.
    #[error(transparent)]
    Listener(#[from] ListenerError),
    /// The resolver could not be constructed.
    #[error("failed to configure the DNS resolver: {0}")]
    Resolver(#[from] ResolveError),
    /// A policy hostname could not be pinned.
    #[error(transparent)]
    Pin(#[from] PinError),
    /// Startup exceeded its total budget.
    #[error("startup exceeded its {}s budget", STARTUP_BUDGET.as_secs())]
    Budget,
    /// An I/O operation failed during startup or while serving.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A proxy that has completed startup and is ready to serve.
pub struct StartedProxy {
    listener: TcpListener,
    state: Arc<ProxyState>,
    local_address: SocketAddrV4,
}

impl StartedProxy {
    /// Returns the loopback address the proxy listens on.
    pub fn local_address(&self) -> SocketAddrV4 {
        self.local_address
    }

    /// Serves client connections until the listener fails.
    pub async fn serve(self) -> io::Result<()> {
        proxy::serve(self.listener, self.state).await
    }
}

/// Acquires the listener, pins every policy hostname, and prepares the shared
/// state.
///
/// No client connection is served and no readiness line is written until this
/// has succeeded, so a partially configured proxy is never observable.
pub async fn start(config: &ProxyConfig) -> Result<StartedProxy, StartupError> {
    let listener = listener::acquire(config.listener)?;
    let listener = TcpListener::from_std(listener)?;
    let SocketAddr::V4(local_address) = listener.local_addr()? else {
        return Err(StartupError::Listener(ListenerError::NotLoopback(
            listener.local_addr()?,
        )));
    };

    let resolver = ConfiguredDnsResolver::new(config.dns_server)?;
    let pinned = PinnedTable::resolve(&config.policy, &config.targets, Arc::new(resolver)).await?;

    let state = Arc::new(ProxyState::new(
        config.policy.clone(),
        pinned,
        Arc::new(TcpUpstreamConnector),
    ));

    Ok(StartedProxy {
        listener,
        state,
        local_address,
    })
}

/// Writes the single readiness line.
///
/// The launcher treats malformed output, extra output before readiness, or a
/// missing line as a startup failure, so this is the only thing the proxy ever
/// writes to standard output.
pub fn write_readiness(writer: &mut impl Write, address: SocketAddrV4) -> io::Result<()> {
    writeln!(writer, "READY {address}")?;
    writer.flush()
}

/// Runs the proxy: bounded startup, readiness announcement, then serving.
pub async fn run(config: &ProxyConfig) -> Result<(), StartupError> {
    let started = timeout(STARTUP_BUDGET, start(config))
        .await
        .map_err(|_elapsed| StartupError::Budget)??;

    let mut stdout = io::stdout().lock();
    write_readiness(&mut stdout, started.local_address())?;
    drop(stdout);

    started.serve().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    #[test]
    fn readiness_line_is_exactly_one_line() {
        let mut output = Vec::new();
        write_readiness(&mut output, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)).unwrap();
        assert_eq!(output, b"READY 127.0.0.1:34567\n");
    }
}
