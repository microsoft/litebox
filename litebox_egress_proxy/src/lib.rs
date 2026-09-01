// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A standalone, hostname-filtering CONNECT egress proxy for LiteBox.
//!
//! Authorized hostnames are resolved on demand through the trusted host
//! resolver, then connected using the returned numeric addresses. CONNECT
//! tunnels relay bytes without inspecting or terminating TLS.

extern crate alloc;

pub mod authority;
pub mod config;
pub mod connector;
pub mod policy;
pub mod proxy;

mod idle_timeout;

use std::io::{self, Write};
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::config::ProxyConfig;
use crate::connector::TcpUpstreamConnector;
use crate::proxy::ProxyState;

/// Runs the proxy: startup, readiness announcement, then serving.
pub async fn run(config: ProxyConfig) -> io::Result<()> {
    let listener = TcpListener::bind(config.listen).await?;
    let local_address = listener.local_addr()?;
    let state = Arc::new(ProxyState::new(
        config.policy,
        Box::new(TcpUpstreamConnector),
    ));

    {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "READY {local_address}")?;
        stdout.flush()?;
    }

    proxy::serve(listener, state).await?;
    Ok(())
}
