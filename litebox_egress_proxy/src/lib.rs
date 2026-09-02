// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A standalone, hostname-filtering HTTP and HTTPS egress proxy for LiteBox.
//!
//! Authorized hostnames are resolved on demand through the trusted host
//! resolver, then connected using the returned numeric addresses. Plain HTTP
//! requests are forwarded without buffering their bodies; HTTPS connections
//! use CONNECT tunnels that relay bytes without inspecting or terminating TLS.

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
use tokio::sync::oneshot;

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

    if config.exit_on_stdin_close {
        let (sender, stdin_closed) = oneshot::channel();
        std::thread::spawn(move || {
            let mut stdin = io::stdin().lock();
            let result = io::copy(&mut stdin, &mut io::sink()).map(|_read| ());
            let _ = sender.send(result);
        });
        tokio::select! {
            result = proxy::serve(listener, state) => result?,
            result = stdin_closed => {
                result.map_err(|_| io::Error::other("standard input watcher stopped"))??;
            }
        }
    } else {
        proxy::serve(listener, state).await?;
    }
    Ok(())
}
