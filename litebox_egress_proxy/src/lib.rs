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
pub mod listener;
pub mod policy;
pub mod proxy;
pub mod upstream;

mod stream;

use std::io::{self, Write};
use std::sync::Arc;

use thiserror::Error;
use tokio::net::TcpListener;

use crate::config::ProxyConfig;
use crate::listener::ListenerError;
use crate::proxy::ProxyState;
use crate::upstream::TcpUpstreamConnector;

/// Reason the proxy could not start.
#[derive(Debug, Error)]
pub enum StartupError {
    /// The listener could not be acquired or validated.
    #[error(transparent)]
    Listener(#[from] ListenerError),
    /// An I/O operation failed during startup or while serving.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Runs the proxy: startup, readiness announcement, then serving.
pub async fn run(config: &ProxyConfig) -> Result<(), StartupError> {
    let (listener, local_address) = listener::acquire(config.listener)?;
    let listener = TcpListener::from_std(listener)?;
    let state = Arc::new(ProxyState::new(
        config.policy.clone(),
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
