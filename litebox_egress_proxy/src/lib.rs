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

/// Acquires the listener and prepares the shared state.
pub fn start(config: &ProxyConfig) -> Result<StartedProxy, StartupError> {
    let listener = listener::acquire(config.listener)?;
    let listener = TcpListener::from_std(listener)?;
    let SocketAddr::V4(local_address) = listener.local_addr()? else {
        return Err(StartupError::Listener(ListenerError::NotLoopback(
            listener.local_addr()?,
        )));
    };

    let state = Arc::new(ProxyState::new(
        config.policy.clone(),
        Arc::new(TcpUpstreamConnector),
    ));

    Ok(StartedProxy {
        listener,
        state,
        local_address,
    })
}

/// Writes the single readiness line.
pub fn write_readiness(writer: &mut impl Write, address: SocketAddrV4) -> io::Result<()> {
    writeln!(writer, "READY {address}")?;
    writer.flush()
}

/// Runs the proxy: startup, readiness announcement, then serving.
pub async fn run(config: &ProxyConfig) -> Result<(), StartupError> {
    let started = start(config)?;

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
