// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Upstream hostname resolution and connection.

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::{Instant, timeout};

use crate::policy::Hostname;

pub(crate) const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A bidirectional upstream byte stream.
pub trait UpstreamStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> UpstreamStream for T {}

/// An owned upstream byte stream.
pub type BoxedUpstreamStream = Box<dyn UpstreamStream>;

/// A future returned by an [`UpstreamConnector`].
pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<BoxedUpstreamStream>> + Send + 'a>>;

/// Resolves and connects to an authorized hostname and port.
pub trait UpstreamConnector: Send + Sync + 'static {
    /// Opens an upstream connection.
    fn connect(&self, host: Hostname, port: u16) -> ConnectFuture<'_>;
}

/// The production connector, using the trusted host resolver.
pub struct TcpUpstreamConnector;

impl UpstreamConnector for TcpUpstreamConnector {
    fn connect(&self, host: Hostname, port: u16) -> ConnectFuture<'_> {
        Box::pin(async move {
            let deadline = Instant::now() + UPSTREAM_CONNECT_TIMEOUT;
            let addresses: Vec<_> = lookup_host((host.as_str(), port)).await?.collect();
            let address_count = addresses.len();
            let mut last_error = None;

            for (index, address) in addresses.into_iter().enumerate() {
                let attempts_left = u32::try_from(address_count - index).unwrap_or(u32::MAX);
                let attempt_timeout =
                    deadline.saturating_duration_since(Instant::now()) / attempts_left;

                match timeout(attempt_timeout, TcpStream::connect(address)).await {
                    Ok(Ok(stream)) => {
                        stream.set_nodelay(true)?;
                        return Ok(Box::new(stream) as BoxedUpstreamStream);
                    }
                    Ok(Err(error)) => last_error = Some(error),
                    Err(_elapsed) => {
                        last_error = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "upstream address connection timed out",
                        ));
                    }
                }
            }

            Err(last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "hostname resolved to no addresses")
            }))
        })
    }
}
