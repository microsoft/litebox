// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Upstream hostname resolution and connection.

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;

use crate::policy::Hostname;

const UPSTREAM_ADDRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

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
            let addresses = lookup_host((host.as_str(), port)).await?;
            let mut last_error = None;

            for address in addresses {
                match timeout(
                    UPSTREAM_ADDRESS_CONNECT_TIMEOUT,
                    TcpStream::connect(address),
                )
                .await
                {
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
