// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Upstream connection abstraction.
//!
//! Request handling only ever dials an address that came from the immutable
//! startup resolution table. The connector is an injected abstraction so that
//! tests can drive the proxy against loopback services without relaxing the
//! address validation that the production resolver performs.

use core::future::Future;
use core::pin::Pin;
use std::io;
use std::net::SocketAddrV4;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// A bidirectional upstream byte stream.
pub trait UpstreamStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> UpstreamStream for T {}

/// An owned upstream byte stream.
pub type BoxedUpstreamStream = Box<dyn UpstreamStream>;

/// A future returned by an [`UpstreamConnector`].
pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<BoxedUpstreamStream>> + Send + 'a>>;

/// Opens upstream TCP connections to pinned addresses.
pub trait UpstreamConnector: Send + Sync + 'static {
    /// Connects to `target`, which is always a pinned address combined with an
    /// authorized destination port.
    fn connect(&self, target: SocketAddrV4) -> ConnectFuture<'_>;
}

/// The production connector: a plain TCP connection with `TCP_NODELAY` set.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpUpstreamConnector;

impl UpstreamConnector for TcpUpstreamConnector {
    fn connect(&self, target: SocketAddrV4) -> ConnectFuture<'_> {
        Box::pin(async move {
            let stream = TcpStream::connect(target).await?;
            // Proxied requests are latency sensitive and already batched by
            // hyper's writer.
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxedUpstreamStream)
        })
    }
}
