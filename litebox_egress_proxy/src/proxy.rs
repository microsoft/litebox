// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Connection acceptance, authorization, and CONNECT tunnelling.
//!
//! Every CONNECT request is authorized before DNS or upstream activity. A
//! successful request consumes its client connection by upgrading it to one
//! bounded bidirectional tunnel.

use core::convert::Infallible;
use core::time::Duration;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::http::uri::Authority;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::authority::{RequestAuthority, parse_authority};
use crate::policy::HostPolicy;
use crate::stream::LimitedStream;
use crate::upstream::{BoxedUpstreamStream, UpstreamConnector};

const MAX_CONCURRENT_CLIENT_CONNECTIONS: usize = 256;
const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADER_FIELDS: usize = 100;
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Response body type produced by the proxy.
type ProxyBody = Empty<Bytes>;

/// Immutable state shared by every connection.
pub struct ProxyState {
    policy: HostPolicy,
    connector: Box<dyn UpstreamConnector>,
}

impl ProxyState {
    /// Builds shared state from a validated policy and upstream connector.
    pub fn new(policy: HostPolicy, connector: Box<dyn UpstreamConnector>) -> Self {
        Self { policy, connector }
    }
}

/// Serves client connections until `listener` fails.
pub async fn serve(listener: TcpListener, state: Arc<ProxyState>) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENT_CONNECTIONS));

    loop {
        let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
            return Err(io::Error::other("connection slot semaphore closed"));
        };

        let stream = match listener.accept().await {
            Ok((stream, _peer)) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            serve_connection(state, stream, permit).await;
        });
    }
}

/// Serves one CONNECT tunnel or rejection on a client connection.
async fn serve_connection(state: Arc<ProxyState>, stream: TcpStream, permit: OwnedSemaphorePermit) {
    if stream.set_nodelay(true).is_err() {
        return;
    }

    let io = TokioIo::new(LimitedStream::new(stream, IDLE_TIMEOUT));
    let permit = Arc::new(permit);
    let service = service_fn(move |request: Request<Incoming>| {
        let state = Arc::clone(&state);
        let permit = Arc::clone(&permit);
        async move { Ok::<_, Infallible>(handle_request(state, permit, request).await) }
    });

    let mut builder = server_http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Some(REQUEST_HEADER_READ_TIMEOUT))
        .max_buf_size(MAX_REQUEST_HEADER_BYTES)
        .max_headers(MAX_HEADER_FIELDS);

    if let Err(error) = builder.serve_connection(io, service).with_upgrades().await {
        diagnostic(format_args!("client connection ended: {error}"));
    }
}

/// Dispatches one request.
async fn handle_request(
    state: Arc<ProxyState>,
    permit: Arc<OwnedSemaphorePermit>,
    request: Request<Incoming>,
) -> Response<ProxyBody> {
    if request.method() != Method::CONNECT {
        return status_response(StatusCode::NOT_IMPLEMENTED);
    }
    handle_connect(&state, permit, request).await
}

/// Handles one CONNECT tunnel request.
async fn handle_connect(
    state: &ProxyState,
    permit: Arc<OwnedSemaphorePermit>,
    mut request: Request<Incoming>,
) -> Response<ProxyBody> {
    if request.headers().contains_key(header::UPGRADE) {
        return status_response(StatusCode::NOT_IMPLEMENTED);
    }
    if request.headers().contains_key(header::TRANSFER_ENCODING)
        || request.headers().contains_key(header::CONTENT_LENGTH)
        || request.headers().get_all(header::HOST).iter().count() > 1
    {
        return status_response(StatusCode::BAD_REQUEST);
    }

    let Some(authority) = connect_authority(request.uri()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };

    if !host_header_is_consistent(&request, &authority) {
        return status_response(StatusCode::BAD_REQUEST);
    }

    if !state.policy.allows(authority.host(), authority.port()) {
        return status_response(StatusCode::FORBIDDEN);
    }

    let upstream = match connect_upstream(state, &authority).await {
        Ok(stream) => LimitedStream::new(stream, IDLE_TIMEOUT),
        Err(status) => return status_response(status),
    };

    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let _permit = permit;
        match upgrade.await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                let mut upstream = upstream;
                if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                {
                    diagnostic(format_args!("tunnel ended: {error}"));
                }
            }
            Err(error) => diagnostic(format_args!("tunnel upgrade failed: {error}")),
        }
    });

    let mut response = Response::new(Empty::new());
    *response.status_mut() = StatusCode::OK;
    response
}

/// Canonicalizes the authority-form target of a CONNECT request.
fn connect_authority(uri: &Uri) -> Option<RequestAuthority> {
    if uri.scheme_str().is_some() || !uri.path().is_empty() || uri.query().is_some() {
        return None;
    }
    let raw = uri.authority().map(Authority::as_str)?;
    parse_authority(raw, None).ok()
}

/// Returns whether a CONNECT Host header matches the request target.
fn host_header_is_consistent(request: &Request<Incoming>, authority: &RequestAuthority) -> bool {
    let Some(value) = request.headers().get(header::HOST) else {
        return true;
    };
    value
        .to_str()
        .ok()
        .and_then(|raw| parse_authority(raw, None).ok())
        .is_some_and(|host_header| &host_header == authority)
}

/// Resolves and connects to an authorized hostname.
async fn connect_upstream(
    state: &ProxyState,
    authority: &RequestAuthority,
) -> Result<BoxedUpstreamStream, StatusCode> {
    let result = timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        state
            .connector
            .connect(authority.host().clone(), authority.port()),
    )
    .await;
    match result {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_error)) => Err(StatusCode::BAD_GATEWAY),
        Err(_elapsed) => Err(StatusCode::GATEWAY_TIMEOUT),
    }
}

fn status_response(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(Empty::new());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

fn diagnostic(message: core::fmt::Arguments<'_>) {
    eprintln!("litebox_egress_proxy: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(raw: &str) -> Uri {
        raw.parse().unwrap()
    }

    #[test]
    fn connect_targets_must_be_authority_form() {
        let authority = connect_authority(&uri("example.com:443")).unwrap();
        assert_eq!(authority.host().as_str(), "example.com");
        assert_eq!(authority.port(), 443);

        assert!(connect_authority(&uri("http://example.com:443")).is_none());
        assert!(connect_authority(&uri("example.com")).is_none());
        assert!(connect_authority(&uri("example.com:0")).is_none());
    }
}
