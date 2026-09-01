// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Connection acceptance, authorization, and CONNECT tunnelling.
//!
//! Every raw-validated CONNECT request is authorized before DNS or upstream
//! activity. A successful request consumes its client connection by upgrading
//! it to one bounded bidirectional tunnel.

use core::convert::Infallible;
use core::error::Error as StdError;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::http::uri::Authority;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::authority::{RequestAuthority, parse_authority};
use crate::headers::validate_connect_framing;
use crate::limits::{
    CLIENT_CLOSE_DRAIN_TIMEOUT, IDLE_TIMEOUT, MAX_CLIENT_CLOSE_DRAIN_BYTES,
    MAX_CONCURRENT_CLIENT_CONNECTIONS, MAX_HEADER_FIELDS, MAX_REQUEST_HEADER_BYTES,
    REQUEST_HEADER_READ_TIMEOUT, UPSTREAM_CONNECT_TIMEOUT,
};
use crate::policy::HostPolicy;
use crate::request_head::read_validated_request_prefix;
use crate::stream::{LimitedStream, PrefixedStream, share_tcp_read};
use crate::upstream::{BoxedUpstreamStream, UpstreamConnector};

/// Boxed error type used by response bodies.
type BoxError = Box<dyn StdError + Send + Sync>;

/// Response body type produced by the proxy.
type ProxyBody = BoxBody<Bytes, BoxError>;

/// Immutable state shared by every connection.
pub struct ProxyState {
    policy: HostPolicy,
    connector: Arc<dyn UpstreamConnector>,
}

impl ProxyState {
    /// Builds shared state from a validated policy and upstream connector.
    pub fn new(policy: HostPolicy, connector: Arc<dyn UpstreamConnector>) -> Self {
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

    let (stream, mut drain_handle) = share_tcp_read(stream);
    let mut stream = LimitedStream::new(stream, IDLE_TIMEOUT);
    let prefix = match read_validated_request_prefix(&mut stream).await {
        Ok(prefix) => prefix.into_bytes(),
        Err(error) => {
            if let Some(response) = error.response() {
                if let Err(write_error) = stream.write_all(response).await {
                    diagnostic(format_args!(
                        "failed to write request rejection after {error}: {write_error}"
                    ));
                } else {
                    let _ = stream.shutdown().await;
                    drain_client_input(&mut stream).await;
                }
            }
            return;
        }
    };

    let io = TokioIo::new(PrefixedStream::new(prefix, stream));
    let connection_slot = Arc::new(Mutex::new(Some(permit)));
    let service_connection_slot = Arc::clone(&connection_slot);
    let service = service_fn(move |request: Request<Incoming>| {
        let state = Arc::clone(&state);
        let connection_slot = Arc::clone(&service_connection_slot);
        async move { Ok::<_, Infallible>(handle_request(state, connection_slot, request).await) }
    });

    let mut builder = server_http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Some(REQUEST_HEADER_READ_TIMEOUT))
        .max_buf_size(MAX_REQUEST_HEADER_BYTES)
        .max_headers(MAX_HEADER_FIELDS)
        .keep_alive(true)
        .half_close(true);

    let result = builder.serve_connection(io, service).with_upgrades().await;
    let upgraded = connection_slot.lock().await.is_none();
    if !upgraded {
        drain_client_input(&mut drain_handle).await;
    }
    if let Err(error) = result {
        diagnostic(format_args!("client connection ended: {error}"));
    }
}

/// Drains bounded client input so unread bytes cannot reset a rejection.
async fn drain_client_input<S>(stream: &mut S)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let drain = async {
        let mut remaining = MAX_CLIENT_CLOSE_DRAIN_BYTES;
        let mut buffer = [0_u8; 1024];
        while remaining != 0 {
            let capacity = remaining.min(buffer.len());
            let read = stream.read(&mut buffer[..capacity]).await?;
            if read == 0 {
                break;
            }
            remaining -= read;
        }
        Ok::<(), io::Error>(())
    };
    let _ = timeout(CLIENT_CLOSE_DRAIN_TIMEOUT, drain).await;
}

/// Dispatches one request.
async fn handle_request(
    state: Arc<ProxyState>,
    connection_slot: Arc<Mutex<Option<OwnedSemaphorePermit>>>,
    request: Request<Incoming>,
) -> Response<ProxyBody> {
    let is_connect = request.method() == Method::CONNECT;
    let mut response = if is_connect {
        handle_connect(&state, connection_slot, request).await
    } else {
        status_response(StatusCode::NOT_IMPLEMENTED)
    };

    if !is_connect || !response.status().is_success() {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// Handles one CONNECT tunnel request.
async fn handle_connect(
    state: &ProxyState,
    connection_slot: Arc<Mutex<Option<OwnedSemaphorePermit>>>,
    mut request: Request<Incoming>,
) -> Response<ProxyBody> {
    if request.headers().contains_key(header::UPGRADE) {
        return status_response(StatusCode::NOT_IMPLEMENTED);
    }
    if validate_connect_framing(request.headers()).is_err() {
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
        Err(failure) => return status_response(failure.status()),
    };

    let Some(permit) = connection_slot.lock().await.take() else {
        return status_response(StatusCode::SERVICE_UNAVAILABLE);
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

    let mut response = Response::new(empty_body());
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

/// Reason no upstream connection could be established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpstreamFailure {
    Failed,
    TimedOut,
}

impl UpstreamFailure {
    fn status(self) -> StatusCode {
        match self {
            Self::Failed => StatusCode::BAD_GATEWAY,
            Self::TimedOut => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

/// Resolves and connects to an authorized hostname.
async fn connect_upstream(
    state: &ProxyState,
    authority: &RequestAuthority,
) -> Result<BoxedUpstreamStream, UpstreamFailure> {
    timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        state
            .connector
            .connect(authority.host().clone(), authority.port()),
    )
    .await
    .map_err(|_elapsed| UpstreamFailure::TimedOut)?
    .map_err(|_error| UpstreamFailure::Failed)
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn status_response(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(empty_body());
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

    #[test]
    fn upstream_failures_map_to_statuses() {
        assert_eq!(UpstreamFailure::Failed.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            UpstreamFailure::TimedOut.status(),
            StatusCode::GATEWAY_TIMEOUT
        );
    }
}
