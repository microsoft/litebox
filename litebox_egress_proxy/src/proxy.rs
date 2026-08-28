// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The proxy itself: connection acceptance, authorization, HTTP forwarding and
//! CONNECT tunnelling.
//!
//! Every raw-validated request is authorized before any DNS or upstream
//! activity against the immutable policy and pinned address table. Plain HTTP
//! responses close the client connection, so no pipelined second request can
//! bypass raw validation. A successful CONNECT consumes its connection by
//! upgrading it to a tunnel. No upstream connection is ever reused.

use core::convert::Infallible;
use core::error::Error as StdError;
use std::io;
use std::net::SocketAddrV4;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::header::{self, HeaderValue};
use hyper::http::uri::Authority;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::authority::{DEFAULT_HTTP_PORT, RequestAuthority, host_header_matches, parse_authority};
use crate::dns::PinnedTable;
use crate::headers::{
    remove_framing_headers, strip_hop_by_hop, validate_connect_framing, validate_request_framing,
    validate_response_framing,
};
use crate::limits::{
    CLIENT_CLOSE_DRAIN_TIMEOUT, IDLE_TIMEOUT, MAX_CLIENT_CLOSE_DRAIN_BYTES,
    MAX_CONCURRENT_CLIENT_CONNECTIONS, MAX_HEADER_FIELDS, MAX_REQUEST_HEADER_BYTES,
    MAX_RESPONSE_HEADER_BYTES, REQUEST_HEADER_READ_TIMEOUT, TOTAL_REQUEST_TIMEOUT,
    UPSTREAM_CONNECT_TIMEOUT,
};
use crate::policy::HostPolicy;
use crate::request_head::read_validated_request_prefix;
use crate::stream::{LimitedStream, PrefixedStream, share_tcp_read};
use crate::upstream::{BoxedUpstreamStream, UpstreamConnector};

/// Boxed error type used by the proxied response bodies.
type BoxError = Box<dyn StdError + Send + Sync>;

/// The response body type produced by the proxy.
type ProxyBody = BoxBody<Bytes, BoxError>;

/// Immutable state shared by every connection.
///
/// The policy and the pinned table are fixed at startup; the connector is an
/// injected abstraction so that the request path can be exercised without a
/// real network.
pub struct ProxyState {
    policy: HostPolicy,
    pinned: PinnedTable,
    connector: Arc<dyn UpstreamConnector>,
}

impl ProxyState {
    /// Builds the shared state from an already validated policy and table.
    pub fn new(
        policy: HostPolicy,
        pinned: PinnedTable,
        connector: Arc<dyn UpstreamConnector>,
    ) -> Self {
        Self {
            policy,
            pinned,
            connector,
        }
    }

    /// Returns the policy in force.
    pub fn policy(&self) -> &HostPolicy {
        &self.policy
    }

    /// Returns the immutable startup resolution table.
    pub fn pinned(&self) -> &PinnedTable {
        &self.pinned
    }
}

/// Serves client connections until `listener` fails.
///
/// At most [`MAX_CONCURRENT_CLIENT_CONNECTIONS`] connections are served at a
/// time; further connections wait in the listener backlog. Accept errors that
/// concern a single connection are ignored, every other accept error fails
/// closed.
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

/// Serves exactly one request or CONNECT tunnel on a client connection.
async fn serve_connection(state: Arc<ProxyState>, stream: TcpStream, permit: OwnedSemaphorePermit) {
    // `set_nodelay` failing means the connection is already unusable.
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

/// Drains bounded client input so unread bytes cannot replace the response
/// with a connection reset during close.
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

/// Dispatches one client request.
async fn handle_request(
    state: Arc<ProxyState>,
    connection_slot: Arc<Mutex<Option<OwnedSemaphorePermit>>>,
    request: Request<Incoming>,
) -> Response<ProxyBody> {
    let is_connect = request.method() == Method::CONNECT;
    let mut response = if is_connect {
        handle_connect(&state, connection_slot, request).await
    } else {
        handle_forward(&state, request).await
    };

    // Plain HTTP and rejected CONNECT requests close after this response, so
    // Hyper cannot dispatch a second head that bypassed raw prevalidation.
    // Successful CONNECT responses omit this header because the connection is
    // consumed by the upgraded tunnel.
    if !is_connect || !response.status().is_success() {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// Handles a plain HTTP/1 forward-proxy request.
async fn handle_forward(state: &ProxyState, request: Request<Incoming>) -> Response<ProxyBody> {
    if !matches!(request.version(), Version::HTTP_10 | Version::HTTP_11) {
        return status_response(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
    }

    // Protocol upgrades other than CONNECT are not supported.
    if request.headers().contains_key(header::UPGRADE) {
        return status_response(StatusCode::NOT_IMPLEMENTED);
    }

    if validate_request_framing(request.headers(), request.version()).is_err() {
        return status_response(StatusCode::BAD_REQUEST);
    }

    let Some(authority) = forward_authority(request.uri()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };

    let Some(origin_target) = origin_form_target(request.uri()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };

    if !host_header_is_consistent(&request, &authority, Some(DEFAULT_HTTP_PORT)) {
        return status_response(StatusCode::BAD_REQUEST);
    }

    // Authorization happens before any DNS or upstream activity.
    if !state.policy.allows(authority.host(), authority.port()) {
        return status_response(StatusCode::FORBIDDEN);
    }

    let upstream = match connect_upstream(state, &authority).await {
        Ok(stream) => LimitedStream::with_deadline(stream, IDLE_TIMEOUT, TOTAL_REQUEST_TIMEOUT),
        Err(failure) => return status_response(failure.status()),
    };

    forward_to_upstream(request, &authority, origin_target, upstream).await
}

/// Rewrites and relays a request over its own upstream connection.
async fn forward_to_upstream(
    request: Request<Incoming>,
    authority: &RequestAuthority,
    origin_target: Uri,
    upstream: LimitedStream<BoxedUpstreamStream>,
) -> Response<ProxyBody> {
    let (mut parts, body) = request.into_parts();

    // Absolute-form has already been reduced to origin form for the upstream
    // server.
    parts.uri = origin_target;
    parts.version = Version::HTTP_11;

    strip_hop_by_hop(&mut parts.headers);
    // The outgoing message is framed from the forwarded body, never from a
    // length the client claimed.
    remove_framing_headers(&mut parts.headers);
    parts.headers.remove(header::HOST);
    let Ok(host_value) = HeaderValue::from_str(&authority.host_header_value()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    parts.headers.insert(header::HOST, host_value);

    let handshake = client_http1::Builder::new()
        .max_buf_size(MAX_RESPONSE_HEADER_BYTES)
        .max_headers(MAX_HEADER_FIELDS)
        .handshake(TokioIo::new(upstream))
        .await;

    let (mut sender, connection) = match handshake {
        Ok(pair) => pair,
        Err(error) => {
            diagnostic(format_args!("upstream handshake failed: {error}"));
            return status_response(StatusCode::BAD_GATEWAY);
        }
    };

    // The connection task drives the request and response bodies; it ends when
    // the response body is dropped or the upstream closes.
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            diagnostic(format_args!("upstream connection ended: {error}"));
        }
    });

    let upstream_response = match sender.send_request(Request::from_parts(parts, body)).await {
        Ok(response) => response,
        Err(error) => {
            diagnostic(format_args!("upstream request failed: {error}"));
            return status_response(StatusCode::BAD_GATEWAY);
        }
    };

    let (mut response_parts, response_body) = upstream_response.into_parts();
    if validate_response_framing(&response_parts.headers, response_parts.version).is_err() {
        return status_response(StatusCode::BAD_GATEWAY);
    }
    strip_hop_by_hop(&mut response_parts.headers);
    remove_framing_headers(&mut response_parts.headers);
    Response::from_parts(
        response_parts,
        response_body.map_err(BoxError::from).boxed(),
    )
}

/// Handles a CONNECT tunnel request.
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

    // A `Host` header accompanying CONNECT has to state the port explicitly;
    // there is no scheme from which a default could be derived.
    if !host_header_is_consistent(&request, &authority, None) {
        return status_response(StatusCode::BAD_REQUEST);
    }

    if !state.policy.allows(authority.host(), authority.port()) {
        return status_response(StatusCode::FORBIDDEN);
    }

    // Success is reported only after the upstream connection exists.
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

/// Canonicalizes the authority of an absolute-form `http` request target.
fn forward_authority(uri: &Uri) -> Option<RequestAuthority> {
    // Only absolute-form targets are accepted; origin-form and asterisk-form
    // requests are not proxy requests.
    let scheme = uri.scheme_str()?;
    if !scheme.eq_ignore_ascii_case("http") {
        // `https` absolute URIs are rejected: HTTPS uses CONNECT.
        return None;
    }
    let raw = uri.authority().map(Authority::as_str)?;
    parse_authority(raw, Some(DEFAULT_HTTP_PORT)).ok()
}

/// Reduces an absolute-form target to the origin form sent upstream.
///
/// Control bytes, whitespace and non-ASCII bytes never belong in a request
/// target: each could make the proxy and an upstream server disagree about the
/// resource being requested. Fragments are rejected from the raw target before
/// `hyper` can discard them.
fn origin_form_target(uri: &Uri) -> Option<Uri> {
    let path = uri.path();
    let target = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    if target.is_empty() || !target.is_ascii() {
        return None;
    }
    if target
        .bytes()
        .any(|byte| byte <= 0x20 || byte == 0x7f || byte == b'#')
    {
        return None;
    }
    target.parse::<Uri>().ok()
}

/// Canonicalizes the authority-form target of a CONNECT request.
fn connect_authority(uri: &Uri) -> Option<RequestAuthority> {
    if uri.scheme_str().is_some() || !uri.path().is_empty() || uri.query().is_some() {
        return None;
    }
    let raw = uri.authority().map(Authority::as_str)?;
    // CONNECT requires an explicit, nonzero port.
    parse_authority(raw, None).ok()
}

/// Returns whether the `Host` header, if any, matches the request target.
fn host_header_is_consistent(
    request: &Request<Incoming>,
    authority: &RequestAuthority,
    default_port: Option<u16>,
) -> bool {
    let Some(value) = request.headers().get(header::HOST) else {
        return true;
    };
    value
        .to_str()
        .is_ok_and(|raw| host_header_matches(raw, authority, default_port))
}

/// Reason no upstream connection could be established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpstreamFailure {
    /// The hostname had no pinned address. Authorized hostnames always have
    /// one, so this can only be an internal inconsistency.
    NoPinnedAddress,
    /// Every pinned address refused the connection or failed.
    AllAttemptsFailed,
    /// At least one attempt exceeded the connect timeout and none succeeded.
    TimedOut,
}

impl UpstreamFailure {
    /// Maps the failure onto the status reported to the client.
    fn status(self) -> StatusCode {
        match self {
            Self::NoPinnedAddress | Self::AllAttemptsFailed => StatusCode::BAD_GATEWAY,
            Self::TimedOut => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

/// Attempts pinned addresses in their stable startup order.
async fn connect_upstream(
    state: &ProxyState,
    authority: &RequestAuthority,
) -> Result<BoxedUpstreamStream, UpstreamFailure> {
    let addresses = state.pinned.addresses(authority.host());
    if addresses.is_empty() {
        return Err(UpstreamFailure::NoPinnedAddress);
    }

    let attempts = async {
        for address in addresses {
            let target = SocketAddrV4::new(*address, authority.port());
            if let Ok(stream) = state.connector.connect(target).await {
                return Ok(stream);
            }
        }
        Err(UpstreamFailure::AllAttemptsFailed)
    };
    timeout(UPSTREAM_CONNECT_TIMEOUT, attempts)
        .await
        .unwrap_or(Err(UpstreamFailure::TimedOut))
}

/// Builds an empty proxied body.
fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Builds a bodiless response that also closes the client connection.
fn status_response(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(empty_body());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// Writes one diagnostic line to standard error.
///
/// Diagnostics never contain request bytes: only proxy-generated text and
/// library error messages are logged.
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
    fn forward_targets_must_be_absolute_http() {
        let authority = forward_authority(&uri("http://Example.com/path?q=1")).unwrap();
        assert_eq!(authority.host().as_str(), "example.com");
        assert_eq!(authority.port(), 80);

        assert!(forward_authority(&uri("https://example.com/")).is_none());
        assert!(forward_authority(&uri("/relative")).is_none());
        assert!(forward_authority(&uri("http://user@example.com/")).is_none());
        assert!(forward_authority(&uri("http://192.0.2.5/")).is_none());
    }

    #[test]
    fn origin_form_targets_are_canonical() {
        assert_eq!(
            origin_form_target(&uri("http://example.com/path?q=1"))
                .unwrap()
                .to_string(),
            "/path?q=1"
        );
        assert_eq!(
            origin_form_target(&uri("http://example.com"))
                .unwrap()
                .to_string(),
            "/"
        );
        assert_eq!(
            origin_form_target(&uri("http://example.com?q=1"))
                .unwrap()
                .to_string(),
            "/?q=1"
        );
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
        assert_eq!(
            UpstreamFailure::AllAttemptsFailed.status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            UpstreamFailure::NoPinnedAddress.status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            UpstreamFailure::TimedOut.status(),
            StatusCode::GATEWAY_TIMEOUT
        );
    }
}
