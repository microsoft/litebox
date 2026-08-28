// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hermetic loopback tests for the proxy request path.
//!
//! The tests inject a [`HostResolver`] and an [`UpstreamConnector`] instead of
//! touching DNS or the network. The injected resolver answers with ordinary
//! globally routable addresses, so the pinned table is built under exactly the
//! production address rules, and only the injected connector maps those pinned
//! addresses onto loopback test servers. No production validation is relaxed
//! for these tests.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use litebox_egress_proxy::dns::{
    HostResolver, PinnedTable, ResolveError, ResolveFuture, TargetPolicy,
};
use litebox_egress_proxy::listener::{ListenerSource, acquire};
use litebox_egress_proxy::policy::{HostPolicy, HostRule, Hostname};
use litebox_egress_proxy::proxy::{ProxyState, serve};
use litebox_egress_proxy::upstream::{BoxedUpstreamStream, ConnectFuture, UpstreamConnector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Bound on every test-side network wait.
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A resolver with a fixed, hermetic answer table.
struct StaticResolver {
    answers: HashMap<Hostname, Vec<Ipv4Addr>>,
}

impl HostResolver for StaticResolver {
    fn resolve(&self, host: Hostname) -> ResolveFuture<'_> {
        let answer = self
            .answers
            .get(&host)
            .cloned()
            .ok_or(ResolveError::NoAddresses);
        Box::pin(async move { answer })
    }
}

/// A connector that routes pinned addresses to loopback test servers.
struct LoopbackConnector {
    routes: HashMap<SocketAddrV4, SocketAddr>,
    attempts: Arc<AtomicUsize>,
}

impl UpstreamConnector for LoopbackConnector {
    fn connect(&self, target: SocketAddrV4) -> ConnectFuture<'_> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let route = self.routes.get(&target).copied();
        Box::pin(async move {
            let Some(route) = route else {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            };
            let stream = TcpStream::connect(route).await?;
            Ok(Box::new(stream) as BoxedUpstreamStream)
        })
    }
}

/// A running proxy under test.
struct TestProxy {
    address: SocketAddrV4,
    attempts: Arc<AtomicUsize>,
}

impl TestProxy {
    /// Starts a proxy with `rules` in force, routing `routes` to loopback.
    ///
    /// Every policy hostname resolves to a distinct globally routable address
    /// that satisfies the production address rules, and only the listed
    /// `(host, port)` pairs have a working upstream.
    async fn start(rules: &[&str], routes: &[(&str, u16, SocketAddr)]) -> Self {
        let policy = HostPolicy::from_rules(
            rules
                .iter()
                .map(|rule| rule.parse::<HostRule>().expect("valid rule"))
                .collect::<Vec<_>>(),
        )
        .expect("valid policy");

        let mut answers = HashMap::new();
        for (index, host) in policy.hostnames().enumerate() {
            let last = u8::try_from(index + 1).expect("few test hosts");
            answers.insert(host.clone(), vec![Ipv4Addr::new(93, 184, 216, last)]);
        }

        let mut mapped = HashMap::new();
        for (host, port, address) in routes {
            let host = Hostname::parse(host).expect("valid hostname");
            let pinned = answers.get(&host).expect("routed host is in policy")[0];
            mapped.insert(SocketAddrV4::new(pinned, *port), *address);
        }

        let resolver = StaticResolver { answers };
        let pinned =
            PinnedTable::resolve(&policy, &TargetPolicy::public_only(), Arc::new(resolver))
                .await
                .expect("hermetic resolution succeeds");

        let attempts = Arc::new(AtomicUsize::new(0));
        let connector = LoopbackConnector {
            routes: mapped,
            attempts: Arc::clone(&attempts),
        };
        let state = Arc::new(ProxyState::new(policy, pinned, Arc::new(connector)));

        let listener = acquire(ListenerSource::Bind(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            0,
        )))
        .expect("loopback listener");
        let listener = TcpListener::from_std(listener).expect("async listener");
        let SocketAddr::V4(address) = listener.local_addr().expect("listener address") else {
            panic!("expected an IPv4 listener");
        };

        tokio::spawn(async move {
            let _ = serve(listener, state).await;
        });

        Self { address, attempts }
    }

    /// Number of upstream connection attempts made so far.
    fn upstream_attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    /// Opens a client connection to the proxy.
    async fn connect(&self) -> ProxyClient {
        let stream = timeout(TEST_TIMEOUT, TcpStream::connect(self.address))
            .await
            .expect("connect did not time out")
            .expect("client connects to the proxy");
        ProxyClient {
            stream,
            buffer: Vec::new(),
        }
    }

    /// Sends one request on a fresh connection and reads one response.
    async fn request(&self, raw: &str) -> HttpResponse {
        let mut client = self.connect().await;
        client.send(raw.as_bytes()).await;
        client.read_response().await
    }
}

/// A raw HTTP client, so that malformed requests can be sent verbatim.
struct ProxyClient {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl ProxyClient {
    async fn send(&mut self, bytes: &[u8]) {
        timeout(TEST_TIMEOUT, self.stream.write_all(bytes))
            .await
            .expect("write did not time out")
            .expect("write succeeds");
    }

    /// Reads more bytes into the buffer, returning `false` at end of stream.
    async fn fill(&mut self) -> bool {
        let mut chunk = [0_u8; 4096];
        let read = timeout(TEST_TIMEOUT, self.stream.read(&mut chunk))
            .await
            .expect("read did not time out")
            .expect("read succeeds");
        if read == 0 {
            return false;
        }
        self.buffer.extend_from_slice(&chunk[..read]);
        true
    }

    /// Reads one complete HTTP response.
    async fn read_response(&mut self) -> HttpResponse {
        let head_end = loop {
            if let Some(index) = find_subslice(&self.buffer, b"\r\n\r\n") {
                break index + 4;
            }
            assert!(
                self.fill().await,
                "connection closed before a response head"
            );
        };

        let head = String::from_utf8(self.buffer[..head_end].to_vec()).expect("ASCII head");
        self.buffer.drain(..head_end);

        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .expect("status code");

        let length = header_value(&head, "content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        while self.buffer.len() < length {
            assert!(self.fill().await, "connection closed before the body ended");
        }
        let body = self.buffer.drain(..length).collect::<Vec<_>>();

        HttpResponse { status, head, body }
    }

    /// Reads exactly `length` raw bytes, used for tunnelled traffic.
    async fn read_exact(&mut self, length: usize) -> Vec<u8> {
        while self.buffer.len() < length {
            assert!(
                self.fill().await,
                "connection closed before the tunnel data"
            );
        }
        self.buffer.drain(..length).collect()
    }
}

/// A parsed response.
struct HttpResponse {
    status: u16,
    head: String,
    body: Vec<u8>,
}

/// Finds `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Returns the first value of `name` in a message head.
fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

/// Starts a loopback server that records one request per connection and replies
/// with `response`.
async fn recording_upstream(
    response: &'static str,
) -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let (sender, receiver) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let sender = sender.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0_u8; 4096];

                let head_end = loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                    }
                    if let Some(index) = find_subslice(&buffer, b"\r\n\r\n") {
                        break index + 4;
                    }
                };

                let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
                let body_length = header_value(&head, "content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                let chunked = header_value(&head, "transfer-encoding")
                    .is_some_and(|value| value.eq_ignore_ascii_case("chunked"));

                while buffer.len() < head_end + body_length
                    || (chunked && find_subslice(&buffer, b"0\r\n\r\n").is_none())
                {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                    }
                }

                let _ = sender.send(String::from_utf8_lossy(&buffer).into_owned());
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    (address, receiver)
}

/// Starts a loopback echo server for tunnel tests.
async fn echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("echo listener");
    let address = listener.local_addr().expect("echo address");

    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    address
}

const OK_RESPONSE: &str =
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nhi";

#[tokio::test]
async fn forward_request_is_rewritten_and_relayed() {
    let (upstream, mut requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let response = proxy
        .request(concat!(
            "GET http://Allowed.Example/path?q=1 HTTP/1.1\r\n",
            "Host: allowed.example\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "Connection: X-Secret\r\n",
            "X-Secret: value\r\n",
            "X-Kept: value\r\n",
            "\r\n"
        ))
        .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hi");

    let forwarded = timeout(TEST_TIMEOUT, requests.recv())
        .await
        .expect("upstream received a request")
        .expect("request text");

    assert!(
        forwarded.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
        "unexpected request line in {forwarded:?}"
    );
    assert_eq!(
        header_value(&forwarded, "host").as_deref(),
        Some("allowed.example")
    );
    assert!(header_value(&forwarded, "proxy-connection").is_none());
    assert!(header_value(&forwarded, "connection").is_none());
    assert!(header_value(&forwarded, "x-secret").is_none());
    assert_eq!(header_value(&forwarded, "x-kept").as_deref(), Some("value"));
}

#[tokio::test]
async fn empty_absolute_path_with_query_is_normalized() {
    let (upstream, mut requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let response = proxy
        .request("GET http://allowed.example?query=1 HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
        .await;
    assert_eq!(response.status, 200);

    let forwarded = timeout(TEST_TIMEOUT, requests.recv())
        .await
        .expect("upstream received the request")
        .expect("request text");
    assert!(forwarded.starts_with("GET /?query=1 HTTP/1.1\r\n"));
}

#[tokio::test]
async fn forward_request_body_is_relayed() {
    let (upstream, mut requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:8080"],
        &[("allowed.example", 8080, upstream)],
    )
    .await;

    let response = proxy
        .request(concat!(
            "POST http://allowed.example:8080/submit HTTP/1.1\r\n",
            "Host: allowed.example:8080\r\n",
            "Content-Length: 5\r\n",
            "\r\n",
            "hello"
        ))
        .await;

    assert_eq!(response.status, 200);

    let forwarded = timeout(TEST_TIMEOUT, requests.recv())
        .await
        .expect("upstream received a request")
        .expect("request text");

    assert!(forwarded.starts_with("POST /submit HTTP/1.1\r\n"));
    assert_eq!(
        header_value(&forwarded, "host").as_deref(),
        Some("allowed.example:8080")
    );
    assert!(
        forwarded.ends_with("hello"),
        "body missing in {forwarded:?}"
    );
}

#[tokio::test]
async fn disallowed_host_is_denied_without_upstream_activity() {
    let (upstream, _requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let response = proxy
        .request("GET http://denied.example/ HTTP/1.1\r\nHost: denied.example\r\n\r\n")
        .await;

    assert_eq!(response.status, 403);
    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn denied_request_body_is_drained_before_close() {
    let (upstream, _requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let body = "x".repeat(32 * 1024);
    let request = format!(
        "POST http://denied.example/upload HTTP/1.1\r\n\
         Host: denied.example\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len()
    );

    let mut client = proxy.connect().await;
    client.send(request.as_bytes()).await;
    let response = client.read_response().await;
    assert_eq!(response.status, 403);
    assert!(!client.fill().await);
    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn disallowed_port_is_denied() {
    let (upstream, _requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let response = proxy
        .request("GET http://allowed.example:8443/ HTTP/1.1\r\nHost: allowed.example:8443\r\n\r\n")
        .await;

    assert_eq!(response.status, 403);
    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn reserved_dns_port_is_denied() {
    let (upstream, _requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let response = proxy
        .request("CONNECT allowed.example:53 HTTP/1.1\r\nHost: allowed.example:53\r\n\r\n")
        .await;

    assert_eq!(response.status, 403);
    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn malformed_and_unsupported_requests_are_rejected() {
    let (upstream, _requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    // Host header disagreeing with the request target.
    let mismatched = proxy
        .request("GET http://allowed.example/ HTTP/1.1\r\nHost: other.example\r\n\r\n")
        .await;
    assert_eq!(mismatched.status, 400);

    // HTTPS must use CONNECT.
    let https = proxy
        .request("GET https://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
        .await;
    assert_eq!(https.status, 400);

    // Origin-form targets are not proxy requests.
    let origin_form = proxy
        .request("GET /path HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
        .await;
    assert_eq!(origin_form.status, 400);

    // IP-literal authorities belong to direct policy, not hostname policy.
    let ip_literal = proxy
        .request("GET http://93.184.216.1/ HTTP/1.1\r\nHost: 93.184.216.1\r\n\r\n")
        .await;
    assert_eq!(ip_literal.status, 400);

    // Userinfo could make the proxy and an origin server disagree.
    let userinfo = proxy
        .request("GET http://user@allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
        .await;
    assert_eq!(userinfo.status, 400);

    // Hyper discards fragments, so they must be rejected from the raw target.
    let fragment = proxy
        .request(
            "GET http://allowed.example/path#fragment HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
        )
        .await;
    assert_eq!(fragment.status, 400);

    // Simultaneous Content-Length and Transfer-Encoding is ambiguous framing.
    let ambiguous = proxy
        .request(concat!(
            "POST http://allowed.example/ HTTP/1.1\r\n",
            "Host: allowed.example\r\n",
            "Content-Length: 5\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n"
        ))
        .await;
    assert_eq!(ambiguous.status, 400);

    let reversed_ambiguous = proxy
        .request(concat!(
            "POST http://allowed.example/ HTTP/1.1\r\n",
            "Host: allowed.example\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 5\r\n",
            "\r\n",
            "0\r\n\r\n"
        ))
        .await;
    assert_eq!(reversed_ambiguous.status, 400);

    let duplicate_length = proxy
        .request(concat!(
            "POST http://allowed.example/ HTTP/1.1\r\n",
            "Host: allowed.example\r\n",
            "Content-Length: 0\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        ))
        .await;
    assert_eq!(duplicate_length.status, 400);

    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn upgrade_request_is_rejected() {
    let (upstream, _requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let response = proxy
        .request(concat!(
            "GET http://allowed.example/ HTTP/1.1\r\n",
            "Host: allowed.example\r\n",
            "Upgrade: websocket\r\n",
            "\r\n"
        ))
        .await;

    assert_eq!(response.status, 501);
    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn unreachable_upstream_yields_bad_gateway() {
    // The hostname is allowed and pinned, but nothing routes its address.
    let proxy = TestProxy::start(&["allowed.example:80"], &[]).await;

    let response = proxy
        .request("GET http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
        .await;

    assert_eq!(response.status, 502);
    assert_eq!(proxy.upstream_attempts(), 1);
}

#[tokio::test]
async fn connect_tunnel_relays_bytes() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:443"],
        &[("allowed.example", 443, upstream)],
    )
    .await;

    let mut client = proxy.connect().await;
    client
        .send(
            concat!(
                "CONNECT allowed.example:443 HTTP/1.1\r\n",
                "Host: allowed.example:443\r\n",
                "\r\n",
                "early"
            )
            .as_bytes(),
        )
        .await;

    let response = client.read_response().await;
    assert_eq!(response.status, 200);
    assert!(response.body.is_empty());
    assert!(
        !response
            .head
            .to_ascii_lowercase()
            .contains("connection: close")
    );
    assert_eq!(client.read_exact(5).await, b"early");

    client.send(b"tunnelled").await;
    assert_eq!(client.read_exact(9).await, b"tunnelled");
}

#[tokio::test]
async fn connect_requests_are_validated() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:443"],
        &[("allowed.example", 443, upstream)],
    )
    .await;

    let denied = proxy
        .request("CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n")
        .await;
    assert_eq!(denied.status, 403);

    let no_port = proxy
        .request("CONNECT allowed.example HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
        .await;
    assert_eq!(no_port.status, 400);

    let ip_literal = proxy
        .request("CONNECT 93.184.216.1:443 HTTP/1.1\r\nHost: 93.184.216.1:443\r\n\r\n")
        .await;
    assert_eq!(ip_literal.status, 400);

    let mismatched_host = proxy
        .request("CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:80\r\n\r\n")
        .await;
    assert_eq!(mismatched_host.status, 400);

    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn denied_connect_early_bytes_are_drained_before_close() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:443"],
        &[("allowed.example", 443, upstream)],
    )
    .await;

    let early = "x".repeat(32 * 1024);
    let request = format!(
        "CONNECT denied.example:443 HTTP/1.1\r\n\
         Host: denied.example:443\r\n\
         \r\n\
         {early}"
    );

    let mut client = proxy.connect().await;
    client.send(request.as_bytes()).await;
    let response = client.read_response().await;
    assert_eq!(response.status, 403);
    assert!(!client.fill().await);
    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn each_connection_serves_one_independently_authorized_request() {
    let (upstream, mut requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let mut client = proxy.connect().await;
    client
        .send(
            concat!(
                "GET http://allowed.example/first HTTP/1.1\r\n",
                "Host: allowed.example\r\n",
                "\r\n",
                "GET http://denied.example/second HTTP/1.1\r\n",
                "Host: denied.example\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .await;

    let first = client.read_response().await;
    assert_eq!(first.status, 200);
    assert!(first.head.contains("200"));
    assert!(
        first
            .head
            .to_ascii_lowercase()
            .contains("connection: close")
    );
    assert!(!client.fill().await);

    let second = proxy
        .request("GET http://denied.example/second HTTP/1.1\r\nHost: denied.example\r\n\r\n")
        .await;
    assert_eq!(second.status, 403);

    let forwarded = timeout(TEST_TIMEOUT, requests.recv())
        .await
        .expect("upstream received the first request")
        .expect("request text");
    assert!(forwarded.starts_with("GET /first HTTP/1.1\r\n"));

    // Only the authorized request reached an upstream connection.
    assert_eq!(proxy.upstream_attempts(), 1);
}

#[tokio::test]
async fn malformed_header_syntax_is_rejected() {
    let (upstream, _requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    // Whitespace before a header colon.
    let spaced = proxy
        .request("GET http://allowed.example/ HTTP/1.1\r\nHost : allowed.example\r\n\r\n")
        .await;
    assert_eq!(spaced.status, 400);

    // Obsolete line folding.
    let folded = proxy
        .request(concat!(
            "GET http://allowed.example/ HTTP/1.1\r\n",
            "Host: allowed.example\r\n",
            "X-Folded: one\r\n two\r\n",
            "\r\n"
        ))
        .await;
    assert_eq!(folded.status, 400);

    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn oversized_request_head_is_bounded() {
    let (upstream, _requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let mut request =
        String::from("GET http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\nX-Big: ");
    request.push_str(&"a".repeat(32 * 1024));
    request.push_str("\r\n\r\n");

    let response = proxy.request(&request).await;

    // Raw prevalidation bounds the head before Hyper parses it.
    assert_eq!(response.status, 431);
    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn http_1_0_requests_are_forwarded_as_http_1_1() {
    let (upstream, mut requests) = recording_upstream(OK_RESPONSE).await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let response = proxy
        .request("GET http://allowed.example/legacy HTTP/1.0\r\n\r\n")
        .await;
    assert_eq!(response.status, 200);
    assert!(response.head.starts_with("HTTP/1.0 200"));

    let forwarded = timeout(TEST_TIMEOUT, requests.recv())
        .await
        .expect("upstream received a request")
        .expect("request text");
    assert!(forwarded.starts_with("GET /legacy HTTP/1.1\r\n"));
}
