// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hermetic loopback tests for the CONNECT proxy.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use litebox_egress_proxy::listener::{ListenerSource, acquire};
use litebox_egress_proxy::policy::{HostPolicy, Hostname};
use litebox_egress_proxy::proxy::{ProxyState, serve};
use litebox_egress_proxy::upstream::{BoxedUpstreamStream, ConnectFuture, UpstreamConnector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct LoopbackConnector {
    routes: HashMap<(Hostname, u16), SocketAddr>,
    attempts: Arc<AtomicUsize>,
}

impl UpstreamConnector for LoopbackConnector {
    fn connect(&self, host: Hostname, port: u16) -> ConnectFuture<'_> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let route = self.routes.get(&(host, port)).copied();
        Box::pin(async move {
            let Some(route) = route else {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            };
            let stream = TcpStream::connect(route).await?;
            Ok(Box::new(stream) as BoxedUpstreamStream)
        })
    }
}

struct TestProxy {
    address: SocketAddrV4,
    attempts: Arc<AtomicUsize>,
}

impl TestProxy {
    fn start(rules: &[&str], routes: &[(&str, u16, SocketAddr)]) -> Self {
        let policy = HostPolicy::from_rules(rules.iter().copied()).expect("valid policy");

        let mut mapped = HashMap::new();
        for (host, port, address) in routes {
            let host = Hostname::parse(host).expect("valid hostname");
            mapped.insert((host, *port), *address);
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let connector = LoopbackConnector {
            routes: mapped,
            attempts: Arc::clone(&attempts),
        };
        let state = Arc::new(ProxyState::new(policy, Box::new(connector)));

        let (listener, address) = acquire(ListenerSource::Bind(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            0,
        )))
        .expect("loopback listener");
        let listener = TcpListener::from_std(listener).expect("async listener");

        tokio::spawn(async move {
            let _ = serve(listener, state).await;
        });

        Self { address, attempts }
    }

    fn upstream_attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

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

    async fn request(&self, raw: &str) -> HttpResponse {
        let mut client = self.connect().await;
        client.send(raw.as_bytes()).await;
        client.read_response().await
    }
}

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
        HttpResponse { status, head }
    }

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

struct HttpResponse {
    status: u16,
    head: String,
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

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

#[tokio::test]
async fn connect_tunnel_relays_bytes() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:443"],
        &[("allowed.example", 443, upstream)],
    );

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
async fn allowed_hostname_is_connected_for_each_request() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:443"],
        &[("allowed.example", 443, upstream)],
    );

    for _ in 0..2 {
        let response = proxy
            .request("CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n")
            .await;
        assert_eq!(response.status, 200);
    }

    assert_eq!(proxy.upstream_attempts(), 2);
}

#[tokio::test]
async fn denied_host_and_port_do_not_trigger_network_activity() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:443"],
        &[("allowed.example", 443, upstream)],
    );

    let denied_host = proxy
        .request("CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n")
        .await;
    assert_eq!(denied_host.status, 403);

    let denied_port = proxy
        .request("CONNECT allowed.example:8443 HTTP/1.1\r\nHost: allowed.example:8443\r\n\r\n")
        .await;
    assert_eq!(denied_port.status, 403);

    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn connect_authority_and_framing_are_validated() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:443"],
        &[("allowed.example", 443, upstream)],
    );

    for request in [
        "CONNECT allowed.example HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
        "CONNECT 93.184.216.1:443 HTTP/1.1\r\nHost: 93.184.216.1:443\r\n\r\n",
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:80\r\n\r\n",
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nHost: allowed.example:443\r\n\r\n",
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nContent-Length: 0\r\n\r\n",
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nTransfer-Encoding: chunked\r\n\r\n",
    ] {
        assert_eq!(proxy.request(request).await.status, 400);
    }

    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn explicitly_allowed_dns_port_is_forwarded() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:53"],
        &[("allowed.example", 53, upstream)],
    );

    let response = proxy
        .request("CONNECT allowed.example:53 HTTP/1.1\r\nHost: allowed.example:53\r\n\r\n")
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(proxy.upstream_attempts(), 1);
}

#[tokio::test]
async fn unreachable_upstream_yields_bad_gateway() {
    let proxy = TestProxy::start(&["allowed.example:443"], &[]);

    let response = proxy
        .request("CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n")
        .await;
    assert_eq!(response.status, 502);
    assert_eq!(proxy.upstream_attempts(), 1);
}

#[tokio::test]
async fn unsupported_methods_are_rejected_without_network_activity() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:443"],
        &[("allowed.example", 443, upstream)],
    );

    let response = proxy
        .request("GET http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
        .await;
    assert_eq!(response.status, 501);
    assert_eq!(proxy.upstream_attempts(), 0);
}
