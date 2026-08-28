// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hermetic loopback tests for the HTTP and CONNECT proxy.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use litebox_egress_proxy::connector::{BoxedUpstreamStream, ConnectFuture, UpstreamConnector};
use litebox_egress_proxy::policy::{HostPolicy, Hostname};
use litebox_egress_proxy::proxy::{ProxyState, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
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
    async fn start(rules: &[&str], routes: &[(&str, u16, SocketAddr)]) -> Self {
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

        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener");
        let SocketAddr::V4(address) = listener.local_addr().expect("listener address") else {
            panic!("expected IPv4 loopback");
        };

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

    async fn request(&self, raw: &str) -> u16 {
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

    async fn read_response(&mut self) -> u16 {
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
        head.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .expect("status code")
    }

    async fn read_exact(&mut self, length: usize) -> Vec<u8> {
        while self.buffer.len() < length {
            assert!(
                self.fill().await,
                "connection closed before the expected data"
            );
        }
        self.buffer.drain(..length).collect()
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

async fn recording_upstream() -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let (sender, receiver) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let sender = sender.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                let head_end = loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if let Some(index) = find_subslice(&request, b"\r\n\r\n") {
                        break index + 4;
                    }
                };

                let head = String::from_utf8_lossy(&request[..head_end]);
                let body_length = header_value(&head, "content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                while request.len() < head_end + body_length {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                }

                let _ = sender.send(String::from_utf8_lossy(&request).into_owned());
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nhi",
                    )
                    .await;
            });
        }
    });

    (address, receiver)
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
async fn http_request_is_rewritten_and_relayed() {
    let (upstream, mut requests) = recording_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:80"],
        &[("allowed.example", 80, upstream)],
    )
    .await;

    let mut client = proxy.connect().await;
    client
        .send(
            concat!(
                "POST http://Allowed.Example/path?q=1 HTTP/1.1\r\n",
                "Host: allowed.example\r\n",
                "Content-Length: 5\r\n",
                "Proxy-Connection: keep-alive\r\n",
                "Connection: X-Secret\r\n",
                "X-Secret: value\r\n",
                "X-Kept: value\r\n",
                "\r\n",
                "hello"
            )
            .as_bytes(),
        )
        .await;

    assert_eq!(client.read_response().await, 200);
    assert_eq!(client.read_exact(2).await, b"hi");
    assert!(!client.fill().await);

    let forwarded = timeout(TEST_TIMEOUT, requests.recv())
        .await
        .expect("upstream request did not time out")
        .expect("upstream received the request");
    assert!(forwarded.starts_with("POST /path?q=1 HTTP/1.1\r\n"));
    assert_eq!(header_value(&forwarded, "host"), Some("allowed.example"));
    assert_eq!(header_value(&forwarded, "content-length"), Some("5"));
    assert!(header_value(&forwarded, "proxy-connection").is_none());
    assert!(header_value(&forwarded, "connection").is_none());
    assert!(header_value(&forwarded, "x-secret").is_none());
    assert_eq!(header_value(&forwarded, "x-kept"), Some("value"));
    assert!(forwarded.ends_with("hello"));
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

    assert_eq!(client.read_response().await, 200);
    assert_eq!(client.read_exact(5).await, b"early");

    client.send(b"tunnelled").await;
    assert_eq!(client.read_exact(9).await, b"tunnelled");
}

#[tokio::test]
async fn firewall_rejects_without_network_activity() {
    let upstream = echo_upstream().await;
    let proxy = TestProxy::start(
        &["allowed.example:80", "allowed.example:443"],
        &[("allowed.example", 443, upstream)],
    )
    .await;

    for (request, expected_status) in [
        (
            "CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n",
            403,
        ),
        (
            "CONNECT allowed.example:8443 HTTP/1.1\r\nHost: allowed.example:8443\r\n\r\n",
            403,
        ),
        (
            "CONNECT allowed.example HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
            400,
        ),
        (
            "CONNECT 93.184.216.1:443 HTTP/1.1\r\nHost: 93.184.216.1:443\r\n\r\n",
            400,
        ),
        (
            "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:80\r\n\r\n",
            400,
        ),
        (
            "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nHost: allowed.example:443\r\n\r\n",
            400,
        ),
        (
            "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nContent-Length: 0\r\n\r\n",
            400,
        ),
        (
            "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nTransfer-Encoding: chunked\r\n\r\n",
            400,
        ),
        (
            "GET http://denied.example/ HTTP/1.1\r\nHost: denied.example\r\n\r\n",
            403,
        ),
        (
            "GET http://allowed.example:8080/ HTTP/1.1\r\nHost: allowed.example:8080\r\n\r\n",
            403,
        ),
        (
            "GET https://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
            400,
        ),
        (
            "GET /relative HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
            400,
        ),
        (
            "GET http://93.184.216.1/ HTTP/1.1\r\nHost: 93.184.216.1\r\n\r\n",
            400,
        ),
        (
            "GET http://allowed.example/ HTTP/1.1\r\nHost: other.example\r\n\r\n",
            400,
        ),
        (
            "GET http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\nHost: allowed.example\r\n\r\n",
            400,
        ),
        (
            "GET http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\nUpgrade: websocket\r\n\r\n",
            501,
        ),
        (
            "POST http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n",
            417,
        ),
        (
            "GET http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\nConnection: bad token\r\n\r\n",
            400,
        ),
    ] {
        assert_eq!(proxy.request(request).await, expected_status, "{request:?}");
    }

    assert_eq!(proxy.upstream_attempts(), 0);
}

#[tokio::test]
async fn unreachable_upstream_yields_bad_gateway() {
    let proxy = TestProxy::start(&["allowed.example:443"], &[]).await;

    let response = proxy
        .request("CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n")
        .await;
    assert_eq!(response, 502);
    assert_eq!(proxy.upstream_attempts(), 1);
}
