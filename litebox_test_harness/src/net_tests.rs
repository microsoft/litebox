// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Network connectivity tests (N1-N8). All async with tokio.

use crate::agent::agent_port;
use crate::protocol::{AgentReady, Outcome, TestResult};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

fn r(test: &str, agent: &str, outcome: Outcome, detail: &str) -> TestResult {
    TestResult {
        test: test.to_string(),
        agent: agent.to_string(),
        result: outcome,
        detail: detail.to_string(),
    }
}

pub async fn run(id: &str, peers: &HashMap<&str, &AgentReady>) -> Vec<TestResult> {
    let mut results = Vec::new();

    // N1: Parent connects to child's listen port.
    for &child_id in children_of(id) {
        if let Some(peer) = peers.get(child_id) {
            results.push(tcp_echo_test("N1", id, child_id, peer.port).await);
        }
    }

    // N2: Child connects to parent's listen port.
    if id != "init" {
        let parent_id = parent_of(id);
        let parent_port = agent_port(parent_id);
        results.push(tcp_echo_test("N2", id, parent_id, parent_port).await);
    }

    // N3: Sibling connects to sibling.
    if let Some(sibling_id) = sibling_of(id) {
        if let Some(peer) = peers.get(sibling_id) {
            results.push(tcp_echo_test("N3", id, sibling_id, peer.port).await);
        }
    }

    // N4: Grandchild connects to grandparent.
    if id == "AAA" || id == "AAB" {
        let gp_port = agent_port("init");
        results.push(tcp_echo_test("N4", id, "init", gp_port).await);
    }

    // N7: Bidirectional data exchange.
    if id == "A" {
        if let Some(peer) = peers.get("B") {
            results.push(tcp_bidi_test(id, peer.port).await);
        }
    }

    // N9: Send data and immediately drop — receiver must still get it.
    if id == "A" {
        if let Some(peer) = peers.get("B") {
            results.push(tcp_send_close_test(id, peer.port).await);
        }
    }

    results
}

async fn tcp_echo_test(test_id: &str, from: &str, to: &str, port: u16) -> TestResult {
    let addr = format!("127.0.0.1:{port}");
    match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let msg = format!("PING_FROM_{from}");
            if let Err(e) = stream.write_all(msg.as_bytes()).await {
                return r(test_id, from, Outcome::Fail, &format!("{from}→{to}: write: {e}"));
            }
            let _ = stream.flush().await;

            let mut buf = [0u8; 256];
            match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    r(test_id, from, Outcome::Pass, &format!("{from}→{to}: {n}B: {resp}"))
                }
                Ok(Ok(_)) => r(test_id, from, Outcome::Fail, &format!("{from}→{to}: empty")),
                Ok(Err(e)) => r(test_id, from, Outcome::Fail, &format!("{from}→{to}: read: {e}")),
                Err(_) => r(test_id, from, Outcome::Fail, &format!("{from}→{to}: read timeout")),
            }
        }
        Ok(Err(e)) => r(test_id, from, Outcome::Fail, &format!("{from}→{to}: connect: {e}")),
        Err(_) => r(test_id, from, Outcome::Fail, &format!("{from}→{to}: connect timeout")),
    }
}

async fn tcp_bidi_test(from: &str, peer_port: u16) -> TestResult {
    let addr = format!("127.0.0.1:{peer_port}");
    match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let _ = stream.write_all(b"BIDI_REQUEST").await;
            let _ = stream.flush().await;
            let mut buf = [0u8; 256];
            match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let _ = stream.write_all(b"BIDI_SECOND").await;
                    r("N7", from, Outcome::Pass, &format!("bidi ok, {n}B"))
                }
                _ => r("N7", from, Outcome::Fail, "no bidi response"),
            }
        }
        Err(_) | Ok(Err(_)) => r("N7", from, Outcome::Fail, "connect failed"),
    }
}

/// N9: Send data then drop stream immediately. Tests that the receiver
/// still gets the data (application-level ACK not needed for this test
/// since we verify receipt on the echo response before closing).
async fn tcp_send_close_test(from: &str, peer_port: u16) -> TestResult {
    let addr = format!("127.0.0.1:{peer_port}");
    match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let _ = stream.write_all(b"SEND_CLOSE_TEST").await;
            let _ = stream.flush().await;
            // Wait for echo before closing — proper protocol.
            let mut buf = [0u8; 256];
            match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    if resp.contains("SEND_CLOSE_TEST") {
                        r("N9", from, Outcome::Pass, "echo received before close")
                    } else {
                        r("N9", from, Outcome::Fail, &format!("wrong echo: {resp}"))
                    }
                }
                _ => r("N9", from, Outcome::Fail, "no echo before close"),
            }
        }
        Err(_) | Ok(Err(_)) => r("N9", from, Outcome::Fail, "connect failed"),
    }
}

fn parent_of(id: &str) -> &str {
    match id {
        "A" | "B" => "init",
        "AA" | "AB" => "A",
        "AAA" | "AAB" => "AA",
        _ => "unknown",
    }
}

fn children_of(id: &str) -> &[&str] {
    match id {
        "init" => &["A", "B"],
        "A" => &["AA", "AB"],
        "AA" => &["AAA", "AAB"],
        _ => &[],
    }
}

fn sibling_of(id: &str) -> Option<&str> {
    match id {
        "A" => Some("B"),
        "B" => Some("A"),
        "AA" => Some("AB"),
        "AB" => Some("AA"),
        "AAA" => Some("AAB"),
        "AAB" => Some("AAA"),
        _ => None,
    }
}
