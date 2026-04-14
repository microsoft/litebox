// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Network connectivity tests (N1-N8).

use crate::agent::agent_port;
use crate::protocol::{AgentReady, Outcome, TestResult};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn result(test: &str, agent: &str, outcome: Outcome, detail: &str) -> TestResult {
    TestResult {
        test: test.to_string(),
        agent: agent.to_string(),
        result: outcome,
        detail: detail.to_string(),
    }
}

/// Run network tests appropriate for this agent's position.
pub fn run(id: &str, peers: &HashMap<&str, &AgentReady>) -> Vec<TestResult> {
    let mut results = Vec::new();

    // N1: Parent connects to child's listen port via 127.0.0.1.
    // Only agents with children run this.
    for &child_id in children_of(id) {
        if let Some(peer) = peers.get(child_id) {
            let r = tcp_echo_test("N1", id, child_id, peer.port);
            results.push(r);
        }
    }

    // N2: Child connects to parent's listen port via 127.0.0.1.
    if id != "init" {
        let parent_id = parent_of(id);
        let parent_port = agent_port(parent_id);
        let r = tcp_echo_test("N2", id, parent_id, parent_port);
        results.push(r);
    }

    // N3: Sibling connects to sibling.
    if let Some(sibling_id) = sibling_of(id) {
        if let Some(peer) = peers.get(sibling_id) {
            let r = tcp_echo_test("N3", id, sibling_id, peer.port);
            results.push(r);
        }
    }

    // N4: Grandchild connects to grandparent.
    // Only AAA and AAB run this (connecting to init).
    if id == "AAA" || id == "AAB" {
        let gp_port = agent_port("init");
        let r = tcp_echo_test("N4", id, "init", gp_port);
        results.push(r);
    }

    // N7: Bidirectional data exchange.
    // Agent A tests bidirectional with B.
    if id == "A" {
        if let Some(peer) = peers.get("B") {
            let r = tcp_bidi_test(id, peer.port);
            results.push(r);
        }
    }

    results
}

/// Test TCP connectivity by connecting to a peer and sending/receiving data.
fn tcp_echo_test(test_id: &str, from: &str, to: &str, port: u16) -> TestResult {
    let addr = format!("127.0.0.1:{port}");
    match TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_secs(5),
    ) {
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .ok();
            let msg = format!("PING_FROM_{from}");
            if let Err(e) = stream.write_all(msg.as_bytes()) {
                return result(
                    test_id,
                    from,
                    Outcome::Fail,
                    &format!("{from}→{to}: write failed: {e}"),
                );
            }
            // Read echo response.
            let mut buf = [0u8; 256];
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    result(
                        test_id,
                        from,
                        Outcome::Pass,
                        &format!("{from}→{to}: got {n}B: {response}"),
                    )
                }
                Ok(_) => result(
                    test_id,
                    from,
                    Outcome::Fail,
                    &format!("{from}→{to}: empty response"),
                ),
                Err(e) => result(
                    test_id,
                    from,
                    Outcome::Fail,
                    &format!("{from}→{to}: read failed: {e}"),
                ),
            }
        }
        Err(e) => result(
            test_id,
            from,
            Outcome::Fail,
            &format!("{from}→{to} port {port}: connect failed: {e}"),
        ),
    }
}

/// Test bidirectional data exchange.
fn tcp_bidi_test(from: &str, peer_port: u16) -> TestResult {
    let addr = format!("127.0.0.1:{peer_port}");
    match TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_secs(5),
    ) {
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .ok();
            // Send data.
            let _ = stream.write_all(b"BIDI_REQUEST");
            let mut buf = [0u8; 256];
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => {
                    // Send a second message.
                    let _ = stream.write_all(b"BIDI_SECOND");
                    result("N7", from, Outcome::Pass, &format!("bidi ok, {n}B received"))
                }
                _ => result("N7", from, Outcome::Fail, "no bidi response"),
            }
        }
        Err(e) => result("N7", from, Outcome::Fail, &format!("connect: {e}")),
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
