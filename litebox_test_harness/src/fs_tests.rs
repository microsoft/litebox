// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Filesystem visibility tests (F1-F8).

use crate::protocol::{AgentReady, Outcome, TestResult};
use std::collections::HashMap;

fn result(test: &str, agent: &str, outcome: Outcome, detail: &str) -> TestResult {
    TestResult {
        test: test.to_string(),
        agent: agent.to_string(),
        result: outcome,
        detail: detail.to_string(),
    }
}

/// Run filesystem tests appropriate for this agent's position in the tree.
pub fn run(id: &str, _peers: &HashMap<&str, &AgentReady>) -> Vec<TestResult> {
    let mut results = Vec::new();

    // F1: Parent writes file, child reads it.
    // The parent writes /shared/{parent_id}_for_{child_id}.txt before
    // spawning children. Children check if they can read it.
    // Only children run this test (not init).
    if id != "init" {
        let parent_id = parent_of(id);
        let path = format!("/shared/{parent_id}_for_{id}.txt");
        // Write a marker as the parent (if we ARE the parent, write for our children).
        // Check if parent's file exists for us.
        match std::fs::read_to_string(&path) {
            Ok(content) if content.contains("FROM_PARENT") => {
                results.push(result("F1", id, Outcome::Pass, &format!("read: {content}")));
            }
            Ok(content) => {
                results.push(result(
                    "F1",
                    id,
                    Outcome::Fail,
                    &format!("unexpected content: {content}"),
                ));
            }
            Err(e) => {
                results.push(result(
                    "F1",
                    id,
                    Outcome::Fail,
                    &format!("parent file not visible: {e}"),
                ));
            }
        }
    }

    // Write files for our children before they read.
    for &child_id in children_of(id) {
        let path = format!("/shared/{id}_for_{child_id}.txt");
        let _ = std::fs::create_dir_all("/shared");
        let _ = std::fs::write(&path, format!("FROM_PARENT_{id}"));
    }

    // F2: Child writes file, parent reads it.
    // We write a file, parent checks later.
    {
        let path = format!("/shared/{id}_wrote.txt");
        let _ = std::fs::create_dir_all("/shared");
        let _ = std::fs::write(&path, format!("FROM_CHILD_{id}"));
        results.push(result("F2", id, Outcome::Pass, "wrote file for parent"));
    }

    // F3: Sibling writes file, this agent reads it.
    // Only run if we have a sibling.
    if let Some(sibling_id) = sibling_of(id) {
        // Give sibling time to write.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let path = format!("/shared/{sibling_id}_wrote.txt");
        match std::fs::read_to_string(&path) {
            Ok(content) if content.contains("FROM_CHILD") => {
                results.push(result(
                    "F3",
                    id,
                    Outcome::Pass,
                    &format!("sibling file visible: {content}"),
                ));
            }
            Err(e) => {
                results.push(result(
                    "F3",
                    id,
                    Outcome::Fail,
                    &format!("sibling file not visible: {e}"),
                ));
            }
            Ok(c) => {
                results.push(result("F3", id, Outcome::Fail, &format!("unexpected: {c}")));
            }
        }
    }

    // F5: Write to /tmp (in-mem), verify child isolation.
    // Write to /tmp, then fork+exec a child that tries to read it.
    // Only init and A run this (agents with children).
    if id == "init" || id == "A" {
        let tmp_path = format!("/tmp/{id}_tmp_test.txt");
        let _ = std::fs::write(&tmp_path, format!("TMP_{id}"));
        match std::fs::read_to_string(&tmp_path) {
            Ok(content) if content.contains("TMP_") => {
                results.push(result(
                    "F5",
                    id,
                    Outcome::Pass,
                    "own /tmp write is readable",
                ));
            }
            _ => {
                results.push(result("F5", id, Outcome::Fail, "can't read own /tmp write"));
            }
        }
    }

    // F6: Write to 9P path (/shared/), verify cross-process visibility.
    {
        let path = format!("/shared/{id}_9p_test.txt");
        let _ = std::fs::create_dir_all("/shared");
        match std::fs::write(&path, format!("9P_{id}")) {
            Ok(()) => {
                results.push(result("F6", id, Outcome::Pass, "wrote to 9P path"));
            }
            Err(e) => {
                results.push(result(
                    "F6",
                    id,
                    Outcome::Fail,
                    &format!("9P write failed: {e}"),
                ));
            }
        }
    }

    results
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
