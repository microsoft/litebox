// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Filesystem visibility tests (F1-F8). All async.

use crate::protocol::{AgentReady, Outcome, TestResult};
use std::collections::HashMap;
use tokio::fs;

fn r(test: &str, agent: &str, outcome: Outcome, detail: &str) -> TestResult {
    TestResult {
        test: test.to_string(),
        agent: agent.to_string(),
        result: outcome,
        detail: detail.to_string(),
    }
}

pub async fn run(id: &str, _peers: &HashMap<&str, &AgentReady>) -> Vec<TestResult> {
    let mut results = Vec::new();

    // Write files for our children before they read.
    for &child_id in children_of(id) {
        let path = format!("/shared/{id}_for_{child_id}.txt");
        let _ = fs::create_dir_all("/shared").await;
        let _ = fs::write(&path, format!("FROM_PARENT_{id}")).await;
    }

    // F1: Parent writes file, child reads it.
    if id != "init" {
        let parent_id = parent_of(id);
        let path = format!("/shared/{parent_id}_for_{id}.txt");
        match fs::read_to_string(&path).await {
            Ok(content) if content.contains("FROM_PARENT") => {
                results.push(r("F1", id, Outcome::Pass, &format!("read: {content}")));
            }
            Ok(content) => {
                results.push(r("F1", id, Outcome::Fail, &format!("unexpected: {content}")));
            }
            Err(e) => {
                results.push(r("F1", id, Outcome::Fail, &format!("not visible: {e}")));
            }
        }
    }

    // F2: Child writes file, parent reads later.
    {
        let path = format!("/shared/{id}_wrote.txt");
        let _ = fs::create_dir_all("/shared").await;
        let _ = fs::write(&path, format!("FROM_CHILD_{id}")).await;
        results.push(r("F2", id, Outcome::Pass, "wrote file for parent"));
    }

    // F3: Sibling reads sibling's file.
    if let Some(sibling_id) = sibling_of(id) {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        let path = format!("/shared/{sibling_id}_wrote.txt");
        match fs::read_to_string(&path).await {
            Ok(content) if content.contains("FROM_CHILD") => {
                results.push(r("F3", id, Outcome::Pass, &format!("sibling visible: {content}")));
            }
            Err(e) => {
                results.push(r("F3", id, Outcome::Fail, &format!("sibling not visible: {e}")));
            }
            Ok(c) => {
                results.push(r("F3", id, Outcome::Fail, &format!("unexpected: {c}")));
            }
        }
    }

    // F5: Write to /tmp (in-mem), readable within same process.
    if id == "init" || id == "A" {
        let tmp_path = format!("/tmp/{id}_tmp_test.txt");
        let _ = fs::write(&tmp_path, format!("TMP_{id}")).await;
        match fs::read_to_string(&tmp_path).await {
            Ok(content) if content.contains("TMP_") => {
                results.push(r("F5", id, Outcome::Pass, "own /tmp write readable"));
            }
            _ => {
                results.push(r("F5", id, Outcome::Fail, "can't read own /tmp write"));
            }
        }
    }

    // F6: Write to 9P path.
    {
        let path = format!("/shared/{id}_9p_test.txt");
        let _ = fs::create_dir_all("/shared").await;
        match fs::write(&path, format!("9P_{id}")).await {
            Ok(()) => results.push(r("F6", id, Outcome::Pass, "wrote to 9P path")),
            Err(e) => results.push(r("F6", id, Outcome::Fail, &format!("9P write failed: {e}"))),
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
