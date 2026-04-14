// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox process tree test harness.
//!
//! Two modes:
//! - `spawn-tree` — coordinator: spawns tree, drives tests through pipes
//! - `agent` — command executor: reads commands from stdin, responds on stdout

mod agent;
mod coordinator;
mod protocol;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("spawn-tree");
    let self_exe = &args[0];

    match cmd {
        "spawn-tree" => {
            let results = coordinator::run_all(self_exe);
            let passed = results.iter().filter(|r| r.2).count();
            let failed = results.iter().filter(|r| !r.2).count();
            // Print JSON results to stdout.
            for (test, agent, pass, detail) in &results {
                let status = if *pass { "pass" } else { "fail" };
                println!(
                    "{}",
                    serde_json::json!({"test": test, "agent": agent, "result": status, "detail": detail})
                );
            }
            eprintln!(
                "\n=== SUMMARY: {} total, {} passed, {} failed ===",
                results.len(), passed, failed
            );
            if failed > 0 {
                std::process::exit(1);
            }
        }
        "agent" => {
            agent::run(self_exe);
        }
        "echo-test" => {
            println!("ECHO_TEST_OK");
        }
        "exit-with" => {
            let code: i32 = args
                .get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            std::process::exit(code);
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    }
}
