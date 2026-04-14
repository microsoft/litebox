// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox process tree test harness.
//!
//! This binary serves dual purpose:
//! - **Inside the sandbox**: spawns a process tree, runs filesystem/network/
//!   fork tests at each node, and reports results as JSON.
//! - **On the host**: integration tests build this binary, construct a minimal
//!   rootfs, launch litebox, and assert test results.
//!
//! # Subcommands (sandbox agent mode)
//!
//! - `spawn-tree` — coordinator: create tree, wait for agents, run tests
//! - `agent --id X --coord-port P` — tree node: register, run tests, report
//! - `echo-test` — print "ECHO_TEST_OK" and exit (used by fork tests)
//! - `pipe-test` — run a pipe-in-subshell pattern (tests X4 deadlock)
//! - `write-marker PATH` — write "MARKER" to a file (used by X5)
//! - `sleep-test` — sleep 2 seconds and exit (used by X6)
//! - `env-check VAR` — print the value of an environment variable
//! - `cwd-check` — print the current working directory
//! - `pipe-echo` — read stdin, write to stdout (used by E3)
//! - `stderr-test` — write to both stdout and stderr (used by E4)
//! - `exit-with CODE` — exit with the given code (used by E5)

mod agent;
mod env_tests;
mod fork_tests;
mod fs_tests;
mod net_tests;
mod protocol;

use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("spawn-tree");
    let self_exe = &args[0];

    match cmd {
        "spawn-tree" => {
            let results = agent::run_coordinator(self_exe);
            let passed = results.iter().filter(|r| r.result == protocol::Outcome::Pass).count();
            let failed = results.iter().filter(|r| r.result == protocol::Outcome::Fail).count();
            let xfail = results.iter().filter(|r| r.result == protocol::Outcome::Xfail).count();
            eprintln!(
                "\n=== SUMMARY: {} total, {} passed, {} failed, {} xfail ===",
                results.len(), passed, failed, xfail
            );
            if failed > 0 {
                std::process::exit(1);
            }
        }
        "agent" => {
            let id = args.iter()
                .position(|a| a == "--id")
                .and_then(|i| args.get(i + 1))
                .map(String::as_str)
                .unwrap_or("unknown");
            let coord_port: u16 = args.iter()
                .position(|a| a == "--coord-port")
                .and_then(|i| args.get(i + 1))
                .and_then(|s| s.parse().ok())
                .unwrap_or(9000);
            agent::run_agent(self_exe, id, coord_port);
        }
        "echo-test" => {
            println!("ECHO_TEST_OK");
        }
        "pipe-test" => {
            // Simulate $(echo foo | cat) — fork+pipe+fork pattern.
            // This is expected to deadlock in litebox's delayed-fork.
            let child = std::process::Command::new("sh")
                .arg("-c")
                .arg("echo PIPE_TEST | cat")
                .stdout(std::process::Stdio::piped())
                .spawn();
            match child {
                Ok(child) => {
                    let output = child.wait_with_output().unwrap();
                    let s = String::from_utf8_lossy(&output.stdout);
                    println!("{s}");
                }
                Err(e) => {
                    eprintln!("pipe-test spawn failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        "write-marker" => {
            let path = args.get(2).expect("write-marker requires a path");
            std::fs::write(path, "MARKER").expect("write failed");
        }
        "sleep-test" => {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        "env-check" => {
            let var = args.get(2).expect("env-check requires a variable name");
            match std::env::var(var) {
                Ok(val) => println!("{val}"),
                Err(_) => println!("NOT_SET"),
            }
        }
        "cwd-check" => {
            match std::env::current_dir() {
                Ok(dir) => println!("{}", dir.display()),
                Err(e) => println!("ERROR: {e}"),
            }
        }
        "pipe-echo" => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf).ok();
            std::io::stdout().write_all(&buf).ok();
        }
        "stderr-test" => {
            println!("STDOUT_OK");
            eprintln!("STDERR_OK");
        }
        "exit-with" => {
            let code: i32 = args.get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            std::process::exit(code);
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: litebox-test-agent <spawn-tree|agent|echo-test|...>");
            std::process::exit(1);
        }
    }
}
