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
            // Print JSON results to stdout.
            for r in &results {
                println!("{}", serde_json::to_string(r).unwrap());
            }
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
            agent::run_agent(self_exe, id);
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
        "tcp-pair-test" => {
            // Minimal test of cross-worker TCP.
            // Init binds port 9000, forks a child that connects and sends data.
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("0.0.0.0:9000").unwrap();
            listener.set_nonblocking(true).unwrap();
            eprintln!("[tcp-pair-test] listening on 9000");

            // Fork a child that connects and sends data.
            let child = std::process::Command::new(self_exe)
                .arg("tcp-send")
                .arg("127.0.0.1:9000")
                .arg("HELLO_FROM_CHILD")
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn();
            match child {
                Ok(mut c) => {
                    eprintln!("[tcp-pair-test] child spawned, waiting...");
                    // Poll accept for up to 10 seconds.
                    let start = std::time::Instant::now();
                    while start.elapsed() < std::time::Duration::from_secs(10) {
                        match listener.accept() {
                            Ok((mut stream, addr)) => {
                                eprintln!("[tcp-pair-test] accepted from {addr}");
                                stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
                                let mut buf = [0u8; 256];
                                match stream.read(&mut buf) {
                                    Ok(n) => {
                                        let data = String::from_utf8_lossy(&buf[..n]);
                                        println!("RECEIVED:{data}");
                                    }
                                    Err(e) => println!("READ_ERROR:{e}"),
                                }
                                break;
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                            Err(e) => {
                                println!("ACCEPT_ERROR:{e}");
                                break;
                            }
                        }
                    }
                    let _ = c.wait();
                }
                Err(e) => println!("SPAWN_ERROR:{e}"),
            }
        }
        "tcp-send" => {
            // Child: connect to addr and send data, keeping connection open briefly.
            let addr = args.get(2).expect("tcp-send requires addr");
            let data = args.get(3).expect("tcp-send requires data");
            eprintln!("[tcp-send] connecting to {addr}...");
            match std::net::TcpStream::connect_timeout(
                &addr.parse().unwrap(),
                std::time::Duration::from_secs(5),
            ) {
                Ok(mut stream) => {
                    use std::io::Write;
                    eprintln!("[tcp-send] connected, sending {}", data.len());
                    stream.write_all(data.as_bytes()).unwrap();
                    stream.flush().unwrap();
                    eprintln!("[tcp-send] done");
                }
                Err(e) => eprintln!("[tcp-send] connect failed: {e}"),
            }
        }
        "fork-diag" => {
            // Fork+exec a child that runs the "diag" subcommand.
            // This tests whether a worker process can execute and report.
            eprintln!("[fork-diag] spawning child with diag...");
            match std::process::Command::new(self_exe)
                .arg("diag")
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .output()
            {
                Ok(output) => {
                    eprintln!("[fork-diag] child exit={}", output.status);
                }
                Err(e) => {
                    eprintln!("[fork-diag] spawn failed: {e}");
                }
            }
        }
        "diag" => {
            // Diagnostic: report what works in this process.
            // Used to debug worker process capabilities.
            eprintln!("[diag] pid={} args={:?}", std::process::id(), &args[1..]);
            eprintln!("[diag] cwd={:?}", std::env::current_dir());

            // Test file write
            match std::fs::write("/shared/diag-test.txt", "DIAG_OK") {
                Ok(()) => eprintln!("[diag] file write: OK"),
                Err(e) => eprintln!("[diag] file write: FAIL ({e})"),
            }

            // Test TCP connect to localhost:9000 (coordinator)
            match std::net::TcpStream::connect_timeout(
                &"127.0.0.1:9000".parse().unwrap(),
                std::time::Duration::from_secs(3),
            ) {
                Ok(_) => eprintln!("[diag] TCP connect 127.0.0.1:9000: OK"),
                Err(e) => eprintln!("[diag] TCP connect 127.0.0.1:9000: FAIL ({e})"),
            }

            // Test TCP bind
            match std::net::TcpListener::bind("0.0.0.0:9099") {
                Ok(_) => eprintln!("[diag] TCP bind 0.0.0.0:9099: OK"),
                Err(e) => eprintln!("[diag] TCP bind 0.0.0.0:9099: FAIL ({e})"),
            }

            // Test fork+exec of self
            match std::process::Command::new(&args[0])
                .arg("echo-test")
                .stdout(std::process::Stdio::piped())
                .output()
            {
                Ok(out) => {
                    let s = String::from_utf8_lossy(&out.stdout);
                    eprintln!("[diag] fork+exec self: exit={} out={}", out.status, s.trim());
                }
                Err(e) => eprintln!("[diag] fork+exec self: FAIL ({e})"),
            }

            eprintln!("[diag] done");
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: litebox-test-agent <spawn-tree|agent|echo-test|...>");
            std::process::exit(1);
        }
    }
}
