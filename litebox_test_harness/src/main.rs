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
//! - `agent --id X` — tree node: register, run tests, report
//! - `echo-test` — print "ECHO_TEST_OK" and exit (used by fork tests)
//! - `pipe-test` — run a pipe-in-subshell pattern (tests X4 deadlock)
//! - `write-marker PATH` — write "MARKER" to a file (used by X5)
//! - `sleep-test` — sleep 2 seconds and exit (used by X6)
//! - `env-check VAR` — print the value of an environment variable
//! - `cwd-check` — print the current working directory
//! - `pipe-echo` — read stdin, write to stdout (used by E3)
//! - `stderr-test` — write to both stdout and stderr (used by E4)
//! - `exit-with CODE` — exit with the given code (used by E5)
//! - `tcp-pair-test` — minimal cross-worker TCP test
//! - `tcp-send ADDR DATA` — connect and send data
//! - `fork-diag` — fork+exec a child running diag
//! - `diag` — diagnostic: report process capabilities

mod agent;
mod env_tests;
mod fork_tests;
mod fs_tests;
mod net_tests;
mod protocol;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("spawn-tree");
    let self_exe = &args[0];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    match cmd {
        "spawn-tree" => {
            let results = agent::run_coordinator(self_exe);
            let passed = results.iter().filter(|r| r.result == protocol::Outcome::Pass).count();
            let failed = results.iter().filter(|r| r.result == protocol::Outcome::Fail).count();
            let xfail = results.iter().filter(|r| r.result == protocol::Outcome::Xfail).count();
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
            rt.block_on(async {
                let output = tokio::process::Command::new("sh")
                    .arg("-c")
                    .arg("echo PIPE_TEST | cat")
                    .stdout(std::process::Stdio::piped())
                    .output()
                    .await;
                match output {
                    Ok(out) => println!("{}", String::from_utf8_lossy(&out.stdout)),
                    Err(e) => {
                        eprintln!("pipe-test spawn failed: {e}");
                        std::process::exit(1);
                    }
                }
            });
        }
        "write-marker" => {
            let path = args.get(2).expect("write-marker requires a path");
            rt.block_on(async {
                tokio::fs::write(path, "MARKER").await.expect("write failed");
            });
        }
        "sleep-test" => {
            rt.block_on(tokio::time::sleep(std::time::Duration::from_secs(2)));
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
            rt.block_on(async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                tokio::io::stdin().read_to_end(&mut buf).await.ok();
                tokio::io::stdout().write_all(&buf).await.ok();
            });
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
            rt.block_on(async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                use tokio::net::TcpListener;

                let listener = TcpListener::bind("0.0.0.0:9000").await.unwrap();
                eprintln!("[tcp-pair-test] listening on 9000");

                let child = tokio::process::Command::new(self_exe)
                    .arg("tcp-send")
                    .arg("127.0.0.1:9000")
                    .arg("HELLO_FROM_CHILD")
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .spawn();
                match child {
                    Ok(mut c) => {
                        eprintln!("[tcp-pair-test] child spawned, waiting...");
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            listener.accept(),
                        )
                        .await
                        {
                            Ok(Ok((mut stream, addr))) => {
                                eprintln!("[tcp-pair-test] accepted from {addr}");
                                let mut buf = [0u8; 256];
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    stream.read(&mut buf),
                                )
                                .await
                                {
                                    Ok(Ok(n)) => {
                                        let data = String::from_utf8_lossy(&buf[..n]);
                                        println!("RECEIVED:{data}");
                                    }
                                    Ok(Err(e)) => println!("READ_ERROR:{e}"),
                                    Err(_) => println!("READ_TIMEOUT"),
                                }
                            }
                            Ok(Err(e)) => println!("ACCEPT_ERROR:{e}"),
                            Err(_) => println!("ACCEPT_TIMEOUT"),
                        }
                        let _ = c.wait().await;
                    }
                    Err(e) => println!("SPAWN_ERROR:{e}"),
                }
            });
        }
        "tcp-send" => {
            let addr = args.get(2).expect("tcp-send requires addr").clone();
            let data = args.get(3).expect("tcp-send requires data").clone();
            rt.block_on(async {
                use tokio::io::AsyncWriteExt;
                eprintln!("[tcp-send] connecting to {addr}...");
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        eprintln!("[tcp-send] connected, sending {}", data.len());
                        let _ = stream.write_all(data.as_bytes()).await;
                        let _ = stream.flush().await;
                        eprintln!("[tcp-send] done");
                    }
                    Ok(Err(e)) => eprintln!("[tcp-send] connect failed: {e}"),
                    Err(_) => eprintln!("[tcp-send] connect timeout"),
                }
            });
        }
        "fork-diag" => {
            rt.block_on(async {
                eprintln!("[fork-diag] spawning child with diag...");
                match tokio::process::Command::new(self_exe)
                    .arg("diag")
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .output()
                    .await
                {
                    Ok(output) => eprintln!("[fork-diag] child exit={}", output.status),
                    Err(e) => eprintln!("[fork-diag] spawn failed: {e}"),
                }
            });
        }
        "diag" => {
            rt.block_on(async {
                use tokio::io::AsyncWriteExt;

                eprintln!("[diag] pid={} args={:?}", std::process::id(), &args[1..]);
                eprintln!("[diag] cwd={:?}", std::env::current_dir());

                match tokio::fs::write("/shared/diag-test.txt", "DIAG_OK").await {
                    Ok(()) => eprintln!("[diag] file write: OK"),
                    Err(e) => eprintln!("[diag] file write: FAIL ({e})"),
                }

                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    tokio::net::TcpStream::connect("127.0.0.1:9000"),
                )
                .await
                {
                    Ok(Ok(_)) => eprintln!("[diag] TCP connect 127.0.0.1:9000: OK"),
                    Ok(Err(e)) => eprintln!("[diag] TCP connect 127.0.0.1:9000: FAIL ({e})"),
                    Err(_) => eprintln!("[diag] TCP connect 127.0.0.1:9000: TIMEOUT"),
                }

                match tokio::net::TcpListener::bind("0.0.0.0:9099").await {
                    Ok(_) => eprintln!("[diag] TCP bind 0.0.0.0:9099: OK"),
                    Err(e) => eprintln!("[diag] TCP bind 0.0.0.0:9099: FAIL ({e})"),
                }

                match tokio::process::Command::new(&args[0])
                    .arg("echo-test")
                    .stdout(std::process::Stdio::piped())
                    .output()
                    .await
                {
                    Ok(out) => {
                        let s = String::from_utf8_lossy(&out.stdout);
                        eprintln!("[diag] fork+exec self: exit={} out={}", out.status, s.trim());
                    }
                    Err(e) => eprintln!("[diag] fork+exec self: FAIL ({e})"),
                }

                eprintln!("[diag] done");
            });
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: litebox-test-agent <spawn-tree|agent|echo-test|...>");
            std::process::exit(1);
        }
    }
}
