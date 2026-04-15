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
            let pass_count = results.iter().filter(|r| r.outcome() == "pass").count();
            let fail_count = results.iter().filter(|r| r.outcome() == "FAIL").count();
            let xfail_count = results.iter().filter(|r| r.outcome() == "xfail").count();
            let xpass_count = results.iter().filter(|r| r.outcome() == "XPASS").count();
            // Print JSON results to stdout.
            for r in &results {
                println!(
                    "{}",
                    serde_json::json!({
                        "test": r.id,
                        "agent": r.agent,
                        "result": r.outcome(),
                        "detail": r.detail,
                    })
                );
            }
            eprintln!(
                "\n=== SUMMARY: {} total, {} passed, {} failed, {} xfail, {} xpass ===",
                results.len(), pass_count, fail_count, xfail_count, xpass_count
            );
            // Exit non-zero only for unexpected results.
            if fail_count > 0 || xpass_count > 0 {
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
        // --- Subcommands used as child-process behaviors by tests ---
        "unix-echo-server" => {
            // Usage: unix-echo-server <path>
            // Binds a Unix domain socket, accepts ONE connection, echoes
            // received data back, then exits. Prints LISTENING when ready.
            let path = args.get(2).expect("unix-echo-server requires <path>");
            let _ = std::fs::remove_file(path);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                let listener = tokio::net::UnixListener::bind(path).expect("bind failed");
                println!("LISTENING");
                let (mut stream, _) = listener.accept().await.expect("accept failed");
                let mut buf = [0u8; 4096];
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let _ = stream.write_all(&buf[..n]).await;
                        let _ = stream.flush().await;
                    }
                    _ => {}
                }
            });
            let _ = std::fs::remove_file(path);
        }
        "unix-echo-client" => {
            // Usage: unix-echo-client <path> <data>
            // Connects to a Unix domain socket, sends data, reads response,
            // prints it to stdout.
            let path = args.get(2).expect("unix-echo-client requires <path>");
            let data = args.get(3).expect("unix-echo-client requires <data>");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut stream = tokio::net::UnixStream::connect(path)
                    .await
                    .expect("connect failed");
                stream.write_all(data.as_bytes()).await.expect("write failed");
                stream.flush().await.expect("flush failed");
                let mut buf = [0u8; 4096];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) => {
                        let resp = String::from_utf8_lossy(&buf[..n]);
                        println!("{resp}");
                    }
                    Ok(Err(e)) => {
                        eprintln!("read error: {e}");
                        std::process::exit(1);
                    }
                    Err(_) => {
                        eprintln!("read timeout");
                        std::process::exit(1);
                    }
                }
            });
        }
        "trigger-delayed-fork" => {
            // Usage: trigger-delayed-fork <cmd> [args...]
            // Triggers a delayed-fork by doing a non-pre-exec syscall (mmap
            // via Vec allocation), then fork+execs the given command.
            // Used to test nested delayed-fork: the parent forks this process,
            // which migrates to a worker, then fork+execs <cmd>.
            if args.len() < 3 {
                eprintln!("usage: trigger-delayed-fork <cmd> [args...]");
                std::process::exit(1);
            }

            // Force a non-pre-exec syscall to trigger delayed-fork migration.
            let _trigger: Vec<u8> = vec![0u8; 64 * 1024];
            assert_eq!(_trigger[0], 0);

            // Fork+exec the given command from within the delayed-fork child.
            let output = std::process::Command::new(&args[2])
                .args(&args[3..])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .expect("nested fork+exec failed");
            let stdout = String::from_utf8_lossy(&output.stdout);
            print!("{stdout}");
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    }
}
