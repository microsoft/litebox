// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test coordinator. Runs as the init process, drives all test
//! operations through pipes to child agents.

pub(crate) mod fork_matrix;
pub(crate) mod matrix;
pub(crate) mod special_cases;
pub(crate) mod vscode;

use crate::protocol::{Command, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::Duration;

/// Create an Exec command with default 10s timeout.
pub(crate) fn exec(args: Vec<String>) -> Command {
    Command::Exec {
        args,
        timeout_secs: None,
    }
}

/// Create an Exec command with a custom timeout.
pub(crate) fn exec_timeout(args: Vec<String>, secs: u64) -> Command {
    Command::Exec {
        args,
        timeout_secs: Some(secs),
    }
}

struct Child {
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    #[allow(dead_code)]
    process: tokio::process::Child,
}

/// Expected outcome of a test.
#[derive(Debug, Clone)]
pub(crate) enum Expectation {
    /// Test is expected to pass.
    Pass,
    /// Test is expected to fail (known limitation). Contains reason.
    Fail(String),
}

/// Result of a single test.
#[derive(Debug, Clone)]
pub struct TestResult {
    pub id: String,
    pub agent: String,
    pub actual_pass: bool,
    pub expected: Expectation,
    pub detail: String,
}

impl TestResult {
    /// Effective outcome: pass, fail, xfail, or xpass.
    pub fn outcome(&self) -> &'static str {
        match (&self.expected, self.actual_pass) {
            (Expectation::Pass, true) => "pass",
            (Expectation::Pass, false) => "FAIL",
            (Expectation::Fail(_), false) => "xfail",
            (Expectation::Fail(_), true) => "XPASS",
        }
    }

    /// True if the outcome is unexpected (FAIL or XPASS).
    pub fn is_unexpected(&self) -> bool {
        matches!(self.outcome(), "FAIL" | "XPASS")
    }
}

pub(crate) struct TestRunner {
    children: std::collections::HashMap<String, Child>,
    results: Vec<TestResult>,
    pub(crate) self_exe: String,
}

impl TestRunner {
    /// Record a test expected to pass.
    fn record(&mut self, test: &str, agent: &str, pass: bool, detail: &str) {
        self.record_expected(test, agent, pass, Expectation::Pass, detail);
    }

    /// Record a test with an expected failure (known limitation).
    fn record_xfail(&mut self, test: &str, agent: &str, pass: bool, reason: &str, detail: &str) {
        self.record_expected(
            test,
            agent,
            pass,
            Expectation::Fail(reason.to_string()),
            detail,
        );
    }

    fn record_expected(
        &mut self,
        test: &str,
        agent: &str,
        pass: bool,
        expected: Expectation,
        detail: &str,
    ) {
        let result = TestResult {
            id: test.to_string(),
            agent: agent.to_string(),
            actual_pass: pass,
            expected,
            detail: detail.to_string(),
        };
        let outcome = result.outcome();
        eprintln!("  {outcome}: {test} [{agent}] {detail}");
        self.results.push(result);
    }

    async fn send(&mut self, target: &str, cmd: Command) -> Response {
        if target == "init" {
            return self.exec_local(&cmd).await;
        }
        // Route through the tree: "A" → direct child,
        // "AA" → forward through A, "AAA" → forward through A → AA.
        let (direct, rest) = route(target);
        let child = match self.children.get_mut(direct) {
            Some(c) => c,
            None => {
                return Response::Error {
                    error: format!("no child {direct}"),
                };
            }
        };
        let actual_cmd = wrap_forwards(rest, cmd);
        send_cmd(child, &actual_cmd).await
    }

    async fn exec_local(&self, cmd: &Command) -> Response {
        match cmd {
            Command::FsRead { path } => match tokio::fs::read_to_string(path).await {
                Ok(data) => Response::Ok { data: Some(data) },
                Err(_) => Response::NotFound,
            },
            Command::FsWrite { path, data } => {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                match tokio::fs::write(path, data).await {
                    Ok(()) => Response::Ok { data: None },
                    Err(e) => Response::Error {
                        error: format!("{e}"),
                    },
                }
            }
            Command::FsDelete { path } => match tokio::fs::remove_file(path).await {
                Ok(()) => Response::Ok { data: None },
                Err(e) => Response::Error {
                    error: format!("{e}"),
                },
            },
            Command::FsSymlink { target, link } => {
                #[cfg(unix)]
                match tokio::fs::symlink(target, link).await {
                    Ok(()) => Response::Ok { data: None },
                    Err(e) => Response::Error {
                        error: format!("symlink: {e}"),
                    },
                }
                #[cfg(not(unix))]
                Response::Error {
                    error: "symlink not supported on this platform".to_string(),
                }
            }
            Command::FsReadlink { path } => match tokio::fs::read_link(path).await {
                Ok(target) => Response::Ok {
                    data: Some(target.to_string_lossy().into_owned()),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::NotFound,
                Err(e) => Response::Error {
                    error: format!("readlink: {e}"),
                },
            },
            Command::FsStat { path } => match tokio::fs::symlink_metadata(path).await {
                Ok(meta) => {
                    let kind = if meta.is_symlink() {
                        "symlink"
                    } else if meta.is_dir() {
                        "dir"
                    } else {
                        "file"
                    };
                    Response::Ok {
                        data: Some(kind.to_string()),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::NotFound,
                Err(e) => Response::Error {
                    error: format!("stat: {e}"),
                },
            },
            Command::NetConnect { addr, data } => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        let _ = stream.write_all(data.as_bytes()).await;
                        let _ = stream.flush().await;
                        let mut buf = [0u8; 4096];
                        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(n)) if n > 0 => Response::Connected {
                                echo: String::from_utf8_lossy(&buf[..n]).to_string(),
                            },
                            _ => Response::ConnectFailed {
                                error: "no echo".to_string(),
                            },
                        }
                    }
                    Ok(Err(e)) => Response::ConnectFailed {
                        error: format!("{e}"),
                    },
                    Err(_) => Response::ConnectFailed {
                        error: "timeout".to_string(),
                    },
                }
            }
            _ => Response::Error {
                error: "not implemented locally".to_string(),
            },
        }
    }
}

/// Run all tests as the coordinator.
pub fn run_all(self_exe: &str) -> Vec<TestResult> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run_tests(self_exe))
}

async fn run_tests(self_exe: &str) -> Vec<TestResult> {
    // Create the non-PIE binary for SpawnRemote tests.
    // This is a minimal non-PIE ELF that does execve("/litebox-test-harness", argv)
    // to force remote worker migration, then hands off to the real PIE agent.
    {
        let nonpie = "/litebox-test-harness-nonpie";
        let elf = generate_nonpie_execve_wrapper();
        if std::fs::write(nonpie, &elf).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(nonpie, std::fs::Permissions::from_mode(0o755));
            }
            eprintln!("[coord] created {nonpie} (non-PIE execve wrapper)");
        }
    }

    let mut runner = TestRunner {
        children: std::collections::HashMap::new(),
        results: Vec::new(),
        self_exe: self_exe.to_string(),
    };

    // Spawn direct children A and B.
    eprintln!("[coord] spawning children");
    for id in &["A", "B"] {
        match spawn_child(self_exe).await {
            Ok(child) => {
                runner.children.insert(id.to_string(), child);
                // Tell child to spawn its own children.
                let sub = match *id {
                    "A" => vec!["AA".to_string(), "AB".to_string()],
                    _ => vec![],
                };
                if !sub.is_empty() {
                    let r = send_cmd(
                        runner.children.get_mut(*id).unwrap(),
                        &Command::Spawn { children: sub },
                    )
                    .await;
                    eprintln!("[coord] {id} spawn children: {r:?}");
                }
            }
            Err(e) => eprintln!("[coord] spawn {id} failed: {e}"),
        }
    }

    // Tell A's child AA to spawn AAA, AAB.
    let r = runner
        .send(
            "AA",
            Command::Spawn {
                children: vec!["AAA".to_string(), "AAB".to_string()],
            },
        )
        .await;
    eprintln!("[coord] AA spawn children: {r:?}");

    // === Matrix Tests (capability × topology × dimensions) ===
    eprintln!("[coord] === Matrix Tests ===");
    matrix::run_matrix_tests(&mut runner).await;

    // === Fork Matrix Tests (shell patterns, exec binary/method, delayed fork, stress) ===
    eprintln!("[coord] === Fork Matrix Tests ===");
    fork_matrix::run_fork_matrix_tests(&mut runner).await;

    // === VS Code Reproduction Tests ===
    eprintln!("[coord] === VS Code Reproduction Tests ===");
    vscode::vscode_repro_tests(&mut runner).await;

    // === Contamination Sequence Tests (run LAST — depend on accumulated state) ===
    eprintln!("[coord] === Contamination Sequence Tests ===");
    // Canary: test that agent A can still exec.
    {
        let canary_cmd = crate::protocol::Command::Exec {
            args: vec![runner.self_exe.clone(), "echo-test".into()],
            timeout_secs: None,
        };
        let resp = runner.send("A", canary_cmd).await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        runner.record("X_canary.pre_sequence", "A", pass, &format!("{resp:?}"));
    }
    special_cases::contamination_sequence_tests(&mut runner).await;

    // === Netlink / getifaddrs Tests ===
    special_cases::netlink_tests(&mut runner).await;

    // === Unix Socket Tests ===
    special_cases::unix_socket_tests(&mut runner).await;

    // === Node.js Exit Tests ===
    special_cases::node_exit_tests(&mut runner).await;

    // === Terminal Ioctl Matrix ===
    special_cases::terminal_ioctl_tests(&mut runner).await;

    // === Filesystem I/O Matrix ===
    special_cases::fs_io_tests(&mut runner).await;

    // === Cross-Worker Tests ===
    special_cases::cross_worker_tests(&mut runner).await;

    // Shutdown all children.
    for (id, mut child) in runner.children.drain() {
        let _ = send_cmd(&mut child, &Command::Exit).await;
        let _ = child.process.wait().await;
        eprintln!("[coord] {id} exited");
    }

    runner.results
}

/// Route a targetlike "AAA" to (direct_child, remaining_path).
/// "A" → ("A", None), "AA" → ("A", Some("AA")), "AAA" → ("A", Some("AAA"))
fn route(target: &str) -> (&str, Option<&str>) {
    match target {
        "A" | "B" => (target, None),
        s if s.starts_with("A") => ("A", Some(s)),
        _ => (target, None),
    }
}

/// Wrap a command in Forward layers for routing through the tree.
fn wrap_forwards(remaining: Option<&str>, cmd: Command) -> Command {
    match remaining {
        None => cmd,
        Some(target) => {
            // "AA" → forward to AA, "AAA" → forward to AA which forwards to AAA
            if target == "AA" || target == "AB" {
                Command::Forward {
                    target: target.to_string(),
                    inner: Box::new(cmd),
                }
            } else if target.starts_with("AA") {
                // "AAA" or "AAB" → forward to AA, then forward to target
                Command::Forward {
                    target: "AA".to_string(),
                    inner: Box::new(Command::Forward {
                        target: target.to_string(),
                        inner: Box::new(cmd),
                    }),
                }
            } else {
                Command::Forward {
                    target: target.to_string(),
                    inner: Box::new(cmd),
                }
            }
        }
    }
}

async fn spawn_child(self_exe: &str) -> Result<Child, String> {
    let mut child = tokio::process::Command::new(self_exe)
        .arg("agent")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("{e}"))?;

    let stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;

    Ok(Child {
        stdin,
        stdout: BufReader::new(stdout),
        process: child,
    })
}

async fn send_cmd(child: &mut Child, cmd: &Command) -> Response {
    // Use a longer response timeout for Exec commands with custom timeouts.
    // Dig through Forward wrappers to find the inner command's timeout.
    let inner_timeout = {
        let mut c = cmd;
        loop {
            match c {
                Command::Forward { inner, .. } => c = inner,
                Command::Exec {
                    timeout_secs: Some(t),
                    ..
                } => break Some(*t),
                _ => break None,
            }
        }
    };
    let response_timeout = match inner_timeout {
        Some(t) => Duration::from_secs(t + 5),
        None => Duration::from_secs(15),
    };

    let json = serde_json::to_string(cmd).unwrap();
    if child
        .stdin
        .write_all(format!("{json}\n").as_bytes())
        .await
        .is_err()
    {
        return Response::Error {
            error: "write failed".to_string(),
        };
    }
    let _ = child.stdin.flush().await;

    let mut line = String::new();
    match tokio::time::timeout(response_timeout, child.stdout.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => match serde_json::from_str(line.trim()) {
            Ok(resp) => resp,
            Err(e) => Response::Error {
                error: format!("parse: {e}: {line}"),
            },
        },
        Ok(Ok(_)) => Response::Error {
            error: "EOF".into(),
        },
        Ok(Err(e)) => Response::Error {
            error: format!("read: {e}"),
        },
        Err(_) => Response::Error {
            error: "timeout".into(),
        },
    }
}

/// Generate a minimal non-PIE ELF (ET_EXEC) that does:
///   execve("/litebox-test-harness", argv, envp)
///
/// This binary forces remote worker migration (because it's non-PIE),
/// then immediately replaces itself with the real PIE test harness,
/// passing through all command-line arguments.
///
/// The machine code reads argc/argv from the Linux process stack layout
/// (rsp points to argc at process entry), sets argv[0] to the target path,
/// and calls execve.
fn generate_nonpie_execve_wrapper() -> Vec<u8> {
    // Target binary to exec into
    let target = b"/litebox-test-harness\0";

    // x86-64 machine code at entry:
    //   ; On Linux entry: [rsp] = argc, [rsp+8] = argv[0], [rsp+16] = argv[1], ...
    //   ; After argv: NULL, then envp array
    //
    //   lea rdi, [rip + target]      ; path = "/litebox-test-harness"
    //   mov rsi, rsp                 ; argv = stack (argc at [rsp], but we need argv array)
    //   add rsi, 8                   ; rsi = &argv[0]
    //   mov [rsi], rdi               ; argv[0] = path (replace with target)
    //
    //   ; Find envp: skip argc + argv pointers + NULL
    //   mov rcx, [rsp]               ; rcx = argc
    //   lea rdx, [rsi + rcx*8 + 8]   ; rdx = &argv[argc+1] = envp
    //
    //   mov rax, 59                  ; SYS_execve
    //   syscall
    //
    //   ; If execve fails, exit(127)
    //   mov rax, 60                  ; SYS_exit
    //   mov rdi, 127
    //   syscall
    //
    // Assembled:
    let code: &[u8] = &[
        // lea rdi, [rip + offset_to_target]
        0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00, // patched below
        // mov rsi, rsp
        0x48, 0x89, 0xe6, // add rsi, 8
        0x48, 0x83, 0xc6, 0x08, // mov [rsi], rdi
        0x48, 0x89, 0x3e, // mov rcx, [rsp]
        0x48, 0x8b, 0x0c, 0x24, // lea rdx, [rsi + rcx*8 + 8]
        0x48, 0x8d, 0x54, 0xce, 0x08, // mov rax, 59
        0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, // syscall
        0x0f, 0x05, // mov rax, 60
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rdi, 127
        0x48, 0xc7, 0xc7, 0x7f, 0x00, 0x00, 0x00, // syscall
        0x0f, 0x05,
    ];

    // Use 0x10000 as the base address — within the partition's valid range.
    // 0x400000 (the typical non-PIE base) may be outside the init slot.
    let base_addr: u64 = 0x10000;
    let ehdr_size: u16 = 64;
    let phdr_size: u16 = 56;
    let code_offset = (ehdr_size + phdr_size) as u64;
    let target_offset = code_offset + code.len() as u64;
    let entry = base_addr + code_offset;
    let file_size = target_offset as usize + target.len();

    // Patch the RIP-relative offset for `lea rdi, [rip + target]`
    // At the lea instruction (offset 0 in code), RIP = entry + 7 (after the lea)
    // target is at entry + code.len()
    // offset = target_addr - rip = (code.len() - 7) as i32
    let rip_offset = (code.len() as i32) - 7;
    let mut code_patched = code.to_vec();
    code_patched[3..7].copy_from_slice(&rip_offset.to_le_bytes());

    let mut elf = Vec::with_capacity(file_size);

    // ELF header (64 bytes)
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // magic
    elf.push(2); // ELFCLASS64
    elf.push(1); // ELFDATA2LSB
    elf.push(1); // EV_CURRENT
    elf.push(0); // ELFOSABI_NONE
    elf.extend_from_slice(&[0; 8]); // padding
    elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC (non-PIE!)
    elf.extend_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes()); // version
    elf.extend_from_slice(&entry.to_le_bytes()); // e_entry
    elf.extend_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&ehdr_size.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&phdr_size.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    // Program header (56 bytes) - PT_LOAD
    elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_R | PF_X
    elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    elf.extend_from_slice(&base_addr.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&base_addr.to_le_bytes()); // p_paddr
    elf.extend_from_slice(&(file_size as u64).to_le_bytes()); // p_filesz
    elf.extend_from_slice(&(file_size as u64).to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // Code
    elf.extend_from_slice(&code_patched);

    // Target path string
    elf.extend_from_slice(target);

    elf
}
