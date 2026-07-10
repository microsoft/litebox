// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Integration tests for the `--ssh` mode (and presets `--vscode-server`
// and `--interactive`).
//
// Each test:
//   1. starts `litebox-vscode` as a detached docker container with the
//      tool_executor in the desired `--ssh*` mode,
//   2. waits for dropbear to listen on the forwarded host port,
//   3. runs an `ssh` client from the host to verify behaviour,
//   4. tears down the container.
//
// Tests are marked `#[ignore]` by default because they require:
//   - the `litebox-vscode` docker image built (see `litebox_tool_executor/rootfs/Dockerfile`),
//   - litebox binaries built (`cargo build -p litebox_tool_executor -p litebox_broker -p litebox_runner_linux_userland`),
//   - an `ssh` client on PATH,
//   - docker daemon reachable.
//
// Run explicitly with:
//   cargo test -p litebox_tool_executor --test ssh_mode -- --ignored

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

const NATIVE_DOCKER_HOST: &str = "unix:///run/litebox-docker.sock";
const NATIVE_DOCKER_SOCK: &str = "/run/litebox-docker.sock";

fn docker_command() -> Command {
    let mut cmd = Command::new("docker");
    // Default to the native in-distro dockerd only when no daemon was
    // chosen AND its socket exists — a portable fallback to the default
    // docker daemon on CI / other machines.
    if std::env::var_os("DOCKER_HOST").is_none()
        && std::path::Path::new(NATIVE_DOCKER_SOCK).exists()
    {
        cmd.env("DOCKER_HOST", NATIVE_DOCKER_HOST);
    }
    cmd
}

// Allocate a port in the range 22300..22399 for each test invocation.
// Using static atomic + PID-shift keeps tests in this binary independent
// of each other and unlikely to collide with anything else on the host.
static NEXT_PORT_OFFSET: AtomicU16 = AtomicU16::new(0);

fn next_port() -> u16 {
    let off = NEXT_PORT_OFFSET.fetch_add(1, Ordering::Relaxed);
    let pid_lsb = (std::process::id() as u16) & 0x3F; // 6 bits → 0..63
    22300 + (pid_lsb * 64) + (off % 64)
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is litebox_tool_executor/; go up one.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn debug_bin_dir() -> PathBuf {
    workspace_root().join("target/debug")
}

fn require_prereqs() -> Result<(), String> {
    let bin = debug_bin_dir();
    for b in [
        "litebox_tool_executor",
        "litebox_broker",
        "litebox_runner_linux_userland",
    ] {
        if !bin.join(b).is_file() {
            return Err(format!(
                "missing binary {}/{b}. Build with: cargo build -p litebox_tool_executor -p litebox_broker -p litebox_runner_linux_userland",
                bin.display()
            ));
        }
    }
    if docker_command().arg("--version").output().is_err() {
        return Err("docker not on PATH".into());
    }
    if Command::new("ssh").arg("-V").output().is_err() {
        return Err("ssh not on PATH".into());
    }
    let out = docker_command()
        .args(["image", "inspect", "litebox-vscode"])
        .output()
        .map_err(|e| format!("docker inspect failed: {e}"))?;
    if !out.status.success() {
        return Err("litebox-vscode image not present. Build with: \
             DOCKER_HOST=unix:///run/litebox-docker.sock docker build --target litebox-vscode -t litebox-vscode \
             -f litebox_tool_executor/rootfs/Dockerfile ."
            .into());
    }
    Ok(())
}

struct SandboxContainer {
    name: String,
}

impl Drop for SandboxContainer {
    fn drop(&mut self) {
        let _ = docker_command().args(["rm", "-f", &self.name]).output();
    }
}

/// Start a litebox-vscode container with `tool_executor_args` passed to
/// the tool executor inside the container. Returns once dropbear is
/// listening on the forwarded host port.
fn start_sandbox(name: &str, host_port: u16, tool_executor_args: &[&str]) -> SandboxContainer {
    let bin_mount = format!("{}:/opt/litebox:ro", debug_bin_dir().display());

    // Build the in-container tool-executor invocation.
    let mut exec_args: Vec<String> = vec![
        "/opt/litebox/litebox_tool_executor".into(),
        "--rootfs".into(),
        "/".into(),
        "--record-baseline".into(),
        "--ssh-port".into(),
        "22".into(), // dropbear always binds 22; host:port forwards to it.
    ];
    for a in tool_executor_args {
        exec_args.push((*a).into());
    }
    let exec_cmd = exec_args
        .iter()
        .map(|s| shell_escape(s))
        .collect::<Vec<_>>()
        .join(" ");

    // We wrap the invocation with `passwd -d root` to clear root's
    // password. Combined with dropbear's `-B` (allow blank-password
    // logins), this lets `ssh root@...` authenticate without prompting.
    // The litebox-vscode image ships root with a hashed password; for
    // self-contained tests we want noninteractive auth.
    let wrapped = format!("passwd -d root >/dev/null 2>&1; exec {exec_cmd}");

    // Always remove any old container with this name first.
    let _ = docker_command().args(["rm", "-f", name]).output();

    let out = docker_command()
        .args([
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "--cap-add=SYS_PTRACE",
            "-p",
        ])
        .arg(format!("{host_port}:22"))
        .args(["-v", &bin_mount])
        .arg("litebox-vscode")
        .args(["bash", "-c", &wrapped])
        .output()
        .expect("docker run");
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        panic!("docker run failed: {stderr}");
    }

    // Poll TCP until dropbear is up (max 30 s).
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{host_port}").parse().unwrap(),
            Duration::from_millis(500),
        )
        .is_ok()
        {
            // dropbear under litebox can accept the TCP connection
            // before its kex setup is complete. Give it enough time
            // to be ready for a real SSH handshake. ~3s empirically
            // covers the observed kex-exchange-identification reset.
            std::thread::sleep(Duration::from_secs(3));
            return SandboxContainer {
                name: name.to_string(),
            };
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let logs = docker_command().args(["logs", name]).output();
    let logs_str = logs
        .as_ref()
        .map(|o| {
            format!(
                "stdout=\n{}\nstderr=\n{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_else(|e| format!("(docker logs failed: {e})"));
    let _ = docker_command().args(["rm", "-f", name]).output();
    panic!("timed out waiting for sshd on host port {host_port}; container logs:\n{logs_str}");
}

/// Quote a single argv element for safe inclusion in a `bash -c` string.
fn shell_escape(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:=@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn ssh_exec(host_port: u16, opts: &[&str], cmd: &str) -> std::process::Output {
    let mut args: Vec<String> = vec![
        "-p".into(),
        host_port.to_string(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=5".into(),
        // Force password auth (empty password works because of `passwd -d`
        // and dropbear `-B`); disable pubkey to keep auth path
        // deterministic across hosts.
        "-o".into(),
        "PreferredAuthentications=password".into(),
        "-o".into(),
        "PubkeyAuthentication=no".into(),
        "-o".into(),
        "NumberOfPasswordPrompts=1".into(),
    ];
    for o in opts {
        args.push((*o).into());
    }
    args.push("root@127.0.0.1".into());
    args.push(cmd.into());
    Command::new("ssh")
        .args(&args)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("ssh client failed to spawn")
}

// ── tests ─────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn t_ssh_basic_echo() {
    if let Err(why) = require_prereqs() {
        eprintln!("SKIP: {why}");
        return;
    }
    let port = next_port();
    let _box = start_sandbox("ltb-ssh-basic", port, &["--ssh"]);
    let out = ssh_exec(port, &[], "echo hello-from-ssh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "ssh exit failed: stderr = {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("hello-from-ssh"),
        "expected hello-from-ssh; stdout = {stdout:?}"
    );
}

#[test]
#[ignore]
fn t_ssh_isatty_true_with_tt() {
    if let Err(why) = require_prereqs() {
        eprintln!("SKIP: {why}");
        return;
    }
    let port = next_port();
    let _box = start_sandbox("ltb-ssh-tty", port, &["--ssh"]);
    // -tt forces PTY allocation even when ssh's own stdin isn't a TTY
    // (the test process has piped stdin). We assert isatty(0)==true via
    // bash's `[ -t 0 ]`. This is the property a TUI agent (Copilot etc.)
    // actually checks before engaging setRawMode.
    //
    // Note: the `tty` (1) command will report "not a tty" inside the
    // sandbox today because /proc/self/fd/0 readlink returns
    // "/dev/stdin" instead of the underlying /dev/pts/N. That's a
    // separate cosmetic /proc shim gap; not a blocker for raw mode
    // engagement. Tracked separately.
    let out = ssh_exec(
        port,
        &["-tt"],
        "echo \"fd0=$([ -t 0 ] && echo TTY || echo PIPE)\"; exit",
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("fd0=TTY"),
        "expected fd0=TTY from `[ -t 0 ]` over SSH -tt; got {stdout:?}"
    );
}

#[test]
#[ignore]
fn t_ssh_command_forces_session_command() {
    if let Err(why) = require_prereqs() {
        eprintln!("SKIP: {why}");
        return;
    }
    let port = next_port();
    let _box = start_sandbox(
        "ltb-ssh-cmd",
        port,
        // Forced command: prints a sentinel then exits.
        &["--ssh", "--ssh-command", "echo forced-cmd-ran; exit 0"],
    );
    // Client doesn't specify a command; dropbear should run the forced one.
    let out = ssh_exec(port, &[], "");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("forced-cmd-ran"),
        "expected forced-cmd-ran; got stdout = {stdout:?}"
    );
}

#[test]
#[ignore]
fn t_vscode_server_preset_still_works() {
    if let Err(why) = require_prereqs() {
        eprintln!("SKIP: {why}");
        return;
    }
    let port = next_port();
    let _box = start_sandbox("ltb-vscode", port, &["--vscode-server"]);
    // Just a smoke check: VS Code preset doesn't force a command; we
    // can still run `echo` over SSH.
    let out = ssh_exec(port, &[], "echo vscode-preset-ok");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("vscode-preset-ok"),
        "vscode-server preset broke; stdout = {stdout:?}"
    );
}

#[test]
#[ignore]
fn t_interactive_preset_pins_shell() {
    if let Err(why) = require_prereqs() {
        eprintln!("SKIP: {why}");
        return;
    }
    let port = next_port();
    let _box = start_sandbox("ltb-interactive", port, &["--interactive"]);
    // With --interactive, every session lands at the configured shell
    // (default /usr/bin/bash). The client doesn't specify a command;
    // dropbear's -c forces bash. We pipe an `echo` through bash's
    // stdin to verify a real bash is running.
    let mut child = Command::new("ssh")
        .args([
            "-p",
            &port.to_string(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "root@127.0.0.1",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn ssh");
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("ssh stdin");
        writeln!(stdin, "echo interactive-bash-ok && exit").expect("write");
    }
    let out = child.wait_with_output().expect("ssh wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("interactive-bash-ok"),
        "interactive preset didn't run bash; stdout = {stdout:?}"
    );
}
