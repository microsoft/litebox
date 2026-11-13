// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs `guest_service_test_client` against a fake guest service behind a fake hybrid vsock
//! bridge.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};

use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
use litebox_guest_service_protocol::guest_service::{
    CloseStdinRequest, CreateContainerRequest, Empty, ExecProcessRequest, ReadStreamRequest,
    ReadStreamResponse, ReleaseProcessRequest, SignalProcessRequest, TtyWinResizeRequest,
    WaitProcessRequest, WaitProcessResponse, WriteStreamRequest, WriteStreamResponse,
};
use litebox_guest_service_protocol::guest_service_ttrpc::{GuestService, create_guest_service};
use ttrpc::TtrpcContext;

/// A process of the fake: `/echo [CODE]` writes its input to its stdout once it ends, and exits
/// with CODE (default 0); `/kill SIGNAL` does so too, but then SIGNAL kills it; `/ready` first
/// writes `ready`, then its input as it comes, and exits once it has some.
#[derive(Default)]
struct Process {
    program: String,
    /// How it ends: its status and signal, as `WaitProcess` reports them.
    end: (i32, i32),
    input: Vec<u8>,
    input_closed: bool,
    /// The output not read yet, and whether it ended.
    output: Vec<u8>,
    output_ended: bool,
    exit: Option<(i32, i32)>,
}

#[derive(Default)]
struct Fake {
    processes: Mutex<HashMap<String, Process>>,
    changed: Condvar,
}

impl Fake {
    fn update<T>(&self, exec_id: &str, update: impl FnOnce(&mut Process) -> T) -> T {
        let mut processes = self.processes.lock().unwrap();
        let process = processes.get_mut(exec_id).expect("a known exec ID");
        let result = update(process);
        if process.exit.is_none() && process.program != "init" {
            let done = if process.program == "/ready" {
                !process.input.is_empty()
            } else {
                process.input_closed
            };
            if done {
                process.output.append(&mut process.input);
                process.output_ended = true;
                process.exit = Some(process.end);
            }
        }
        self.changed.notify_all();
        result
    }

    fn wait_for<T>(&self, exec_id: &str, mut ready: impl FnMut(&mut Process) -> Option<T>) -> T {
        let mut processes = self.processes.lock().unwrap();
        loop {
            if let Some(result) = ready(processes.get_mut(exec_id).expect("a known exec ID")) {
                return result;
            }
            processes = self.changed.wait(processes).unwrap();
        }
    }
}

impl GuestService for Fake {
    fn create_container(
        &self,
        _ctx: &TtrpcContext,
        _request: CreateContainerRequest,
    ) -> ttrpc::Result<Empty> {
        let init = Process {
            program: "init".to_owned(),
            ..Default::default()
        };
        self.processes.lock().unwrap().insert(String::new(), init);
        Ok(Empty::new())
    }

    fn start_container(&self, _ctx: &TtrpcContext, _request: Empty) -> ttrpc::Result<Empty> {
        Ok(Empty::new())
    }

    fn exec_process(
        &self,
        _ctx: &TtrpcContext,
        request: ExecProcessRequest,
    ) -> ttrpc::Result<Empty> {
        let args = &request.process.args;
        let process = Process {
            program: args[0].clone(),
            end: match (
                args[0].as_str(),
                args.get(1).map(|arg| arg.parse().unwrap()),
            ) {
                ("/kill", Some(signal)) => (128 + signal, signal),
                (_, code) => (code.unwrap_or(0), 0),
            },
            output: if args[0] == "/ready" {
                b"ready\n".to_vec()
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        self.processes
            .lock()
            .unwrap()
            .insert(request.exec_id, process);
        Ok(Empty::new())
    }

    fn signal_process(
        &self,
        _ctx: &TtrpcContext,
        request: SignalProcessRequest,
    ) -> ttrpc::Result<Empty> {
        let signal = i32::try_from(request.signal).unwrap();
        self.update(&request.exec_id, |process| {
            process.exit = Some((128 + signal, signal));
        });
        Ok(Empty::new())
    }

    fn wait_process(
        &self,
        _ctx: &TtrpcContext,
        request: WaitProcessRequest,
    ) -> ttrpc::Result<WaitProcessResponse> {
        let (status, signal) = self.wait_for(&request.exec_id, |process| process.exit);
        Ok(WaitProcessResponse {
            status,
            signal,
            ..Default::default()
        })
    }

    fn release_process(
        &self,
        _ctx: &TtrpcContext,
        request: ReleaseProcessRequest,
    ) -> ttrpc::Result<Empty> {
        self.processes.lock().unwrap().remove(&request.exec_id);
        Ok(Empty::new())
    }

    fn write_stdin(
        &self,
        _ctx: &TtrpcContext,
        request: WriteStreamRequest,
    ) -> ttrpc::Result<WriteStreamResponse> {
        let len = u32::try_from(request.data.len()).unwrap();
        self.update(&request.exec_id, |process| {
            process.input.extend_from_slice(&request.data);
        });
        Ok(WriteStreamResponse {
            len,
            ..Default::default()
        })
    }

    fn read_stdout(
        &self,
        _ctx: &TtrpcContext,
        request: ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        let data = self.wait_for(&request.exec_id, |process| {
            (!process.output.is_empty() || process.output_ended)
                .then(|| std::mem::take(&mut process.output))
        });
        Ok(ReadStreamResponse {
            data,
            ..Default::default()
        })
    }

    fn read_stderr(
        &self,
        _ctx: &TtrpcContext,
        _request: ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        Ok(ReadStreamResponse::new())
    }

    fn close_stdin(&self, _ctx: &TtrpcContext, request: CloseStdinRequest) -> ttrpc::Result<Empty> {
        self.update(&request.exec_id, |process| process.input_closed = true);
        Ok(Empty::new())
    }

    fn tty_win_resize(
        &self,
        _ctx: &TtrpcContext,
        _request: TtyWinResizeRequest,
    ) -> ttrpc::Result<Empty> {
        Ok(Empty::new())
    }
}

/// Serves the fake on a ttrpc socket in `dir`, behind a bridge at `dir/bridge`, which answers
/// `CONNECT` to the guest service's port and forwards the connection to the fake.
fn serve(dir: &Path) -> (ttrpc::Server, PathBuf) {
    let service = dir.join("service");
    let mut server = ttrpc::Server::new()
        .bind(&format!("unix://{}", service.display()))
        .unwrap()
        .register_service(create_guest_service(Arc::new(Fake::default())));
    server.start().unwrap();
    let bridge = dir.join("bridge");
    let listener = UnixListener::bind(&bridge).unwrap();
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let mut client = client.unwrap();
            let mut line = Vec::new();
            BufReader::with_capacity(1, &client)
                .read_until(b'\n', &mut line)
                .unwrap();
            assert_eq!(line, format!("CONNECT {GUEST_SERVICE_PORT}\n").as_bytes());
            client.write_all(b"OK 1234\n").unwrap();
            let guest = UnixStream::connect(&service).unwrap();
            for (mut from, mut to) in [
                (client.try_clone().unwrap(), guest.try_clone().unwrap()),
                (guest, client),
            ] {
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut from, &mut to);
                    let _ = to.shutdown(std::net::Shutdown::Write);
                });
            }
        }
    });
    (server, bridge)
}

/// Runs the client on `programs` (with `input`, if any), and returns whether it passed, its
/// stdout, and the runs' output.
fn run_client(programs: &str, input: Option<&str>) -> (bool, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let (server, bridge) = serve(dir.path());
    std::fs::write(dir.path().join("programs.json"), programs).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_guest_service_test_client"));
    command
        .arg("--bridge")
        .arg(&bridge)
        .arg("--output")
        .arg(dir.path().join("output"))
        .arg(dir.path().join("programs.json"));
    if let Some(input) = input {
        std::fs::write(dir.path().join("input"), input).unwrap();
        command.arg("--input").arg(dir.path().join("input"));
    }
    let result = command.output().unwrap();
    server.shutdown();
    let output = std::fs::read_to_string(dir.path().join("output")).unwrap_or_default();
    (
        result.status.success(),
        String::from_utf8(result.stdout).unwrap(),
        output,
    )
}

#[test]
fn runs_pass_with_their_input_output_and_status() {
    let (passed, report, output) = run_client(
        r#"[
            { "argv": ["/echo"], "stdin": "hi\n", "expect_stdout": "hi\n", "expect_stderr": "" },
            { "concurrent": [{ "argv": ["/echo", "3"], "expect_exit_code": 3 }, { "argv": ["/echo"] }] },
            { "argv": ["/kill", "9"], "expect_signal": 9 },
            { "argv": ["/ready"], "console_stdin": true, "expect_stdout": "ready\nin\n" }
        ]"#,
        Some("in\n"),
    );
    assert!(passed, "{report}");
    for run in 0..5 {
        assert!(report.contains(&format!("PASS  run {run} ")), "{report}");
    }
    assert_eq!(output, "hi\nready\nin\n");
}

/// An exit with a signal death's status is no signal death, nor the reverse.
#[test]
fn a_signal_death_and_an_exit_with_its_status_differ() {
    for (run, failure) in [
        (
            r#"[{ "argv": ["/echo", "134"], "expect_signal": 6 }]"#,
            "exited with 134, expected killed by signal 6",
        ),
        (
            r#"[{ "argv": ["/kill", "6"], "expect_exit_code": 134 }]"#,
            "killed by signal 6, expected exited with 134",
        ),
    ] {
        let (passed, report, _) = run_client(run, None);
        assert!(!passed, "{report}");
        assert!(report.contains(failure), "{report}");
    }
}

#[test]
fn a_run_that_ends_otherwise_fails() {
    let (passed, report, _) = run_client(
        r#"[
            { "argv": ["/echo"], "stdin": "hi\n", "expect_stdout": "bye\n" },
            { "argv": ["/echo", "1"] }
        ]"#,
        None,
    );
    assert!(!passed, "{report}");
    assert!(
        report.contains("FAIL  run 0 (/echo): stdout was"),
        "{report}"
    );
    // Runs stop at the first failure.
    assert!(!report.contains("run 1"), "{report}");
}
