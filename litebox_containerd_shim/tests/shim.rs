// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs the shim daemon as containerd does, against a fake containerd event service, with the
//! real broker, runner and guest service. Each test builds the static guest service, the broker,
//! the runner, and `tests/guest.c` with `cc -static`. Needs no root.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

#[path = "support/cargo.rs"]
mod cargo;

use containerd_shim::api::{
    CloseIORequest, ConnectRequest, CreateTaskRequest, DeleteRequest, DeleteResponse,
    ExecProcessRequest, KillRequest, ResizePtyRequest, ShutdownRequest, StartRequest, StateRequest,
    Status, WaitRequest,
};
use containerd_shim::protos::events::task::{
    TaskCreate, TaskDelete, TaskExecAdded, TaskExecStarted, TaskExit, TaskStart,
};
use containerd_shim::protos::protobuf::well_known_types::any::Any;
use containerd_shim::protos::protobuf::{Message, MessageField};
use containerd_shim::protos::shim::events::ForwardRequest;
use containerd_shim::protos::shim_sync::{Client, Events, TaskClient, create_events};
use containerd_shim::protos::ttrpc::{self, Code, Server, TtrpcContext, context};
use containerd_shim::protos::types::empty::Empty;

const SHIM: &str = env!("CARGO_BIN_EXE_containerd-shim-litebox-v1");
const NAMESPACE: &str = "litebox-test";
const TIMEOUT: Duration = Duration::from_mins(1);

fn deadline() -> context::Context {
    context::with_timeout(i64::try_from(TIMEOUT.as_nanos()).unwrap())
}

/// Polls `done` until it holds, failing with `what` after [`TIMEOUT`].
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < TIMEOUT, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The events the shim publishes, as `topic summary`.
#[derive(Default)]
struct EventLog {
    events: Mutex<Vec<String>>,
    published: Condvar,
}

impl Events for EventLog {
    fn forward(&self, _ctx: &TtrpcContext, request: ForwardRequest) -> ttrpc::Result<Empty> {
        let envelope = request.envelope.unwrap_or_default();
        assert_eq!(envelope.namespace, NAMESPACE);
        let value = &envelope.event.value;
        let summary = match envelope.topic.as_str() {
            "/tasks/create" => TaskCreate::parse_from_bytes(value).unwrap().container_id,
            "/tasks/start" => TaskStart::parse_from_bytes(value).unwrap().container_id,
            "/tasks/exec-added" => TaskExecAdded::parse_from_bytes(value).unwrap().exec_id,
            "/tasks/exec-started" => TaskExecStarted::parse_from_bytes(value).unwrap().exec_id,
            "/tasks/exit" => {
                let event = TaskExit::parse_from_bytes(value).unwrap();
                format!("{} {}", event.id, event.exit_status)
            }
            "/tasks/delete" => {
                let event = TaskDelete::parse_from_bytes(value).unwrap();
                format!("{} {}", event.container_id, event.exit_status)
            }
            topic => panic!("unexpected event topic {topic}"),
        };
        let mut events = self.events.lock().unwrap();
        events.push(format!("{} {summary}", envelope.topic));
        self.published.notify_all();
        Ok(Empty::new())
    }
}

/// A shim daemon serving the container `c`, whose image holds the guest as `/usr/bin/guest`,
/// `/bin -> usr/bin`, `/usr/bin/sh -> /bin/guest`, and an `/etc/passwd`.
struct Shim {
    dir: tempfile::TempDir,
    daemon: Child,
    client: TaskClient,
    events: Arc<EventLog>,
    _event_server: Server,
    bundle: PathBuf,
}

impl Shim {
    fn launch(process: &serde_json::Value) -> Self {
        let guest_service = cargo::build_static_guest_service();
        let (built_broker, built_runner) = cargo::build_broker_and_runner();
        let dir = tempfile::Builder::new().prefix("lbx").tempdir().unwrap();
        // Through a link, which a test can remove.
        let broker = dir.path().join("litebox-broker-userland");
        std::os::unix::fs::symlink(built_broker, &broker).unwrap();
        let bundle = dir.path().join("c");
        let rootfs = bundle.join("rootfs");
        for directory in ["usr/bin", "usr/lib", "etc", "data"] {
            std::fs::create_dir_all(rootfs.join(directory)).unwrap();
        }
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/guest.c");
        let status = Command::new("cc")
            .args(["-static", "-O1", "-o"])
            .arg(rootfs.join("usr/bin/guest"))
            .arg(&source)
            .status()
            .expect("the shim tests need a C compiler, `cc`");
        assert!(status.success());
        std::os::unix::fs::symlink("usr/bin", rootfs.join("bin")).unwrap();
        std::os::unix::fs::symlink("/bin/guest", rootfs.join("usr/bin/sh")).unwrap();
        std::fs::write(
            rootfs.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/x\n",
        )
        .unwrap();
        let config = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": process,
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc"},
                {"destination": "/run", "type": "tmpfs", "source": "tmpfs"},
            ],
            // The daemon's network, as `ctr run --net-host` asks.
            "linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}]},
        });
        std::fs::write(bundle.join("config.json"), config.to_string()).unwrap();
        let events = Arc::new(EventLog::default());
        let event_socket = dir.path().join("events.sock");
        let mut event_server = Server::new()
            .bind(&format!("unix://{}", event_socket.display()))
            .unwrap()
            .register_service(create_events(events.clone()));
        event_server.start().unwrap();
        // Like containerd, run the daemon in a directory with its `log`.
        let work = dir.path().join("shim");
        std::fs::create_dir(&work).unwrap();
        File::create(work.join("log")).unwrap();
        let socket = dir.path().join("shim.sock");
        let address = format!("unix://{}", socket.display());
        let daemon = shim_command()
            .args(["-socket", &address])
            .current_dir(&work)
            .env("TTRPC_ADDRESS", &event_socket)
            .env("LITEBOX_GUEST_SERVICE", guest_service)
            .env("LITEBOX_BROKER", broker)
            .env("LITEBOX_RUNNER", built_runner)
            .env("LITEBOX_SHIM_STATE_ROOT", dir.path().join("state"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(dir.path().join("stderr")).unwrap())
            .spawn()
            .unwrap();
        wait_until("the shim daemon did not listen", || socket.exists());
        let client = TaskClient::new(Client::connect(&address).unwrap());
        Self {
            dir,
            daemon,
            client,
            events,
            _event_server: event_server,
            bundle,
        }
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_str().unwrap().to_owned()
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.path().join("state").join(NAMESPACE).join("c")
    }

    /// Changes the container's spec before `Create`.
    fn configure(&self, change: impl FnOnce(&mut serde_json::Value)) {
        let config = self.bundle.join("config.json");
        let mut spec = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        change(&mut spec);
        std::fs::write(&config, serde_json::to_string(&spec).unwrap()).unwrap();
    }

    fn output(&self, name: &str) -> String {
        std::fs::read_to_string(self.path(name)).unwrap_or_default()
    }

    fn wait_output(&self, name: &str, text: &str) {
        wait_until(&format!("{name} never showed {text:?}"), || {
            self.output(name).contains(text)
        });
    }

    fn mkfifo(&self, name: &str) -> String {
        let path = self.path(name);
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        path
    }

    /// `Create`, with stdout in `c.out` and stderr in `logs/c.err`, in a missing directory, and
    /// the request's other fields as `change` sets them.
    fn create_by(&self, change: impl FnOnce(&mut CreateTaskRequest)) -> ttrpc::Result<u32> {
        let mut request = CreateTaskRequest {
            id: "c".to_owned(),
            bundle: self.bundle.to_str().unwrap().to_owned(),
            stdout: format!("file://{}", self.path("c.out")),
            stderr: format!("file://{}", self.path("logs/c.err")),
            ..Default::default()
        };
        change(&mut request);
        self.client
            .create(deadline(), &request)
            .map(|response| response.pid)
    }

    fn create_with(&self, stdin: &str, terminal: bool) -> ttrpc::Result<u32> {
        self.create_by(|request| {
            stdin.clone_into(&mut request.stdin);
            request.terminal = terminal;
        })
    }

    fn create(&self) -> ttrpc::Result<u32> {
        self.create_with("", false)
    }

    fn start(&self, exec_id: &str) -> ttrpc::Result<u32> {
        let request = StartRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        self.client
            .start(deadline(), &request)
            .map(|response| response.pid)
    }

    /// `Exec` of `args`, with stdout in `<exec_id>.out`.
    fn exec(
        &self,
        exec_id: &str,
        args: &[&str],
        stdin: &str,
        terminal: bool,
    ) -> ttrpc::Result<Empty> {
        let request = ExecProcessRequest {
            stdin: stdin.to_owned(),
            stdout: format!("file://{}", self.path(&format!("{exec_id}.out"))),
            terminal,
            ..exec_request(exec_id, args)
        };
        self.client.exec(deadline(), &request)
    }

    /// Runs the exec process `exec_id` to its end; returns its status and output.
    fn run(&self, exec_id: &str, args: &[&str]) -> (u32, String) {
        self.exec(exec_id, args, "", false).unwrap();
        self.start(exec_id).unwrap();
        let status = self.wait(exec_id);
        self.delete(exec_id).unwrap();
        (status, self.output(&format!("{exec_id}.out")))
    }

    /// Starts the exec process `exec_id` of `args`, with stdout to the new FIFO `<exec_id>.out`
    /// as a plain path; returns the FIFO.
    fn start_to_fifo(&self, exec_id: &str, args: &[&str]) -> String {
        let fifo = self.mkfifo(&format!("{exec_id}.out"));
        let request = ExecProcessRequest {
            stdout: fifo.clone(),
            ..exec_request(exec_id, args)
        };
        self.client.exec(deadline(), &request).unwrap();
        self.start(exec_id).unwrap();
        fifo
    }

    fn wait(&self, exec_id: &str) -> u32 {
        let request = WaitRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        self.client.wait(deadline(), &request).unwrap().exit_status
    }

    fn close_stdin(&self, exec_id: &str) {
        let request = CloseIORequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            stdin: true,
            ..Default::default()
        };
        self.client.close_io(deadline(), &request).unwrap();
    }

    /// The process's status and exit status.
    fn state(&self, exec_id: &str) -> (Status, u32) {
        let request = StateRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        let response = self.client.state(deadline(), &request).unwrap();
        (response.status.enum_value().unwrap(), response.exit_status)
    }

    fn kill(&self, exec_id: &str, signal: u32, all: bool) -> ttrpc::Result<Empty> {
        let request = KillRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            signal,
            all,
            ..Default::default()
        };
        self.client.kill(deadline(), &request)
    }

    fn resize(&self, exec_id: &str, width: u32, height: u32) {
        let request = ResizePtyRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            width,
            height,
            ..Default::default()
        };
        self.client.resize_pty(deadline(), &request).unwrap();
    }

    fn delete(&self, exec_id: &str) -> ttrpc::Result<u32> {
        let request = DeleteRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        self.client
            .delete(deadline(), &request)
            .map(|response| response.exit_status)
    }

    /// Runs the shim's `delete` action, as containerd does after the daemon died.
    fn delete_action(&self) -> u32 {
        let output = shim_command()
            .arg("-bundle")
            .arg(&self.bundle)
            .arg("delete")
            .current_dir(&self.bundle)
            .env("TTRPC_ADDRESS", self.path("events.sock"))
            .env("LITEBOX_SHIM_STATE_ROOT", self.dir.path().join("state"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        DeleteResponse::parse_from_bytes(&output.stdout)
            .unwrap()
            .exit_status
    }

    /// Waits for `count` events and returns them.
    fn events(&self, count: usize) -> Vec<String> {
        let events = self.events.events.lock().unwrap();
        let (events, _) = self
            .events
            .published
            .wait_timeout_while(events, TIMEOUT, |events| events.len() < count)
            .unwrap();
        events.clone()
    }

    fn shutdown(&self) {
        let request = ShutdownRequest {
            id: "c".to_owned(),
            ..Default::default()
        };
        self.client.shutdown(deadline(), &request).unwrap();
    }

    /// Deletes the container and goes on as [`Self::finish_deleted`].
    fn finish(&mut self, broker: u32) {
        self.delete("").unwrap();
        self.finish_deleted(broker);
    }

    /// Kills the init with `SIGKILL` and goes on as [`Self::finish`].
    fn kill_and_finish(&mut self, broker: u32) {
        self.kill("", 9, false).unwrap();
        assert_eq!(self.wait(""), 137);
        self.finish(broker);
    }

    /// Adds a `poststop` hook that writes its state to `poststop`.
    fn record_poststop(&self) {
        let hook = script(self, "hook", "cat > \"$1\"\n");
        let state = self.path("poststop");
        self.configure(|spec| {
            spec["hooks"] =
                serde_json::json!({"poststop": [{"path": hook, "args": ["hook", state]}]});
        });
    }

    /// Checks that the broker and the state directory are gone, and asks the daemon to exit, as
    /// containerd does.
    fn finish_deleted(&mut self, broker: u32) {
        assert!(is_gone(broker));
        assert!(!self.state_dir().exists());
        self.shutdown();
        wait_until("the daemon did not exit", || {
            self.daemon.try_wait().unwrap().is_some()
        });
    }
}

impl Drop for Shim {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        if std::thread::panicking() || std::env::var_os("LBX_SHOW").is_some() {
            eprintln!("daemon stderr:\n{}", self.output("stderr"));
            eprintln!("shim log:\n{}", self.output("shim/log"));
        }
    }
}

/// The shim's command, with the flags that containerd always passes.
fn shim_command() -> Command {
    let mut command = Command::new(SHIM);
    let address = "/run/containerd/containerd.sock";
    command.args(["-namespace", NAMESPACE, "-id", "c", "-address", address]);
    command
}

fn code(error: &ttrpc::Error) -> Code {
    match error {
        ttrpc::Error::RpcStatus(status) => status.code(),
        other => panic!("not a status: {other:?}"),
    }
}

fn process(args: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "args": args,
        "env": ["PATH=/bin"],
        "cwd": "/",
        "user": {"uid": 0, "gid": 0},
    })
}

/// An `Exec` request of `args`, without I/O.
fn exec_request(exec_id: &str, args: &[&str]) -> ExecProcessRequest {
    ExecProcessRequest {
        id: "c".to_owned(),
        exec_id: exec_id.to_owned(),
        spec: MessageField::some(Any {
            value: process(args).to_string().into_bytes(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The fields of `/proc/<pid>/stat` after the command name: `state ppid pgrp ...`.
fn stat_fields(pid: u32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(") ")?;
    Some(rest.split(' ').map(str::to_owned).collect())
}

/// Whether the process `pid` is gone: reaped, or a zombie.
fn is_gone(pid: u32) -> bool {
    stat_fields(pid).is_none_or(|fields| fields[0] == "Z")
}

/// The live processes whose `/proc/<pid>/stat` field `index` (after the command name) is `value`.
fn processes_with(index: usize, value: u32) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            stat_fields(*pid)
                .is_some_and(|fields| fields[index] == value.to_string() && fields[0] != "Z")
        })
        .collect()
}

/// The live processes of the process group of `pid`, the broker's: the guardian, the broker and
/// its runners.
fn group_members(pid: u32) -> impl Fn() -> usize {
    let group = stat_fields(pid).unwrap()[2].parse().unwrap();
    move || processes_with(2, group).len()
}

#[test]
fn a_container_runs_and_reports_its_exit() {
    let mut init = process(&["sh", "exit", "3"]);
    init["cwd"] = "/bin/../new".into();
    init["env"] = serde_json::json!(["PATH=/first:/bin"]);
    let mut shim = Shim::launch(&init);
    // The guest user owns it, and may not execute it: the search goes on.
    let first = shim.bundle.join("rootfs/first");
    std::fs::create_dir(&first).unwrap();
    std::fs::write(first.join("sh"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(first.join("sh"), std::fs::Permissions::from_mode(0o641)).unwrap();
    shim.configure(|spec| {
        spec["annotations"] = serde_json::json!({"io.litebox.egress.tcp": "10.1.0.0/16:80-81"});
    });
    let pid = shim.create().unwrap();
    // The init's pid is the broker's, which allows the annotation's egress.
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap();
    assert!(cmdline.contains("litebox-broker-userland"), "{cmdline}");
    assert!(
        cmdline.contains("--allow-tcp-destination\u{0}10.1.0.0/16:80-81\u{0}"),
        "{cmdline}"
    );
    assert_eq!(shim.start("").unwrap(), pid);
    assert_eq!(shim.wait(""), 3);
    // Through `/usr/bin/sh -> /bin/guest` and `/bin -> usr/bin`; as the guest user for now, though
    // the spec's uid is 0 (until LiteBox has `setuid`); in the working directory, resolved as runc
    // does; with `HOME` from `/etc/passwd`.
    assert_eq!(
        shim.output("c.out"),
        "ids=1000,1000 cwd=/usr/new\nargv[0]=[sh]\nargv[1]=[exit]\nargv[2]=[3]\nenv=[PATH=/first:/bin]\nenv=[HOME=/root]\n"
    );
    assert_eq!(shim.output("logs/c.err"), "stderr\n");
    assert_eq!(code(&shim.kill("", 9, false).unwrap_err()), Code::NOT_FOUND);
    let late = shim.exec("e1", &["guest", "exit", "0"], "", false);
    assert_eq!(code(&late.unwrap_err()), Code::FAILED_PRECONDITION);
    shim.finish(pid);
    assert_eq!(
        shim.events(4),
        [
            "/tasks/create c",
            "/tasks/start c",
            "/tasks/exit c 3",
            "/tasks/delete c 3"
        ]
    );
}

#[test]
fn execs_take_input_and_their_output_comes_before_their_exit() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    // An exec ID can be used again once deleted, even while its input was open.
    shim.exec("e1", &["guest", "exit", "4"], &shim.mkfifo("in1"), false)
        .unwrap();
    assert_eq!(shim.start("e1").unwrap(), pid);
    assert_eq!(shim.wait("e1"), 4);
    shim.delete("e1").unwrap();
    let stdin = shim.mkfifo("in2");
    shim.exec("e1", &["guest", "cat"], &stdin, false).unwrap();
    shim.start("e1").unwrap();
    let mut input = std::fs::OpenOptions::new()
        .write(true)
        .open(&stdin)
        .unwrap();
    // Past the last poll of the first `e1`'s input.
    std::thread::sleep(Duration::from_millis(300));
    input.write_all(b"hello\n").unwrap();
    shim.close_stdin("e1");
    assert_eq!(shim.wait("e1"), 0);
    assert!(shim.output("e1.out").ends_with("line=[hello]\neof\n"));
    shim.delete("e1").unwrap();
    // The output reaches its host end before containerd learns of the exit.
    shim.exec("e2", &["guest", "lines", "20000"], "", false)
        .unwrap();
    shim.start("e2").unwrap();
    wait_until("no exit", || {
        shim.events(11).contains(&"/tasks/exit e2 0".to_owned())
    });
    assert!(shim.output("e2.out").ends_with("line 19999\n"));
    shim.delete("e2").unwrap();
    shim.kill("", 9, true).unwrap();
    assert_eq!(shim.wait(""), 137);
    shim.finish(pid);
    assert_eq!(
        shim.events(13),
        [
            "/tasks/create c",
            "/tasks/start c",
            "/tasks/exec-added e1",
            "/tasks/exec-started e1",
            "/tasks/exit e1 4",
            "/tasks/exec-added e1",
            "/tasks/exec-started e1",
            "/tasks/exit e1 0",
            "/tasks/exec-added e2",
            "/tasks/exec-started e2",
            "/tasks/exit e2 0",
            "/tasks/exit c 137",
            "/tasks/delete c 137",
        ]
    );
}

#[test]
fn a_reader_of_the_output_may_start_after_the_exit() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    // More than the FIFO and the guest service hold, from a child: the exec exits at once.
    let fifo = shim.start_to_fifo("e1", &["guest", "lines", "20000", "child"]);
    assert_eq!(shim.wait("e1"), 0);
    // Past the shim's 5 s without data.
    std::thread::sleep(Duration::from_secs(6));
    let output = std::fs::read_to_string(&fifo).unwrap();
    let lines: Vec<_> = (0..20_000).map(|line| format!("line {line}\n")).collect();
    assert!(output.ends_with(&lines.concat()), "{} bytes", output.len());
    shim.delete("e1").unwrap();
    shim.kill_and_finish(pid);
}

#[test]
fn an_exec_s_output_ends_once_idle_or_at_its_delete() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    let read = |fifo: String| {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || sender.send(std::fs::read_to_string(fifo).unwrap()));
        receiver
    };
    // The execs exit at once; their children keep stdout: silent, or printing every second.
    let silent = read(shim.start_to_fifo("e1", &["guest", "hold", "0"]));
    let ticking = read(shim.start_to_fifo("e2", &["guest", "hold", "1"]));
    // Once the copier had no data for 5 s, which the exit's publication already waited.
    let silent = silent.recv_timeout(Duration::from_secs(12));
    assert!(silent.is_ok(), "e1's output did not end");
    assert_eq!(shim.wait("e1"), 0);
    assert_eq!(shim.wait("e2"), 0);
    // Recent periodic output must keep the stream open beyond another whole idle interval.
    assert!(
        matches!(
            ticking.recv_timeout(Duration::from_secs(6)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "e2's periodic output ended before Delete"
    );
    shim.delete("e2").unwrap();
    let ticks = ticking.recv_timeout(Duration::from_secs(10));
    assert!(ticks.expect("e2's output did not end").ends_with("tick\n"));
    shim.delete("e1").unwrap();
    shim.kill_and_finish(pid);
}

#[test]
fn an_exec_s_delete_closes_its_unread_output() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    // The exec exits at once; its child fills the FIFO, which nobody reads.
    let fifo = shim.start_to_fifo("e1", &["guest", "lines", "50000", "child"]);
    assert_eq!(shim.wait("e1"), 0);
    let fds = format!("/proc/{}/fd", shim.daemon.id());
    let open = || {
        std::fs::read_dir(&fds).unwrap().any(|fd| {
            fd.and_then(|fd| std::fs::read_link(fd.path()))
                .is_ok_and(|target| target == Path::new(&fifo))
        })
    };
    assert!(open());
    shim.delete("e1").unwrap();
    // The shim's `DRAIN_TIMEOUT` (5 s), and a margin.
    let deleted = Instant::now();
    while open() && deleted.elapsed() < Duration::from_secs(8) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!open(), "the daemon still has e1's FIFO open");
    shim.kill_and_finish(pid);
}

#[test]
fn a_terminal_init_takes_a_resize_before_start() {
    let mut init = process(&["guest", "signals"]);
    init["terminal"] = true.into();
    let mut shim = Shim::launch(&init);
    let pid = shim.create_with("", true).unwrap();
    shim.resize("", 123, 45);
    shim.start("").unwrap();
    shim.wait_output("c.out", "tty=111 foreground=1 size=45x123\r\n");
    shim.kill_and_finish(pid);
}

#[test]
fn terminals_take_input_resizes_and_interrupts() {
    let mut init = process(&["guest", "signals"]);
    init["terminal"] = true.into();
    init["consoleSize"] = serde_json::json!({"height": 24, "width": 80});
    let mut shim = Shim::launch(&init);
    let stdin = shim.mkfifo("c.in");
    let pid = shim.create_with(&stdin, true).unwrap();
    shim.start("").unwrap();
    // Output processing turns each newline into CR LF.
    shim.wait_output("c.out", "tty=111 foreground=1 size=24x80\r\n");
    let mut input = std::fs::OpenOptions::new()
        .write(true)
        .open(&stdin)
        .unwrap();
    input.write_all(b"hello\r").unwrap();
    shim.wait_output("c.out", "line=[hello]\r\n");
    input.write_all(b"\x03").unwrap();
    shim.wait_output("c.out", "caught 2\r\n");
    shim.resize("", 100, 30);
    shim.wait_output("c.out", "resized 30x100\r\n");
    // An exec process's terminal is its own.
    shim.exec("e1", &["guest", "signals"], "", true).unwrap();
    shim.start("e1").unwrap();
    shim.wait_output("e1.out", "tty=111 foreground=1 size=0x0\r\n");
    shim.resize("e1", 9, 8);
    shim.wait_output("e1.out", "resized 8x9\r\n");
    shim.kill("e1", 15, false).unwrap();
    assert_eq!(shim.wait("e1"), 7);
    shim.delete("e1").unwrap();
    input.write_all(b"exit 5\r").unwrap();
    assert_eq!(shim.wait(""), 5);
    assert!(!shim.output("c.out").contains("resized 8x9"));
    shim.finish(pid);
}

#[test]
fn a_terminal_whose_input_ends_before_start_starts() {
    let mut init = process(&["guest", "exit", "4"]);
    init["terminal"] = true.into();
    let mut shim = Shim::launch(&init);
    let pid = shim.create_with(&shim.mkfifo("c.in"), true).unwrap();
    // Past the shim's `CloseStdin`, which the guest service refuses until the init starts.
    shim.close_stdin("");
    std::thread::sleep(Duration::from_millis(500));
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 4);
    assert!(shim.output("c.out").contains("argv[0]=[guest]"));
    shim.finish(pid);
}

#[test]
fn kills_reach_their_process() {
    let mut shim = Shim::launch(&process(&["guest", "signals"]));
    // Its input never ends.
    let pid = shim.create_with(&shim.mkfifo("c.in"), false).unwrap();
    shim.start("").unwrap();
    // A missing program, searched for or not, is the request's mistake; the guest service's
    // message, which names it, is truncated.
    let long = format!("/no/such/{}", "program/".repeat(1024));
    for program in ["missing", "/no/such/program", &long] {
        shim.exec("e0", &[program], "", false).unwrap();
        let ttrpc::Error::RpcStatus(status) = shim.start("e0").unwrap_err() else {
            unreachable!()
        };
        assert_eq!(status.code(), Code::INVALID_ARGUMENT, "{status:?}");
        let length = status.message.len();
        assert!(length < 4200, "{length} bytes");
        shim.delete("e0").unwrap();
    }
    shim.exec("e1", &["guest", "family"], "", false).unwrap();
    shim.start("e1").unwrap();
    shim.wait_output("e1.out", "child\n");
    // Not supported yet, as LiteBox would end the process: `SIGSTOP` fails, and it runs on.
    let stop = shim.kill("e1", 19, false).unwrap_err();
    assert_eq!(code(&stop), Code::UNIMPLEMENTED);
    assert_eq!(shim.state("e1"), (Status::RUNNING, 0));
    shim.kill("e1", 9, false).unwrap();
    assert_eq!(shim.wait("e1"), 137);
    assert_eq!(
        code(&shim.kill("e1", 9, false).unwrap_err()),
        Code::NOT_FOUND
    );
    shim.delete("e1").unwrap();
    shim.kill("", 15, false).unwrap();
    assert_eq!(shim.wait(""), 7);
    assert!(shim.output("c.out").ends_with("caught 15\n"));
    shim.finish(pid);
}

#[test]
fn a_native_snapshot_is_read_without_mounting_it() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "6"]));
    // containerd's native snapshotter binds a directory, the image, in place of the spec's root.
    // Neither the spec's root nor the bundle's `rootfs` holds the image: only the bind's source.
    let snapshot = shim.dir.path().join("snapshot");
    std::fs::rename(shim.bundle.join("rootfs"), &snapshot).unwrap();
    std::fs::create_dir(shim.bundle.join("rootfs")).unwrap();
    shim.configure(|spec| spec["root"]["path"] = "not-a-mounted-rootfs".into());
    let pid = shim
        .create_by(|request| {
            request.rootfs = vec![containerd_shim::protos::types::mount::Mount {
                type_: "bind".to_owned(),
                source: snapshot.to_str().unwrap().to_owned(),
                options: vec!["rbind".to_owned(), "rw".to_owned()],
                ..Default::default()
            }];
        })
        .unwrap();
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 6);
    assert!(shim.output("c.out").starts_with("ids=1000,1000 cwd=/\n"));
    shim.finish(pid);
}

#[test]
fn a_created_container_is_deleted_with_its_broker() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let pid = shim.create().unwrap();
    assert!(shim.state_dir().join("rootfs.tar").exists());
    shim.finish(pid);
    assert_eq!(
        shim.events(3),
        [
            "/tasks/create c",
            "/tasks/exit c 137",
            "/tasks/delete c 137"
        ]
    );
    assert_eq!(shim.output("c.out"), "");
}

#[test]
fn the_broker_group_dies_with_the_daemon() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    shim.record_poststop();
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    shim.wait_output("c.out", "child\n");
    let members = group_members(pid);
    assert!(members() > 3, "{}", members());
    shim.daemon.kill().unwrap();
    shim.daemon.wait().unwrap();
    wait_until("the broker's group outlived the daemon", || members() == 0);
    assert_eq!(shim.delete_action(), 137);
    assert!(!shim.state_dir().exists());
    // The `delete` action ran the `poststop` hook.
    let state: serde_json::Value = serde_json::from_str(&shim.output("poststop")).unwrap();
    assert_eq!(
        (&state["status"], &state["pid"]),
        (&"stopped".into(), &0.into())
    );
}

/// Writes the executable `#!/bin/sh` script `name` in the test's directory; returns its path.
fn script(shim: &Shim, name: &str, body: &str) -> String {
    let path = shim.path(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn hooks_run_on_the_host_with_the_state() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let dir = shim.dir.path().display().to_string();
    // `hook <stage> <seconds>` keeps its state, and notes when it starts and ends.
    let hook = script(
        &shim,
        "hook",
        &format!("cat > {dir}/$1\necho $1 >> {dir}/order\nsleep $2\necho $1 end >> {dir}/order\n"),
    );
    let fail = script(
        &shim,
        "fail",
        &format!(
            "cat > {dir}/$1\necho boom >&2\nhead -c 5000000 /dev/zero | tr '\\0' x >&2\nexit 1\n"
        ),
    );
    let hooks = |path: &str, name: &str, seconds: u32| serde_json::json!([{"path": path, "args": ["hook", name, seconds.to_string()], "timeout": 30}]);
    // A failing `createRuntime` hook fails `Create`, which ends the broker and runs `poststop`.
    shim.configure(|spec| {
        spec["hooks"] = serde_json::json!({
            "createRuntime": hooks(&fail, "failed", 0),
            "poststop": hooks(&hook, "poststop", 0),
        });
    });
    let error = shim.create().unwrap_err();
    assert_eq!(code(&error), Code::INTERNAL);
    let ttrpc::Error::RpcStatus(status) = error else {
        unreachable!()
    };
    // Its stderr, escaped and bounded, so that the error fits in a message.
    let stderr = format!(r#"stderr "boom\n{}""#, "x".repeat(4091));
    assert!(status.message.ends_with(&stderr), "{status:?}");
    let failed: serde_json::Value = serde_json::from_str(&shim.output("failed")).unwrap();
    assert!(is_gone(failed["pid"].as_u64().unwrap().try_into().unwrap()));
    assert!(!shim.state_dir().exists());
    assert_eq!(shim.output("order"), "poststop\npoststop end\n");
    std::fs::remove_file(shim.path("order")).unwrap();
    shim.configure(|spec| {
        spec["hooks"] = serde_json::json!({
            "createRuntime": hooks(&hook, "createRuntime", 1),
            "poststart": hooks(&hook, "poststart", 1),
            "poststop": hooks(&hook, "poststop", 0),
        });
    });
    let started = |stage: &str| shim.output("order").contains(&format!("{stage}\n"));
    let pid = std::thread::scope(|scope| {
        let create = scope.spawn(|| shim.create().unwrap());
        wait_until("no createRuntime hook", || started("createRuntime"));
        // containerd's `delete` action leaves a live daemon's state alone, and runs no hook.
        shim.delete_action();
        assert!(shim.state_dir().exists());
        // `Shutdown` waits for `Create`, and then finds a container.
        shim.shutdown();
        assert_eq!(shim.output("order"), "createRuntime\ncreateRuntime end\n");
        create.join().unwrap()
    });
    std::thread::scope(|scope| {
        let start = scope.spawn(|| shim.start("").unwrap());
        wait_until("no poststart hook", || started("poststart"));
        // The init exits at once, but its `Delete` waits for `poststart`.
        assert_eq!(shim.wait(""), 0);
        shim.delete("").unwrap();
        start.join().unwrap();
    });
    shim.finish_deleted(pid);
    assert_eq!(
        shim.output("order"),
        "createRuntime\ncreateRuntime end\npoststart\npoststart end\npoststop\npoststop end\n"
    );
    assert_eq!(
        shim.events(4),
        [
            "/tasks/create c",
            "/tasks/start c",
            "/tasks/exit c 0",
            "/tasks/delete c 0"
        ]
    );
    // A stopped container has no pid.
    for (stage, status, pid) in [
        ("createRuntime", "creating", pid),
        ("poststart", "running", pid),
        ("poststop", "stopped", 0),
    ] {
        let state: serde_json::Value = serde_json::from_str(&shim.output(stage)).unwrap();
        assert_eq!(state["id"], "c");
        assert_eq!(state["pid"], pid);
        assert_eq!(state["bundle"], shim.bundle.to_str().unwrap());
        assert_eq!(state["status"], status);
    }
}

#[test]
fn a_logging_program_gets_the_output() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    // Ready once `$2.go` exists.
    script(
        &shim,
        "logging program",
        "echo $$ > \"$2.pid\"\nwhile [ ! -e \"$2.go\" ]; do sleep 0.01; done\nexec 5>&-\n\
         printf '[%s]' \"$@\" > \"$2.args\"\nenv > \"$2.env\"\n\
         cat <&3 > \"$2.out\" &\ncat <&4 > \"$2.err\"\nwait\nexec sleep 30\n",
    );
    let uri = format!(
        "binary://{}?log={}&a+b=c%2Bd",
        shim.path("logging%20program"),
        shim.path("log").replace('/', "%2F")
    );
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    let request = ExecProcessRequest {
        stdout: uri.clone(),
        stderr: uri,
        ..exec_request("e1", &["guest", "exit", "0"])
    };
    shim.client.exec(deadline(), &request).unwrap();
    std::thread::scope(|scope| {
        let start = scope.spawn(|| shim.start("e1"));
        wait_until("no logging program", || !shim.output("log.pid").is_empty());
        // The program may call the shim before it is ready.
        let connect = ConnectRequest {
            id: "c".to_owned(),
            ..Default::default()
        };
        let connected = shim.client.connect(deadline(), &connect).unwrap();
        assert_eq!(connected.task_pid, pid);
        std::fs::write(shim.path("log.go"), "").unwrap();
        assert_eq!(start.join().unwrap().unwrap(), pid);
    });
    assert_eq!(shim.wait("e1"), 0);
    // Past the drain's timeout, `Delete` ends it and reaps it; it read everything before.
    let logger: u32 = shim.output("log.pid").trim().parse().unwrap();
    shim.delete("e1").unwrap();
    assert!(stat_fields(logger).is_none());
    assert!(shim.output("log.out").contains("argv[0]=[guest]\n"));
    assert_eq!(shim.output("log.err"), "stderr\n");
    let args = format!("[log][{}][a b][c+d]", shim.path("log"));
    assert_eq!(shim.output("log.args"), args);
    let env = shim.output("log.env");
    let env: Vec<&str> = env.lines().collect();
    assert!(env.contains(&"CONTAINER_ID=c"), "{env:?}");
    assert!(env.contains(&"CONTAINER_NAMESPACE=litebox-test"), "{env:?}");
    assert!(
        !env.iter().any(|entry| entry.starts_with("LITEBOX_")),
        "{env:?}"
    );
    shim.kill_and_finish(pid);
}

#[test]
fn the_delete_action_finishes_a_delete_cut_short() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    shim.record_poststop();
    // It notes `SIGTERM` and goes on: `Delete` waits 13 s for it.
    let logger = script(
        &shim,
        "logger",
        "trap 'echo > \"$2.term\"' TERM\necho $$ > \"$2.pid\"\nexec 5>&-\n\
         cat <&3 >/dev/null &\ncat <&4 >/dev/null\nwait\nwhile :; do sleep 1; done\n",
    );
    let uri = format!("binary://{logger}?log={}", shim.path("log"));
    shim.create_by(|request| {
        request.stdout = uri.clone();
        request.stderr = uri;
    })
    .unwrap();
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 0);
    let daemon = rustix::process::Pid::from_raw(shim.daemon.id().try_into().unwrap()).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| shim.delete(""));
        // While `Delete` ends the logging program, after it stopped the broker.
        shim.wait_output("log.term", "\n");
        rustix::process::kill_process(daemon, rustix::process::Signal::KILL).unwrap();
    });
    shim.daemon.wait().unwrap();
    let logger = shim.output("log.pid").trim().parse().unwrap();
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(logger).unwrap(),
        rustix::process::Signal::KILL,
    )
    .unwrap();
    assert_eq!(shim.delete_action(), 137);
    assert!(!shim.state_dir().exists());
    let state: serde_json::Value = serde_json::from_str(&shim.output("poststop")).unwrap();
    assert_eq!(state["status"], "stopped");
}

#[test]
fn a_broker_that_dies_before_start_stops_the_init() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let pid = shim.create().unwrap();
    let broker = rustix::process::Pid::from_raw(pid.try_into().unwrap()).unwrap();
    rustix::process::kill_process(broker, rustix::process::Signal::KILL).unwrap();
    wait_until("the init did not stop", || {
        shim.state("") == (Status::STOPPED, 255)
    });
    assert_eq!(shim.wait(""), 255);
    shim.finish(pid);
    assert_eq!(
        shim.events(3),
        [
            "/tasks/create c",
            "/tasks/exit c 255",
            "/tasks/delete c 255"
        ]
    );
}

#[test]
fn a_broker_that_dies_stops_created_execs_and_refuses_more() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    // An exec whose unread output fills its FIFO: its exit, and so the init's, waits 5 s for it.
    let fifo = shim.start_to_fifo("e0", &["guest", "lines", "50000"]);
    let flags = rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK;
    let probe = rustix::fs::open(&fifo, flags, rustix::fs::Mode::empty()).unwrap();
    wait_until("e0's FIFO did not fill", || {
        rustix::io::write(&probe, b"\n").is_err()
    });
    shim.exec("e1", &["guest", "exit", "0"], "", false).unwrap();
    let broker = rustix::process::Pid::from_raw(pid.try_into().unwrap()).unwrap();
    rustix::process::kill_process(broker, rustix::process::Signal::KILL).unwrap();
    assert_eq!(shim.wait("e1"), 255);
    let late = shim.exec("e2", &["guest", "exit", "0"], "", false);
    assert_eq!(code(&late.unwrap_err()), Code::FAILED_PRECONDITION);
    assert_eq!(shim.wait(""), 255);
    shim.finish(pid);
}

#[test]
fn a_dead_guest_service_stops_the_broker() {
    let mut shim = Shim::launch(&process(&["guest", "kill-service"]));
    let pid = shim.create().unwrap();
    let members = group_members(pid);
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 255);
    assert_eq!(members(), 0);
    shim.finish(pid);
}

/// Stops the runners of `broker`, the test's own broker, the guest service's among them; then
/// checks that `Start` of `exec_id`, with a deadline well above the shim's, fails after the
/// shim's 30 s.
fn start_unanswered(shim: &Shim, broker: u32, exec_id: &str) {
    let runners = processes_with(1, broker);
    assert_ne!(runners.len(), 0, "the broker has no runners");
    for runner in runners {
        let runner = rustix::process::Pid::from_raw(runner.try_into().unwrap()).unwrap();
        rustix::process::kill_process(runner, rustix::process::Signal::STOP).unwrap();
    }
    let request = StartRequest {
        id: "c".to_owned(),
        exec_id: exec_id.to_owned(),
        ..Default::default()
    };
    let started = Instant::now();
    let patient = context::with_timeout(i64::try_from((TIMEOUT * 2).as_nanos()).unwrap());
    let error = shim.client.start(patient, &request).unwrap_err();
    let elapsed = started.elapsed();
    let expected = Duration::from_secs(29)..Duration::from_secs(50);
    assert!(expected.contains(&elapsed), "{elapsed:?}: {error:?}");
}

#[test]
fn a_guest_service_that_does_not_answer_is_taken_for_dead() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let pid = shim.create().unwrap();
    start_unanswered(&shim, pid, "");
    assert_eq!(shim.state(""), (Status::STOPPED, 255));
    shim.finish(pid);
    assert_eq!(
        shim.events(3),
        [
            "/tasks/create c",
            "/tasks/exit c 255",
            "/tasks/delete c 255"
        ]
    );
}

#[test]
fn a_guest_service_that_does_not_answer_an_exec_is_taken_for_dead() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    shim.exec("e1", &["guest", "exit", "0"], "", false).unwrap();
    start_unanswered(&shim, pid, "e1");
    // The init's watcher saw the broker stop.
    assert_eq!(shim.wait(""), 255);
    shim.finish(pid);
    assert_eq!(
        shim.events(5),
        [
            "/tasks/create c",
            "/tasks/start c",
            "/tasks/exec-added e1",
            "/tasks/exit c 255",
            "/tasks/delete c 255"
        ]
    );
}

#[test]
fn binds_copy_files_and_serve_directories() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    let (hosts, resolv, data) = (shim.path("hosts"), shim.path("resolv"), shim.path("data"));
    std::fs::write(&hosts, "hosts\n").unwrap();
    std::fs::write(&resolv, "nameserver 127.0.0.53\nnameserver 192.0.2.1\n").unwrap();
    std::fs::create_dir(&data).unwrap();
    std::fs::write(shim.path("data/in"), "from the host\n").unwrap();
    shim.configure(|spec| {
        spec["mounts"].as_array_mut().unwrap().extend([
            serde_json::json!({"destination": "/etc/hosts", "type": "bind", "source": hosts, "options": ["rbind", "ro"]}),
            serde_json::json!({"destination": "/etc/resolv.conf", "type": "bind", "source": resolv}),
            // Beneath `/bin -> usr/bin`: served at `/usr/bin/data`.
            serde_json::json!({"destination": "/bin/data", "type": "bind", "source": data, "options": ["rbind"]}),
        ]);
    });
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    let (status, output) = shim.run(
        "e1",
        &[
            "guest",
            "read",
            "/bin/sh",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/bin/data/in",
            "/usr/bin/data/in",
        ],
    );
    assert_eq!(status, 0, "{output}");
    let expected = "link=/bin/guest\nhosts\nnameserver 192.0.2.1\n\
                    # Added by the LiteBox shim: IPv4 only, for glibc.\noptions no-aaaa\n\
                    from the host\nfrom the host\n";
    assert!(output.ends_with(expected), "{output}");
    assert_eq!(
        shim.run("e2", &["guest", "write", "/bin/data/out", "from the guest"])
            .0,
        0
    );
    assert_eq!(shim.output("data/out"), "from the guest");
    shim.kill_and_finish(pid);
}

#[test]
fn refused_or_unsupported_specs_and_annotations_fail_create() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let config = std::fs::read(shim.bundle.join("config.json")).unwrap();
    let data = shim.path("data");
    std::fs::create_dir(&data).unwrap();
    let cases: [(&str, serde_json::Value, Code); 8] = [
        (
            "hooks",
            serde_json::json!({"createContainer": [{"path": "/bin/true"}]}),
            Code::UNIMPLEMENTED,
        ),
        // Not supported yet: a new network namespace, without a path or with an empty one.
        (
            "linux",
            serde_json::json!({"namespaces": [{"type": "network"}]}),
            Code::UNIMPLEMENTED,
        ),
        (
            "linux",
            serde_json::json!({"namespaces": [{"type": "network", "path": ""}]}),
            Code::UNIMPLEMENTED,
        ),
        // Not supported yet: mounts of other types, read-only directory binds, binds nested in a
        // directory bind.
        (
            "mounts",
            serde_json::json!([{"destination": "/mnt", "type": "nfs", "source": "x"}]),
            Code::UNIMPLEMENTED,
        ),
        (
            "mounts",
            serde_json::json!([{"destination": "/d", "type": "bind", "source": data, "options": ["ro"]}]),
            Code::UNIMPLEMENTED,
        ),
        (
            "mounts",
            serde_json::json!([
                {"destination": "/d/child", "type": "bind", "source": data},
                {"destination": "/d", "type": "bind", "source": data},
            ]),
            Code::UNIMPLEMENTED,
        ),
        (
            "annotations",
            serde_json::json!({"io.litebox.egress.udp": "10.0.0.1/8:53"}),
            Code::INVALID_ARGUMENT,
        ),
        (
            "annotations",
            serde_json::json!({"io.LiteBox.other": "x"}),
            Code::INVALID_ARGUMENT,
        ),
    ];
    for (field, value, expected) in cases {
        shim.configure(|spec| spec[field] = value.clone());
        assert_eq!(
            code(&shim.create().unwrap_err()),
            expected,
            "{field}: {value}"
        );
        std::fs::write(shim.bundle.join("config.json"), &config).unwrap();
    }
    // Not supported, as in Kata Containers: checkpoints.
    let refused = shim
        .create_by(|request| request.checkpoint = shim.path("checkpoint"))
        .unwrap_err();
    assert_eq!(code(&refused), Code::UNIMPLEMENTED);
    assert!(!shim.state_dir().exists());
    // A missing broker fails at once.
    let broker = std::fs::read_link(shim.path("litebox-broker-userland")).unwrap();
    std::fs::remove_file(shim.path("litebox-broker-userland")).unwrap();
    assert_eq!(code(&shim.create().unwrap_err()), Code::INTERNAL);
    assert!(!shim.state_dir().exists());
    std::os::unix::fs::symlink(broker, shim.path("litebox-broker-userland")).unwrap();
    // A live daemon of an earlier container with this ID keeps its state locked, and the state.
    let earlier = shim.state_dir();
    std::fs::create_dir(&earlier).unwrap();
    std::fs::write(earlier.join("mark"), "").unwrap();
    let lock = File::open(&earlier).unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
    assert_eq!(code(&shim.create().unwrap_err()), Code::FAILED_PRECONDITION);
    assert!(earlier.join("mark").exists());
    drop(lock);
    // Namespaces' paths are ignored; an init that cannot start ends the container.
    shim.configure(|spec| {
        spec["process"]["args"] = serde_json::json!(["/no/such/program"]);
        spec["linux"] = serde_json::json!({"namespaces": [
            {"type": "pid", "path": "/proc/1/ns/pid"},
            {"type": "network", "path": "/proc/1/ns/net"},
        ]});
    });
    let pid = shim.create().unwrap();
    let members = group_members(pid);
    assert_eq!(code(&shim.start("").unwrap_err()), Code::INVALID_ARGUMENT);
    assert_eq!(shim.wait(""), 127);
    assert_eq!(members(), 0);
    shim.finish(pid);
}
