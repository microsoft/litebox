// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs the shim daemon as containerd does, against a fake containerd event service, with real
//! runners. Needs no root, except the ignored tests: without root, the daemon mounts nothing and
//! its runners stay in its network namespace.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use containerd_shim::api::{
    CloseIORequest, CreateTaskRequest, DeleteRequest, DeleteResponse, ExecProcessRequest,
    KillRequest, PidsRequest, ResizePtyRequest, ShutdownRequest, StartRequest, StateRequest,
    StateResponse, Status, WaitRequest,
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

/// The events the shim publishes, summarized as `topic [exec ID] [status]`; `/tasks/create`
/// shows `terminal` after its container ID if its process has a terminal, and `/tasks/delete`
/// shows its container ID and its quoted exec ID.
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
        let topic = envelope.topic.as_str();
        assert!(envelope.timestamp.is_some());
        let (event_type, summary) = match topic {
            "/tasks/create" => {
                let event = TaskCreate::parse_from_bytes(value).unwrap();
                let terminal = if event.io.terminal { " terminal" } else { "" };
                ("TaskCreate", format!("{}{terminal}", event.container_id))
            }
            "/tasks/start" => (
                "TaskStart",
                TaskStart::parse_from_bytes(value).unwrap().container_id,
            ),
            "/tasks/exec-added" => (
                "TaskExecAdded",
                TaskExecAdded::parse_from_bytes(value).unwrap().exec_id,
            ),
            "/tasks/exec-started" => (
                "TaskExecStarted",
                TaskExecStarted::parse_from_bytes(value).unwrap().exec_id,
            ),
            "/tasks/exit" => {
                let event = TaskExit::parse_from_bytes(value).unwrap();
                ("TaskExit", format!("{} {}", event.id, event.exit_status))
            }
            "/tasks/delete" => {
                let event = TaskDelete::parse_from_bytes(value).unwrap();
                (
                    "TaskDelete",
                    format!(
                        "{} {:?} {}",
                        event.container_id, event.id, event.exit_status
                    ),
                )
            }
            _ => panic!("unexpected event topic {topic}"),
        };
        assert_eq!(
            envelope.event.type_url,
            format!("containerd.events.{event_type}")
        );
        self.events
            .lock()
            .unwrap()
            .push(format!("{topic} {summary}"));
        self.published.notify_all();
        Ok(Empty::new())
    }
}

/// A shim daemon serving one container.
struct Shim {
    dir: tempfile::TempDir,
    daemon: Child,
    client: TaskClient,
    events: Arc<EventLog>,
    event_server: Server,
    bundle: PathBuf,
}

/// Serves a fake containerd event service at `socket`.
fn serve_events(socket: &Path) -> (Arc<EventLog>, Server) {
    let events = Arc::new(EventLog::default());
    let mut server = Server::new()
        .bind(&format!("unix://{}", socket.display()))
        .unwrap()
        .register_service(create_events(events.clone()));
    server.start().unwrap();
    (events, server)
}

impl Shim {
    /// Launches a daemon for the container `c`, whose root file system holds the guest as
    /// `/bin/guest`, with the host directory `data` bound at `/data`, and whose init process is
    /// `process`.
    fn launch(process: &serde_json::Value) -> Self {
        let dir = tempfile::Builder::new().prefix("lbx").tempdir().unwrap();
        let bundle = dir.path().join("c");
        let rootfs = bundle.join("rootfs");
        for directory in ["bin", "tmp", "etc", "usr/lib"] {
            std::fs::create_dir_all(rootfs.join(directory)).unwrap();
        }
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("in"), "from the host\n").unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/guest.c");
        let status = Command::new("cc")
            .args(["-static", "-pthread", "-O1", "-o"])
            .arg(rootfs.join("bin/guest"))
            .arg(&source)
            .status()
            .expect("the shim tests need a C compiler, `cc`");
        assert!(status.success());
        // Absolute image symlinks, which name paths of the container, not of the host.
        std::os::unix::fs::symlink("/bin/guest", rootfs.join("bin/sh")).unwrap();
        std::fs::write(rootfs.join("usr/lib/os-release"), "ID=lbx\n").unwrap();
        std::os::unix::fs::symlink("/usr/lib/os-release", rootfs.join("etc/os-release")).unwrap();
        std::fs::write(
            rootfs.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\n",
        )
        .unwrap();
        let config = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": process,
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc"},
                {"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["mode=1777"]},
                {"destination": "/data", "type": "bind", "source": data, "options": ["rbind", "rw"]},
            ],
            "linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "network"}]},
        });
        std::fs::write(bundle.join("config.json"), config.to_string()).unwrap();

        let event_socket = dir.path().join("events.sock");
        let (events, event_server) = serve_events(&event_socket);

        // Like containerd, run the daemon in a directory with its `log` file.
        let work = dir.path().join("shim");
        std::fs::create_dir(&work).unwrap();
        File::create(work.join("log")).unwrap();
        Self::mkfifo_in(dir.path(), "c.err");
        let socket = dir.path().join("shim.sock");
        let address = format!("unix://{}", socket.display());
        let daemon = Command::new(SHIM)
            .args(["-namespace", NAMESPACE, "-id", "c"])
            .args(["-address", "/run/containerd/containerd.sock"])
            .args(["-socket", &address])
            .current_dir(&work)
            .env("TTRPC_ADDRESS", &event_socket)
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
            event_server,
            bundle,
        }
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_str().unwrap().to_owned()
    }

    /// Changes the container's spec before `Create`.
    fn configure(&self, change: impl FnOnce(&mut serde_json::Value)) {
        let config = self.bundle.join("config.json");
        let mut spec = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        change(&mut spec);
        std::fs::write(&config, serde_json::to_string(&spec).unwrap()).unwrap();
    }

    /// Runs the exec process `exec_id` to its end and returns its status and output.
    fn run(&self, exec_id: &str, args: &[&str]) -> (u32, String) {
        self.exec(exec_id, &process(args), "").unwrap();
        self.start(exec_id).unwrap();
        let status = self.wait(exec_id);
        self.delete(exec_id).unwrap();
        (status, self.output(&format!("{exec_id}.out")))
    }

    fn output(&self, name: &str) -> String {
        std::fs::read_to_string(self.path(name)).unwrap_or_default()
    }

    /// Waits until `text` appears in the output file `name`.
    fn wait_output(&self, name: &str, text: &str) {
        wait_until(&format!("{name} never showed {text:?}"), || {
            self.output(name).contains(text)
        });
    }

    fn mkfifo(&self, name: &str) -> String {
        Self::mkfifo_in(self.dir.path(), name)
    }

    fn mkfifo_in(dir: &Path, name: &str) -> String {
        let path = dir.join(name).to_str().unwrap().to_owned();
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

    /// The `Create` request of the container, whose stdout is `c.out` and stderr the FIFO `c.err`.
    fn create_request(&self, stdin: &str) -> CreateTaskRequest {
        CreateTaskRequest {
            id: "c".to_owned(),
            bundle: self.bundle.to_str().unwrap().to_owned(),
            stdin: stdin.to_owned(),
            stdout: format!("file://{}", self.path("c.out")),
            stderr: self.path("c.err"),
            ..Default::default()
        }
    }

    fn create(&self, stdin: &str) -> ttrpc::Result<u32> {
        self.client
            .create(deadline(), &self.create_request(stdin))
            .map(|response| response.pid)
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

    /// The `Exec` request of `exec_id`, whose stdout is `<exec_id>.out`.
    fn exec_request(
        &self,
        exec_id: &str,
        process: &serde_json::Value,
        stdin: &str,
    ) -> ExecProcessRequest {
        ExecProcessRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            stdin: stdin.to_owned(),
            stdout: format!("file://{}", self.path(&format!("{exec_id}.out"))),
            spec: MessageField::some(Any {
                value: process.to_string().into_bytes(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn exec(&self, exec_id: &str, process: &serde_json::Value, stdin: &str) -> ttrpc::Result<()> {
        let request = self.exec_request(exec_id, process, stdin);
        self.client.exec(deadline(), &request).map(drop)
    }

    fn wait(&self, exec_id: &str) -> u32 {
        let request = WaitRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        self.client.wait(deadline(), &request).unwrap().exit_status
    }

    /// Sends `Wait` for `exec_id` with the RPC deadline `timeout` and returns the status code of
    /// the response, which the generated client cannot see: it gives up at the deadline.
    fn wait_code(&self, exec_id: &str, timeout: Duration) -> Code {
        let wait = WaitRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        let request = ttrpc::Request {
            service: "containerd.task.v2.Task".to_owned(),
            method: "Wait".to_owned(),
            payload: wait.write_to_bytes().unwrap(),
            timeout_nano: i64::try_from(timeout.as_nanos()).unwrap(),
            ..Default::default()
        };
        let payload = request.write_to_bytes().unwrap();
        let length = u32::try_from(payload.len()).unwrap();
        let header: Vec<u8> = ttrpc::MessageHeader::new_request(1, length).into();
        let mut stream = UnixStream::connect(self.dir.path().join("shim.sock")).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.write_all(&[header, payload].concat()).unwrap();
        let mut header = [0; ttrpc::proto::MESSAGE_HEADER_LENGTH];
        stream.read_exact(&mut header).unwrap();
        let mut response = vec![0; ttrpc::MessageHeader::from(header).length as usize];
        stream.read_exact(&mut response).unwrap();
        ttrpc::Response::parse_from_bytes(&response)
            .unwrap()
            .status()
            .code()
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

    fn resize(&self, exec_id: &str, width: u32, height: u32) -> ttrpc::Result<Empty> {
        let request = ResizePtyRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            width,
            height,
            ..Default::default()
        };
        self.client.resize_pty(deadline(), &request)
    }

    fn state(&self, exec_id: &str) -> StateResponse {
        let request = StateRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        self.client.state(deadline(), &request).unwrap()
    }

    fn status(&self, exec_id: &str) -> Status {
        self.state(exec_id).status.enum_value_or_default()
    }

    fn pids(&self) -> Vec<u32> {
        let request = PidsRequest {
            id: "c".to_owned(),
            ..Default::default()
        };
        let mut pids = self.client.pids(deadline(), &request).unwrap().processes;
        pids.sort_by_key(|process| process.pid);
        pids.iter().map(|process| process.pid).collect()
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

    /// Runs the shim's `delete` action in the bundle, as containerd does after the daemon exited,
    /// and returns the status it reports.
    fn delete_action(&self) -> u32 {
        let output = Command::new(SHIM)
            .args(["-namespace", NAMESPACE, "-id", "c"])
            .args(["-address", "/run/containerd/containerd.sock"])
            .arg("-bundle")
            .arg(&self.bundle)
            .arg("delete")
            .current_dir(&self.bundle)
            .env("TTRPC_ADDRESS", self.path("events.sock"))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
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

    /// Asks the daemon to exit, as containerd does after `Delete`, and waits until it did.
    fn shut_down(mut self) {
        let request = ShutdownRequest {
            id: "c".to_owned(),
            ..Default::default()
        };
        self.client.shutdown(deadline(), &request).unwrap();
        wait_until("the daemon did not exit", || {
            self.daemon.try_wait().unwrap().is_some()
        });
        assert!(!self.bundle.join("litebox").exists());
    }
}

impl Drop for Shim {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        if std::thread::panicking() {
            eprintln!("daemon stderr:\n{}", self.output("stderr"));
            eprintln!("shim log:\n{}", self.output("shim/log"));
        }
    }
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
        "env": ["PATH=/bin", "SECRET=hunter2"],
        "cwd": "/tmp",
        "user": {"uid": 0, "gid": 0},
    })
}

/// Reads the stderr FIFO `path` to its end in the background.
fn drain(path: String) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || std::fs::read_to_string(path).unwrap())
}

#[test]
fn init_runs_once_started_and_reports_its_exit() {
    // The program is found in `PATH` through an absolute image symlink, and keeps its name.
    let shim = Shim::launch(&process(&["sh", "exit", "3"]));
    let pid = shim.create("").unwrap();
    let stderr = drain(shim.path("c.err"));
    assert_eq!(shim.status(""), Status::CREATED);
    // The runner waits behind its gate, with no guest value on its command line.
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    let cmdline = String::from_utf8_lossy(&cmdline);
    assert!(cmdline.contains("__litebox-runner"), "{cmdline}");
    assert!(
        !cmdline.contains("hunter2") && !cmdline.contains("exit"),
        "{cmdline}"
    );
    assert_eq!(code(&shim.create("").unwrap_err()), Code::ALREADY_EXISTS);
    assert_eq!(code(&shim.start("e9").unwrap_err()), Code::NOT_FOUND);

    assert_eq!(shim.start("").unwrap(), pid);
    assert_eq!(shim.wait(""), 3);
    assert_eq!(shim.status(""), Status::STOPPED);
    assert_eq!(
        shim.output("c.out"),
        "pid=1 ids=0,0 cwd=/tmp\nargv[0]=[sh]\nargv[1]=[exit]\nargv[2]=[3]\n\
         env=[PATH=/bin]\nenv=[SECRET=hunter2]\nenv=[HOME=/root]\n"
    );
    assert_eq!(
        code(&shim.kill("", 15, false).unwrap_err()),
        Code::NOT_FOUND
    );
    assert_eq!(shim.delete("").unwrap(), 3);
    assert_eq!(stderr.join().unwrap(), "stderr\n");
    assert_eq!(
        shim.events(4),
        [
            "/tasks/create c",
            "/tasks/start c",
            "/tasks/exit c 3",
            "/tasks/delete c \"\" 3"
        ]
    );
    shim.shut_down();
}

#[test]
fn execs_share_the_container_and_signals_reach_guests() {
    let shim = Shim::launch(&process(&["guest", "term"]));
    let init = shim.create("").unwrap();
    let _stderr = drain(shim.path("c.err"));
    shim.start("").unwrap();
    shim.wait_output("c.out", "ready\n");

    let fifo = shim.mkfifo("e1.in");
    shim.exec("e1", &process(&["guest", "cat"]), &fifo).unwrap();
    assert_eq!(shim.status("e1"), Status::CREATED);
    let exec = shim.start("e1").unwrap();
    let mut pids = vec![init, exec];
    pids.sort_unstable();
    assert_eq!(shim.pids(), pids);
    // The input ends only with CloseIO, even after the writer closes its end, as with runc.
    let mut writer = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
    writer.write_all(b"hello\n").unwrap();
    shim.wait_output("e1.out", "hello\n");
    drop(writer);
    assert_eq!(
        shim.wait_code("e1", Duration::from_millis(100)),
        Code::DEADLINE_EXCEEDED
    );
    // Without a reader this open fails instead of blocking.
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    writer.write_all(b"again\n").unwrap();
    shim.close_stdin("e1");
    assert_eq!(shim.wait("e1"), 0);
    drop(writer);
    let output = shim.output("e1.out");
    // A root process of the same broker as the init process, which is process 1.
    assert!(
        output.starts_with("pid=") && !output.starts_with("pid=1 "),
        "{output}"
    );
    assert!(output.ends_with("hello\nagain\neof\n"), "{output}");
    assert_eq!(shim.pids(), [init]);
    assert_eq!(shim.delete("e1").unwrap(), 0);

    shim.exec("e2", &process(&["guest", "exit", "4"]), "")
        .unwrap();
    assert_eq!(
        code(&shim.kill("e2", 15, false).unwrap_err()),
        Code::FAILED_PRECONDITION
    );
    assert_eq!(shim.delete("e2").unwrap(), 0);

    // A failed start reports no exit to containerd.
    shim.exec("e3", &process(&["missing"]), "").unwrap();
    assert_eq!(code(&shim.start("e3").unwrap_err()), Code::INVALID_ARGUMENT);
    assert_eq!(shim.status("e3"), Status::STOPPED);
    assert_eq!(shim.wait("e3"), 255);
    assert_eq!(shim.delete("e3").unwrap(), 255);

    // Input written and closed before the start still reaches the process, then its end.
    let fifo = shim.mkfifo("e4.in");
    // Read-write, since no reader holds the FIFO open yet.
    let mut writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fifo)
        .unwrap();
    writer.write_all(b"early\n").unwrap();
    shim.exec("e4", &process(&["guest", "cat"]), &fifo).unwrap();
    shim.close_stdin("e4");
    shim.start("e4").unwrap();
    assert_eq!(shim.wait("e4"), 0);
    drop(writer);
    let output = shim.output("e4.out");
    assert!(output.ends_with("early\neof\n"), "{output}");
    shim.delete("e4").unwrap();

    // SIGKILL ends the runner itself.
    shim.exec("e5", &process(&["guest", "sleep"]), "").unwrap();
    shim.start("e5").unwrap();
    shim.kill("e5", 9, false).unwrap();
    assert_eq!(shim.wait("e5"), 137);
    shim.delete("e5").unwrap();

    assert_eq!(
        code(&shim.kill("", 19, false).unwrap_err()),
        Code::UNIMPLEMENTED
    );
    // A signal other than SIGKILL goes through the broker to the guest, whose handler exits 7.
    shim.kill("", 15, false).unwrap();
    assert_eq!(shim.wait(""), 7);
    assert!(shim.output("c.out").ends_with("caught 15\n"));
    assert_eq!(shim.delete("").unwrap(), 7);
    assert_eq!(
        shim.events(15),
        [
            "/tasks/create c",
            "/tasks/start c",
            "/tasks/exec-added e1",
            "/tasks/exec-started e1",
            "/tasks/exit e1 0",
            "/tasks/exec-added e2",
            "/tasks/exec-added e3",
            "/tasks/exec-added e4",
            "/tasks/exec-started e4",
            "/tasks/exit e4 0",
            "/tasks/exec-added e5",
            "/tasks/exec-started e5",
            "/tasks/exit e5 137",
            "/tasks/exit c 7",
            "/tasks/delete c \"\" 7",
        ]
    );
    shim.shut_down();
}

#[test]
fn guests_fork_and_the_init_exit_ends_the_container() {
    let shim = Shim::launch(&process(&["/bin/guest", "family"]));
    // The init process exits only once its input ends, which no writer of the FIFO causes.
    shim.create(&shim.mkfifo("c.in")).unwrap();
    let _stderr = drain(shim.path("c.err"));
    shim.start("").unwrap();
    shim.exec("e1", &process(&["guest", "shm"]), "").unwrap();
    shim.start("e1").unwrap();
    assert_eq!(shim.wait("e1"), 0);
    assert!(shim.output("e1.out").ends_with("shm=1777\n"));
    // Image symlinks resolve in the guest, and the bind at `/data` serves the host directory,
    // for reads and writes.
    shim.exec(
        "e2",
        &process(&["guest", "read", "/bin/sh", "/etc/os-release", "/data/in"]),
        "",
    )
    .unwrap();
    shim.start("e2").unwrap();
    assert_eq!(shim.wait("e2"), 0);
    let output = shim.output("e2.out");
    assert!(
        output.ends_with("link=/bin/guest\nID=lbx\nfrom the host\n"),
        "{output}"
    );
    shim.exec(
        "e3",
        &process(&["guest", "write", "/data/out", "from the guest"]),
        "",
    )
    .unwrap();
    shim.start("e3").unwrap();
    assert_eq!(shim.wait("e3"), 0);
    assert_eq!(shim.output("data/out"), "from the guest");
    shim.exec("e4", &process(&["guest", "threads"]), "")
        .unwrap();
    shim.start("e4").unwrap();
    assert_eq!(shim.wait("e4"), 0);
    assert!(shim.output("e4.out").ends_with("threads=13\n"));
    shim.exec("e5", &process(&["guest", "sleep"]), "").unwrap();
    shim.start("e5").unwrap();
    // The init process exits while its forked child and the exec process still run.
    shim.wait_output("c.out", "child pid=");
    shim.close_stdin("");
    assert_eq!(shim.wait(""), 0);
    assert_eq!(shim.wait("e5"), 137);
    let output = shim.output("c.out");
    for expected in ["child pid=", "vfork child exited 5\n"] {
        assert!(output.contains(expected), "{output}");
    }
    assert_eq!(shim.pids(), Vec::<u32>::new());
    for exec_id in ["e1", "e2", "e3", "e4", "e5", ""] {
        shim.delete(exec_id).unwrap();
    }
    let events = shim.events(19);
    assert_eq!(
        events[events.len() - 3..],
        [
            "/tasks/exit e5 137",
            "/tasks/exit c 0",
            "/tasks/delete c \"\" 0"
        ]
    );
    shim.shut_down();
}

#[test]
fn close_io_ends_the_input_while_a_producer_keeps_writing() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let shim = Shim::launch(&process(&["guest", "cat"]));
    let fifo = shim.mkfifo("c.in");
    shim.create(&fifo).unwrap();
    let _stderr = drain(shim.path("c.err"));
    shim.start("").unwrap();
    // Also a reader, so the producer's writes never fail once the shim stops reading.
    let producer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let producing = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let chunk = [b'y'; 4096];
            while !stop.load(Ordering::Relaxed) {
                match rustix::io::write(&producer, &chunk) {
                    Ok(_) => {}
                    Err(rustix::io::Errno::AGAIN) => std::thread::yield_now(),
                    Err(error) => panic!("the producer failed: {error}"),
                }
            }
        })
    };
    shim.wait_output("c.out", "yyyy");
    shim.close_stdin("");
    assert_eq!(shim.wait(""), 0);
    assert!(!producing.is_finished());
    stop.store(true, Ordering::Relaxed);
    producing.join().unwrap();
    let output = shim.output("c.out");
    let tail = &output[output.len().saturating_sub(100)..];
    assert!(tail.ends_with("yyyyeof\n"), "{tail}");
    shim.delete("").unwrap();
    shim.shut_down();
}

#[test]
fn terminals_give_processes_a_controlling_terminal() {
    let shim = Shim::launch(&process(&["guest", "tty"]));
    shim.configure(|spec| {
        spec["process"]["terminal"] = true.into();
        spec["process"]["consoleSize"] = serde_json::json!({"height": 24, "width": 80});
    });
    let fifo = shim.mkfifo("c.in");
    // The stderr FIFO is unused: the terminal's output is stdout.
    let request = CreateTaskRequest {
        terminal: true,
        ..shim.create_request(&fifo)
    };
    shim.client.create(deadline(), &request).unwrap();
    assert!(shim.state("").terminal);
    assert_eq!(shim.events(1)[0], "/tasks/create c terminal");
    shim.start("").unwrap();
    // Output processing turns each newline into CR LF.
    shim.wait_output("c.out", "tty=111 foreground=1 leader=1 size=24x80\r\n");
    let mut input = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
    input.write_all(b"hello\r").unwrap();
    shim.wait_output("c.out", "hello\r\nline=[hello]\r\n");
    input.write_all(b"\x03").unwrap();
    shim.wait_output("c.out", "interrupted\r\n");
    shim.resize("", 100, 30).unwrap();
    shim.wait_output("c.out", "resized 30x100\r\n");

    // As with runc, an exec process's request decides its terminal. This one has none, so
    // resizing it does nothing.
    let mut spec = process(&["guest", "tty"]);
    spec["terminal"] = true.into();
    shim.exec("e0", &spec, "").unwrap();
    assert!(!shim.state("e0").terminal);
    shim.start("e0").unwrap();
    shim.resize("e0", 3, 2).unwrap();
    assert_eq!(shim.wait("e0"), 0);
    assert!(shim.output("e0.out").ends_with("]\neof\n"));
    shim.delete("e0").unwrap();

    // This one has a terminal of its own, which starts without a size: it has none to resize
    // before it starts.
    let exec_fifo = shim.mkfifo("e1.in");
    let exec = ExecProcessRequest {
        terminal: true,
        ..shim.exec_request("e1", &process(&["guest", "tty"]), &exec_fifo)
    };
    shim.client.exec(deadline(), &exec).unwrap();
    assert!(shim.state("e1").terminal);
    shim.resize("e1", 9, 8).unwrap();
    shim.start("e1").unwrap();
    shim.wait_output("e1.out", "tty=111 foreground=1 leader=1 size=0x0\r\n");
    // After `CloseIO`, the input flows until no client writes the FIFO, which hangs up the
    // terminal.
    let mut exec_input = std::fs::OpenOptions::new()
        .write(true)
        .open(&exec_fifo)
        .unwrap();
    exec_input.write_all(b"before\r").unwrap();
    shim.close_stdin("e1");
    exec_input.write_all(b"after\r").unwrap();
    shim.wait_output("e1.out", "line=[before]\r\n");
    shim.wait_output("e1.out", "line=[after]\r\n");
    shim.resize("e1", 3, 2).unwrap();
    shim.wait_output("e1.out", "resized 2x3\r\n");
    assert_eq!(shim.status("e1"), Status::RUNNING);
    drop(exec_input);
    assert_eq!(shim.wait("e1"), 128 + 1);
    // Its terminal closed with its output.
    assert_eq!(code(&shim.resize("e1", 3, 2).unwrap_err()), Code::NOT_FOUND);
    shim.delete("e1").unwrap();

    input.write_all(b"exit 7\r").unwrap();
    assert_eq!(shim.wait(""), 7);
    let output = shim.output("c.out");
    // The exec process's terminal is its own.
    assert!(!output.contains("before"), "{output}");
    shim.delete("").unwrap();
    shim.shut_down();
}

#[test]
fn a_terminal_outlives_the_closing_of_its_last_descriptor() {
    let shim = Shim::launch(&process(&["guest", "reopen"]));
    shim.configure(|spec| spec["process"]["terminal"] = true.into());
    // Without stdin, only the output keeps the terminal open.
    let request = CreateTaskRequest {
        terminal: true,
        ..shim.create_request("")
    };
    shim.client.create(deadline(), &request).unwrap();
    shim.start("").unwrap();
    shim.wait_output("c.out", "closing\r\n");
    shim.resize("", 6, 5).unwrap();
    assert_eq!(shim.wait(""), 0);
    assert!(shim.output("c.out").ends_with("reopened 5x6\r\n"));
    shim.delete("").unwrap();
    shim.shut_down();
}

#[test]
fn kill_all_ends_every_process() {
    // The init process survives the signal, so that the container's end, which kills every
    // runner, cannot overtake the exec process's handling of it.
    let shim = Shim::launch(&process(&["guest", "trap"]));
    shim.create(&shim.mkfifo("c.in")).unwrap();
    let _stderr = drain(shim.path("c.err"));
    shim.start("").unwrap();
    shim.wait_output("c.out", "ready\n");
    shim.exec("e1", &process(&["guest", "sleep"]), "").unwrap();
    shim.start("e1").unwrap();
    shim.wait_output("e1.out", "argv[1]=[sleep]\n");
    shim.kill("", 15, true).unwrap();
    assert_eq!(shim.wait("e1"), 143);
    shim.wait_output("c.out", "trapped\n");
    shim.close_stdin("");
    assert_eq!(shim.wait(""), 0);
    let events = shim.events(6);
    assert_eq!(events[4..], ["/tasks/exit e1 143", "/tasks/exit c 0"]);
    shim.delete("e1").unwrap();
    shim.delete("").unwrap();
    shim.shut_down();
}

#[test]
fn a_container_deleted_before_it_starts_never_runs() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    shim.create("").unwrap();
    let _stderr = drain(shim.path("c.err"));
    assert_eq!(shim.delete("").unwrap(), 137);
    assert_eq!(shim.output("c.out"), "");
    assert_eq!(
        shim.events(3),
        [
            "/tasks/create c",
            "/tasks/exit c 137",
            "/tasks/delete c \"\" 137"
        ]
    );
    shim.shut_down();
}

#[test]
fn a_created_container_ends_when_killed() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    shim.create("").unwrap();
    let _stderr = drain(shim.path("c.err"));
    assert_eq!(
        shim.wait_code("", Duration::from_millis(100)),
        Code::DEADLINE_EXCEEDED
    );
    shim.kill("", 9, false).unwrap();
    assert_eq!(shim.wait(""), 137);
    assert_eq!(shim.events(2), ["/tasks/create c", "/tasks/exit c 137"]);
    assert_eq!(
        code(&shim.start("").unwrap_err()),
        Code::FAILED_PRECONDITION
    );
    assert_eq!(shim.delete("").unwrap(), 137);
    assert_eq!(shim.output("c.out"), "");
    assert_eq!(
        shim.events(3),
        [
            "/tasks/create c",
            "/tasks/exit c 137",
            "/tasks/delete c \"\" 137"
        ]
    );
    shim.shut_down();
}

#[test]
fn a_created_container_ends_when_its_runner_dies() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let pid = shim.create("").unwrap();
    let _stderr = drain(shim.path("c.err"));
    let pid = libc::pid_t::try_from(pid).unwrap();
    // SAFETY: `kill` takes no pointers.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    assert_eq!(shim.wait(""), 137);
    assert_eq!(shim.status(""), Status::STOPPED);
    assert_eq!(shim.events(2), ["/tasks/create c", "/tasks/exit c 137"]);
    assert_eq!(shim.pids(), Vec::<u32>::new());
    assert_eq!(shim.delete("").unwrap(), 137);
    assert_eq!(shim.output("c.out"), "");
    shim.shut_down();
}

#[test]
fn bind_sources_must_be_directories_or_files() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let fifo = shim.mkfifo("fifo");
    shim.configure(|spec| spec["mounts"][2]["source"] = fifo.into());
    assert_eq!(code(&shim.create("").unwrap_err()), Code::UNIMPLEMENTED);
    shim.shut_down();
}

#[test]
fn file_binds_and_read_only_mounts_reach_the_guest() {
    let shim = Shim::launch(&process(&["guest", "cat"]));
    let hosts = shim.path("hosts");
    std::fs::write(&hosts, "hosts\n").unwrap();
    let release = shim.path("release");
    std::fs::write(&release, "ID=host\n").unwrap();
    let data = shim.path("data");
    // A read-only root, with a read-write file bind where the image has no file, a read-only file
    // bind over an image symlink, and a read-only directory bind.
    shim.configure(|spec| {
        spec["root"]["readonly"] = true.into();
        let mounts = spec["mounts"].as_array_mut().unwrap();
        mounts.extend([
            serde_json::json!({"destination": "/etc/hosts", "type": "bind", "source": hosts, "options": ["rbind", "rprivate"]}),
            serde_json::json!({"destination": "/etc/os-release", "type": "bind", "source": release, "options": ["bind", "ro"]}),
            serde_json::json!({"destination": "/ro", "type": "bind", "source": data, "options": ["rbind", "ro"]}),
        ]);
    });
    shim.create(&shim.mkfifo("c.in")).unwrap();
    let _stderr = drain(shim.path("c.err"));
    shim.start("").unwrap();

    let (status, output) = shim.run(
        "e1",
        &[
            "guest",
            "read",
            "/bin/sh",
            "/etc/hosts",
            "/etc/os-release",
            "/ro/in",
        ],
    );
    assert_eq!(status, 0, "{output}");
    assert!(
        output.ends_with("link=/bin/guest\nhosts\nID=host\nfrom the host\n"),
        "{output}"
    );
    assert_eq!(
        shim.run("e2", &["guest", "write", "/etc/hosts", "guest"]).0,
        0
    );
    assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "guest");
    assert_eq!(shim.run("e3", &["guest", "write", "/data/out", "rw"]).0, 0);
    assert_eq!(shim.output("data/out"), "rw");
    // EROFS.
    for (exec_id, path) in [
        ("e4", "/etc/os-release"),
        ("e5", "/ro/in"),
        ("e6", "/tmp/new"),
    ] {
        let (status, output) = shim.run(exec_id, &["guest", "write", path, "x"]);
        assert_eq!(status, 51, "{path}");
        assert!(output.ends_with("errno=30\n"), "{path}: {output}");
    }
    assert_eq!(std::fs::read_to_string(&release).unwrap(), "ID=host\n");
    assert_eq!(shim.output("data/in"), "from the host\n");
    assert!(!shim.bundle.join("rootfs/tmp/new").exists());
    shim.close_stdin("");
    assert_eq!(shim.wait(""), 0);
    shim.delete("").unwrap();
    shim.shut_down();
}

/// Writes a hook script, which records its `argv[0]`, whether the shim's environment reached it,
/// and its OCI state as a line `<argv[0]> <TTRPC_ADDRESS or clean> <state>` in `hooks.log`, then
/// exits with its first argument.
fn hook_script(shim: &Shim) -> String {
    let script = shim.path("hook.sh");
    let content = r#"read -r state
printf '%s %s %s\n' "$(tr '\0' '\n' </proc/$$/cmdline | head -n 1)" "${TTRPC_ADDRESS:-clean}" "$state" >>"$LOG"
exit "${1:-0}"
"#;
    std::fs::write(&script, content).unwrap();
    script
}

/// A hook named `name` that runs `script` with `args`, writing to the `hooks.log` of `shim`.
fn hook(shim: &Shim, script: &str, name: &str, args: &[&str]) -> serde_json::Value {
    let mut command = vec![name, script];
    command.extend(args);
    serde_json::json!({
        "path": "/bin/sh",
        "args": command,
        "env": [format!("LOG={}", shim.path("hooks.log")), "PATH=/usr/bin:/bin"],
    })
}

/// The hooks that ran, as their names, and their OCI states.
fn hook_runs(shim: &Shim) -> Vec<(String, serde_json::Value)> {
    shim.output("hooks.log")
        .lines()
        .map(|line| {
            let (name, rest) = line.split_once(' ').unwrap();
            let (environment, state) = rest.split_once(' ').unwrap();
            assert_eq!(environment, "clean", "{line}");
            (name.to_owned(), serde_json::from_str(state).unwrap())
        })
        .collect()
}

#[test]
fn hooks_run_at_their_lifecycle_points() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let script = hook_script(&shim);
    // A timeout too long to represent is none.
    let mut prestart = hook(&shim, &script, "prestart", &[]);
    prestart["timeout"] = i64::MAX.into();
    // Without `env`, a hook inherits the daemon's environment.
    let inheriting = serde_json::json!({
        "path": "/bin/sh",
        "args": ["sh", "-c", format!("echo \"$TTRPC_ADDRESS\" >{}", shim.path("inherited"))],
    });
    let hooks = serde_json::json!({
        "poststop": [hook(&shim, &script, "poststop", &[])],
        "poststart": [
            hook(&shim, &script, "poststart-fails", &["1"]),
            hook(&shim, &script, "poststart", &[]),
        ],
        "createContainer": [hook(&shim, &script, "createContainer", &[])],
        "createRuntime": [hook(&shim, &script, "createRuntime", &[]), inheriting],
        "prestart": [prestart],
    });
    shim.configure(|spec| {
        spec["hooks"] = hooks;
        spec["annotations"] = serde_json::json!({"a": "b"});
    });
    let pid = shim.create("").unwrap();
    let _stderr = drain(shim.path("c.err"));
    let state = |status: &str| {
        serde_json::json!({
            "ociVersion": "1.2.0",
            "id": "c",
            "status": status,
            "pid": pid,
            "bundle": shim.bundle,
            "annotations": {"a": "b"},
        })
    };
    let created = ["prestart", "createRuntime", "createContainer"]
        .map(|name| (name.to_owned(), state("creating")));
    assert_eq!(hook_runs(&shim), created);
    assert_eq!(
        shim.output("inherited"),
        format!("{}\n", shim.path("events.sock"))
    );
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 0);
    shim.delete("").unwrap();
    let mut all = created.to_vec();
    // A stopped container has no process.
    let mut stopped = state("stopped");
    stopped.as_object_mut().unwrap().remove("pid");
    all.extend([
        ("poststart-fails".to_owned(), state("running")),
        ("poststart".to_owned(), state("running")),
        ("poststop".to_owned(), stopped),
    ]);
    assert_eq!(hook_runs(&shim), all);
    // Not again by the `delete` action that follows the daemon's exit.
    assert_eq!(shim.delete_action(), 137);
    assert_eq!(hook_runs(&shim), all);
    shim.shut_down();
}

#[test]
fn create_hooks_run_before_the_init_process_is_looked_up() {
    for install in [true, false] {
        let shim = Shim::launch(&process(&["installed", "exit", "5"]));
        let script = hook_script(&shim);
        let bin = shim.bundle.join("rootfs/bin");
        let mut create = vec![hook(&shim, &script, "createRuntime", &[])];
        if install {
            create.push(serde_json::json!({
                "path": "/bin/cp",
                "args": ["cp", bin.join("guest"), bin.join("installed")],
            }));
        }
        let hooks = serde_json::json!({
            "createRuntime": create,
            "poststop": [hook(&shim, &script, "poststop", &[])],
        });
        shim.configure(|spec| spec["hooks"] = hooks);
        if install {
            shim.create("").unwrap();
            let _stderr = drain(shim.path("c.err"));
            shim.start("").unwrap();
            assert_eq!(shim.wait(""), 5);
            shim.delete("").unwrap();
        } else {
            // A failure after the create hooks ran is undone by the poststop hooks.
            assert_eq!(code(&shim.create("").unwrap_err()), Code::INVALID_ARGUMENT);
        }
        let names: Vec<String> = hook_runs(&shim).into_iter().map(|run| run.0).collect();
        assert_eq!(names, ["createRuntime", "poststop"], "install {install}");
        shim.shut_down();
    }
}

#[test]
fn the_delete_action_runs_the_poststop_hooks_of_a_dead_daemon() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let script = hook_script(&shim);
    let hooks = serde_json::json!({"poststop": [hook(&shim, &script, "poststop", &[])]});
    shim.configure(|spec| spec["hooks"] = hooks);
    shim.create("").unwrap();
    shim.daemon.kill().unwrap();
    shim.daemon.wait().unwrap();
    assert_eq!(shim.delete_action(), 137);
    let stopped = serde_json::json!({
        "ociVersion": "1.2.0",
        "id": "c",
        "status": "stopped",
        "bundle": shim.bundle,
        "annotations": {},
    });
    assert_eq!(hook_runs(&shim), [("poststop".to_owned(), stopped)]);
    // Only once.
    shim.delete_action();
    assert_eq!(hook_runs(&shim).len(), 1);
}

#[test]
fn a_failing_create_hook_fails_create() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let script = hook_script(&shim);
    let hooks = serde_json::json!({
        "createRuntime": [hook(&shim, &script, "createRuntime", &["3"])],
        "createContainer": [hook(&shim, &script, "createContainer", &[])],
        "poststop": [hook(&shim, &script, "poststop", &[])],
    });
    shim.configure(|spec| spec["hooks"] = hooks);
    assert_eq!(code(&shim.create("").unwrap_err()), Code::INTERNAL);
    // The later create hooks do not run, but the poststop hooks do.
    let runs = hook_runs(&shim);
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].0, "createRuntime");
    assert_eq!(runs[0].1["status"], "creating");
    assert_eq!(runs[1].0, "poststop");
    assert_eq!(runs[1].1["status"], "stopped");
    assert_eq!(runs[1].1.get("pid"), None);
    // The runner is reaped before `Create` fails.
    let runner = runs[0].1["pid"].as_u64().unwrap();
    assert!(!Path::new(&format!("/proc/{runner}")).exists());
    shim.shut_down();
}

#[test]
fn a_hook_that_times_out_is_killed() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    // Reports its process ID, which `sleep` keeps.
    let sleeper = serde_json::json!({
        "path": "/bin/sh",
        "args": ["sh", "-c", format!("echo $$ >{} && exec sleep 600", shim.path("hook.pid"))],
        "env": ["PATH=/usr/bin:/bin"],
        "timeout": 1,
    });
    shim.configure(|spec| spec["hooks"] = serde_json::json!({"prestart": [sleeper]}));
    assert_eq!(code(&shim.create("").unwrap_err()), Code::INTERNAL);
    let hook = shim.output("hook.pid");
    assert_ne!(hook, "");
    // Killed and reaped.
    assert!(!Path::new(&format!("/proc/{}", hook.trim())).exists());
    shim.shut_down();
}

/// Creates the container of `shim` with its outputs in the logging binary `script`, which receives
/// the arguments `dir <the test directory>`.
fn create_logged(shim: &Shim, script: &str) {
    let logger = shim.path("logger.sh");
    std::fs::write(&logger, script).unwrap();
    std::fs::set_permissions(&logger, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let uri = format!("binary://{logger}?dir={}", shim.dir.path().display());
    let request = CreateTaskRequest {
        stdout: uri.clone(),
        stderr: uri,
        ..shim.create_request("")
    };
    shim.client.create(deadline(), &request).unwrap();
}

#[test]
fn binary_logs_reach_the_logging_binary() {
    let shim = Shim::launch(&process(&["guest", "exit", "3"]));
    create_logged(
        &shim,
        "#!/bin/sh\n\
         echo $$ >\"$2/logger.pid\"\n\
         echo \"$# $1 $CONTAINER_ID $CONTAINER_NAMESPACE ${TTRPC_ADDRESS:-clean}\" >\"$2/logger.env\"\n\
         exec 5>&-\n\
         /bin/cat <&3 >\"$2/logger.out\" &\n\
         /bin/cat <&4 >\"$2/logger.err\"\n\
         wait\n",
    );
    assert_eq!(shim.output("logger.env"), "2 dir c litebox-test clean\n");
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 3);
    shim.delete("").unwrap();
    shim.wait_output("logger.out", "argv[2]=[3]\n");
    shim.wait_output("logger.err", "stderr\n");
    let pid = shim.output("logger.pid");
    wait_until("the logging binary was not reaped", || {
        !Path::new(&format!("/proc/{}", pid.trim())).exists()
    });
    shim.shut_down();
}

#[test]
fn a_lingering_logging_binary_is_killed_before_the_daemon_exits() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    // Ready, but it never exits on its own: `sleep` holds its inputs without reading them.
    create_logged(
        &shim,
        "#!/bin/sh\n\
         echo $$ >\"$2/logger.pid\"\n\
         exec 5>&-\n\
         exec /bin/sleep 600\n",
    );
    let pid = shim.output("logger.pid");
    assert_ne!(pid, "");
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 0);
    shim.delete("").unwrap();
    shim.shut_down();
    assert!(!Path::new(&format!("/proc/{}", pid.trim())).exists());
}

#[test]
fn file_binds_create_their_missing_parent_directories() {
    let launch = |read_only: bool| {
        let shim = Shim::launch(&process(&["guest", "read", "/bin/sh", "/newdir/sub/f"]));
        let file = shim.path("file");
        std::fs::write(&file, "bound\n").unwrap();
        shim.configure(|spec| {
            spec["root"]["readonly"] = read_only.into();
            spec["mounts"].as_array_mut().unwrap().push(serde_json::json!(
                {"destination": "/newdir/sub/f", "type": "bind", "source": file, "options": ["rbind", "ro"]}
            ));
        });
        shim
    };
    let shim = launch(false);
    shim.create("").unwrap();
    let _stderr = drain(shim.path("c.err"));
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 0);
    let output = shim.output("c.out");
    assert!(output.ends_with("link=/bin/guest\nbound\n"), "{output}");
    assert!(shim.bundle.join("rootfs/newdir/sub").is_dir());
    shim.delete("").unwrap();
    shim.shut_down();

    // A read-only root cannot have them created.
    let shim = launch(true);
    assert_eq!(code(&shim.create("").unwrap_err()), Code::UNIMPLEMENTED);
    assert!(!shim.bundle.join("rootfs/newdir").exists());
    shim.shut_down();

    // Nor can a parent that is only an ancestor of another mount's destination.
    let shim = launch(false);
    shim.configure(|spec| {
        let mounts = spec["mounts"].as_array_mut().unwrap();
        mounts.pop();
        mounts.extend([
            serde_json::json!({"destination": "/newdir/data", "type": "bind", "source": shim.path("data"), "options": ["rbind"]}),
            serde_json::json!({"destination": "/newdir/f", "type": "bind", "source": shim.path("file"), "options": ["rbind"]}),
        ]);
    });
    assert_eq!(code(&shim.create("").unwrap_err()), Code::UNIMPLEMENTED);
    shim.shut_down();
}

fn net_namespace(pid: u32) -> PathBuf {
    std::fs::read_link(format!("/proc/{pid}/ns/net")).unwrap()
}

#[test]
#[ignore = "needs root"]
fn runners_join_the_spec_network_namespace() {
    let daemon_namespace = net_namespace(std::process::id());
    let mut other = Command::new("unshare")
        .args(["--net", "sleep", "600"])
        .spawn()
        .unwrap();
    wait_until("no new network namespace", || {
        net_namespace(other.id()) != daemon_namespace
    });
    let other_namespace = net_namespace(other.id());
    let path = format!("/proc/{}/ns/net", other.id());
    for (namespaces, expected) in [
        (serde_json::json!([{"type": "network"}]), None),
        (
            serde_json::json!([{"type": "pid"}]),
            Some(&daemon_namespace),
        ),
        (
            serde_json::json!([{"type": "network", "path": path}]),
            Some(&other_namespace),
        ),
    ] {
        let shim = Shim::launch(&process(&["guest", "exit", "0"]));
        assert_eq!(net_namespace(shim.daemon.id()), daemon_namespace);
        shim.configure(|spec| spec["linux"]["namespaces"] = namespaces.clone());
        let runner = net_namespace(shim.create("").unwrap());
        match expected {
            Some(expected) => assert_eq!(&runner, expected, "{namespaces}"),
            None => assert!(
                runner != daemon_namespace && runner != other_namespace,
                "{namespaces}"
            ),
        }
        shim.delete("").unwrap();
        shim.shut_down();
    }
    other.kill().unwrap();
    other.wait().unwrap();
}

#[test]
fn non_root_users_reach_the_guest() {
    let mut init = process(&["guest", "exit", "0"]);
    init["user"] = serde_json::json!({"uid": 1000, "gid": 2000, "additionalGids": [3]});
    // Created for the init process, as by runc.
    init["cwd"] = "/new/dir".into();
    let shim = Shim::launch(&init);
    shim.create("").unwrap();
    let _stderr = drain(shim.path("c.err"));
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 0);
    let output = shim.output("c.out");
    assert!(
        output.starts_with("pid=1 ids=1000,2000 cwd=/new/dir\n"),
        "{output}"
    );
    // No entry of `/etc/passwd` has the user's ID.
    assert!(output.ends_with("env=[HOME=/]\n"), "{output}");
    shim.delete("").unwrap();
    shim.shut_down();
}

#[test]
fn an_endless_passwd_has_no_home() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let passwd = shim.bundle.join("rootfs/etc/passwd");
    std::fs::remove_file(&passwd).unwrap();
    std::os::unix::fs::symlink("/dev/urandom", &passwd).unwrap();
    let request = CreateTaskRequest {
        stderr: String::new(),
        ..shim.create_request("")
    };
    // Short, since reading the device to its end would never finish.
    let timeout = i64::try_from(Duration::from_secs(10).as_nanos()).unwrap();
    shim.client
        .create(context::with_timeout(timeout), &request)
        .unwrap();
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 0);
    let output = shim.output("c.out");
    assert!(output.ends_with("env=[HOME=/]\n"), "{output}");
    shim.delete("").unwrap();
    shim.shut_down();
}

#[test]
fn events_reach_a_restarted_containerd() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    shim.create("").unwrap();
    let _stderr = drain(shim.path("c.err"));
    assert_eq!(shim.events(1), ["/tasks/create c"]);
    // The publisher's connection breaks, and a new event service listens at the same address.
    let socket = shim.dir.path().join("events.sock");
    std::fs::remove_file(&socket).unwrap();
    let (events, server) = serve_events(&socket);
    shim.events = events;
    std::mem::replace(&mut shim.event_server, server).shutdown();
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 0);
    assert_eq!(shim.events(2), ["/tasks/start c", "/tasks/exit c 0"]);
    shim.delete("").unwrap();
    shim.shut_down();
}
