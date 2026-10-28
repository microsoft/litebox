// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs the shim daemon as containerd does, against a fake containerd event service, with real
//! runners. Needs no root: the daemon then mounts nothing.

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
    CloseIORequest, CreateTaskRequest, DeleteRequest, ExecProcessRequest, KillRequest, PidsRequest,
    ShutdownRequest, StartRequest, StateRequest, Status, WaitRequest,
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

/// The events the shim publishes, summarized as `topic [exec ID] [status]`; `/tasks/delete`
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
            "/tasks/create" => (
                "TaskCreate",
                TaskCreate::parse_from_bytes(value).unwrap().container_id,
            ),
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

    fn create(&self, stdin: &str) -> ttrpc::Result<u32> {
        let request = CreateTaskRequest {
            id: "c".to_owned(),
            bundle: self.bundle.to_str().unwrap().to_owned(),
            stdin: stdin.to_owned(),
            stdout: format!("file://{}", self.path("c.out")),
            stderr: self.path("c.err"),
            ..Default::default()
        };
        self.client
            .create(deadline(), &request)
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

    fn exec(&self, exec_id: &str, process: &serde_json::Value, stdin: &str) -> ttrpc::Result<()> {
        let request = ExecProcessRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            stdin: stdin.to_owned(),
            stdout: format!("file://{}", self.path(&format!("{exec_id}.out"))),
            spec: MessageField::some(Any {
                value: process.to_string().into_bytes(),
                ..Default::default()
            }),
            ..Default::default()
        };
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

    fn status(&self, exec_id: &str) -> Status {
        let request = StateRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        let state = self.client.state(deadline(), &request).unwrap();
        state.status.enum_value_or_default()
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
    assert!(shim.pids().is_empty());
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
    assert!(shim.output("c.out").is_empty());
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
    assert!(shim.output("c.out").is_empty());
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
    assert!(shim.pids().is_empty());
    assert_eq!(shim.delete("").unwrap(), 137);
    assert!(shim.output("c.out").is_empty());
    shim.shut_down();
}

#[test]
fn file_bind_sources_are_unimplemented() {
    let shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let config = shim.bundle.join("config.json");
    let mut spec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    spec["mounts"][2]["source"] = shim.path("data/in").into();
    std::fs::write(&config, spec.to_string()).unwrap();
    assert_eq!(code(&shim.create("").unwrap_err()), Code::UNIMPLEMENTED);
    shim.shut_down();
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
        id: "c".to_owned(),
        bundle: shim.bundle.to_str().unwrap().to_owned(),
        stdout: format!("file://{}", shim.path("c.out")),
        ..Default::default()
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
