// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs the shim as containerd does, with a fake event service and the real broker and runner.
//! Guests are built with GCC in WSL (`LITEBOX_WSL_DISTRO`, else the default distribution). The
//! container needs administrator rights, the Containers feature, and a Windows image's layers:
//! `LITEBOX_TEST_WINDOWS_LAYERS` names their folders, `;`-separated and topmost first, such as
//! nanoserver:ltsc2025's under containerd's `windows` snapshotter or Docker's `windowsfilter`
//! driver (as CI gives them, through `.github/tools/pull_windows_test_layers.ps1`). So the tests
//! are ignored by default.

#![cfg(all(windows, target_arch = "x86_64"))]

use std::ffi::{OsStr, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr::null_mut;
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[path = "support/cargo.rs"]
mod cargo;
#[path = "support/common.rs"]
mod common;

use common::{EventLog, TIMEOUT, code, deadline, process, wait_until};
use containerd_shim::api::{
    CloseIORequest, CreateTaskRequest, DeleteRequest, DeleteResponse, ExecProcessRequest,
    KillRequest, ShutdownRequest, StartRequest, StateRequest, Status, WaitRequest,
};
use containerd_shim::protos::protobuf::well_known_types::any::Any;
use containerd_shim::protos::protobuf::{Message, MessageField};
use containerd_shim::protos::shim_sync::{Client, TaskClient, create_events};
use containerd_shim::protos::ttrpc::{self, Code, Server};
use containerd_shim::protos::types::empty::Empty;
use litebox_containerd_shim::Backend;
use tar_core::EntryType;
use tar_core::builder::EntryBuilder;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_SEM_TIMEOUT, ERROR_SHARING_VIOLATION, FILETIME, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAGS_AND_ATTRIBUTES, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::HostComputeNetwork::{
    HcnCloseEndpoint, HcnCloseNamespace, HcnCloseNetwork, HcnCreateEndpoint, HcnCreateNamespace,
    HcnCreateNetwork, HcnDeleteEndpoint, HcnDeleteNamespace, HcnDeleteNetwork,
    HcnEnumerateEndpoints, HcnEnumerateNamespaces, HcnEnumerateNetworks, HcnModifyNamespace,
    HcnOpenNamespace, HcnQueryEndpointProperties, HcnQueryNamespaceProperties,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};
use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};

const SHIM: &str = env!("CARGO_BIN_EXE_containerd-shim-litebox-v1");

/// hcsshim's `driverInfo`, of the filter driver.
#[repr(C)]
struct DriverInfo {
    flavour: isize,
    home_dir: PCWSTR,
}

/// hcsshim's `WC_LAYER_DESCRIPTOR`.
#[repr(C)]
struct LayerDescriptor {
    layer_id: GUID,
    flags: u32,
    path: PCWSTR,
}

// As hcsshim's `wclayer.CreateScratchLayer` calls them; counts are pointer-sized.
#[link(name = "vmcompute", kind = "raw-dylib")]
unsafe extern "system" {
    fn CreateSandboxLayer(
        info: *const DriverInfo,
        id: PCWSTR,
        parent: PCWSTR,
        layers: *const LayerDescriptor,
        count: usize,
    ) -> HRESULT;
    fn NameToGuid(name: PCWSTR, guid: *mut GUID) -> HRESULT;
}

fn pipe_name(namespace: &str, name: &str) -> String {
    format!(r"\\.\pipe\litebox-shim-test-{namespace}-{name}")
}

struct Shim {
    dir: tempfile::TempDir,
    /// Also scopes the daemon's log pipe.
    namespace: String,
    daemon: Child,
    client: TaskClient,
    events: Arc<EventLog>,
    event_pipe: String,
    _event_server: Server,
    log: Option<JoinHandle<()>>,
    bundle: PathBuf,
}

impl Shim {
    fn launch(process: &serde_json::Value) -> Self {
        let dir = tempfile::Builder::new().prefix("lbx").tempdir().unwrap();
        let namespace = dir.path().file_name().unwrap().to_str().unwrap().to_owned();
        let (guest_service, broker, runner, guest) = fixtures(dir.path());
        add_runtime_library(broker.parent().unwrap());
        let layers = layer_folders(dir.path());
        let bundle = dir.path().join("c");
        std::fs::create_dir(&bundle).unwrap();
        write_image(&bundle.join("rootfs.tar"), &std::fs::read(guest).unwrap());
        let config = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs.tar"},
            "process": process,
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc"},
                {"destination": "/run", "type": "tmpfs", "source": "tmpfs"},
            ],
            // Windows refuses a Linux network namespace.
            "linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}]},
            "windows": {"layerFolders": layers},
        });
        std::fs::write(bundle.join("config.json"), config.to_string()).unwrap();
        let events = Arc::new(EventLog::new(&namespace));
        let event_pipe = pipe_name(&namespace, "events");
        let mut event_server = Server::new()
            .bind(&event_pipe)
            .unwrap()
            .register_service(create_events(events.clone()));
        event_server.start().unwrap();
        // The daemon opens its publisher once the process starts, not once our listener is ready.
        wait_event_pipe(&event_pipe);
        // We skip `start`, but shutdown still reads the address it normally writes.
        let work = dir.path().join("shim");
        std::fs::create_dir(&work).unwrap();
        let socket = pipe_name(&namespace, "task");
        std::fs::write(work.join("address"), &socket).unwrap();
        let stderr = dir.path().join("stderr");
        let mut daemon = shim_command(&namespace)
            .args(["-socket", &socket])
            .current_dir(&work)
            .env("TTRPC_ADDRESS", &event_pipe)
            .env("LITEBOX_GUEST_SERVICE", guest_service)
            .env("LITEBOX_BROKER", broker)
            .env("LITEBOX_RUNNER", runner)
            .env("LITEBOX_SHIM_STATE_ROOT", state_root(dir.path()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let client = TaskClient::new(connect_task(&mut daemon, &socket, &stderr));
        let log = copy_log(&namespace, &dir.path().join("log"));
        Self {
            dir,
            namespace,
            daemon,
            client,
            events,
            event_pipe,
            _event_server: event_server,
            log,
            bundle,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn file_uri(&self, name: &str) -> String {
        url::Url::from_file_path(self.path(name))
            .unwrap()
            .to_string()
    }

    fn state_dir(&self) -> PathBuf {
        state_root(self.dir.path()).join(&self.namespace).join("c")
    }

    fn configure(&self, change: impl FnOnce(&mut serde_json::Value)) {
        let config = self.bundle.join("config.json");
        let mut spec = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        change(&mut spec);
        std::fs::write(&config, serde_json::to_string(&spec).unwrap()).unwrap();
    }

    /// The scratch's disk is open while attached.
    fn layers_mounted(&self) -> bool {
        let disk = self.dir.path().join("scratch").join("sandbox.vhdx");
        match OpenOptions::new().read(true).share_mode(0).open(&disk) {
            Ok(_) => false,
            Err(error) if error.raw_os_error() == i32::try_from(ERROR_SHARING_VIOLATION).ok() => {
                true
            }
            Err(error) => panic!("cannot open {}: {error}", disk.display()),
        }
    }

    /// Neither the state nor the layers' record is left, nor the layers mounted.
    fn assert_cleaned_up(&self) {
        let namespace = state_root(self.dir.path()).join(&self.namespace);
        let left: Vec<_> = std::fs::read_dir(namespace)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "left in the state root: {left:?}");
        assert!(!self.layers_mounted());
    }

    fn output(&self, name: &str) -> String {
        std::fs::read_to_string(self.path(name)).unwrap_or_default()
    }

    fn wait_output(&self, name: &str, text: &str) {
        wait_until(&format!("{name} never showed {text:?}"), || {
            self.output(name).contains(text)
        });
    }

    fn input(&self, name: &str) -> (String, File) {
        self.pipe(name, PIPE_ACCESS_OUTBOUND)
    }

    fn output_pipe(&self, name: &str) -> (String, File) {
        self.pipe(name, PIPE_ACCESS_INBOUND)
    }

    /// A named pipe's server end, as containerd makes for a task's stdio.
    fn pipe(&self, name: &str, access: FILE_FLAGS_AND_ATTRIBUTES) -> (String, File) {
        let uri = pipe_name(&self.namespace, name);
        let wide: Vec<u16> = uri.encode_utf16().chain([0]).collect();
        // SAFETY: `wide` is a NUL-terminated name that outlives the call; with no security
        // attributes, the handle is not inherited and has the default DACL.
        let pipe = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                access,
                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(pipe, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
        // SAFETY: the call succeeded, so this owns `pipe`.
        let pipe = File::from(unsafe { OwnedHandle::from_raw_handle(pipe) });
        (uri, pipe)
    }

    fn create_with(&self, stdin: &str) -> ttrpc::Result<u32> {
        let request = CreateTaskRequest {
            id: "c".to_owned(),
            bundle: self.bundle.to_str().unwrap().to_owned(),
            stdin: stdin.to_owned(),
            stdout: self.file_uri("c.out"),
            stderr: self.file_uri("logs/c.err"),
            ..Default::default()
        };
        self.client
            .create(deadline(), &request)
            .map(|response| response.pid)
    }

    fn create(&self) -> ttrpc::Result<u32> {
        self.create_with("")
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

    fn exec(&self, exec_id: &str, args: &[&str], stdin: &str) -> ttrpc::Result<Empty> {
        self.exec_to(
            exec_id,
            args,
            stdin,
            &self.file_uri(&format!("{exec_id}.out")),
        )
    }

    fn exec_to(
        &self,
        exec_id: &str,
        args: &[&str],
        stdin: &str,
        stdout: &str,
    ) -> ttrpc::Result<Empty> {
        let request = ExecProcessRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            stdin: stdin.to_owned(),
            stdout: stdout.to_owned(),
            spec: MessageField::some(Any {
                value: process(args).to_string().into_bytes(),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.client.exec(deadline(), &request)
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

    fn state(&self, exec_id: &str) -> (Status, u32) {
        let request = StateRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        let response = self.client.state(deadline(), &request).unwrap();
        (response.status.enum_value().unwrap(), response.exit_status)
    }

    fn kill(&self, exec_id: &str, signal: u32) -> ttrpc::Result<Empty> {
        let request = KillRequest {
            id: "c".to_owned(),
            exec_id: exec_id.to_owned(),
            signal,
            ..Default::default()
        };
        self.client.kill(deadline(), &request)
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

    /// As containerd runs it after the daemon died.
    fn delete_action(&self) -> u32 {
        let output = shim_command(&self.namespace)
            .arg("-bundle")
            .arg(&self.bundle)
            .arg("delete")
            .current_dir(&self.bundle)
            .env("TTRPC_ADDRESS", &self.event_pipe)
            .env("LITEBOX_SHIM_STATE_ROOT", state_root(self.dir.path()))
            .stdin(Stdio::null())
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

    fn events(&self, count: usize) -> Vec<String> {
        self.events.wait_for(count)
    }

    fn finish(&mut self, broker: u32) {
        self.delete("").unwrap();
        assert!(is_gone(broker));
        self.assert_cleaned_up();
        let request = ShutdownRequest {
            id: "c".to_owned(),
            ..Default::default()
        };
        // containerd accepts the daemon closing the connection first.
        match self.client.shutdown(deadline(), &request) {
            Ok(_) | Err(ttrpc::Error::Socket(_)) => {}
            Err(error) => panic!("shutdown: {error:?}"),
        }
        wait_until("the daemon did not exit", || {
            self.daemon.try_wait().unwrap().is_some()
        });
        let status = self.daemon.wait().unwrap();
        assert!(status.success(), "the daemon exited with {status}");
    }
}

impl Drop for Shim {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        if let Some(log) = self.log.take() {
            let _ = log.join();
        }
        if std::thread::panicking() || std::env::var_os("LBX_SHOW").is_some() {
            eprintln!("daemon stderr:\n{}", self.output("stderr"));
            eprintln!("shim log:\n{}", self.output("log"));
        }
    }
}

/// Only `start`, which the tests do not run, uses containerd's address.
fn shim_command(namespace: &str) -> Command {
    let mut command = Command::new(SHIM);
    command.args([
        "-namespace",
        namespace,
        "-id",
        "c",
        "-address",
        "containerd",
    ]);
    command
}

fn state_root(dir: &Path) -> PathBuf {
    dir.join("s")
}

fn wait_event_pipe(pipe: &str) {
    let wide: Vec<u16> = pipe.encode_utf16().chain([0]).collect();
    wait_until(
        &format!("the event pipe {pipe} did not start listening"),
        || {
            // SAFETY: `wide` is a NUL-terminated pipe name valid for the duration of the call.
            if unsafe { WaitNamedPipeW(wide.as_ptr(), 1) } != 0 {
                return true;
            }
            let error = io::Error::last_os_error();
            match error
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok())
            {
                Some(ERROR_FILE_NOT_FOUND | ERROR_SEM_TIMEOUT) => false,
                _ => panic!("waiting for the event pipe {pipe}: {error}"),
            }
        },
    );
}

fn connect_task(daemon: &mut Child, pipe: &str, stderr: &Path) -> Client {
    // ttrpc creates the pipe on its listener thread, so closing stdout doesn't signal readiness.
    let start = Instant::now();
    let error = loop {
        match Client::connect(pipe) {
            Ok(client) => return client,
            Err(error) => {
                let transient = matches!(
                    error,
                    ttrpc::Error::Windows(code)
                        if matches!(u32::try_from(code), Ok(ERROR_FILE_NOT_FOUND | ERROR_PIPE_BUSY))
                );
                if !transient || start.elapsed() >= TIMEOUT || daemon.try_wait().unwrap().is_some()
                {
                    break error;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    if daemon.try_wait().unwrap().is_none() {
        daemon.kill().expect("could not stop the shim daemon");
    }
    let status = daemon.wait().expect("could not reap the shim daemon");
    let stderr = std::fs::read_to_string(stderr).expect("could not read shim daemon stderr");
    panic!("cannot connect to the task pipe {pipe}: {error:?}; daemon exit: {status}\n{stderr}");
}

/// The daemon blocks on its log only while a connected reader does not read.
fn copy_log(namespace: &str, path: &Path) -> Option<JoinHandle<()>> {
    let mut pipe = File::open(format!(r"\\.\pipe\containerd-shim-{namespace}-c-log")).ok()?;
    let mut file = File::create(path).unwrap();
    Some(std::thread::spawn(move || {
        let _ = io::copy(&mut pipe, &mut file);
    }))
}

fn accept(pipe: File) -> File {
    // SAFETY: `pipe` is a named pipe's server end, open and synchronous; no `OVERLAPPED`.
    if unsafe { ConnectNamedPipe(pipe.as_raw_handle(), std::ptr::null_mut()) } == 0 {
        let error = io::Error::last_os_error();
        let connected = i32::try_from(ERROR_PIPE_CONNECTED).unwrap();
        assert_eq!(error.raw_os_error(), Some(connected), "{error}");
    }
    pipe
}

fn fixtures(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    if let Some(prebuilt) = std::env::var_os("LITEBOX_SHIM_TEST_FIXTURES") {
        let [guest_service, broker, runner, guest] = [
            "litebox-guest-service",
            "litebox-broker-userland.exe",
            "litebox_runner_linux_on_windows_userland.exe",
            "guest",
        ]
        .map(|name| {
            let path = Path::new(&prebuilt).join(name);
            assert!(
                path.is_file(),
                "missing shim test fixture {}",
                path.display()
            );
            path
        });
        return (guest_service, broker, runner, guest);
    }
    let (guest_service, broker, runner) =
        cargo::build_programs(Backend::Userland, &dir.join("programs"));
    let guest = dir.join("guest");
    build_guest(&guest);
    (guest_service, broker, runner, guest)
}

/// Nano Server has no `vcruntime140.dll`: the shim copies the one next to the broker.
fn add_runtime_library(dir: &Path) {
    let runtime = dir.join("vcruntime140.dll");
    if runtime.exists() {
        return;
    }
    let system = std::env::var_os("SystemRoot").expect("SystemRoot is set");
    let source = Path::new(&system).join(r"System32\vcruntime140.dll");
    // Tests share a prebuilt fixture directory, so another may have copied it meanwhile.
    if let Err(error) = std::fs::copy(&source, &runtime) {
        assert!(
            runtime.exists(),
            "cannot copy {}: {error}",
            source.display()
        );
    }
}

/// `LITEBOX_TEST_WINDOWS_LAYERS`'s folders, then a new scratch layer's in `dir`.
fn layer_folders(dir: &Path) -> Vec<PathBuf> {
    let parents = std::env::var_os("LITEBOX_TEST_WINDOWS_LAYERS").expect(
        "LITEBOX_TEST_WINDOWS_LAYERS names a Windows image's layer folders, such as \
         nanoserver:ltsc2025's",
    );
    let parents: Vec<PathBuf> = std::env::split_paths(&parents).collect();
    let scratch = dir.join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    create_scratch(&scratch, &parents);
    parents.into_iter().chain([scratch]).collect()
}

/// As containerd's `windows` snapshotter prepares a container's snapshot.
fn create_scratch(scratch: &Path, parents: &[PathBuf]) {
    let wide = |text: &OsStr| -> Vec<u16> { text.encode_wide().chain([0]).collect() };
    let paths: Vec<Vec<u16>> = parents.iter().map(|path| wide(path.as_os_str())).collect();
    let descriptors: Vec<LayerDescriptor> = (parents.iter().zip(&paths))
        .map(|(parent, path)| {
            let mut layer_id = GUID::from_u128(0);
            let name = wide(parent.file_name().unwrap());
            // SAFETY: the NUL-terminated name and `layer_id` outlive the call, which writes only
            // `layer_id`.
            let code = unsafe { NameToGuid(name.as_ptr(), &raw mut layer_id) };
            assert!(
                code >= 0,
                "NameToGuid: {}",
                io::Error::from_raw_os_error(code)
            );
            LayerDescriptor {
                layer_id,
                flags: 0,
                path: path.as_ptr(),
            }
        })
        .collect();
    let empty = [0_u16];
    let info = DriverInfo {
        flavour: 1,
        home_dir: empty.as_ptr(),
    };
    let id = wide(scratch.as_os_str());
    // SAFETY: `info`, the NUL-terminated `id`, the descriptors and the paths they point to outlive
    // the call; no parent ID, as hcsshim passes none.
    let code = unsafe {
        CreateSandboxLayer(
            &raw const info,
            id.as_ptr(),
            std::ptr::null(),
            descriptors.as_ptr(),
            descriptors.len(),
        )
    };
    assert!(
        code >= 0,
        "cannot create a scratch layer on {parents:?}: {}",
        io::Error::from_raw_os_error(code)
    );
}

/// HCN objects are host-wide and outlive their handles. Their IDs are fixed, and a host-wide lock,
/// held until they are deleted, lets a run delete a crashed run's without touching a live one's.
struct TestNetwork {
    /// The endpoint's, which HNS assigns.
    address: Ipv4Addr,
    created: Created,
    _lock: File,
}

impl TestNetwork {
    const NETWORK: u128 = 0x6c697465_626f_7874_6573_740000000001;
    const ENDPOINT: u128 = 0x6c697465_626f_7874_6573_740000000002;
    const NAMESPACE: u128 = 0x6c697465_626f_7874_6573_740000000003;
    const DNS_SERVER: &str = "192.0.2.53";
    const DNS_SEARCH: &str = "litebox.test";

    fn create() -> Self {
        let lock = Path::new(&std::env::var_os("ProgramData").expect("ProgramData is set"))
            .join("litebox-shim-test-network.lock");
        let lock = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock)
            .unwrap_or_else(|error| panic!("cannot open {}: {error}", lock.display()));
        lock.lock().unwrap();
        // A crashed run's. HCN documents no not-found error for namespaces, so they are listed.
        let ids = [
            (Self::NETWORK, Kind::Network),
            (Self::ENDPOINT, Kind::Endpoint),
            (Self::NAMESPACE, Kind::Namespace),
        ];
        Created(
            ids.into_iter()
                .filter(|&(id, kind)| kind.exists(id))
                .collect(),
        )
        .delete();
        let mut created = Created(Vec::new());
        let schema = serde_json::json!({"Major": 2, "Minor": 0});
        let network = serde_json::json!({
            "SchemaVersion": schema,
            "Name": "litebox-shim-test",
            "Type": "NAT",
            "Ipams": [{"Type": "Static", "Subnets": [{
                "IpAddressPrefix": "192.168.252.0/24",
                "Routes": [{"NextHop": "192.168.252.1", "DestinationPrefix": "0.0.0.0/0"}],
            }]}],
        });
        let settings = wide(&network.to_string());
        let mut raw = null_mut();
        hcn("create the network", |record| {
            // SAFETY: the ID, the NUL-terminated settings, `raw` and `record` outlive the call.
            unsafe {
                HcnCreateNetwork(
                    &GUID::from_u128(Self::NETWORK),
                    settings.as_ptr(),
                    &raw mut raw,
                    record,
                )
            }
        });
        created.0.push((Self::NETWORK, Kind::Network));
        let network = HcnHandle(raw, HcnCloseNetwork);
        let endpoint = serde_json::json!({
            "SchemaVersion": schema,
            "Name": "litebox-shim-test",
            "HostComputeNetwork": hyphenated(Self::NETWORK),
            "Dns": {"ServerList": [Self::DNS_SERVER], "Search": [Self::DNS_SEARCH]},
        });
        let settings = wide(&endpoint.to_string());
        hcn("create the endpoint", |record| {
            // SAFETY: as for the network, which is open.
            unsafe {
                HcnCreateEndpoint(
                    network.0,
                    &GUID::from_u128(Self::ENDPOINT),
                    settings.as_ptr(),
                    &raw mut raw,
                    record,
                )
            }
        });
        created.0.push((Self::ENDPOINT, Kind::Endpoint));
        let endpoint = HcnHandle(raw, HcnCloseEndpoint);
        let query = wide(HCN_QUERY);
        let mut properties = null_mut();
        hcn("query the endpoint", |record| {
            // SAFETY: the endpoint is open, and the NUL-terminated query, `properties` and `record`
            // outlive the call.
            unsafe {
                HcnQueryEndpointProperties(endpoint.0, query.as_ptr(), &raw mut properties, record)
            }
        });
        // SAFETY: HCN gives the caller its document.
        let properties: serde_json::Value = serde_json::from_str(&unsafe { take(properties) })
            .expect("HCN's endpoint document is JSON");
        let address = field(&field(&properties, "IpConfigurations")[0], "IpAddress");
        let address = (address.as_str().and_then(|address| address.parse().ok()))
            .unwrap_or_else(|| panic!("the endpoint has no IPv4 address: {properties}"));
        let namespace = serde_json::json!({"SchemaVersion": schema});
        let settings = wide(&namespace.to_string());
        hcn("create the namespace", |record| {
            // SAFETY: as for the network.
            unsafe {
                HcnCreateNamespace(
                    &GUID::from_u128(Self::NAMESPACE),
                    settings.as_ptr(),
                    &raw mut raw,
                    record,
                )
            }
        });
        created.0.push((Self::NAMESPACE, Kind::Namespace));
        let namespace = HcnHandle(raw, HcnCloseNamespace);
        let add = serde_json::json!({
            "ResourceType": "Endpoint",
            "RequestType": "Add",
            "Settings": {"EndpointId": hyphenated(Self::ENDPOINT)},
        });
        let settings = wide(&add.to_string());
        hcn("add the endpoint to the namespace", |record| {
            // SAFETY: the namespace is open, and the NUL-terminated settings and `record` outlive
            // the call.
            unsafe { HcnModifyNamespace(namespace.0, settings.as_ptr(), record) }
        });
        Self {
            address,
            created,
            _lock: lock,
        }
    }
}

/// Schema 2.0 documents, as hcsshim's `hcn` package asks for them.
const HCN_QUERY: &str = r#"{"SchemaVersion":{"Major":2,"Minor":0},"Flags":0}"#;

type Enumerate = unsafe extern "system" fn(PCWSTR, *mut PWSTR, *mut PWSTR) -> HRESULT;
type Delete = unsafe extern "system" fn(*const GUID, *mut PWSTR) -> HRESULT;

#[derive(Clone, Copy)]
enum Kind {
    Network,
    Endpoint,
    Namespace,
}

impl Kind {
    fn calls(self) -> (&'static str, Enumerate, Delete) {
        match self {
            Self::Network => ("network", HcnEnumerateNetworks, HcnDeleteNetwork),
            Self::Endpoint => ("endpoint", HcnEnumerateEndpoints, HcnDeleteEndpoint),
            Self::Namespace => ("namespace", HcnEnumerateNamespaces, HcnDeleteNamespace),
        }
    }

    fn exists(self, id: u128) -> bool {
        let (name, enumerate, _) = self.calls();
        let query = wide(HCN_QUERY);
        let mut ids = null_mut();
        hcn(&format!("list the {name}s"), |record| {
            // SAFETY: the NUL-terminated query, `ids` and `record` outlive the call.
            unsafe { enumerate(query.as_ptr(), &raw mut ids, record) }
        });
        // SAFETY: HCN gives the caller its document on success.
        let ids = unsafe { take(ids) };
        let listed: Option<Vec<String>> = serde_json::from_str(&ids)
            .unwrap_or_else(|error| panic!("HCN's {name} list {ids:?} is not JSON: {error}"));
        let id = hyphenated(id);
        (listed.into_iter().flatten())
            .any(|listed| listed.trim_matches(['{', '}']).eq_ignore_ascii_case(&id))
    }
}

/// HCN objects, oldest first, which are deleted newest first, as each may use those before it.
struct Created(Vec<(u128, Kind)>);

impl Created {
    /// As hcsshim's tests do, a namespace's endpoints are detached first. Panics with HCN's record
    /// at the first failure, leaving the rest to `drop`.
    fn delete(&mut self) {
        while let Some(&(id, kind)) = self.0.last() {
            if let Kind::Namespace = kind {
                detach_endpoints(id);
            }
            let (name, _, delete) = kind.calls();
            hcn(&format!("delete the {name} {}", hyphenated(id)), |record| {
                // SAFETY: the ID and `record` outlive the call.
                unsafe { delete(&GUID::from_u128(id), record) }
            });
            self.0.pop();
        }
    }
}

impl Drop for Created {
    fn drop(&mut self) {
        for &(id, kind) in self.0.iter().rev() {
            let (_, _, delete) = kind.calls();
            let mut record = null_mut();
            // SAFETY: the ID and `record` outlive the call.
            unsafe { delete(&GUID::from_u128(id), &raw mut record) };
            // SAFETY: HCN gives the caller its error record, if any.
            unsafe { take(record) };
        }
    }
}

fn detach_endpoints(id: u128) {
    let mut raw = null_mut();
    hcn("open the namespace", |record| {
        // SAFETY: the ID, `raw` and `record` outlive the call.
        unsafe { HcnOpenNamespace(&GUID::from_u128(id), &raw mut raw, record) }
    });
    let namespace = HcnHandle(raw, HcnCloseNamespace);
    let query = wide(HCN_QUERY);
    let mut properties = null_mut();
    hcn("query the namespace", |record| {
        // SAFETY: the namespace is open, and the NUL-terminated query, `properties` and `record`
        // outlive the call.
        unsafe {
            HcnQueryNamespaceProperties(namespace.0, query.as_ptr(), &raw mut properties, record)
        }
    });
    // SAFETY: HCN gives the caller its document on success.
    let properties: serde_json::Value = serde_json::from_str(&unsafe { take(properties) })
        .expect("HCN's namespace document is JSON");
    let resources = field(&properties, "Resources")
        .as_array()
        .into_iter()
        .flatten();
    for resource in resources.filter(|resource| field(resource, "Type") == "Endpoint") {
        let remove = serde_json::json!({
            "ResourceType": "Endpoint",
            "RequestType": "Remove",
            "Settings": {"EndpointId": field(field(resource, "Data"), "ID")},
        });
        let settings = wide(&remove.to_string());
        hcn(&format!("detach the endpoint {resource}"), |record| {
            // SAFETY: the namespace is open, and the NUL-terminated settings and `record` outlive
            // the call.
            unsafe { HcnModifyNamespace(namespace.0, settings.as_ptr(), record) }
        });
    }
}

struct HcnHandle(
    *mut c_void,
    unsafe extern "system" fn(*const c_void) -> HRESULT,
);

impl Drop for HcnHandle {
    fn drop(&mut self) {
        // SAFETY: the object is open, and the function is its kind's.
        unsafe { (self.1)(self.0) };
    }
}

fn hcn(what: &str, call: impl FnOnce(*mut PWSTR) -> HRESULT) {
    let mut record = null_mut();
    let code = call(&raw mut record);
    // SAFETY: HCN gives the caller its error record, if any.
    let record = unsafe { take(record) };
    assert!(
        code >= 0 && record.is_empty(),
        "cannot {what}: {} {record}",
        io::Error::from_raw_os_error(code)
    );
}

/// # Safety
///
/// `text` is null, or a NUL-terminated string that HCN allocated for the caller.
unsafe fn take(text: PWSTR) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: the caller's.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `length` units precede the NUL.
    let string = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    // SAFETY: the caller's; nothing uses it any longer.
    unsafe { CoTaskMemFree(text.cast()) };
    string
}

/// In any case, as hcsshim's decoder (Go's) reads HCN's documents.
fn field<'v>(value: &'v serde_json::Value, name: &str) -> &'v serde_json::Value {
    (value.as_object().into_iter().flatten())
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map_or(&serde_json::Value::Null, |(_, value)| value)
}

fn hyphenated(id: u128) -> String {
    let hex = format!("{id:032x}");
    let parts = [
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..],
    ];
    parts.join("-")
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn build_guest(output: &Path) {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut wsl = Command::new("wsl.exe");
    if let Some(distribution) = std::env::var_os("LITEBOX_WSL_DISTRO") {
        wsl.arg("--distribution").arg(distribution);
    }
    let status = wsl
        .arg("--cd")
        .arg(workspace)
        .args([
            "--exec",
            "bash",
            "litebox_runner_linux_on_windows_userland/tests/build_windows_linux_guest.sh",
            "litebox_containerd_shim/tests/guest.c",
        ])
        .arg(output)
        .arg("static")
        .stdin(Stdio::null())
        .status()
        .expect(
            "the containerd-shim tests need WSL, with an x86-64 Linux distribution that has GCC",
        );
    assert!(
        status.success(),
        "building tests/guest.c in WSL failed: {status}"
    );
}

fn write_image(path: &Path, guest: &[u8]) {
    let passwd = b"root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/x\n";
    let (directory, file, symlink) = (EntryType::Directory, EntryType::Regular, EntryType::Symlink);
    let entries: [(&str, EntryType, u32, &[u8]); 9] = [
        ("usr", directory, 0o755, b""),
        ("usr/bin", directory, 0o755, b""),
        ("usr/bin/guest", file, 0o755, guest),
        ("usr/bin/sh", symlink, 0o777, b"/bin/guest"),
        ("bin", symlink, 0o777, b"usr/bin"),
        ("etc", directory, 0o755, b""),
        ("etc/passwd", file, 0o644, passwd),
        ("first", directory, 0o755, b""),
        ("first/sh", file, 0o641, b"#!/bin/sh\n"),
    ];
    let mut archive = Vec::new();
    for (name, entry_type, mode, data) in entries {
        let mut entry = EntryBuilder::new_gnu();
        entry.path(name).entry_type(entry_type);
        let content = if entry_type == symlink {
            entry.link_name(data);
            &[][..]
        } else {
            data
        };
        let size = u64::try_from(content.len()).unwrap();
        entry.mode(mode).and_then(|entry| entry.size(size)).unwrap();
        archive.extend_from_slice(&entry.finish_bytes());
        archive.extend_from_slice(content);
        archive.resize(archive.len().next_multiple_of(512), 0);
    }
    archive.extend_from_slice(&[0; 1024]);
    std::fs::write(path, archive).unwrap();
}

struct ProcessEntry {
    id: u32,
    parent: u32,
    executable: String,
}

fn processes() -> Vec<ProcessEntry> {
    // SAFETY: plain call.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    assert_ne!(
        snapshot,
        INVALID_HANDLE_VALUE,
        "{}",
        io::Error::last_os_error()
    );
    // SAFETY: the call succeeded, so this owns `snapshot`.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap(),
        ..PROCESSENTRY32W::default()
    };
    let mut entries = Vec::new();
    // SAFETY: `snapshot` is open, and `entry` outlives the call, which writes only it.
    let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    while more {
        let name = &entry.szExeFile;
        let length = name
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(name.len());
        entries.push(ProcessEntry {
            id: entry.th32ProcessID,
            parent: entry.th32ParentProcessID,
            executable: String::from_utf16_lossy(&name[..length]),
        });
        // SAFETY: as for `Process32FirstW`.
        more = unsafe { Process32NextW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    }
    entries
}

fn executable(pid: u32) -> Option<String> {
    let entry = processes().into_iter().find(|entry| entry.id == pid)?;
    Some(entry.executable)
}

fn tree(pid: u32) -> Vec<u32> {
    let entries = processes();
    let mut tree = vec![pid];
    let mut next = 0;
    while let Some(&parent) = tree.get(next) {
        next += 1;
        // A new process can reuse a dead parent's PID; require the child to be younger.
        let Some(born) = created(parent) else {
            continue;
        };
        let children: Vec<u32> = (entries.iter())
            .filter(|entry| entry.parent == parent && !tree.contains(&entry.id))
            .filter(|entry| created(entry.id).is_some_and(|time| time >= born))
            .map(|entry| entry.id)
            .collect();
        tree.extend(children);
    }
    tree
}

/// When `pid` was created, if it is still open to us.
fn created(pid: u32) -> Option<u64> {
    // SAFETY: plain call.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    // SAFETY: the call succeeded, so this owns `process`.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut times = [FILETIME::default(); 4];
    let [creation, exit, kernel, user] = &mut times;
    // SAFETY: `process` is open with `PROCESS_QUERY_LIMITED_INFORMATION`, and the call writes only
    // the four times.
    let ok = unsafe { GetProcessTimes(process.as_raw_handle(), creation, exit, kernel, user) };
    (ok != 0).then(|| u64::from(creation.dwHighDateTime) << 32 | u64::from(creation.dwLowDateTime))
}

/// True if `pid` never existed too.
fn is_gone(pid: u32) -> bool {
    // SAFETY: plain call.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        let error = io::Error::last_os_error();
        let missing = i32::try_from(ERROR_INVALID_PARAMETER).unwrap();
        assert_eq!(error.raw_os_error(), Some(missing), "{error}");
        return true;
    }
    // SAFETY: the call succeeded, so this owns `process`.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    // SAFETY: `process` is open with `SYNCHRONIZE`.
    unsafe { WaitForSingleObject(process.as_raw_handle(), 0) == WAIT_OBJECT_0 }
}

fn terminate(pid: u32) {
    // SAFETY: plain call.
    let process = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    assert!(!process.is_null(), "{}", io::Error::last_os_error());
    // SAFETY: the call succeeded, so this owns `process`.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    // SAFETY: `process` is open with `PROCESS_TERMINATE`.
    let terminated = unsafe { TerminateProcess(process.as_raw_handle(), 1) };
    assert_ne!(terminated, 0, "{}", io::Error::last_os_error());
}

#[test]
#[ignore = "needs administrator rights, the Containers feature and LITEBOX_TEST_WINDOWS_LAYERS"]
fn a_container_runs_and_reports_its_exit() {
    let mut init = process(&["sh", "exit", "3"]);
    init["cwd"] = "/bin/../new".into();
    init["env"] = serde_json::json!(["PATH=/first:/bin"]);
    let mut shim = Shim::launch(&init);
    let pid = shim.create().unwrap();
    let broker = executable(pid);
    assert_eq!(broker.as_deref(), Some("litebox-broker-userland.exe"));
    assert_eq!(shim.start("").unwrap(), pid);
    assert_eq!(shim.wait(""), 3);
    assert_eq!(
        shim.output("c.out"),
        "ids=1000,1000 cwd=/usr/new\nargv[0]=[sh]\nargv[1]=[exit]\nargv[2]=[3]\nenv=[PATH=/first:/bin]\nenv=[HOME=/root]\n"
    );
    assert_eq!(shim.output("logs/c.err"), "stderr\n");
    assert_eq!(code(&shim.kill("", 9).unwrap_err()), Code::NOT_FOUND);
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
#[ignore = "needs administrator rights, the Containers feature and LITEBOX_TEST_WINDOWS_LAYERS"]
fn execs_take_input_from_named_pipes_and_kills_reach_their_process() {
    let mut shim = Shim::launch(&process(&["guest", "signals"]));
    let (uri, pipe) = shim.input("c.in");
    let pid = shim.create_with(&uri).unwrap();
    shim.start("").unwrap();
    let _input = accept(pipe);
    let (uri, pipe) = shim.input("e1.in");
    shim.exec("e1", &["guest", "cat"], &uri).unwrap();
    assert_eq!(shim.start("e1").unwrap(), pid);
    let mut input = accept(pipe);
    input.write_all(b"hello\n").unwrap();
    drop(input);
    assert_eq!(shim.wait("e1"), 0);
    assert!(shim.output("e1.out").ends_with("line=[hello]\neof\n"));
    shim.delete("e1").unwrap();
    // CloseIO ends the input while its writer stays open.
    let (uri, pipe) = shim.input("e1.in2");
    shim.exec("e1", &["guest", "cat"], &uri).unwrap();
    shim.start("e1").unwrap();
    let mut input = accept(pipe);
    input.write_all(b"held\n").unwrap();
    shim.close_stdin("e1");
    assert_eq!(shim.wait("e1"), 0);
    assert!(shim.output("e1.out").ends_with("line=[held]\neof\n"));
    shim.delete("e1").unwrap();
    drop(input);
    shim.exec("e2", &["guest", "family"], "").unwrap();
    shim.start("e2").unwrap();
    shim.wait_output("e2.out", "child\n");
    shim.kill("e2", 9).unwrap();
    assert_eq!(shim.wait("e2"), 137);
    shim.delete("e2").unwrap();
    shim.kill("", 15).unwrap();
    assert_eq!(shim.wait(""), 7);
    assert!(shim.output("c.out").ends_with("caught 15\n"));
    shim.finish(pid);
}

#[test]
#[ignore = "needs administrator rights, the Containers feature and LITEBOX_TEST_WINDOWS_LAYERS"]
fn an_exec_s_delete_closes_its_unread_output() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    // The exec exits at once; its child fills the pipe, which nobody reads.
    let (uri, pipe) = shim.output_pipe("e1.out");
    shim.exec_to("e1", &["guest", "lines", "50000", "child"], "", &uri)
        .unwrap();
    shim.start("e1").unwrap();
    let pipe = accept(pipe);
    assert_eq!(shim.wait("e1"), 0);
    shim.delete("e1").unwrap();
    // The shim's write poll (1 s), and a margin. A shim that still held the pipe would now
    // write the rest.
    std::thread::sleep(Duration::from_secs(3));
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || sender.send(io::read_to_string(pipe)));
    let output = receiver
        .recv_timeout(TIMEOUT)
        .expect("e1's output did not end");
    let output = output.unwrap();
    assert!(!output.ends_with("line 49999\n"), "{} bytes", output.len());
    shim.kill("", 9).unwrap();
    assert_eq!(shim.wait(""), 137);
    shim.finish(pid);
}

#[test]
#[ignore = "needs administrator rights, the Containers feature and LITEBOX_TEST_WINDOWS_LAYERS"]
fn a_created_container_is_deleted_with_its_broker() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let pid = shim.create().unwrap();
    assert!(shim.state_dir().join("rootfs.tar").exists());
    assert!(shim.layers_mounted());
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
#[ignore = "needs administrator rights, the Containers feature and LITEBOX_TEST_WINDOWS_LAYERS"]
fn the_broker_and_its_runners_die_with_the_daemon() {
    let mut shim = Shim::launch(&process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    shim.wait_output("c.out", "child\n");
    let broker = tree(pid);
    assert!(
        broker.len() > 3,
        "expected broker and at least three runners: {broker:?}"
    );
    shim.daemon.kill().unwrap();
    shim.daemon.wait().unwrap();
    wait_until("the broker's processes outlived the daemon", || {
        broker.iter().all(|pid| is_gone(*pid))
    });
    assert_eq!(shim.delete_action(), 137);
    shim.assert_cleaned_up();
}

#[test]
#[ignore = "needs administrator rights, the Containers feature and LITEBOX_TEST_WINDOWS_LAYERS"]
fn a_broker_that_dies_before_start_stops_the_init() {
    let mut shim = Shim::launch(&process(&["guest", "exit", "0"]));
    let pid = shim.create().unwrap();
    terminate(pid);
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
#[ignore = "needs administrator rights, the Containers feature and LITEBOX_TEST_WINDOWS_LAYERS"]
fn a_network_namespace_gives_the_guest_its_dns_and_serves_its_listeners() {
    let mut network = TestNetwork::create();
    let mut shim = Shim::launch(&process(&["guest", "serve"]));
    shim.configure(|spec| {
        let namespace = hyphenated(TestNetwork::NAMESPACE);
        spec["windows"]["network"] = serde_json::json!({"networkNamespace": namespace});
        spec["annotations"] = serde_json::json!({"io.litebox.ingress.tcp": "0.0.0.0/0"});
    });
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    shim.exec("e1", &["guest", "read", "/bin", "/etc/resolv.conf"], "")
        .unwrap();
    shim.start("e1").unwrap();
    assert_eq!(shim.wait("e1"), 0);
    let resolv_conf = format!(
        "link=usr/bin\nsearch {}\nnameserver {}\n\
         # Added by the LiteBox shim: IPv4 only, for glibc.\noptions no-aaaa\n",
        TestNetwork::DNS_SEARCH,
        TestNetwork::DNS_SERVER
    );
    let output = shim.output("e1.out");
    assert!(output.ends_with(&resolv_conf), "{output}");
    shim.delete("e1").unwrap();
    shim.wait_output("c.out", "listening\n");
    let server = SocketAddr::from((network.address, 80));
    let stream = TcpStream::connect_timeout(&server, TIMEOUT)
        .unwrap_or_else(|error| panic!("cannot connect to {server}: {error}"));
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    assert_eq!(io::read_to_string(stream).unwrap(), "hello");
    assert_eq!(shim.wait(""), 0);
    shim.finish(pid);
    network.created.delete();
}
