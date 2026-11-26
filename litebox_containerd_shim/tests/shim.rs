// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs the shim daemon as containerd does, against a fake containerd event service, with the
//! real broker and guest service, on each backend: `userland::<test>`; and, ignored by default,
//! `vm::<test>`, in QEMU with `vhost-device-vsock` (`VHOST_DEVICE_VSOCK`, else from `PATH`), and
//! `ch::<test>`, in Cloud Hypervisor (`CLOUD_HYPERVISOR`, else from `PATH`), both with `virtiofsd`
//! (`VIRTIOFSD`, else as the shim finds it).

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::fs::File;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

#[path = "support/cargo.rs"]
mod cargo;
#[path = "support/common.rs"]
mod common;

use common::{EventLog, TIMEOUT, code, deadline, process, wait_until};
use containerd_shim::api::{
    CloseIORequest, ConnectRequest, CreateTaskRequest, DeleteRequest, DeleteResponse,
    ExecProcessRequest, KillRequest, ResizePtyRequest, ShutdownRequest, StartRequest, StateRequest,
    Status, WaitRequest,
};
use containerd_shim::protos::protobuf::well_known_types::any::Any;
use containerd_shim::protos::protobuf::{Message, MessageField};
use containerd_shim::protos::shim_sync::{Client, TaskClient, create_events};
use containerd_shim::protos::ttrpc::{self, Code, Server, context};
use containerd_shim::protos::types::empty::Empty;
use containerd_shim::protos::types::introspection::RuntimeInfo;
use containerd_shim::protos::types::mount::Mount;

const NAMESPACE: &str = "litebox-test";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Userland,
    /// In QEMU.
    Vm,
    CloudHypervisor,
}

impl Backend {
    /// The backend's shim, as containerd finds it by the runtime's name.
    fn shim(self) -> &'static str {
        match self {
            Self::Userland => env!("CARGO_BIN_EXE_containerd-shim-litebox-v1"),
            Self::Vm => env!("CARGO_BIN_EXE_containerd-shim-litebox-vm-v1"),
            Self::CloudHypervisor => env!("CARGO_BIN_EXE_containerd-shim-litebox-ch-v1"),
        }
    }

    /// The program that the shim starts the broker with, through a link that a test can remove.
    fn broker_program(self) -> &'static str {
        match self {
            Self::Userland => "litebox-broker-userland",
            Self::Vm | Self::CloudHypervisor => "litebox_runner_vm_kernel",
        }
    }
}

/// Defines each test `test(backend)` once per backend, as `userland::test`, `vm::test` and
/// `ch::test`; each of `one vmm`, which does not depend on the VMM, only as `userland::test` and
/// `vm::test`.
macro_rules! on_both_backends {
    (
        $($test:ident),* $(,)?;
        one vmm: $($one_vmm:ident),* $(,)?;
        privileged: $($privileged:ident),* $(,)?;
        as root: $($root:ident),* $(,)?;
        vm only: $($vm_only:ident),* $(,)?;
        vm only as root: $($vm_root:ident),* $(,)?
    ) => {
        mod userland {
            $(
                #[test]
                fn $test() {
                    super::$test(super::Backend::Userland);
                }
            )*
            $(
                #[test]
                fn $one_vmm() {
                    super::$one_vmm(super::Backend::Userland);
                }
            )*
            $(
                #[test]
                #[ignore = "needs mount privilege; CI runs it under `unshare -rm`"]
                fn $privileged() {
                    super::$privileged(super::Backend::Userland);
                }
            )*
            $(
                #[test]
                #[ignore = "needs root; CI runs it under `unshare --map-auto -rm`"]
                fn $root() {
                    super::$root(super::Backend::Userland);
                }
            )*
        }
        mod vm {
            $(
                #[test]
                #[ignore = "boots QEMU; CI runs it in the QEMU job"]
                fn $test() {
                    super::$test(super::Backend::Vm);
                }
            )*
            $(
                #[test]
                #[ignore = "boots QEMU; CI runs it in the QEMU job"]
                fn $one_vmm() {
                    super::$one_vmm(super::Backend::Vm);
                }
            )*
            $(
                #[test]
                #[ignore = "boots QEMU, and needs mount privilege; CI runs it in the QEMU job under \
                            `unshare -rm`"]
                fn $privileged() {
                    super::$privileged(super::Backend::Vm);
                }
            )*
            $(
                #[test]
                #[ignore = "boots QEMU, and needs root; CI runs it in the QEMU job under \
                            `unshare --map-auto -rm`"]
                fn $root() {
                    super::$root(super::Backend::Vm);
                }
            )*
            $(
                #[test]
                #[ignore = "boots QEMU; CI runs it in the QEMU job"]
                fn $vm_only() {
                    super::$vm_only();
                }
            )*
            $(
                #[test]
                #[ignore = "boots QEMU, and needs root and users other than root; CI runs it in the \
                            QEMU job under `unshare --map-auto -rm`"]
                fn $vm_root() {
                    super::$vm_root(super::Backend::Vm);
                }
            )*
        }
        mod ch {
            $(
                #[test]
                #[ignore = "boots Cloud Hypervisor; CI runs it in the VMM job"]
                fn $test() {
                    super::$test(super::Backend::CloudHypervisor);
                }
            )*
            $(
                #[test]
                #[ignore = "boots Cloud Hypervisor, and needs mount privilege; CI runs it in the VMM \
                            job under `unshare -rm`"]
                fn $privileged() {
                    super::$privileged(super::Backend::CloudHypervisor);
                }
            )*
            $(
                #[test]
                #[ignore = "boots Cloud Hypervisor, and needs root; CI runs it in the VMM job under \
                            `unshare --map-auto -rm`"]
                fn $root() {
                    super::$root(super::Backend::CloudHypervisor);
                }
            )*
            $(
                #[test]
                #[ignore = "boots Cloud Hypervisor, and needs root and users other than root; CI \
                            runs it in the VMM job under `unshare --map-auto -rm`"]
                fn $vm_root() {
                    super::$vm_root(super::Backend::CloudHypervisor);
                }
            )*
        }
    };
}

on_both_backends! {
    a_container_runs_and_reports_its_exit,
    the_broker_group_dies_with_the_daemon,
    binds_copy_files_and_serve_directories,
    a_container_with_a_small_memory_limit_runs,
    refused_or_unsupported_specs_and_annotations_fail_create;
    one vmm: execs_take_input_and_their_output_comes_before_their_exit,
    a_reader_of_the_output_may_start_after_the_exit,
    an_exec_s_output_ends_once_idle_or_at_its_delete,
    an_exec_s_delete_closes_its_unread_output,
    a_terminal_init_takes_a_resize_before_start,
    terminals_take_input_resizes_and_interrupts,
    a_terminal_whose_input_ends_before_start_starts,
    kills_reach_their_process,
    without_mount_privilege_root_file_system_mounts_fail_create,
    a_created_container_is_deleted_with_its_broker,
    hooks_run_on_the_host_with_the_state,
    a_logging_program_gets_the_output,
    the_delete_action_finishes_a_delete_cut_short,
    a_cleanup_that_outlasts_the_delete_action_goes_on,
    a_broker_that_dies_before_start_stops_the_init,
    a_broker_that_dies_stops_created_execs_and_refuses_more,
    the_container_cannot_kill_the_guest_service,
    a_guest_service_that_does_not_answer_is_taken_for_dead,
    a_guest_service_that_does_not_answer_an_exec_is_taken_for_dead;
    privileged: with_mount_privilege_bind_and_overlay_mounts_are_read_then_unmounted;
    as root: as_root_the_broker_joins_or_creates_the_container_s_network_namespace;
    vm only: a_dead_vsock_device_stops_the_broker, qemu_takes_the_cpu_quota_and_prefers_kvm,
        a_vm_that_boots_late_starts;
    vm only as root: with_litebox_user_the_vm_runs_as_that_user,
        as_root_a_vm_takes_back_a_state_directory_another_user_owns,
}

/// containerd runs a runtime type's shim by the type's name, and checks the name the shim reports.
#[test]
fn each_backends_shim_reports_its_runtime() {
    for (backend, runtime) in [
        (Backend::Userland, "io.containerd.litebox.v1"),
        (Backend::Vm, "io.containerd.litebox-vm.v1"),
        (Backend::CloudHypervisor, "io.containerd.litebox-ch.v1"),
    ] {
        let output = Command::new(backend.shim()).arg("-info").output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let info = RuntimeInfo::parse_from_bytes(&output.stdout).unwrap();
        assert_eq!(info.name, runtime);
    }
}

/// A shim daemon serving the container `c` on `backend`, whose image holds the guest as
/// `/usr/bin/guest`, `/bin -> usr/bin`, `/usr/bin/sh -> /bin/guest`, and an `/etc/passwd`.
struct Shim {
    backend: Backend,
    dir: tempfile::TempDir,
    daemon: Child,
    client: TaskClient,
    events: Arc<EventLog>,
    _event_server: Server,
    bundle: PathBuf,
}

impl Shim {
    fn launch(backend: Backend, process: &serde_json::Value) -> Self {
        Self::launch_as(backend, process, &[], 0)
    }

    /// [`Self::launch`], with the daemon's environment variables `env` added, and its umask
    /// `umask`.
    fn launch_as(
        backend: Backend,
        process: &serde_json::Value,
        env: &[(&str, &str)],
        umask: u32,
    ) -> Self {
        let dir = tempfile::Builder::new().prefix("lbx").tempdir().unwrap();
        let (guest_service, built_program, built_runner) =
            cargo::build_programs(backend, &dir.path().join("programs"));
        // Through a link, which a test can remove.
        let program = dir.path().join(backend.broker_program());
        std::os::unix::fs::symlink(built_program, &program).unwrap();
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
        let events = Arc::new(EventLog::new(NAMESPACE));
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
        let mut daemon = shim_command(backend);
        match backend {
            Backend::Userland => daemon
                .env("LITEBOX_BROKER", program)
                .env("LITEBOX_RUNNER", built_runner),
            Backend::Vm | Backend::CloudHypervisor => {
                for (variable, shims) in [
                    ("VIRTIOFSD", "LITEBOX_VIRTIOFSD"),
                    ("CLOUD_HYPERVISOR", "LITEBOX_CLOUD_HYPERVISOR"),
                ] {
                    if let Some(value) = std::env::var_os(variable) {
                        daemon.env(shims, value);
                    }
                }
                daemon
                    .env("LITEBOX_VM_KERNEL", program)
                    .env("LITEBOX_VM_RUNNER", built_runner)
                    .env(
                        "LITEBOX_VHOST_DEVICE_VSOCK",
                        std::env::var_os("VHOST_DEVICE_VSOCK")
                            .unwrap_or_else(|| "vhost-device-vsock".into()),
                    )
            }
        };
        let daemon = daemon
            .args(["-socket", &address])
            .current_dir(&work)
            .env("TTRPC_ADDRESS", &event_socket)
            .env("LITEBOX_GUEST_SERVICE", guest_service)
            .env("LITEBOX_SHIM_STATE_ROOT", dir.path().join("state"))
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(dir.path().join("stderr")).unwrap());
        let me = std::process::id();
        // SAFETY: the hook makes async-signal-safe calls only.
        unsafe {
            daemon.pre_exec(move || {
                // A killed test drops no `Shim`: its daemon dies with the test's thread instead. The
                // test may have died before the death signal was armed.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                    || u32::try_from(libc::getppid()) != Ok(me)
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // The daemon inherits it; even the most permissive must leave its socket its own.
        let umask = rustix::process::umask(rustix::fs::Mode::from_raw_mode(umask));
        let daemon = daemon.spawn().unwrap();
        rustix::process::umask(umask);
        // The daemon's socket exists before it listens.
        let mut connection = None;
        wait_until("the shim daemon did not listen", || {
            connection = Client::connect(&address).ok();
            connection.is_some()
        });
        assert_eq!(socket.metadata().unwrap().mode() & 0o077, 0);
        let client = TaskClient::new(connection.expect("connected"));
        Self {
            backend,
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
        self.delete_action_while(|_| {})
    }

    /// Runs the shim's `delete` action, calling `during` with its pid meanwhile.
    fn delete_action_while(&self, during: impl FnOnce(u32)) -> u32 {
        let delete = self.delete_action_command().spawn().unwrap();
        during(delete.id());
        let output = delete.wait_with_output().unwrap();
        // Nothing to unmount is no error, not even for an unprivileged action.
        assert!(!String::from_utf8_lossy(&output.stderr).contains("cannot unmount"));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        DeleteResponse::parse_from_bytes(&output.stdout)
            .unwrap()
            .exit_status
    }

    /// The shim's `delete` action, as containerd runs it, with its output piped.
    fn delete_action_command(&self) -> Command {
        let mut command = shim_command(self.backend);
        command
            .arg("-bundle")
            .arg(&self.bundle)
            .arg("delete")
            .current_dir(&self.bundle)
            .env("TTRPC_ADDRESS", self.path("events.sock"))
            .env("LITEBOX_SHIM_STATE_ROOT", self.dir.path().join("state"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Waits for `count` events and returns them.
    fn events(&self, count: usize) -> Vec<String> {
        self.events.wait_for(count)
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

/// `backend`'s shim command, with the flags that containerd always passes.
fn shim_command(backend: Backend) -> Command {
    let mut command = Command::new(backend.shim());
    let address = "/run/containerd/containerd.sock";
    command.args(["-namespace", NAMESPACE, "-id", "c", "-address", address]);
    command
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
/// its runners; or the guardian, vhost-device-vsock and QEMU.
fn group_members(pid: u32) -> impl Fn() -> usize {
    let group = stat_fields(pid).unwrap()[2].parse().unwrap();
    move || processes_with(2, group).len()
}

fn a_container_runs_and_reports_its_exit(backend: Backend) {
    let mut init = process(&["sh", "exit", "3"]);
    init["cwd"] = "/bin/../new".into();
    init["env"] = serde_json::json!(["PATH=/first:/bin"]);
    let mut shim = Shim::launch(backend, &init);
    // The guest user owns it, and may not execute it: the search goes on.
    let first = shim.bundle.join("rootfs/first");
    std::fs::create_dir(&first).unwrap();
    std::fs::write(first.join("sh"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(first.join("sh"), std::fs::Permissions::from_mode(0o641)).unwrap();
    // Cloud Hypervisor's has no network yet.
    if backend != Backend::CloudHypervisor {
        shim.configure(|spec| {
            spec["annotations"] = serde_json::json!({"io.litebox.egress.tcp": "10.1.0.0/16:80-81"});
        });
    }
    let pid = shim.create().unwrap();
    // The init's pid is the broker's, which allows the annotation's egress; or QEMU's, whose
    // payload does.
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap();
    match backend {
        Backend::Userland => {
            assert!(cmdline.contains("litebox-broker-userland"), "{cmdline}");
            assert!(
                cmdline.contains("--allow-tcp-destination\u{0}10.1.0.0/16:80-81\u{0}"),
                "{cmdline}"
            );
        }
        Backend::CloudHypervisor => {
            assert!(cmdline.contains("cloud-hypervisor"), "{cmdline}");
        }
        Backend::Vm => {
            assert!(cmdline.contains("qemu-system-x86_64"), "{cmdline}");
            assert!(cmdline.contains("virtio-net-pci"), "{cmdline}");
            let payload = shim.state_dir().join("payload.tar");
            let policy = Command::new("tar")
                .arg("-xOf")
                .arg(payload)
                .arg("policy")
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&policy.stdout),
                "egress tcp 10.1.0.0/16:80-81\n"
            );
        }
    }
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
fn a_published_port_reaches_a_guest_server() {
    // Below every host's ephemeral range, so no other test's ephemeral bind takes it meanwhile.
    let host = "127.0.0.1:20880";
    let mut shim = Shim::launch(Backend::Userland, &process(&["guest", "serve"]));
    let annotations = serde_json::json!({
        "io.litebox.publish.tcp": format!("{host}:80"),
        "io.litebox.ingress.tcp": "10.0.2.1/32", // The client, as the guest sees it.
    });
    shim.configure(|spec| spec["annotations"] = annotations);
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    shim.wait_output("c.out", "listening\n");
    let stream = std::net::TcpStream::connect(host).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    assert_eq!(std::io::read_to_string(stream).unwrap(), "hello");
    assert_eq!(shim.wait(""), 0);
    shim.finish(pid);
}

fn execs_take_input_and_their_output_comes_before_their_exit(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
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

fn a_reader_of_the_output_may_start_after_the_exit(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
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

fn an_exec_s_output_ends_once_idle_or_at_its_delete(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
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

fn an_exec_s_delete_closes_its_unread_output(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
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

fn a_terminal_init_takes_a_resize_before_start(backend: Backend) {
    let mut init = process(&["guest", "signals"]);
    init["terminal"] = true.into();
    let mut shim = Shim::launch(backend, &init);
    let pid = shim.create_with("", true).unwrap();
    shim.resize("", 123, 45);
    shim.start("").unwrap();
    shim.wait_output("c.out", "tty=111 foreground=1 size=45x123\r\n");
    shim.kill_and_finish(pid);
}

fn terminals_take_input_resizes_and_interrupts(backend: Backend) {
    let mut init = process(&["guest", "signals"]);
    init["terminal"] = true.into();
    init["consoleSize"] = serde_json::json!({"height": 24, "width": 80});
    let mut shim = Shim::launch(backend, &init);
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

fn a_terminal_whose_input_ends_before_start_starts(backend: Backend) {
    let mut init = process(&["guest", "exit", "4"]);
    init["terminal"] = true.into();
    let mut shim = Shim::launch(backend, &init);
    let pid = shim.create_with(&shim.mkfifo("c.in"), true).unwrap();
    // Past the shim's `CloseStdin`, which the guest service refuses until the init starts.
    shim.close_stdin("");
    std::thread::sleep(Duration::from_millis(500));
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 4);
    assert!(shim.output("c.out").contains("argv[0]=[guest]"));
    shim.finish(pid);
}

fn kills_reach_their_process(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "signals"]));
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

/// `Create` with the root file system mounts `(type, source, options)`.
fn create_mounted(shim: &Shim, mounts: &[(&str, &Path, &str)]) -> ttrpc::Result<u32> {
    let mounts = mounts.iter().map(|(type_, source, options)| Mount {
        type_: (*type_).to_owned(),
        source: source.to_str().unwrap().to_owned(),
        options: options.split(',').map(str::to_owned).collect(),
        ..Default::default()
    });
    shim.create_by(|request| request.rootfs = mounts.collect())
}

/// Whether anything is mounted at or below `path`, by the canonical, octal-escaped (`\040`) mount
/// points of `/proc/self/mountinfo`.
fn mounted_below(path: &Path) -> bool {
    let path = path.canonicalize().unwrap();
    let mounts = std::fs::read("/proc/self/mountinfo").unwrap();
    mounts.split(|&byte| byte == b'\n').any(|line| {
        let Some(mut point) = line.split(|&byte| byte == b' ').nth(4) else {
            return false;
        };
        let mut decoded = Vec::new();
        while let Some((&byte, rest)) = point.split_first() {
            let octal = rest
                .get(..3)
                .and_then(|digits| u8::from_str_radix(std::str::from_utf8(digits).ok()?, 8).ok());
            let (byte, skipped) = match octal {
                Some(code) if byte == b'\\' => (code, 3),
                _ => (byte, 0),
            };
            decoded.push(byte);
            point = &rest[skipped..];
        }
        Path::new(OsStr::from_bytes(&decoded)).starts_with(&path)
    })
}

/// Whether this process may mount: a bind mount of a scratch directory onto itself, undone.
fn can_mount() -> bool {
    let dir = tempfile::tempdir().unwrap();
    let bound = rustix::mount::mount_bind(dir.path(), dir.path()).is_ok();
    if bound {
        rustix::mount::unmount(dir.path(), rustix::mount::UnmountFlags::DETACH).unwrap();
    }
    bound
}

fn without_mount_privilege_root_file_system_mounts_fail_create(backend: Backend) {
    if can_mount() {
        eprintln!("skipped: runs without mount privilege only");
        return;
    }
    let shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
    let started = Instant::now();
    let rootfs = shim.bundle.join("rootfs");
    let failed = create_mounted(&shim, &[("bind", &rootfs, "rbind")]);
    let ttrpc::Error::RpcStatus(status) = failed.unwrap_err() else {
        unreachable!()
    };
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(status.code(), Code::INTERNAL);
    assert!(status.message.contains("EPERM"), "{status:?}");
    assert!(!shim.state_dir().exists());
}

fn with_mount_privilege_bind_and_overlay_mounts_are_read_then_unmounted(backend: Backend) {
    let args = ["guest", "read", "/bin/sh", "/etc/upper", "/etc/hidden"];
    for round in ["failed", "bind", "overlay"] {
        let overlay = round == "overlay";
        let mut shim = Shim::launch(backend, &process(&args));
        // containerd's snapshot, outside the bundle, whose `rootfs` the shim creates.
        let dir = shim.dir.path().to_owned();
        let (lower, upper, work) = (dir.join("lower"), dir.join("upper"), dir.join("work"));
        std::fs::rename(shim.bundle.join("rootfs"), &lower).unwrap();
        if round == "failed" {
            // The second mount fails once the first one is made.
            let mounts = [
                ("bind", &*lower, "rbind"),
                ("bind", &dir.join("none"), "rbind"),
            ];
            let ttrpc::Error::RpcStatus(status) = create_mounted(&shim, &mounts).unwrap_err()
            else {
                unreachable!()
            };
            assert!(status.message.contains("none: "), "{status:?}");
            assert!(!mounted_below(&dir) && !shim.state_dir().exists());
            continue;
        }
        let created = if overlay {
            std::fs::create_dir_all(upper.join("etc")).unwrap();
            std::fs::create_dir(&work).unwrap();
            std::fs::write(upper.join("etc/upper"), "upper\n").unwrap();
            // A whiteout: the upper layer hides the lower one's file.
            let whiteout = rustix::fs::mknodat(
                rustix::fs::CWD,
                upper.join("etc/hidden"),
                rustix::fs::FileType::CharacterDevice,
                rustix::fs::Mode::empty(),
                0,
            );
            match whiteout {
                Ok(()) => std::fs::write(lower.join("etc/hidden"), "hidden\n").unwrap(),
                Err(_) => eprintln!("no whiteout: mknod of 0:0 is refused here"),
            }
            let (work, upper, lower) = (work.display(), upper.display(), lower.display());
            let options = format!("index=off,workdir={work},upperdir={upper},lowerdir={lower}");
            create_mounted(&shim, &[("overlay", Path::new("overlay"), &options)])
        } else {
            std::fs::write(lower.join("etc/upper"), "upper\n").unwrap();
            // Named through a symlink, which unmounting must resolve.
            std::os::unix::fs::symlink(&shim.bundle, dir.join("link")).unwrap();
            shim.bundle = dir.join("link");
            create_mounted(&shim, &[("bind", &lower, "rbind,rw")])
        };
        let pid = created.unwrap();
        assert!(!mounted_below(&shim.bundle), "{round}");
        shim.start("").unwrap();
        // The lower layer's guest and link, the upper layer's file, no hidden file (82).
        assert_eq!(shim.wait(""), 82);
        let output = shim.output("c.out");
        assert!(output.ends_with("link=/bin/guest\nupper\n"), "{output}");
        if overlay {
            shim.finish(pid);
        } else {
            let members = group_members(pid);
            shim.daemon.kill().unwrap();
            shim.daemon.wait().unwrap();
            wait_until("the broker's group outlived the daemon", || members() == 0);
            // A dead daemon's orphaned mounter holds the bundle's lock, and mounts while the
            // `delete` action's cleaner waits for it.
            let lock = File::open(&shim.bundle).unwrap();
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
            let bundle = shim.bundle.canonicalize().unwrap();
            let deleted = shim.delete_action_while(|delete| {
                let waits = || {
                    processes_with(1, delete).into_iter().any(|cleaner| {
                        let fds = std::fs::read_dir(format!("/proc/{cleaner}/fd")).into_iter();
                        let mut fds = fds.flatten().flatten();
                        fds.any(|fd| std::fs::read_link(fd.path()).is_ok_and(|open| open == bundle))
                    })
                };
                wait_until(
                    "the delete action's cleaner did not lock the bundle",
                    || waits() || is_gone(delete),
                );
                rustix::mount::mount_bind(&lower, bundle.join("rootfs")).unwrap();
                drop(lock);
            });
            assert_eq!(deleted, 137);
        }
        assert!(!mounted_below(&dir));
    }
}

#[test]
#[ignore = "needs root and users other than root; CI runs it under `unshare --map-auto -rm`"]
fn with_litebox_user_the_guardian_broker_and_runners_run_as_that_user() {
    // With `LITEBOX_ROOT_BROKER=1`, the guardian and the broker stay root, and only they can read
    // below a 0700 directory of root's.
    for root_broker in ["0", "1"] {
        let env = [
            ("LITEBOX_USER", "4242:4243"),
            ("LITEBOX_ROOT_BROKER", root_broker),
        ];
        // The strictest umask: what the user reads must not depend on it.
        let mut shim = Shim::launch_as(
            Backend::Userland,
            &process(&["guest", "family"]),
            &env,
            0o077,
        );
        // The user traverses it to the broker and the state root.
        std::fs::set_permissions(shim.dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
        let private = shim.path("private");
        std::fs::create_dir(&private).unwrap();
        let mode = if root_broker == "1" { 0o700 } else { 0o755 };
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(mode)).unwrap();
        let data = shim.path("private/data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(shim.path("private/data/in"), "in\n").unwrap();
        shim.configure(|spec| {
            spec["mounts"] = serde_json::json!([{"destination": "/data", "type": "bind", "source": data, "options": ["ro"]}]);
        });
        let broker = shim.create().unwrap();
        shim.start("").unwrap();
        shim.wait_output("c.out", "child\n");
        // The daemon's umask is 0: the bridge must still be the broker's user's only.
        let sockets = std::fs::read_dir(shim.path("state/.vsock")).unwrap();
        let bridge = sockets.map(|dir| dir.unwrap().path().join("vsock")).next();
        assert_eq!(bridge.unwrap().metadata().unwrap().mode() & 0o077, 0);
        let guardian = stat_fields(broker).unwrap()[1].parse().unwrap();
        // The guest service's, the init's and its child's.
        let runners = processes_with(1, broker);
        assert!(runners.len() >= 3, "{runners:?}");
        for pid in [guardian, broker].into_iter().chain(runners) {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
            let ids: Vec<_> = status
                .lines()
                .filter(|line| {
                    ["Uid:", "Gid:", "Groups:"]
                        .iter()
                        .any(|name| line.starts_with(name))
                })
                .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect();
            if root_broker == "1" && [guardian, broker].contains(&pid) {
                assert_eq!(ids[..2], ["Uid: 0 0 0 0", "Gid: 0 0 0 0"], "{pid}");
                continue;
            }
            let expected = [
                "Uid: 4242 4242 4242 4242",
                "Gid: 4243 4243 4243 4243",
                "Groups:",
            ];
            assert_eq!(ids, expected, "{pid}");
        }
        let (status, output) = shim.run("e1", &["guest", "read", "/bin/sh", "/data/in"]);
        assert_eq!(status, 0, "{output}");
        assert!(output.ends_with("link=/bin/guest\nin\n"), "{output}");
        shim.kill_and_finish(broker);
    }
}

/// The VMM, here the daemon's user's, opens the payload in the state directory by path: an earlier
/// container's broker user, who may own the directory, loses it.
fn as_root_a_vm_takes_back_a_state_directory_another_user_owns(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
    let state = shim.state_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&state)
        .unwrap();
    std::os::unix::fs::chown(&state, Some(4242), Some(4243)).unwrap();
    let vmm = shim.create().unwrap();
    let daemon = std::fs::metadata(shim.dir.path()).unwrap().uid();
    let metadata = std::fs::metadata(&state).unwrap();
    assert_eq!((metadata.uid(), metadata.mode() & 0o7777), (daemon, 0o700));
    shim.start("").unwrap();
    assert_eq!(shim.wait(""), 0);
    shim.finish(vmm);
}

/// The VM's guardian, device daemon, if any, and VMM have `/dev/kvm`'s group as their only
/// supplementary group, unless it is root's or the overflow group (one the user namespace does not
/// map).
fn with_litebox_user_the_vm_runs_as_that_user(backend: Backend) {
    let env = [("LITEBOX_USER", "4242:4243"), ("LITEBOX_ROOT_BROKER", "1")];
    // The strictest umask: what the user reads must not depend on it.
    let mut shim = Shim::launch_as(backend, &process(&["guest", "family"]), &env, 0o077);
    // The user traverses it to the VM's programs and the state root.
    std::fs::set_permissions(shim.dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
    let vmm = shim.create().unwrap();
    // The state directory, with the payload, is the daemon's: the user only traverses it.
    let daemon = std::fs::metadata(shim.dir.path()).unwrap().uid();
    let state = std::fs::metadata(shim.state_dir()).unwrap();
    assert_eq!(
        (state.uid(), state.gid(), state.mode() & 0o7777),
        (daemon, 4243, 0o710)
    );
    shim.start("").unwrap();
    shim.wait_output("c.out", "child\n");
    let guardian = stat_fields(vmm).unwrap()[1].parse().unwrap();
    // The device daemon and QEMU, or Cloud Hypervisor.
    let children = processes_with(1, guardian);
    let expected = if backend == Backend::Vm { 2 } else { 1 };
    assert_eq!(children.len(), expected, "{children:?}");
    // `/dev/kvm`'s group, unless there is none (TCG), or it is root's or the overflow group.
    let overflow: u32 = std::fs::read_to_string("/proc/sys/kernel/overflowgid")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let expected: Vec<String> = std::fs::metadata("/dev/kvm")
        .ok()
        .map(|kvm| kvm.gid())
        .filter(|kvm| ![0, overflow].contains(kvm))
        .map(|kvm| kvm.to_string())
        .into_iter()
        .collect();
    for pid in [guardian].into_iter().chain(children) {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let line = |name| status.lines().find(|line| line.starts_with(name)).unwrap();
        let ids = |name| line(name).split_whitespace().skip(1).collect::<Vec<_>>();
        assert_eq!(ids("Uid:"), ["4242"; 4], "{pid}");
        assert_eq!(ids("Gid:"), ["4243"; 4], "{pid}");
        assert_eq!(ids("Groups:"), expected, "{pid}");
    }
    shim.kill_and_finish(vmm);
}

fn as_root_the_broker_joins_or_creates_the_container_s_network_namespace(backend: Backend) {
    let namespace = |pid: &dyn std::fmt::Display| {
        let path = format!("/proc/{pid}/ns/net");
        std::fs::metadata(path).unwrap().ino()
    };
    // Joined: one held by a child, killed alone before anything can panic.
    let mut holder = Command::new("unshare")
        .args(["--net", "sleep", "60"])
        .spawn()
        .unwrap();
    wait_until("the child did not unshare", || {
        namespace(&holder.id()) != namespace(&"self")
    });
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
    let path = format!("/proc/{}/ns/net", holder.id());
    shim.configure(|spec| {
        spec["linux"] = serde_json::json!({"namespaces": [{"type": "network", "path": path}]});
    });
    let broker = shim.create();
    let joined = broker.as_ref().map(|broker| namespace(broker));
    let held = namespace(&holder.id());
    holder.kill().unwrap();
    holder.wait().unwrap();
    assert_eq!(joined.unwrap(), held);
    shim.finish(broker.unwrap());
    // New: its loopback up, and the guest runs.
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
    shim.configure(|spec| {
        spec["linux"] = serde_json::json!({"namespaces": [{"type": "network"}]});
    });
    let broker = shim.create().unwrap();
    assert_ne!(namespace(&broker), namespace(&"self"));
    let lo = Command::new("nsenter")
        .arg(format!("--net=/proc/{broker}/ns/net"))
        .args(["ip", "-o", "link", "show", "lo"])
        .output()
        .unwrap();
    let lo = String::from_utf8_lossy(&lo.stdout);
    assert!(lo.contains(",UP"), "{lo}");
    shim.start("").unwrap();
    shim.wait_output("c.out", "child\n");
    shim.kill_and_finish(broker);
}

fn a_created_container_is_deleted_with_its_broker(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
    let pid = shim.create().unwrap();
    let image = match backend {
        Backend::Userland => "rootfs.tar",
        Backend::Vm | Backend::CloudHypervisor => "payload.tar",
    };
    assert!(shim.state_dir().join(image).exists());
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

fn the_broker_group_dies_with_the_daemon(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
    shim.record_poststop();
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    shim.wait_output("c.out", "child\n");
    let members = group_members(pid);
    // The guardian, the broker and its runners; the guardian, vhost-device-vsock and QEMU; or the
    // guardian and Cloud Hypervisor.
    let expected = match backend {
        Backend::Userland => 4..usize::MAX,
        Backend::Vm => 3..4,
        Backend::CloudHypervisor => 2..3,
    };
    assert!(expected.contains(&members()), "{}", members());
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

fn hooks_run_on_the_host_with_the_state(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
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

fn a_logging_program_gets_the_output(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
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

fn the_delete_action_finishes_a_delete_cut_short(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
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
        request.stdout.clone_from(&uri);
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

/// containerd kills the `delete` action after 5 s, and runs it again only once it reloads.
fn a_cleanup_that_outlasts_the_delete_action_goes_on(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
    let hook = script(&shim, "hook", "sleep 6\ncat > \"$1\"\n");
    let state = shim.path("poststop");
    shim.configure(|spec| {
        spec["hooks"] = serde_json::json!({"poststop": [{"path": hook, "args": ["hook", state]}]});
    });
    shim.create().unwrap();
    shim.daemon.kill().unwrap();
    shim.daemon.wait().unwrap();
    let started = Instant::now();
    let output = shim.delete_action_command().output().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5), "{output:?}");
    // Failed, so that containerd keeps the bundle.
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("the cleanup goes on"),
        "{output:?}"
    );
    wait_until("the poststop hook did not run", || {
        std::fs::read_to_string(&state)
            .is_ok_and(|state| serde_json::from_str::<serde_json::Value>(&state).is_ok())
    });
    assert!(!shim.state_dir().exists());
    assert_eq!(shim.delete_action(), 137);
}

fn a_broker_that_dies_before_start_stops_the_init(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
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

fn a_dead_vsock_device_stops_the_broker() {
    let mut shim = Shim::launch(Backend::Vm, &process(&["guest", "exit", "0"]));
    shim.record_poststop();
    let pid = shim.create().unwrap();
    let members = group_members(pid);
    let group = stat_fields(pid).unwrap()[2].parse().unwrap();
    // Its command name, truncated.
    let device = processes_with(2, group)
        .into_iter()
        .find(|&member| {
            std::fs::read_to_string(format!("/proc/{member}/comm"))
                .is_ok_and(|comm| comm == "vhost-device-vs\n")
        })
        .expect("the guardian's vhost-device-vsock");
    let device = rustix::process::Pid::from_raw(device.try_into().unwrap()).unwrap();
    rustix::process::kill_process(device, rustix::process::Signal::KILL).unwrap();
    wait_until("the init did not stop", || {
        shim.state("") == (Status::STOPPED, 255)
    });
    wait_until("the broker's group outlived its vsock device", || {
        members() == 0
    });
    assert_eq!(shim.wait(""), 255);
    shim.finish(pid);
    let state: serde_json::Value = serde_json::from_str(&shim.output("poststop")).unwrap();
    assert_eq!(state["status"], "stopped");
}

/// A VM whose vsock device starts after the shim's 30 s for the guest service to listen, here as
/// QEMU starts late, still starts: its boot has no deadline.
fn a_vm_that_boots_late_starts() {
    let wrapper = tempfile::tempdir().unwrap();
    let qemu = wrapper.path().join("qemu");
    std::fs::write(
        &qemu,
        "#!/bin/sh\nsleep 35\nexec qemu-system-x86_64 \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&qemu, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = [("LITEBOX_QEMU", qemu.to_str().unwrap())];
    let mut shim = Shim::launch_as(Backend::Vm, &process(&["guest", "exit", "0"]), &env, 0);
    let created = Instant::now();
    let pid = shim.create().unwrap();
    assert!(created.elapsed() > Duration::from_secs(35));
    assert_eq!(shim.start("").unwrap(), pid);
    assert_eq!(shim.wait(""), 0);
    shim.finish(pid);
}

fn a_broker_that_dies_stops_created_execs_and_refuses_more(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    // An exec whose unread output fills its FIFO: its exit, and so the init's, waits 5 s for it.
    let fifo = shim.start_to_fifo("e0", &["guest", "lines", "50000"]);
    let flags = rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK;
    let probe = rustix::fs::open(&fifo, flags, rustix::fs::Mode::empty()).unwrap();
    // Full once no page of its buffer is free, and the shim's writes wait (smaller ones, merged
    // into the last page, may still fit).
    wait_until("e0's FIFO did not fill", || {
        let mut fds = [rustix::event::PollFd::new(
            &probe,
            rustix::event::PollFlags::OUT,
        )];
        let now = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        rustix::event::poll(&mut fds, Some(&now)) == Ok(0)
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

// Userland only: the VM's guest service, its init, ends only with the VM.
#[test]
fn a_dead_guest_service_stops_the_broker() {
    let mut shim = Shim::launch(Backend::Userland, &process(&["guest", "family"]));
    let pid = shim.create().unwrap();
    let members = group_members(pid);
    let [service] = processes_with(1, pid)[..] else {
        panic!("the broker has runners other than the guest service's")
    };
    shim.start("").unwrap();
    shim.wait_output("c.out", "child\n");
    let service = rustix::process::Pid::from_raw(service.try_into().unwrap()).unwrap();
    rustix::process::kill_process(service, rustix::process::Signal::KILL).unwrap();
    assert_eq!(shim.wait(""), 255);
    assert_eq!(members(), 0);
    shim.finish(pid);
}

fn the_container_cannot_kill_the_guest_service(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "kill-service"]));
    let pid = shim.create().unwrap();
    shim.start("").unwrap();
    shim.wait_output("c.out", "sent 1\n");
    assert_eq!(shim.run("e1", &["guest", "exit", "5"]).0, 5);
    shim.kill_and_finish(pid);
}

/// Stops the guest service of the broker `pid`, then checks that `Start` of `exec_id` fails after
/// the shim's 30 s.
fn start_unanswered(shim: &Shim, pid: u32, exec_id: &str) {
    let stopped = match shim.backend {
        Backend::Userland => processes_with(1, pid),
        Backend::Vm | Backend::CloudHypervisor => vec![pid],
    };
    assert_ne!(stopped.len(), 0, "the broker has no runners");
    for process in stopped {
        let process = rustix::process::Pid::from_raw(process.try_into().unwrap()).unwrap();
        rustix::process::kill_process(process, rustix::process::Signal::STOP).unwrap();
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

fn a_guest_service_that_does_not_answer_is_taken_for_dead(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
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

fn a_guest_service_that_does_not_answer_an_exec_is_taken_for_dead(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
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

fn binds_copy_files_and_serve_directories(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "family"]));
    let (hosts, resolv) = (shim.path("hosts"), shim.path("resolv"));
    std::fs::write(&hosts, "hosts\n").unwrap();
    std::fs::write(&resolv, "nameserver 127.0.0.53\nnameserver 192.0.2.1\n").unwrap();
    let read_only = shim.path("read-only");
    std::fs::create_dir(&read_only).unwrap();
    std::fs::write(shim.path("read-only/in"), "read-only\n").unwrap();
    std::os::unix::fs::symlink("in", shim.path("read-only/link")).unwrap();
    std::fs::create_dir(shim.path("read-only/child")).unwrap();
    std::fs::write(shim.path("read-only/marker"), "parent\n").unwrap();
    std::fs::write(shim.path("read-only/child/marker"), "child\n").unwrap();
    // Without mounts, the spec's root, here outside the bundle, is the image; `rootfs` is unused.
    let image = shim.path("image");
    std::fs::rename(shim.bundle.join("rootfs"), &image).unwrap();
    shim.configure(|spec| {
        spec["root"]["path"] = image.into();
        spec["mounts"].as_array_mut().unwrap().extend([
            serde_json::json!({"destination": "/etc/hosts", "type": "bind", "source": hosts, "options": ["rbind", "ro"]}),
            serde_json::json!({"destination": "/etc/resolv.conf", "type": "bind", "source": resolv}),
            // Beneath `/bin -> usr/bin`: served at `/usr/bin/ro`.
            serde_json::json!({"destination": "/bin/ro", "type": "bind", "source": read_only, "options": ["rbind", "ro"]}),
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
            "/bin/ro/in",
            "/usr/bin/ro/in",
        ],
    );
    assert_eq!(status, 0, "{output}");
    let expected = "link=/bin/guest\nhosts\nnameserver 192.0.2.1\n\
                    # Added by the LiteBox shim: IPv4 only, for glibc.\noptions no-aaaa\n\
                    read-only\nread-only\n";
    assert!(output.ends_with(expected), "{output}");
    // A symlink in a directory bind, read and followed.
    let (status, output) = shim.run("e2", &["guest", "read", "/bin/ro/link", "/bin/ro/link"]);
    assert_eq!(status, 0, "{output}");
    assert!(output.ends_with("link=in\nread-only\n"), "{output}");
    // Relative to a directory in the bind: its parent's file, its own, and out of the bind and back.
    for (exec_id, dir, path, expected) in [
        ("e5", "/bin/ro/child", "../marker", "parent\n"),
        ("e6", "/bin/ro/child", "marker", "child\n"),
        ("e7", "/bin/ro", "../ro/in", "read-only\n"),
    ] {
        let (status, output) = shim.run(exec_id, &["guest", "readat", dir, path]);
        assert_eq!(status, 0, "{output}");
        assert!(output.ends_with(expected), "{dir} {path}: {output}");
    }
    // A read-only directory bind refuses changes, of its files and of its entries.
    for (exec_id, path) in [("e3", "/bin/ro/in"), ("e4", "/usr/bin/ro/out")] {
        let (status, output) = shim.run(exec_id, &["guest", "write", path, "from the guest"]);
        assert_eq!(status, 51, "{output}");
        assert!(
            output.ends_with("write: Read-only file system\n"),
            "{output}"
        );
    }
    let entries: Vec<_> = std::fs::read_dir(&read_only).unwrap().collect();
    assert_eq!(entries.len(), 4);
    assert_eq!(shim.output("read-only/in"), "read-only\n");
    shim.kill_and_finish(pid);
}

fn a_container_with_a_small_memory_limit_runs(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "3"]));
    // The VM takes the limit besides its own memory.
    shim.configure(|spec| {
        spec["linux"]["resources"] = serde_json::json!({"memory": {"limit": 16 << 20}});
    });
    let pid = shim.create().unwrap();
    assert_eq!(shim.start("").unwrap(), pid);
    assert_eq!(shim.wait(""), 3);
    shim.finish(pid);
}

/// QEMU's `-smp` is the CPU quota's, at most the host's CPUs, and it takes KVM, falling back to TCG.
fn qemu_takes_the_cpu_quota_and_prefers_kvm() {
    let mut shim = Shim::launch(Backend::Vm, &process(&["guest", "exit", "0"]));
    shim.configure(|spec| {
        spec["linux"]["resources"] =
            serde_json::json!({"cpu": {"quota": 200_000, "period": 100_000}});
    });
    let qemu = shim.create().unwrap();
    let command_line = std::fs::read(format!("/proc/{qemu}/cmdline")).unwrap();
    let args: Vec<&[u8]> = command_line.split(|byte| *byte == 0).collect();
    let option = |name: &[u8]| {
        args.iter()
            .position(|arg| *arg == name)
            .map(|index| String::from_utf8_lossy(args[index + 1]))
    };
    let host = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    assert_eq!(option(b"-smp").as_deref(), Some(&*2.min(host).to_string()));
    let accel: &[&[u8]] = &[b"-accel", b"kvm", b"-accel", b"tcg"];
    assert!(args.windows(4).any(|window| window == accel), "{args:?}");
    // Without egress rules, no network device.
    assert_eq!(option(b"-netdev"), None, "{args:?}");
    assert_eq!(shim.start("").unwrap(), qemu);
    assert_eq!(shim.wait(""), 0);
    shim.finish(qemu);
}

fn refused_or_unsupported_specs_and_annotations_fail_create(backend: Backend) {
    let mut shim = Shim::launch(backend, &process(&["guest", "exit", "0"]));
    let config = std::fs::read(shim.bundle.join("config.json")).unwrap();
    let data = shim.path("data");
    std::fs::create_dir(&data).unwrap();
    let fifo = shim.path("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let mut cases: Vec<(&str, serde_json::Value, Code)> = vec![
        (
            "hooks",
            serde_json::json!({"createContainer": [{"path": "/bin/true"}]}),
            Code::UNIMPLEMENTED,
        ),
        // A network namespace path that is no namespace, and blocks an open: a FIFO.
        (
            "linux",
            serde_json::json!({"namespaces": [{"type": "network", "path": fifo}]}),
            Code::INTERNAL,
        ),
        // Not supported yet: mounts of other types, binds nested in a directory bind, writable
        // directory binds.
        (
            "mounts",
            serde_json::json!([{"destination": "/mnt", "type": "nfs", "source": "x"}]),
            Code::UNIMPLEMENTED,
        ),
        (
            "mounts",
            serde_json::json!([
                {"destination": "/d/child", "type": "bind", "source": data, "options": ["ro"]},
                {"destination": "/d", "type": "bind", "source": data, "options": ["ro"]},
            ]),
            Code::UNIMPLEMENTED,
        ),
        (
            "mounts",
            serde_json::json!([{"destination": "/d", "type": "bind", "source": data}]),
            Code::UNIMPLEMENTED,
        ),
        (
            "annotations",
            serde_json::json!({"io.litebox.egress.udp": "10.0.0.1/8:53"}),
            Code::INVALID_ARGUMENT,
        ),
    ];
    if backend == Backend::CloudHypervisor {
        // It has no network yet; and a comma separates its options.
        let bind = serde_json::json!({"destination": "/a,b", "type": "bind", "source": data, "options": ["ro"]});
        cases.push((
            "annotations",
            serde_json::json!({"io.litebox.egress.tcp": "10.1.0.0/16:80"}),
            Code::UNIMPLEMENTED,
        ));
        cases.push(("mounts", serde_json::json!([bind]), Code::UNIMPLEMENTED));
    }
    if backend != Backend::Userland {
        // The VM publishes no ports yet.
        cases.push((
            "annotations",
            serde_json::json!({"io.litebox.publish.tcp": "127.0.0.1:20881:80"}),
            Code::UNIMPLEMENTED,
        ));
        // One directory bind at most, at a guest path of at most 36 bytes, its virtio-fs tag.
        let bind = |destination: &str| serde_json::json!({"destination": destination, "type": "bind", "source": data, "options": ["ro"]});
        cases.push((
            "mounts",
            serde_json::json!([bind("/first"), bind("/second")]),
            Code::UNIMPLEMENTED,
        ));
        cases.push((
            "mounts",
            serde_json::json!([bind("/a/directory/bind/beyond/thirty-six/bytes")]),
            Code::UNIMPLEMENTED,
        ));
    }
    for (field, value, expected) in cases {
        shim.configure(|spec| spec[field] = value.clone());
        let failed = code(&shim.create().unwrap_err());
        assert_eq!(failed, expected, "{field}: {value}");
        std::fs::write(shim.bundle.join("config.json"), &config).unwrap();
    }
    // Not supported, as in Kata Containers: checkpoints.
    let refused = shim
        .create_by(|request| request.checkpoint = shim.path("checkpoint"))
        .unwrap_err();
    assert_eq!(code(&refused), Code::UNIMPLEMENTED);
    assert!(!shim.state_dir().exists());
    // A missing broker, or VM kernel, fails at once.
    let link = shim.path(backend.broker_program());
    let program = std::fs::read_link(&link).unwrap();
    std::fs::remove_file(&link).unwrap();
    assert_eq!(code(&shim.create().unwrap_err()), Code::INTERNAL);
    assert!(!shim.state_dir().exists());
    std::os::unix::fs::symlink(program, &link).unwrap();
    // A live daemon of an earlier container with this ID keeps its state locked, and the state.
    let earlier = shim.state_dir();
    std::fs::create_dir(&earlier).unwrap();
    std::fs::write(earlier.join("mark"), "").unwrap();
    let lock = File::open(&earlier).unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
    assert_eq!(code(&shim.create().unwrap_err()), Code::FAILED_PRECONDITION);
    assert!(earlier.join("mark").exists());
    drop(lock);
    // Other namespaces' paths are ignored; an init that cannot start ends the container.
    shim.configure(|spec| {
        spec["process"]["args"] = serde_json::json!(["/no/such/program"]);
        spec["linux"] =
            serde_json::json!({"namespaces": [{"type": "pid", "path": "/proc/1/ns/pid"}]});
    });
    let pid = shim.create().unwrap();
    let members = group_members(pid);
    assert_eq!(code(&shim.start("").unwrap_err()), Code::INVALID_ARGUMENT);
    assert_eq!(shim.wait(""), 127);
    assert_eq!(members(), 0);
    shim.finish(pid);
}
