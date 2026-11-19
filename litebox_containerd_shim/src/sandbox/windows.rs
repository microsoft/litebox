// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows broker lifecycle and state. As runhcs does, the shim creates a process-isolated
//! container through the Host Compute Service: a server silo on the host's kernel, whose `C:` is
//! its image's layers (such as Nano Server's) and in which the HCS starts the system processes
//! (smss, lsass, CExecSvc, ...) that its programs need. The shim then starts the broker in it, as
//! `ContainerUser`, and maps into it, read-only, the broker and the runner, the state directory
//! (the root archive) and the binds, and, writable, the bridge's directory. The container has no
//! network yet.

mod bridge;
mod hcs;
mod layers;
mod logger;
mod security;

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use windows_sys::Win32::Foundation::{ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GETFINALPATHNAMEBYHANDLE_FLAGS,
    GetFileInformationByHandle, GetFinalPathNameByHandleW, VOLUME_NAME_DOS, VOLUME_NAME_GUID,
};
use windows_sys::core::HRESULT;

pub(crate) use self::bridge::{client, connect_bridge};
pub(crate) use self::layers::folders as layer_folders;
pub(crate) use self::logger::init_log;
pub(crate) use self::security::private_root;
use super::{
    Broker, Ended, STOP_TIMEOUT, StateDir, broker_arguments, broker_program, log_lines, program,
    stable_name,
};
use crate::spec::{Bind, Network, Plan};
use crate::{Backend, Result, internal};

const RUNNER: &str = "litebox_runner_linux_on_windows_userland.exe";
const LOCK_ACCESS: u32 = FILE_ADD_FILE;
/// Canonical `SOCKADDR_UN` path budget after the NUL and `_4294967295` port suffix.
const MAX_BRIDGE_PATH: usize = 96;
/// The owner that `hcsdiag list` shows.
const OWNER: &str = "containerd-shim-litebox-v1";
const CONTAINER_USER: &str = "ContainerUser";
/// `ContainerUser` as the host's ACLs name it: the same SID in every container.
const CONTAINER_USER_SID: &str = "S-1-5-93-2-2";
const READ: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
const BIN_DIR: &str = r"C:\litebox\bin";
const RUNNER_DIR: &str = r"C:\litebox\runner";
const STATE_DIR: &str = r"C:\litebox\state";
const RUN_DIR: &str = r"C:\litebox\run";
const BINDS_DIR: &str = r"C:\litebox\binds";

/// The broker runs as the container's `ContainerUser`, whom [`grant_access`] admits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Deprivileged {
    #[default]
    ContainerUser,
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the platforms' contract: Linux's can fail"
)]
pub fn deprivileged() -> Result<Deprivileged> {
    Ok(Deprivileged::ContainerUser)
}

pub fn grant_access(state: &StateDir, _: Backend) -> io::Result<()> {
    // Not inherited: the broker reads only what [`grant_read`] grants there.
    let ace = format!("(A;;{READ:#x};;;{CONTAINER_USER_SID})");
    security::share_with(&state.path, &ace)?;
    // Without `FILE_DELETE_CHILD`: the broker deletes only what it created.
    let modify = READ | FILE_GENERIC_WRITE | DELETE;
    let ace = format!("(A;OICI;{modify:#x};;;{CONTAINER_USER_SID})");
    security::share_with(&state.sockets, &ace)
}

pub fn run_private_mode(_: &[OsString]) {}

/// Not below the state root, whose path may be long: the broker's sockets must fit in
/// [`MAX_BRIDGE_PATH`].
pub fn socket_root(_: &Path) -> PathBuf {
    base_dir().join("lbx-shim")
}

pub fn socket_dir(root: &Path, namespace: &str, id: &str) -> PathBuf {
    let root_name = root.to_string_lossy();
    let parts = [root_name.as_bytes(), namespace.as_bytes(), id.as_bytes()];
    socket_root(root).join(stable_name(&parts))
}

/// None of the host's: the broker's temporary files are on the container's scratch layer.
pub fn temp_dir(_: &Path, sockets: &Path, _: Deprivileged) -> PathBuf {
    sockets.to_owned()
}

pub fn default_state_root() -> PathBuf {
    base_dir().join("containerd-shim-litebox")
}

fn base_dir() -> PathBuf {
    let program_data = std::env::var_os("ProgramData").filter(|_| security::is_elevated());
    program_data.map_or_else(std::env::temp_dir, PathBuf::from)
}

pub fn create_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

pub fn create_traversable(path: &Path) -> io::Result<()> {
    create_dir(path)
}

/// A share-mode lock: unlike `flock`, incompatible opens fail even outside the shim.
pub type Lock = File;

pub fn lock(path: &Path) -> Option<Lock> {
    let locked = open_lock(path).ok()?;
    // The directory may have been replaced since it was opened.
    let current = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .ok()?;
    (identity(&locked).ok()? == identity(&current).ok()?).then_some(locked)
}

fn open_lock(path: &Path) -> io::Result<Lock> {
    let directory = OpenOptions::new()
        .access_mode(LOCK_ACCESS | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::ErrorKind::NotADirectory.into());
    }
    Ok(directory)
}

fn identity(file: &File) -> io::Result<(u32, u64)> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` is open, and `information` outlives the call, which writes only it.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, index))
}

/// A started container, which stops when dropped.
struct Silo {
    // Before the layers: it closes before they unmount.
    system: hcs::System,
    /// The system's exit, until seen.
    running: Mutex<Option<Receiver<()>>>,
    _layers: layers::Mounted,
}

impl Silo {
    fn start(
        id: &str,
        folders: &[PathBuf],
        record: layers::Record,
        mapped: Vec<Value>,
    ) -> io::Result<Self> {
        let layers = layers::mount(folders, record)?;
        let document = json!({
            "Owner": OWNER,
            "SchemaVersion": {"Major": 2, "Minor": 1},
            "Container": {"Storage": layers.storage(), "MappedDirectories": mapped},
            "ShouldTerminateOnLastHandleClosed": true,
        });
        let system = hcs::System::create(id, &document.to_string())?;
        let (exited, stopped) = mpsc::sync_channel(1);
        system.notify_exit(exited)?;
        let silo = Self {
            system,
            running: Mutex::new(Some(stopped)),
            _layers: layers,
        };
        silo.system.start()?;
        Ok(silo)
    }

    fn stop(&self) {
        let mut running = self.running.lock().expect("lock poisoned");
        let Some(stopped) = running.as_ref() else {
            return;
        };
        match self.system.terminate() {
            Ok(true) => match stopped.recv_timeout(STOP_TIMEOUT) {
                Err(RecvTimeoutError::Timeout) => log::error!("the container did not stop in time"),
                _ => *running = None,
            },
            Ok(false) => *running = None,
            Err(error) => log::error!("cannot stop the container: {error}"),
        }
    }
}

impl Drop for Silo {
    /// Waits for the container to stop: its layers cannot unmount before.
    fn drop(&mut self) {
        self.stop();
    }
}

/// What the container sees of the host: the mapped directories, and the broker's inputs.
struct View {
    /// HCS schema `MappedDirectory`s.
    mapped: Vec<Value>,
    broker: PathBuf,
    runner: PathBuf,
    bridge: PathBuf,
    archive: PathBuf,
    binds: Vec<Bind>,
}

impl View {
    fn new(state: &StateDir, binds: &[Bind]) -> io::Result<Self> {
        let (broker_dir, broker) = split(std::path::absolute(broker_program())?)?;
        let (runner_dir, runner) = split(std::path::absolute(program("LITEBOX_RUNNER", RUNNER))?)?;
        let mut mapped = Vec::new();
        let mut map = |host: &Path, container: &str, read_only: bool| -> io::Result<PathBuf> {
            mapped.push(json!({
                "HostPath": host_path(host)?,
                "ContainerPath": container,
                "ReadOnly": read_only,
            }));
            Ok(PathBuf::from(container))
        };
        let bin = map(&broker_dir, BIN_DIR, true)?;
        let runner_dir = if runner_dir == broker_dir {
            bin.clone()
        } else {
            map(&runner_dir, RUNNER_DIR, true)?
        };
        let state_dir = map(&state.path, STATE_DIR, true)?;
        let run_dir = map(&state.sockets, RUN_DIR, false)?;
        // Only read-only directories reach here (see `RootFs::bind`).
        let binds = (binds.iter().enumerate())
            .map(|(index, bind)| {
                let source = map(&bind.source, &format!(r"{BINDS_DIR}\{index}"), true)?;
                Ok(Bind {
                    source,
                    ..bind.clone()
                })
            })
            .collect::<io::Result<_>>()?;
        let (_, bridge) = split(state.bridge())?;
        let (_, archive) = split(state.archive())?;
        Ok(Self {
            mapped,
            broker: bin.join(broker),
            runner: runner_dir.join(runner),
            bridge: run_dir.join(bridge),
            archive: state_dir.join(archive),
            binds,
        })
    }
}

fn split(path: PathBuf) -> io::Result<(PathBuf, OsString)> {
    let name = path.file_name().map(OsStr::to_owned);
    match (path.parent(), name) {
        (Some(directory), Some(name)) => Ok((directory.to_owned(), name)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} names no file", path.display()),
        )),
    }
}

/// The broker's container.
pub struct Tree {
    /// Taken by [`Broker::stop`], which drops it last.
    silo: Mutex<Option<Arc<Silo>>>,
}

impl Tree {
    #[expect(
        clippy::unused_self,
        reason = "the platforms' contract: Linux's bridge opens after the VM boots"
    )]
    pub(super) fn bridge_open(&self) -> bool {
        true
    }
}

/// Stops the container and unmounts the layers that their record names, unless another holds it:
/// a live daemon, or a same-ID container's cleanup or `Create`.
pub fn remove_leftovers(state: &StateDir, _: &Path) -> std::result::Result<(), String> {
    let path = layers_record(state);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    }
    // Whoever may write the record chooses what the shim unmounts.
    private_root(&state.roots[0]).map_err(|error| error.to_string())?;
    let record = layers::Record::open(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    match record {
        Some(mut record) => remove_layers(state, &mut record),
        None => Ok(()),
    }
}

/// `state`'s root must have passed [`private_root`].
fn remove_layers(state: &StateDir, record: &mut layers::Record) -> std::result::Result<(), String> {
    // Names the layers before the container is created.
    if !record.names_layers() {
        return Ok(());
    }
    remove_system(&system_id(state))
        .map_err(|error| format!("cannot stop the container: {error}"))?;
    record.unmount().map_err(|error| {
        format!(
            "cannot unmount the layers that {} names: {error}",
            layers_record(state).display()
        )
    })
}

/// Takes the layers' record, and so the container's system ID, from an earlier container with
/// this ID, removing what it left.
fn claim_layers(state: &StateDir) -> Result<layers::Record> {
    let path = layers_record(state);
    let failed = |error: String| internal(format!("cannot start the broker: {error}"));
    let claimed = layers::Record::claim(&path)
        .map_err(|error| failed(format!("cannot open {}: {error}", path.display())))?;
    let Some(mut record) = claimed else {
        return Err(super::cleanup_pending());
    };
    remove_layers(state, &mut record).map_err(failed)?;
    Ok(record)
}

/// The broker opens `file` by path, through the state directory's mapping, which admits it to the
/// directory alone (see [`grant_access`]).
fn grant_read(file: &File) -> io::Result<()> {
    security::share_file(file, &format!("(A;;{READ:#x};;;{CONTAINER_USER_SID})"))
}

impl Broker {
    pub fn check(_: Backend, plan: &Plan) -> Result<()> {
        let networked = !(plan.publish.is_empty()
            && plan.egress.tcp.is_empty()
            && plan.egress.udp.is_empty()
            && plan.ingress.tcp.is_empty()
            && plan.ingress.udp.is_empty());
        let refused = match &plan.network {
            Network::Join(_) => Some("joining a network namespace"),
            Network::New => Some("a network namespace"),
            Network::Daemon if networked => {
                Some("publishing ports or allowing destinations or sources")
            }
            Network::Daemon => None,
        };
        if let Some(refused) = refused {
            return Err(crate::unsupported(format!(
                "{refused} is not supported on Windows yet"
            )));
        }
        layers::check(&plan.layers)
    }

    /// Calls `exited` after [`Broker::wait`] reports the exit.
    pub fn spawn(
        _: Backend,
        state: &StateDir,
        archive: File,
        binds: &[Bind],
        plan: &Plan,
        exited: impl FnOnce() + Send + 'static,
    ) -> Result<Self> {
        let failed = |error: io::Error| internal(format!("cannot start the broker: {error}"));
        check_bridge(state)?;
        let record = claim_layers(state)?;
        grant_read(&archive).map_err(failed)?;
        let id = system_id(state);
        let view = View::new(state, binds).map_err(failed)?;
        let arguments =
            broker_arguments(&view.bridge, &view.archive, &view.binds, plan, &view.runner);
        let parameters = json!({
            "CommandLine": hcs::command_line(&view.broker, &arguments).map_err(failed)?,
            "WorkingDirectory": r"C:\",
            "User": CONTAINER_USER,
            "CreateStdInPipe": false,
            "CreateStdOutPipe": true,
            "CreateStdErrPipe": true,
        });
        let silo = Silo::start(&id, &plan.layers, record, view.mapped);
        let silo = Arc::new(silo.map_err(failed)?);
        let spawned = (silo.system)
            .create_process(&parameters.to_string())
            .map_err(failed)?;
        let (exit_sender, exit) = mpsc::sync_channel(1);
        (spawned.process)
            .notify_exit(exit_sender.clone())
            .map_err(|error| failed(error.into()))?;
        // An exit before the callback may not call it.
        if let Ok(hcs::Status::Exited(_)) = spawned.process.status() {
            let _ = exit_sender.try_send(());
        }
        log_lines("stdout", spawned.stdout, |_| {});
        let stderr = Mutex::new(log_lines("stderr", spawned.stderr, |_| {}));
        let process = spawned.process;
        let ended = Arc::new(Ended::default());
        let (reaper, weak) = (Arc::clone(&ended), Arc::downgrade(&silo));
        std::thread::spawn(move || {
            let _ = exit.recv();
            match process.status() {
                Ok(status) => log::info!("the broker exited: {status:?}"),
                Err(error) => log::info!("the broker exited: {error}"),
            }
            drop(process);
            // As runhcs ends a container with its init process: the runners go too.
            if let Some(silo) = weak.upgrade() {
                silo.stop();
            }
            reaper.set();
            // After `ended`, which callers wait for while they hold the shim's locks.
            exited();
        });
        Ok(Self {
            pid: spawned.pid,
            ended,
            stderr,
            tree: Tree {
                silo: Mutex::new(Some(silo)),
            },
        })
    }

    /// Stops the container and, before returning, unmounts its layers; later calls do nothing.
    pub fn stop(&self) {
        let Some(silo) = self.tree.silo.lock().expect("lock poisoned").take() else {
            return;
        };
        silo.stop();
        if !self.wait(STOP_TIMEOUT) {
            log::error!("the broker did not exit in time");
        }
        // The last reference once the reaper is done.
        drop(silo);
    }
}

/// Stable, so that the `delete` action finds a dead daemon's container.
fn system_id(state: &StateDir) -> String {
    let path = state.path.to_string_lossy();
    format!("litebox-{}", stable_name(&[path.as_bytes()]))
}

/// Next to the state directory, whose presence means that the `poststop` hooks are still due, so
/// that it may outlive it. No container ID starts with a dot.
fn layers_record(state: &StateDir) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(state.path.file_name().unwrap_or_default());
    name.push(".layers");
    state.path.with_file_name(name)
}

fn remove_system(id: &str) -> io::Result<()> {
    let Some(system) = hcs::System::open(id)? else {
        return Ok(());
    };
    let (exited, stopped) = mpsc::sync_channel(1);
    system.notify_exit(exited)?;
    if system.terminate()? && stopped.recv_timeout(STOP_TIMEOUT).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the leftover container {id} did not stop in time"),
        ));
    }
    Ok(())
}

/// Check the canonical path because Windows can add a verbatim prefix.
fn check_bridge(state: &StateDir) -> Result<()> {
    let bridge = state.bridge();
    let name = bridge.file_name().expect("the bridge has a name");
    let canonical = std::fs::canonicalize(&state.sockets)
        .map_err(|error| {
            internal(format!(
                "cannot resolve {}: {error}",
                state.sockets.display()
            ))
        })?
        .join(name);
    let length = canonical.as_os_str().len();
    if length > MAX_BRIDGE_PATH {
        return Err(crate::error(
            crate::ttrpc::Code::FAILED_PRECONDITION,
            format!(
                "the broker's socket {} is {length} bytes, more than its {MAX_BRIDGE_PATH}: give \
                 the shim a shorter TMP",
                canonical.display()
            ),
        ));
    }
    Ok(())
}

/// The directory `path` as HCS maps it, as hcsshim's `ResolvePath` gives it: through its volume's
/// GUID, unless it has none (a share).
fn host_path(path: &Path) -> io::Result<String> {
    let directory = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    match final_path(&directory, VOLUME_NAME_GUID) {
        Err(error) if is(&error, ERROR_PATH_NOT_FOUND) => final_path(&directory, VOLUME_NAME_DOS),
        resolved => resolved,
    }
}

fn final_path(file: &File, flags: GETFINALPATHNAMEBYHANDLE_FLAGS) -> io::Result<String> {
    let mut path = vec![0u16; 260];
    loop {
        let capacity = u32::try_from(path.len()).unwrap_or(u32::MAX);
        // SAFETY: `file` is open, and `path` holds the `capacity` units that the call may write.
        let length = unsafe {
            GetFinalPathNameByHandleW(file.as_raw_handle(), path.as_mut_ptr(), capacity, flags)
        } as usize;
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if length < path.len() {
            path.truncate(length);
            return String::from_utf16(&path).map_err(io::Error::other);
        }
        // Too small: `length` counts the NUL.
        path.resize(length, 0);
    }
}

fn is(error: &io::Error, code: WIN32_ERROR) -> bool {
    error.raw_os_error() == i32::try_from(code).ok()
}

fn win32_result(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ))
    }
}

/// A Win32 error's `HRESULT` as its code, so that [`is`] matches it.
fn hresult(code: HRESULT) -> io::Result<()> {
    if code >= 0 {
        return Ok(());
    }
    // `FACILITY_WIN32`: `HRESULT_FROM_WIN32`'s.
    let code = if code & 0x1fff_0000 == 0x0007_0000 {
        code & 0xffff
    } else {
        code
    };
    Err(io::Error::from_raw_os_error(code))
}

fn size_u32<T>() -> u32 {
    u32::try_from(size_of::<T>()).expect("a Win32 structure is smaller than 4 GiB")
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Foundation::{ERROR_NOT_READY, ERROR_SHARING_VIOLATION, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    use super::*;

    #[test]
    fn a_state_directory_is_created_and_shared_with_the_container_user() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateDir::at(dir.path().join("s"), "ns", "c");
        state.create(Backend::Userland).unwrap();
        let archive = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(state.archive())
            .unwrap();
        assert!(!dacl(&archive).contains(CONTAINER_USER_SID), "inherited");
        grant_read(&archive).unwrap();
        assert!(dacl(&archive).contains(CONTAINER_USER_SID), "granted");
        drop(archive);
        state.remove();
    }

    #[test]
    fn a_held_layers_record_is_left_to_its_holder() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        // Elevated, `create_dir_all` would make the Administrators its owner.
        private_root(&root).unwrap();
        let state = StateDir::at(root, "ns", "c");
        let path = layers_record(&state);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let scratch = dir.path().join("scratch");
        std::fs::write(&path, scratch.to_string_lossy().as_bytes()).unwrap();
        // As a daemon, or a same-ID cleanup, holds it.
        let held = layers::Record::open(&path).unwrap().expect("the record");
        remove_leftovers(&state, dir.path()).unwrap();
        match claim_layers(&state) {
            Err(crate::ttrpc::Error::RpcStatus(status)) => {
                assert_eq!(status.code(), crate::ttrpc::Code::FAILED_PRECONDITION);
            }
            other => panic!("claimed a held record: {:?}", other.err()),
        }
        drop(held);
        assert!(path.exists());
    }

    #[test]
    fn leftovers_under_a_root_that_others_may_write_to_are_left() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        private_root(&root).unwrap();
        let state = StateDir::at(root.clone(), "ns", "c");
        let record = layers_record(&state);
        std::fs::create_dir_all(record.parent().unwrap()).unwrap();
        let scratch = dir.path().join("scratch");
        std::fs::write(&record, scratch.to_string_lossy().as_bytes()).unwrap();
        security::share_with(&root, "(A;;FA;;;WD)").unwrap();
        let error = remove_leftovers(&state, dir.path()).unwrap_err();
        assert!(error.contains("not a private directory"), "{error}");
        assert!(record.exists());
    }

    /// In SDDL; `file` must be open with `READ_CONTROL`.
    fn dacl(file: &File) -> String {
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `file` is open with `READ_CONTROL`, and `descriptor` outlives the call.
        win32_result(unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut descriptor,
            )
        })
        .unwrap();
        let (mut string, mut length) = (std::ptr::null_mut(), 0);
        // SAFETY: `descriptor` is valid, and `string` and `length` outlive the call.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &raw mut string,
                &raw mut length,
            )
        };
        assert_ne!(converted, 0, "{}", io::Error::last_os_error());
        // SAFETY: the call returned `length` units for the caller to free, as `GetSecurityInfo`
        // did `descriptor`.
        unsafe {
            let sddl =
                String::from_utf16_lossy(std::slice::from_raw_parts(string, length as usize));
            LocalFree(string.cast());
            LocalFree(descriptor);
            sddl
        }
    }

    #[test]
    fn a_lock_is_exclusive_and_leaves_the_directory_usable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        assert!(lock(&path).is_none(), "a missing directory");
        std::fs::create_dir(&path).unwrap();
        let locked = lock(&path).expect("an unlocked directory");
        assert!(lock(&path).is_none(), "a locked directory");
        let refused = open_lock(&path).unwrap_err();
        assert!(is(&refused, ERROR_SHARING_VIOLATION), "{refused:?}");
        std::fs::create_dir(path.join("tmp")).unwrap();
        std::fs::write(path.join("tmp").join("file"), "x").unwrap();
        std::fs::remove_dir_all(&path).unwrap();
        drop(locked);
        assert!(lock(&path).is_none(), "a removed directory");
    }

    #[test]
    fn identity_tells_directories_apart() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (dir.path().join("first"), dir.path().join("second"));
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let locked = lock(&first).unwrap();
        let other = open_lock(&second).unwrap();
        assert_ne!(identity(&locked).unwrap(), identity(&other).unwrap());
        drop(other);
        std::fs::remove_dir(&second).unwrap();
        std::fs::rename(&first, &second).unwrap();
        let moved = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&second)
            .unwrap();
        assert_eq!(identity(&locked).unwrap(), identity(&moved).unwrap());
    }

    #[test]
    fn a_host_path_names_its_volume_by_guid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a dir");
        std::fs::create_dir(&path).unwrap();
        let resolved = host_path(&path).unwrap();
        assert!(resolved.starts_with(r"\\?\Volume{"), "{resolved}");
        assert!(resolved.ends_with(r"\a dir"), "{resolved}");
    }

    #[test]
    fn a_win32_hresult_is_its_error() {
        let not_ready = hresult(0x8007_0015_u32.cast_signed()).unwrap_err();
        assert!(is(&not_ready, ERROR_NOT_READY), "{not_ready:?}");
        let other = hresult(0x8037_0100_u32.cast_signed()).unwrap_err();
        assert_eq!(other.raw_os_error(), Some(0x8037_0100_u32.cast_signed()));
        hresult(1).unwrap();
    }
}
