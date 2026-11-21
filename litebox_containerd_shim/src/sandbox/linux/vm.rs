// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The VM backend: `litebox_runner_vm_kernel` in QEMU, which boots the guest service as process 1.
//! The guardian runs QEMU, whose pid is the broker's, `vhost-device-vsock`, whose hybrid vsock
//! bridge reaches the guest service, and a `virtiofsd` for each directory bind.
//!
//! The payload, QEMU's initrd, holds the VM's Linux runner, the root archive and the `policy`, the
//! egress rules (see `litebox_broker_vm_kernel`'s docs). The VM serves one directory bind at most
//! for now, as a virtio-fs device whose tag is its guest path, which the kernel keeps read-only;
//! `virtiofsd` runs without its sandbox, which needs user namespaces, as the broker's user. With
//! egress rules,
//! guest sockets reach QEMU's user network, which NATs them, as far as the rules let them (see
//! [`Egress`]); without, the VM has no network device. The VM publishes no ports yet. QEMU's NAT
//! keeps one destination per guest UDP port, the last: an unconnected UDP socket that sends to
//! 10.0.2.1 or 10.0.2.3 and to other destinations may lose the replies of those it sent to earlier.
//! QEMU's stdout is the kernel's log, and its stderr the processes' output.
//!
//! The kernel, the runner and `vhost-device-vsock` are next to this executable unless
//! `LITEBOX_VM_KERNEL`, `LITEBOX_VM_RUNNER` or `LITEBOX_VHOST_DEVICE_VSOCK` name them; the kernel
//! and the runner must be of this executable's build. QEMU and `virtiofsd` are, unless `LITEBOX_QEMU`
//! or `LITEBOX_VIRTIOFSD` name them, the first that the broker's user can run next to this
//! executable, on the `PATH`, or in `/usr/libexec`, where distributions install `virtiofsd`.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek as _, SeekFrom};
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use litebox_broker_core::MAX_DESTINATION_RULES;
use tar_core::EntryType;
use tar_core::builder::EntryBuilder;

use super::super::{StateDir, program};
use super::guardian::{DEVICE_FD, LISTENER_FD};
use crate::rootfs::{append, finish};
use crate::spec::{Bind, Egress, Plan};
use crate::{Result, internal, invalid, unsupported};

/// The kernel's line once its vsock device runs, which connections wait for (see
/// `litebox_runner_vm_kernel`'s `devices::VSOCK_STARTED`).
pub const VSOCK_STARTED: &str = "[litebox] vsock device started";

/// The installed names of the VM's kernel, its Linux runner and its vsock device's daemon.
const KERNEL: &str = "litebox_runner_vm_kernel";
const RUNNER: &str = "litebox_runner_linux_on_vm_userland";
const DEVICE_DAEMON: &str = "vhost-device-vsock";
const QEMU: &str = "qemu-system-x86_64";
const VIRTIOFSD: &str = "virtiofsd";
/// The longest tag of a virtio-fs device (`virtio_fs_config`'s).
const MAX_TAG: usize = 36;
/// Guest RAM besides the payload's without a memory limit.
const DEFAULT_MEMORY_MIB: u64 = 2048;
/// Guest RAM besides a memory limit's and the payload's, for the kernel and the guest service.
const OVERHEAD_MEMORY_MIB: u64 = 128;
/// The most guest RAM the kernel uses: its direct map's 512 GiB, less q35's hole below 4 GiB.
const MAX_MEMORY_MIB: u64 = (512 - 2) << 10;

/// Fails if the VM cannot run `plan`: on hosts other than x86-64, with more egress destinations of
/// a protocol than its kernel's broker takes, or with published ports, which it does not serve yet
/// (see the crate's docs).
pub fn check(plan: &Plan) -> Result<()> {
    if cfg!(not(target_arch = "x86_64")) {
        return Err(unsupported("the VM backend runs on x86-64 hosts only"));
    }
    for (protocol, destinations) in [("tcp", &plan.egress.tcp), ("udp", &plan.egress.udp)] {
        if destinations.len() > MAX_DESTINATION_RULES {
            return Err(invalid(format!(
                "io.litebox.egress.{protocol} names {} destinations, more than the broker's \
                 {MAX_DESTINATION_RULES}",
                destinations.len()
            )));
        }
    }
    if !plan.publish.is_empty() {
        return Err(unsupported(
            "the VM backend publishes no ports yet (io.litebox.publish.*)",
        ));
    }
    Ok(())
}

/// The guest's vsock CID, local to its device daemon.
const GUEST_CID: &str = "3";

/// `/dev/kvm`'s group, for the VM's processes to open it, unless it is root's or the overflow
/// group (one the user namespace does not map).
pub fn kvm_group() -> Option<libc::gid_t> {
    let gid = std::fs::metadata("/dev/kvm").ok()?.gid();
    let overflow: libc::gid_t = std::fs::read_to_string("/proc/sys/kernel/overflowgid")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    (gid != 0 && gid != overflow).then_some(gid)
}

/// Lets QEMU, of the broker's user `uid`:`gid`, reopen `stderr`, its own, for the VM's console.
pub fn give_stderr(stderr: &impl AsFd, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::fchown(stderr, Some(uid), Some(gid))
}

/// The guardian's `PATH`, where it finds the VM's programs that their variables do not name (see
/// the module's docs): as the broker's user, it skips those it cannot run.
fn search_path() -> Result<OsString> {
    let beside = std::env::current_exe().unwrap_or_default();
    // glibc's default, without a `PATH`.
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/bin:/usr/bin".into());
    let dirs = (beside.parent().map(Path::to_path_buf).into_iter())
        .chain(std::env::split_paths(&path))
        .chain(std::iter::once(PathBuf::from("/usr/libexec")));
    std::env::join_paths(dirs)
        .map_err(|error| internal(format!("cannot search for the VM's programs: {error}")))
}

/// The most CPUs the kernel starts (`litebox_platform_vm_kernel`'s `MAX_CPUS`).
const MAX_CPUS: usize = 64;

/// The VM's CPUs: the `requested` ones, at least one, and at most `host` and [`MAX_CPUS`].
fn cpus(requested: Option<u32>, host: usize) -> usize {
    requested
        .map_or(1, |cpus| usize::try_from(cpus).unwrap_or(usize::MAX))
        .clamp(1, host.clamp(1, MAX_CPUS))
}

/// Adds the VM guardian's arguments to `command`, packing the payload first.
pub fn guardian_arguments(
    command: &mut Command,
    state: &StateDir,
    archive: File,
    binds: &[Bind],
    plan: &Plan,
) -> Result<()> {
    // TODO: serve any number of directory and file binds, nested ones too, live, through one
    // device for the sandbox exporting a tree the host composes: a device per bind takes a PCI
    // slot each, and file binds are copies in the root archive.
    if binds.len() > 1 {
        return Err(unsupported(format!(
            "the VM backend serves one directory bind at most for now, not {}",
            binds.len()
        )));
    }
    if let Some(bind) = binds.iter().find(|bind| bind.destination.len() > MAX_TAG) {
        return Err(unsupported(format!(
            "the directory bind at {} is too deep for the VM, whose share is mounted at its \
             virtio-fs tag, of at most {MAX_TAG} bytes",
            bind.destination
        )));
    }
    let virtiofsd = std::env::var_os("LITEBOX_VIRTIOFSD").unwrap_or_else(|| VIRTIOFSD.into());
    let kernel = program("LITEBOX_VM_KERNEL", KERNEL);
    if !kernel.is_file() {
        return Err(internal(format!(
            "the VM kernel {} does not exist",
            kernel.display()
        )));
    }
    let runner = program("LITEBOX_VM_RUNNER", RUNNER);
    let policy = policy(&plan.egress);
    let payload_size = pack_payload(state, archive, &runner, policy.as_bytes())?;
    let memory_mib = memory_mib(plan.resources.memory, payload_size);
    let memory = format!("{memory_mib}M");
    let host_cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let cpus = cpus(plan.resources.cpus, host_cpus);
    let socket = state.sockets.join("vhost-user");
    command
        .env("PATH", search_path()?)
        .arg("connect")
        .arg(&socket)
        .arg(program("LITEBOX_VHOST_DEVICE_VSOCK", DEVICE_DAEMON))
        .args(["--guest-cid", GUEST_CID, "--socket"])
        .arg(&socket)
        .arg("--uds-path")
        .arg(state.bridge())
        .arg("--");
    let shares: Vec<PathBuf> = (0..binds.len())
        .map(|index| state.sockets.join(format!("virtiofs{index}")))
        .collect();
    for (bind, socket) in binds.iter().zip(&shares) {
        command
            .arg("listen")
            .arg(socket)
            .arg(&virtiofsd)
            .arg(format!("--fd={LISTENER_FD}"))
            .arg("--shared-dir")
            .arg(&bind.source)
            .args(["--sandbox=none", "--log-level=error", "--"]);
    }
    command.arg(std::env::var_os("LITEBOX_QEMU").unwrap_or_else(|| QEMU.into()));
    command
        .args(["-machine", "q35", "-nodefaults", "-m", &memory])
        // KVM if QEMU, of the broker's user, can use it, else TCG; `max` suits both, and invtsc (not
        // migratable) lets QEMU publish the TSC frequency to the guest.
        .args(["-accel", "kvm", "-accel", "tcg", "-cpu", "max,+invtsc"])
        .args(["-smp", &cpus.to_string(), "-nic", "none", "-kernel"])
        .arg(kernel)
        .arg("-initrd")
        .arg(state.payload())
        .args(["-append", "litebox.log=info"])
        .args(["-serial", "stdio", "-display", "none", "-no-reboot"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        // The console, on QEMU's stderr.
        .args(["-device", "virtio-serial-pci,id=vs0,disable-legacy=on"])
        .args(["-chardev", "file,id=con0,path=/proc/self/fd/2"])
        .args(["-device", "virtconsole,chardev=con0,bus=vs0.0"]);
    // TODO: a NAT that keeps each UDP flow (passt, or a TAP device) (see the module's docs).
    if !policy.is_empty() {
        command
            .args([
                "-netdev",
                "user,id=n0,net=10.0.2.0/24,host=10.0.2.1,ipv6=off",
            ])
            .args(["-device", "virtio-net-pci,netdev=n0,disable-legacy=on"]);
    }
    // Only read-only ones reach here (see `RootFs::bind`).
    for (index, (bind, socket)) in binds.iter().zip(&shares).enumerate() {
        let mut chardev = OsString::from(format!("socket,id=fs{index},path="));
        chardev.push(option_value(socket.as_os_str()));
        let mut device = OsString::from(format!("vhost-user-fs-pci,chardev=fs{index},tag="));
        device.push(option_value(OsStr::new(&bind.destination)));
        command
            .arg("-chardev")
            .arg(chardev)
            .arg("-device")
            .arg(device);
    }
    // vhost-user needs the guest's memory shared with the device daemons, the vsock one's
    // connection the guardian hands QEMU.
    command
        .arg("-object")
        .arg(format!(
            "memory-backend-memfd,id=mem,size={memory},share=on"
        ))
        .args(["-machine", "memory-backend=mem", "-chardev"])
        .arg(format!("socket,id=vhost-vsock,fd={DEVICE_FD}"))
        .args([
            "-device",
            "vhost-user-vsock-pci,chardev=vhost-vsock,disable-legacy=on",
        ]);
    Ok(())
}

/// The payload's `policy` (see `litebox_broker_vm_kernel`'s docs): `egress`'s rules, a line each.
fn policy(egress: &Egress) -> String {
    let mut policy = String::new();
    for (protocol, destinations) in [("tcp", &egress.tcp), ("udp", &egress.udp)] {
        for destination in destinations {
            writeln!(policy, "egress {protocol} {destination}").expect("a `String` takes it");
        }
    }
    policy
}

/// `value` as a value of a QEMU option list, its commas doubled.
fn option_value(value: &OsStr) -> OsString {
    let mut escaped = Vec::with_capacity(value.len());
    for &byte in value.as_bytes() {
        escaped.push(byte);
        if byte == b',' {
            escaped.push(b',');
        }
    }
    OsString::from_vec(escaped)
}

/// The guest RAM, in MiB, for the memory limit `limit` and a payload of `payload` bytes.
fn memory_mib(limit: Option<u64>, payload: u64) -> u64 {
    let mib = |bytes: u64| bytes.div_ceil(1 << 20);
    let memory = limit
        .map_or(DEFAULT_MEMORY_MIB, |limit| {
            mib(limit).saturating_add(OVERHEAD_MEMORY_MIB)
        })
        .saturating_add(mib(payload));
    if memory > MAX_MEMORY_MIB {
        log::warn!(
            "the VM's memory, {memory} MiB, is cut to {MAX_MEMORY_MIB} MiB, the most its kernel \
             uses"
        );
    }
    memory.min(MAX_MEMORY_MIB)
}

/// Packs the payload of `state`, with `policy`, and removes the root archive, read from `archive`.
/// Returns the payload's size.
fn pack_payload(state: &StateDir, mut archive: File, runner: &Path, policy: &[u8]) -> Result<u64> {
    let path = state.payload();
    let failed = |error: io::Error| internal(format!("cannot write {}: {error}", path.display()));
    let unreadable = |source: &Path, error: io::Error| {
        internal(format!("cannot read {}: {error}", source.display()))
    };
    let runner_file = File::open(runner).map_err(|error| unreadable(runner, error))?;
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|error| unreadable(&state.archive(), error))?;
    // Never through a symlink (an earlier container's broker user may have owned the directory),
    // and the daemon's alone, whatever the umask, until `grant_read`.
    let payload = File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(failed)?;
    // QEMU opens it by path.
    super::grant_read(state, &payload).map_err(failed)?;
    let mut writer = BufWriter::new(payload);
    for (name, file, source) in [
        ("linux-runner.elf", runner_file, runner.to_owned()),
        ("rootfs.tar", archive, state.archive()),
    ] {
        let size = file
            .metadata()
            .map_err(|error| unreadable(&source, error))?
            .len();
        append_file(&mut writer, name, Box::new(file), size).map_err(failed)?;
    }
    let size = u64::try_from(policy.len()).expect("small");
    append_file(&mut writer, "policy", Box::new(policy), size).map_err(failed)?;
    let file = finish(writer).map_err(failed)?;
    if let Err(error) = std::fs::remove_file(state.archive()) {
        log::warn!("cannot remove the packed root archive: {error}");
    }
    Ok(file.metadata().map_err(failed)?.len())
}

/// Appends the regular file `name` with `size` bytes of `content` to the payload `writer`.
fn append_file(
    writer: &mut impl io::Write,
    name: &str,
    content: Box<dyn Read + '_>,
    size: u64,
) -> io::Result<()> {
    let mut entry = EntryBuilder::new_gnu();
    entry.path(name).entry_type(EntryType::Regular);
    append(writer, &mut entry, 0o644, content, size)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    use super::{
        MAX_CPUS, MAX_MEMORY_MIB, StateDir, cpus, memory_mib, option_value, pack_payload, policy,
    };

    /// A state directory below `root`, the runner, and an archive written there, open.
    fn packing(root: &Path) -> (StateDir, std::path::PathBuf, File) {
        let state = StateDir::at(root.join("state"), "ns", "c");
        std::fs::create_dir_all(&state.path).unwrap();
        let runner = root.join("runner");
        std::fs::write(&runner, "RUNNER").unwrap();
        let mut archive = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(state.archive())
            .unwrap();
        archive.write_all(b"archive").unwrap();
        (state, runner, archive)
    }

    /// The broker's user owns the directory: it may link the archive's path to a file only root
    /// may read, which root's packing must not take.
    #[test]
    fn the_payload_holds_the_archive_written_whatever_its_path_names_since() {
        let dir = tempfile::tempdir().unwrap();
        let (state, runner, archive) = packing(dir.path());
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "secret").unwrap();
        std::fs::remove_file(state.archive()).unwrap();
        std::os::unix::fs::symlink(&secret, state.archive()).unwrap();
        pack_payload(&state, archive, &runner, b"").unwrap();
        let payload = std::fs::read(state.payload()).unwrap();
        let holds = |bytes: &[u8]| payload.windows(bytes.len()).any(|window| window == bytes);
        assert!(holds(b"archive") && holds(b"RUNNER") && !holds(b"secret"));
        let mode = std::fs::metadata(state.payload()).unwrap().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// Nor may root's packing write through a link at the payload's path.
    #[test]
    fn a_payload_path_that_exists_fails_the_packing_and_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let (state, runner, archive) = packing(dir.path());
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "victim").unwrap();
        std::os::unix::fs::symlink(&victim, state.payload()).unwrap();
        assert!(pack_payload(&state, archive, &runner, b"").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "victim");
    }

    #[test]
    fn the_memory_is_the_limit_the_vms_own_and_the_payload_within_the_kernels_reach() {
        assert_eq!(memory_mib(None, 3 << 20), 2051);
        assert_eq!(memory_mib(Some((512 << 20) + 1), 1), 642);
        assert_eq!(memory_mib(Some(1), 0), 129);
        assert_eq!(memory_mib(Some(8 << 30), 0), 8320);
        assert_eq!(memory_mib(Some(1 << 40), 0), MAX_MEMORY_MIB);
    }

    #[test]
    fn the_cpus_are_the_quotas_within_the_hosts_and_the_kernels() {
        assert_eq!(cpus(None, 8), 1);
        assert_eq!(cpus(Some(0), 8), 1);
        assert_eq!(cpus(Some(2), 8), 2);
        assert_eq!(cpus(Some(16), 8), 8);
        assert_eq!(cpus(Some(u32::MAX), 128), MAX_CPUS);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn more_egress_destinations_than_the_broker_takes_are_refused() {
        let destinations: Vec<String> = (1..=super::MAX_DESTINATION_RULES + 1)
            .map(|port| format!("10.1.0.0/16:{port}"))
            .collect();
        let spec: oci_spec::runtime::Spec = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": {"args": ["sh"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
            "annotations": {"io.litebox.egress.udp": destinations.join(",")},
        }))
        .unwrap();
        let error = super::check(&crate::spec::plan(&spec).unwrap()).unwrap_err();
        assert!(
            format!("{error:?}").contains("io.litebox.egress.udp"),
            "{error:?}"
        );
    }

    #[test]
    fn egress_rules_are_the_kernels_policy() {
        let spec: oci_spec::runtime::Spec = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": {"args": ["sh"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
            "annotations": {
                "io.litebox.egress.tcp": "10.1.0.0/16:80-81,0.0.0.0/0:443",
                "io.litebox.egress.udp": "10.0.2.3/32:53",
            },
        }))
        .unwrap();
        let plan = crate::spec::plan(&spec).unwrap();
        assert_eq!(
            policy(&plan.egress),
            "egress tcp 10.1.0.0/16:80-81\negress tcp 0.0.0.0/0:443\negress udp 10.0.2.3/32:53\n"
        );
    }

    #[test]
    fn option_values_double_their_commas() {
        assert_eq!(option_value(OsStr::new("/a,b,,c")), "/a,,b,,,,c");
    }
}
