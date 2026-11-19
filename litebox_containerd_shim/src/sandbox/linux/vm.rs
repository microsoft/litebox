// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The VM backend: `litebox_runner_vm_kernel` in QEMU, which boots the guest service as process 1.
//! The guardian runs QEMU, whose pid is the broker's, and `vhost-device-vsock`, whose hybrid vsock
//! bridge reaches the guest service.
//!
//! The payload, QEMU's initrd, holds the VM's Linux runner and the root archive. Each directory
//! bind is a read-only virtio-9p device. The VM has no network device. QEMU's stdout is the
//! kernel's log, and its stderr the processes' output.
//!
//! The kernel, the runner and the daemon are next to this executable unless `LITEBOX_VM_KERNEL`,
//! `LITEBOX_VM_RUNNER` or `LITEBOX_VHOST_DEVICE_VSOCK` name them; QEMU is `qemu-system-x86_64`
//! unless `LITEBOX_QEMU` names it.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek as _, SeekFrom};
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::Command;

use tar_core::EntryType;
use tar_core::builder::EntryBuilder;

use super::super::{StateDir, program};
use super::guardian::DEVICE_FD;
use crate::rootfs::{append, finish};
use crate::spec::{Bind, Plan, Resources};
use crate::{Result, internal, unsupported};

/// The kernel's line once its vsock device runs, which connections wait for (see
/// `litebox_runner_vm_kernel`'s `devices::VSOCK_STARTED`).
pub const VSOCK_STARTED: &str = "[litebox] vsock device started";

/// The installed names of the VM's kernel, its Linux runner and its vsock device's daemon.
const KERNEL: &str = "litebox_runner_vm_kernel";
const RUNNER: &str = "litebox_runner_linux_on_vm_userland";
const DEVICE_DAEMON: &str = "vhost-device-vsock";
const QEMU: &str = "qemu-system-x86_64";
/// The longest mount tag of QEMU's virtio-9p devices: its `MAX_TAG_LEN` but the NUL.
const MAX_MOUNT_TAG: usize = 31;
/// Guest RAM besides the payload's without a memory limit.
const DEFAULT_MEMORY_MIB: u64 = 2048;
/// Guest RAM besides a memory limit's and the payload's, for the kernel and the guest service.
const OVERHEAD_MEMORY_MIB: u64 = 128;
/// The most guest RAM the kernel uses: its direct map's 512 GiB, less q35's hole below 4 GiB.
const MAX_MEMORY_MIB: u64 = (512 - 2) << 10;

/// Fails if the VM cannot run `plan`: on hosts other than x86-64, or with egress rules or published
/// ports, as it has no network yet (see the crate's docs).
pub fn check(plan: &Plan) -> Result<()> {
    if cfg!(not(target_arch = "x86_64")) {
        return Err(unsupported("the VM backend runs on x86-64 hosts only"));
    }
    if !plan.egress.tcp.is_empty() || !plan.egress.udp.is_empty() || !plan.publish.is_empty() {
        return Err(unsupported(
            "the VM backend has no network yet (io.litebox.egress.*, io.litebox.publish.*)",
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
    resources: &Resources,
) -> Result<()> {
    if let Some(bind) = binds
        .iter()
        .find(|bind| bind.destination.len() > MAX_MOUNT_TAG)
    {
        return Err(unsupported(format!(
            "the directory bind at {} is too deep for the VM, whose shares are mounted at their \
             9p mount tags, of at most {MAX_MOUNT_TAG} bytes",
            bind.destination
        )));
    }
    let kernel = program("LITEBOX_VM_KERNEL", KERNEL);
    if !kernel.is_file() {
        return Err(internal(format!(
            "the VM kernel {} does not exist",
            kernel.display()
        )));
    }
    let runner = program("LITEBOX_VM_RUNNER", RUNNER);
    let payload_size = pack_payload(state, archive, &runner)?;
    let memory_mib = memory_mib(resources.memory, payload_size);
    let memory = format!("{memory_mib}M");
    let host_cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let cpus = cpus(resources.cpus, host_cpus);
    let socket = state.sockets.join("vhost-user");
    command
        .arg(&socket)
        .arg(program("LITEBOX_VHOST_DEVICE_VSOCK", DEVICE_DAEMON))
        .args(["--guest-cid", GUEST_CID, "--socket"])
        .arg(&socket)
        .arg("--uds-path")
        .arg(state.bridge())
        .arg("--")
        .arg(std::env::var_os("LITEBOX_QEMU").unwrap_or_else(|| QEMU.into()));
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
    // Only read-only ones reach here (see `RootFs::bind`).
    for (index, bind) in binds.iter().enumerate() {
        let mut fsdev = OsString::from(format!("local,id=fs{index},path="));
        fsdev.push(option_value(bind.source.as_os_str()));
        fsdev.push(",security_model=none,readonly=on");
        let mut device = OsString::from(format!("virtio-9p-pci,fsdev=fs{index},mount_tag="));
        device.push(option_value(OsStr::new(&bind.destination)));
        device.push(",disable-legacy=on");
        command.arg("-fsdev").arg(fsdev).arg("-device").arg(device);
    }
    // vhost-user needs the guest's memory shared with the device daemon, whose connection the
    // guardian hands QEMU.
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

/// Packs the payload of `state` and removes the root archive, read from `archive` as written: the
/// broker's user, owning the directory, may have replaced its path. Returns the payload's size.
fn pack_payload(state: &StateDir, mut archive: File, runner: &Path) -> Result<u64> {
    let path = state.payload();
    let failed = |error: io::Error| internal(format!("cannot write {}: {error}", path.display()));
    let unreadable = |source: &Path, error: io::Error| {
        internal(format!("cannot read {}: {error}", source.display()))
    };
    let runner_file = File::open(runner).map_err(|error| unreadable(runner, error))?;
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|error| unreadable(&state.archive(), error))?;
    // Never through a symlink: the broker's user may own the directory.
    let payload = File::create_new(&path).map_err(failed)?;
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
    use std::path::Path;

    use super::{MAX_CPUS, MAX_MEMORY_MIB, StateDir, cpus, memory_mib, option_value, pack_payload};

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
        pack_payload(&state, archive, &runner).unwrap();
        let payload = std::fs::read(state.payload()).unwrap();
        let holds = |bytes: &[u8]| payload.windows(bytes.len()).any(|window| window == bytes);
        assert!(holds(b"archive") && holds(b"RUNNER") && !holds(b"secret"));
    }

    /// Nor may root's packing write through a link at the payload's path.
    #[test]
    fn a_payload_path_that_exists_fails_the_packing_and_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let (state, runner, archive) = packing(dir.path());
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "victim").unwrap();
        std::os::unix::fs::symlink(&victim, state.payload()).unwrap();
        assert!(pack_payload(&state, archive, &runner).is_err());
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

    #[test]
    fn option_values_double_their_commas() {
        assert_eq!(option_value(OsStr::new("/a,b,,c")), "/a,,b,,,,c");
    }
}
