// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! QEMU, with KVM if it can use it, else TCG. `vhost-device-vsock`, a `connect` daemon of the
//! guardian's, bridges its vsock device. QEMU is `qemu-system-x86_64` unless `LITEBOX_QEMU` names
//! it; the daemon is next to this executable unless `LITEBOX_VHOST_DEVICE_VSOCK` names it.
//!
//! With egress rules, guest sockets reach QEMU's user network, which NATs them, as far as the rules
//! let them (see [`Egress`](crate::spec::Egress)); without, the VM has no network device. QEMU's
//! NAT keeps one destination per guest UDP port, the last: an unconnected UDP socket that sends to
//! 10.0.2.1 or 10.0.2.3 and to other destinations may lose the replies of those it sent to earlier.
//! It reports no ICMP errors: a connected guest UDP socket gets no `ECONNREFUSED`, and a datagram
//! that a guest UDP socket sends after one refused may be lost.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::process::Command;

use super::super::guardian::DEVICE_FD;
use super::{GUEST_CID, Vm};
use crate::sandbox::program;

const QEMU: &str = "qemu-system-x86_64";
const DEVICE_DAEMON: &str = "vhost-device-vsock";

/// Adds QEMU's daemon, its vsock device's, to the guardian's arguments `command`.
pub(super) fn daemons(command: &mut Command, vm: &Vm) {
    let socket = vm.state.device_socket("vhost-user");
    command
        .arg("connect")
        .arg(&socket)
        .arg(program("LITEBOX_VHOST_DEVICE_VSOCK", DEVICE_DAEMON))
        .args(["--guest-cid", GUEST_CID, "--socket"])
        .arg(&socket)
        .arg("--uds-path")
        .arg(vm.state.bridge())
        .arg("--");
}

/// Adds QEMU's command for `vm` to the guardian's arguments `command`.
pub(super) fn command(command: &mut Command, vm: &Vm) {
    let memory = format!("{}M", vm.memory_mib);
    command
        .arg(std::env::var_os("LITEBOX_QEMU").unwrap_or_else(|| QEMU.into()))
        .args(["-machine", "q35", "-nodefaults", "-m", &memory])
        // KVM if QEMU, of the broker's user, can use it, else TCG; `max` suits both, and invtsc (not
        // migratable) lets QEMU publish the TSC frequency to the guest.
        .args(["-accel", "kvm", "-accel", "tcg", "-cpu", "max,+invtsc"])
        .args(["-smp", &vm.cpus.to_string(), "-nic", "none", "-kernel"])
        .arg(&vm.kernel)
        .arg("-initrd")
        .arg(vm.state.payload())
        .args(["-append", "litebox.log=info"])
        .args(["-serial", "stdio", "-display", "none", "-no-reboot"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        // The console, on QEMU's stderr.
        .args(["-device", "virtio-serial-pci,id=vs0,disable-legacy=on"])
        .args(["-chardev", "file,id=con0,path=/proc/self/fd/2"])
        .args(["-device", "virtconsole,chardev=con0,bus=vs0.0"]);
    // TODO: a NAT that keeps each UDP flow (passt, or a TAP device) (see the module's docs).
    if vm.network {
        command
            .args([
                "-netdev",
                "user,id=n0,net=10.0.2.0/24,host=10.0.2.1,ipv6=off",
            ])
            .args(["-device", "virtio-net-pci,netdev=n0,disable-legacy=on"]);
    }
    for (index, (tag, socket)) in vm.shares.iter().enumerate() {
        let mut chardev = OsString::from(format!("socket,id=fs{index},path="));
        chardev.push(option_value(socket.as_os_str()));
        let mut device = OsString::from(format!("vhost-user-fs-pci,chardev=fs{index},tag="));
        device.push(option_value(OsStr::new(tag)));
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

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::option_value;

    #[test]
    fn option_values_double_their_commas() {
        assert_eq!(option_value(OsStr::new("/a,b,,c")), "/a,,b,,,,c");
    }
}
