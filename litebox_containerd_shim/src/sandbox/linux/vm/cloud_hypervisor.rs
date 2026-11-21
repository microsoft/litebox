// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cloud Hypervisor, with KVM: its own vsock device bridges the guest's vsock sockets to the
//! bridge's socket, and passt, over vhost-user, is its network device. They are `cloud-hypervisor`
//! and `passt` unless `LITEBOX_CLOUD_HYPERVISOR` and `LITEBOX_PASST` name them.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use litebox_broker_core::socket::{GUEST_IPV4_ADDRESS, HOST_GATEWAY_IPV4_ADDRESS};

use super::{GUEST_CID, Vm};
use crate::spec::Bind;
use crate::{Result, error, unsupported};

const CLOUD_HYPERVISOR: &str = "cloud-hypervisor";
const PASST: &str = "passt";
/// passt's socket.
const NET_SOCKET: &str = "net";
/// The guest's MAC address.
const GUEST_MAC: &str = "52:54:00:12:34:56";

/// Fails if Cloud Hypervisor cannot run the VM: without KVM.
pub(super) fn check() -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        return Err(error(
            crate::ttrpc::Code::FAILED_PRECONDITION,
            "Cloud Hypervisor needs KVM, and there is no /dev/kvm",
        ));
    }
    Ok(())
}

/// Fails if Cloud Hypervisor cannot take the tags of `binds`: one with a comma, which separates its
/// options.
pub(super) fn check_binds(binds: &[Bind]) -> Result<()> {
    match binds.iter().find(|bind| bind.destination.contains(',')) {
        Some(bind) => Err(unsupported(format!(
            "Cloud Hypervisor cannot take the directory bind at {}, whose virtio-fs tag would \
             hold a comma",
            bind.destination
        ))),
        None => Ok(()),
    }
}

/// Adds passt, the network device of `vm` if it has one, to the guardian's arguments `command`.
/// passt must be able to sandbox itself in a user namespace and to create its socket in the socket
/// directory.
pub(super) fn daemons(command: &mut Command, vm: &Vm) {
    if !vm.network {
        return;
    }
    command
        .arg("run")
        .arg(std::env::var_os("LITEBOX_PASST").unwrap_or_else(|| PASST.into()))
        .args(["--vhost-user", "--foreground", "--quiet", "--socket"])
        .arg(vm.state.device_socket(NET_SOCKET))
        .args(["--ipv4-only", "--address"])
        .arg(GUEST_IPV4_ADDRESS.to_string())
        .args(["--netmask", "24", "--gateway"])
        .arg(HOST_GATEWAY_IPV4_ADDRESS.to_string())
        .arg("--map-host-loopback")
        .arg(HOST_GATEWAY_IPV4_ADDRESS.to_string())
        // The guest's addresses are fixed; 10.0.2.1:53 is the namespace's, whatever the host's
        // resolver.
        .args(["--no-dhcp", "--no-ndp", "--no-ra", "--dns", "none", "--"]);
}

/// Adds Cloud Hypervisor's command for `vm` to the guardian's arguments `command`.
pub(super) fn command(command: &mut Command, vm: &Vm) {
    let mut vsock = OsString::from(format!("cid={GUEST_CID},socket="));
    vsock.push(vm.state.bridge());
    command
        .arg(
            std::env::var_os("LITEBOX_CLOUD_HYPERVISOR").unwrap_or_else(|| CLOUD_HYPERVISOR.into()),
        )
        .arg("--kernel")
        .arg(&vm.kernel)
        .arg("--initramfs")
        .arg(vm.state.payload())
        .args(["--cmdline", "litebox.log=info"])
        .arg("--cpus")
        .arg(format!("boot={}", vm.cpus))
        // vhost-user needs the guest's memory shared with the device daemons.
        .arg("--memory")
        .arg(format!("size={}M,shared=on", vm.memory_mib))
        // The kernel's log on stdout, and the console, the processes' output, on stderr.
        .args(["--serial", "tty", "--console", "file=/proc/self/fd/2"])
        .arg("--vsock")
        .arg(vsock);
    for (tag, socket) in &vm.shares {
        let mut fs = OsString::from(format!("tag={tag},socket="));
        fs.push(socket);
        command.arg("--fs").arg(fs);
    }
    if vm.network {
        let mut net = OsString::from(format!("vhost_user=true,mac={GUEST_MAC},socket="));
        net.push(vm.state.device_socket(NET_SOCKET));
        command.arg("--net").arg(net);
    }
}
