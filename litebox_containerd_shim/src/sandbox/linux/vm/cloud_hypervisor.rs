// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cloud Hypervisor, with KVM: its own vsock device bridges the guest's vsock sockets to the
//! bridge's socket. It has no network device yet, so it refuses egress rules. It is
//! `cloud-hypervisor` unless `LITEBOX_CLOUD_HYPERVISOR` names it.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use super::{GUEST_CID, Vm};
use crate::spec::{Bind, Plan};
use crate::{Result, error, unsupported};

const CLOUD_HYPERVISOR: &str = "cloud-hypervisor";

/// Fails if Cloud Hypervisor cannot run `plan`: with egress rules, as it has no network yet, or
/// without KVM.
pub(super) fn check(plan: &Plan) -> Result<()> {
    // TODO: a network, with the VM's ingress (a TAP device, or passt over vhost-user).
    if !plan.egress.tcp.is_empty() || !plan.egress.udp.is_empty() {
        return Err(unsupported(
            "the Cloud Hypervisor backend has no network yet (io.litebox.egress.*)",
        ));
    }
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
}
