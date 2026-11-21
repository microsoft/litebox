// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `containerd-shim-litebox-vm-v1`, the containerd shim of LiteBox on its VM kernel in QEMU (see
//! the library).

#[cfg(target_os = "linux")]
fn main() {
    use litebox_containerd_shim::{Backend, Vmm, main};
    main(Backend::Vm(Vmm::Qemu));
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("containerd-shim-litebox-vm-v1 runs on Linux only");
    std::process::exit(1);
}
