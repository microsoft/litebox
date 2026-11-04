// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The LiteBox guest service: the broker's root process, which creates and supervises the
//! container's processes for the containerd shim, serving `litebox_guest_service_protocol` on
//! vsock port 1024. It logs to its stderr, which the broker forwards to its own.

#![cfg(target_os = "linux")]

mod process;
mod service;

use std::os::fd::IntoRawFd as _;
use std::sync::Arc;

use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
use litebox_guest_service_protocol::guest_service_ttrpc::create_guest_service;

/// Runs the guest service until the broker ends.
pub fn run() -> ! {
    // SAFETY: getpid and getppid take no arguments.
    let ids = unsafe { (libc::getpid(), libc::getppid()) };
    // Only LiteBox's first guest process has these, and confines `kill(-1)` to the guest.
    if ids != (1, 0) {
        eprintln!("litebox-guest-service: not the first process of a LiteBox guest");
        std::process::exit(1);
    }
    let service = Arc::new(service::Service::default());
    let reaper = Arc::clone(&service);
    std::thread::spawn(move || reaper.reap());
    let served = process::vsock_listen(GUEST_SERVICE_PORT).and_then(|listener| {
        let mut server = ttrpc::Server::new()
            .add_listener(listener.into_raw_fd())
            .map_err(std::io::Error::other)?
            .register_service(create_guest_service(service));
        server.start().map_err(std::io::Error::other)?;
        Ok(server)
    });
    match served {
        // The server serves from threads of its own while it lives.
        Ok(_server) => loop {
            std::thread::park();
        },
        Err(error) => {
            eprintln!("litebox-guest-service: cannot serve port {GUEST_SERVICE_PORT}: {error}");
            std::process::exit(1);
        }
    }
}
