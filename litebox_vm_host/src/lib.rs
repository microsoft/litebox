// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The host's end of the LiteBox VM kernel's
//! [control channel](litebox_common_vm_control): an `AF_VSOCK` stream
//! socket connected to the VM's CID.
//!
//! The channel has no authentication: any host process that can open
//! `AF_VSOCK` sockets can control the VM, so use it only on hosts whose users
//! are all trusted (see the protocol's
//! [trust model](litebox_common_vm_control#trust-model)).

use anyhow::{Context as _, Result, bail};
use litebox_common_vm_control::{self as protocol, Decoder, Request, Response, Service, VERSION};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

/// How long to wait between connection attempts.
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

pub struct Connection {
    /// The socket, as a file for `Read` and `Write`.
    stream: File,
    decoder: Decoder,
    service: Service,
}

impl Connection {
    /// Connects to `port` of the VM with `cid`, retrying until `timeout`
    /// (e.g., while the VM boots), and says hello.
    ///
    /// # Errors
    ///
    /// No connection, or the kernel's hello is not one (e.g., it refused the
    /// version).
    pub fn connect(cid: u32, port: u32, timeout: Duration) -> Result<Self> {
        let start = Instant::now();
        let socket = loop {
            match connect_vsock(cid, port) {
                Ok(socket) => break socket,
                Err(_) if start.elapsed() < timeout => std::thread::sleep(RETRY_INTERVAL),
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("connecting to vsock CID {cid}, port {port}"));
                }
            }
        };
        let mut connection = Self {
            stream: File::from(socket),
            decoder: Decoder::default(),
            service: Service::Programs,
        };
        match connection.call(&Request::Hello { version: VERSION })? {
            Response::Hello { version, service } if version == VERSION => {
                connection.service = service;
                Ok(connection)
            }
            response => bail!("unexpected hello: {response:?}"),
        }
    }

    /// What the kernel serves.
    pub fn service(&self) -> Service {
        self.service
    }

    /// Sends `request` and waits for its response.
    ///
    /// # Errors
    ///
    /// The channel broke, or [`Response::Error`].
    pub fn call(&mut self, request: &Request) -> Result<Response> {
        self.stream.write_all(&protocol::encode(request)?)?;
        let mut buffer = [0; 4096];
        loop {
            if let Some(response) = self.decoder.next_message()? {
                if let Response::Error(error) = response {
                    bail!("the kernel refused {}: {error}", request.name());
                }
                return Ok(response);
            }
            let len = self.stream.read(&mut buffer)?;
            if len == 0 {
                bail!("the kernel closed the channel");
            }
            self.decoder.push(&buffer[..len]);
        }
    }

    /// Powers the VM off, with `success` as QEMU's verdict, and closes the
    /// connection, which the kernel waits for.
    ///
    /// # Errors
    ///
    /// The channel broke, or the kernel did not confirm.
    pub fn shutdown(mut self, success: bool) -> Result<()> {
        match self.call(&Request::Shutdown { success })? {
            Response::ShuttingDown => Ok(()),
            response => bail!("unexpected response to shutdown: {response:?}"),
        }
    }
}

/// A stream socket connected to `port` of `cid`.
fn connect_vsock(cid: u32, port: u32) -> io::Result<OwnedFd> {
    // Safety: creates a socket; no memory is passed.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: a new descriptor, which nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // Safety: `sockaddr_vm` is plain integers, for which zero is valid.
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::sa_family_t::try_from(libc::AF_VSOCK).expect("a family fits");
    address.svm_cid = cid;
    address.svm_port = port;
    let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>()).expect("a small struct");
    // Safety: `address` is a valid `sockaddr_vm` of `len` bytes, read only
    // during the call.
    let connected = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            len,
        )
    };
    if connected < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}
