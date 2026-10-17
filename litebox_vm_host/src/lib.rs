// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The host's end of the LiteBox VM kernel's
//! [control channel](litebox_common_vm_control).

use anyhow::{Context as _, Result, bail};
use litebox_common_vm_control::{self as protocol, Decoder, Request, Response, Service, VERSION};
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct Connection {
    stream: UnixStream,
    decoder: Decoder,
    service: Service,
}

impl Connection {
    /// Connects to the channel's Unix socket at `path`, retrying until
    /// `timeout` (e.g., while QEMU starts), and says hello.
    ///
    /// # Errors
    ///
    /// No connection, or the kernel's hello is not one.
    pub fn connect(path: &Path, timeout: Duration) -> Result<Self> {
        let start = Instant::now();
        let stream = loop {
            match UnixStream::connect(path) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("connecting to {}", path.display()));
                }
            }
        };
        let mut connection = Self {
            stream,
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

    /// Powers the VM off, with `success` as QEMU's verdict.
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
