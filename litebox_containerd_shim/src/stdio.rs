// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A process's standard streams: the host ends that containerd names, and the threads that copy
//! between them and the guest service.

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use containerd_shim::protos::ttrpc::context::Context;
use litebox_guest_service_protocol::guest_service::{
    CloseStdinRequest, ReadStreamRequest, WriteStreamRequest,
};
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;
use rustix::event::{PollFd, PollFlags, Timespec};

use crate::{Result, internal, unsupported};

/// The most bytes one read carries.
const CHUNK: u32 = 64 * 1024;

/// Opens the host end that `uri` names: a FIFO (a path, or `fifo://`), or for an output a
/// regular file (`file://`) to append to; `None` for none. A FIFO is opened read-write, so that
/// opening it never blocks, and an input ends only with `CloseIO`, as with runc.
pub fn open(uri: &str, input: bool) -> Result<Option<File>> {
    if uri.is_empty() {
        return Ok(None);
    }
    let (path, fifo) = match uri.split_once("://") {
        None => (uri, true),
        Some(("fifo", path)) => (path, true),
        Some(("file", path)) if !input => (path, false),
        _ => return Err(unsupported(format!("the I/O URI {uri:?}"))),
    };
    let mut options = OpenOptions::new();
    if fifo {
        options.read(true).write(true);
        if input {
            options.custom_flags(libc::O_NONBLOCK);
        }
    } else {
        options.append(true).create(true).mode(0o644);
    }
    let file = options
        .open(path)
        .map_err(|error| internal(format!("cannot open {path}: {error}")))?;
    Ok(Some(file))
}

/// The threads of one process's streams.
pub struct Pumps {
    /// Disconnected once every output ended.
    outputs: mpsc::Receiver<()>,
    stop: Arc<AtomicBool>,
}

impl Pumps {
    /// Starts copying between the host ends and the streams of the guest service's process
    /// `guest_id`; an output without a host end is drained. The input ends once `closing` is set
    /// and what was readable then is forwarded, and is closed in the guest service at its end,
    /// or at once without a host end (but a terminal's, which would hang the terminal up).
    pub fn start(
        client: &Arc<GuestServiceClient>,
        guest_id: &str,
        host: [Option<File>; 3],
        terminal: bool,
        closing: Arc<AtomicBool>,
    ) -> Self {
        let [stdin, stdout, stderr] = host;
        let stop = Arc::new(AtomicBool::new(false));
        let (done, outputs) = mpsc::channel();
        let (client, guest_id) = (Arc::clone(client), guest_id.to_owned());
        if let Some(fifo) = stdin {
            let (client, guest_id, stop) =
                (Arc::clone(&client), guest_id.clone(), Arc::clone(&stop));
            std::thread::spawn(move || copy_input(&client, guest_id, &fifo, &closing, &stop));
        } else if !terminal {
            close_stdin(&client, guest_id.clone());
        }
        let outputs_of_process = if terminal {
            vec![(false, stdout)]
        } else {
            vec![(false, stdout), (true, stderr)]
        };
        for (is_stderr, sink) in outputs_of_process {
            let (client, guest_id, done) = (Arc::clone(&client), guest_id.clone(), done.clone());
            std::thread::spawn(move || {
                copy_output(&client, guest_id, is_stderr, sink);
                drop(done);
            });
        }
        Self { outputs, stop }
    }

    /// Waits up to `timeout` for every output to end; returns whether they did.
    pub fn drain(&self, timeout: Duration) -> bool {
        self.outputs.recv_timeout(timeout) != Err(mpsc::RecvTimeoutError::Timeout)
    }

    /// Stops the input.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn close_stdin(client: &GuestServiceClient, guest_id: String) {
    let request = CloseStdinRequest {
        exec_id: guest_id,
        ..Default::default()
    };
    let _ = client.close_stdin(Context::default(), &request);
}

fn copy_input(
    client: &GuestServiceClient,
    guest_id: String,
    fifo: &File,
    closing: &AtomicBool,
    stop: &AtomicBool,
) {
    let mut buffer = vec![0; CHUNK as usize];
    // Once closing, what is left of what was readable then.
    let mut left: Option<usize> = None;
    while !stop.load(Ordering::SeqCst) {
        if closing.load(Ordering::SeqCst) {
            let pending = rustix::io::ioctl_fionread(fifo).unwrap_or(0);
            if *left.get_or_insert(usize::try_from(pending).unwrap_or(usize::MAX)) == 0 {
                break;
            }
        }
        let mut fds = [PollFd::new(fifo, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        let _ = rustix::event::poll(&mut fds, Some(&timeout));
        let limit = left.unwrap_or(buffer.len()).min(buffer.len());
        let read = match (&*fifo).read(&mut buffer[..limit]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if let Some(left) = &mut left {
            *left -= read;
        }
        let request = WriteStreamRequest {
            exec_id: guest_id.clone(),
            data: buffer[..read].to_vec(),
            ..Default::default()
        };
        if client.write_stdin(Context::default(), &request).is_err() {
            break;
        }
    }
    // Once stopped, the process was released with its streams.
    if !stop.load(Ordering::SeqCst) {
        close_stdin(client, guest_id);
    }
}

/// Copies an output to `sink` until its end; a sink that fails is dropped, and the rest
/// drained, so that the process does not block.
fn copy_output(
    client: &GuestServiceClient,
    guest_id: String,
    stderr: bool,
    mut sink: Option<File>,
) {
    let request = ReadStreamRequest {
        exec_id: guest_id,
        len: CHUNK,
        ..Default::default()
    };
    loop {
        let read = if stderr {
            client.read_stderr(Context::default(), &request)
        } else {
            client.read_stdout(Context::default(), &request)
        };
        let Ok(response) = read else { break };
        if response.data.is_empty() {
            break;
        }
        if let Some(file) = &mut sink
            && file.write_all(&response.data).is_err()
        {
            sink = None;
        }
    }
}
