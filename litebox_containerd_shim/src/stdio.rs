// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A process's standard streams: the host ends that containerd names, `binary://` logging
//! programs (Unix only), and the threads that copy between the host ends and the guest service.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::fs::File;
use std::io::{self, Read as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use containerd_shim::protos::events::task::TaskIO;
use containerd_shim::protos::ttrpc::context::Context;
use litebox_guest_service_protocol::guest_service::{
    CloseStdinRequest, ReadStreamRequest, WriteStreamRequest,
};
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;
use url::Url;

#[cfg(unix)]
pub use self::unix::Logger;
#[cfg(unix)]
use self::unix::{Output, create_dirs, open_fifo, open_file, pending, wait_readable};
#[cfg(windows)]
pub use self::windows::Logger;
#[cfg(windows)]
use self::windows::{Output, create_dirs, open_fifo, open_file, pending, wait_readable};
use crate::{Result, internal, unsupported};

/// The most bytes one read carries.
const CHUNK: u32 = 64 * 1024;

/// How often a waiting input checks whether to end.
const INPUT_POLL: Duration = Duration::from_millis(100);

/// How long a blocked write to a host end waits before it checks again whether to give up.
const WRITE_POLL: Duration = Duration::from_secs(1);

fn open(uri: &str, input: bool) -> Result<Option<File>> {
    let (path, fifo) = match uri.split_once("://") {
        _ if uri.is_empty() => return Ok(None),
        None => (PathBuf::from(uri), true),
        Some(("fifo", path)) => (PathBuf::from(path), true),
        Some(("file", _)) if !input => (parse(uri)?.1, false),
        _ => return Err(unsupported(format!("the I/O URI {uri:?}"))),
    };
    let file = if fifo {
        open_fifo(&path, input)
    } else {
        if let Some(parent) = path.parent() {
            create_dirs(parent).map_err(|error| {
                internal(format!("cannot create {}: {error}", parent.display()))
            })?;
        }
        open_file(&path)
    };
    let file =
        file.map_err(|error| internal(format!("cannot open {}: {error}", path.display())))?;
    Ok(Some(file))
}

fn open_output(uri: &str) -> Result<Option<Output>> {
    let Some(file) = open(uri, false)? else {
        return Ok(None);
    };
    Output::new(file)
        .map(Some)
        .map_err(|error| internal(format!("cannot open {uri}: {error}")))
}

/// The URI `uri`, which must have no host, and its percent-decoded path.
fn parse(uri: &str) -> Result<(Url, PathBuf)> {
    let refuse = || unsupported(format!("the I/O URI {uri:?}"));
    let url = Url::parse(uri).map_err(|_| refuse())?;
    let path = url.to_file_path().map_err(|()| refuse())?;
    Ok((url, path))
}

#[derive(Default)]
pub struct Ends {
    stdin: Option<File>,
    stdout: Option<Output>,
    stderr: Option<Output>,
}

pub struct Host {
    pub ends: Ends,
    /// After `ends`, so that its inputs end before it is reaped.
    pub logger: Option<Logger>,
}

impl Host {
    /// Opens the host ends of `io` for the container `id` of the containerd namespace
    /// `namespace`. As with containerd's runc shim, a `binary://` stdout names a logging program
    /// that reads stderr too, and a terminal's output is all stdout.
    pub fn open(io: &TaskIO, id: &str, namespace: &str) -> Result<Self> {
        let stdin = open(&io.stdin, true)?;
        if io.stdout.starts_with("binary://") {
            let (logger, stdout, stderr) = Logger::spawn(&io.stdout, id, namespace)?;
            let ends = Ends {
                stdin,
                stdout: Some(stdout),
                stderr: (!io.terminal).then_some(stderr),
            };
            return Ok(Self {
                ends,
                logger: Some(logger),
            });
        }
        let stderr = if io.terminal {
            None
        } else {
            open_output(&io.stderr)?
        };
        let ends = Ends {
            stdin,
            stdout: open_output(&io.stdout)?,
            stderr,
        };
        Ok(Self { ends, logger: None })
    }
}

/// The threads of one process's streams, and what its output's copiers do.
pub struct Pumps {
    /// Disconnected once every output ended.
    outputs: mpsc::Receiver<()>,
    activity: Arc<Mutex<Activity>>,
    stop: Arc<AtomicBool>,
}

/// What the output copiers do.
struct Activity {
    /// How many are writing data they read to their host end (or dropping it, without one).
    copying: usize,
    /// When one last finished copying, or the copiers started.
    last: Instant,
}

impl Pumps {
    /// Starts copying between the host ends and the streams of the guest service's process
    /// `guest_id`; an output without a host end is drained. The input ends once `closing` is set
    /// and what was readable then is forwarded, and is closed in the guest service at its end,
    /// or at once without a host end (but a terminal's, which would hang the terminal up). An
    /// output stops writing to its host end once `deleted` is set.
    pub fn start(
        client: &Arc<GuestServiceClient>,
        guest_id: &str,
        Ends {
            stdin,
            stdout,
            stderr,
        }: Ends,
        terminal: bool,
        closing: Arc<AtomicBool>,
        deleted: Arc<AtomicBool>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let (done, outputs) = mpsc::channel();
        let activity = Arc::new(Mutex::new(Activity {
            copying: 0,
            last: Instant::now(),
        }));
        let (client, guest_id) = (Arc::clone(client), guest_id.to_owned());
        if let Some(fifo) = stdin {
            let (client, guest_id, stop) =
                (Arc::clone(&client), guest_id.clone(), Arc::clone(&stop));
            std::thread::spawn(move || copy_input(&client, guest_id, &fifo, &closing, &stop));
        } else if !terminal {
            // From a thread, as the caller holds the shim's locks.
            let (client, guest_id) = (Arc::clone(&client), guest_id.clone());
            std::thread::spawn(move || close_stdin(&client, guest_id));
        }
        let outputs_of_process = if terminal {
            vec![(false, stdout)]
        } else {
            vec![(false, stdout), (true, stderr)]
        };
        for (is_stderr, sink) in outputs_of_process {
            let (client, guest_id, done) = (Arc::clone(&client), guest_id.clone(), done.clone());
            let (activity, deleted) = (Arc::clone(&activity), Arc::clone(&deleted));
            std::thread::spawn(move || {
                copy_output(&client, guest_id, is_stderr, sink, &activity, &deleted);
                drop(done);
            });
        }
        Self {
            outputs,
            activity,
            stop,
        }
    }

    /// Waits up to `timeout` for every output to end; returns whether they did.
    pub fn drain(&self, timeout: Duration) -> bool {
        self.outputs.recv_timeout(timeout) != Err(mpsc::RecvTimeoutError::Timeout)
    }

    /// Waits for every output to end, without a time limit while one copies data to its host
    /// end or did within `idle`, until `deleted` is set (seen within `idle`); returns whether
    /// they ended.
    pub fn finish(&self, idle: Duration, deleted: &AtomicBool) -> bool {
        loop {
            let activity = self.activity.lock().expect("not poisoned");
            let wait = if activity.copying > 0 {
                idle
            } else {
                idle.saturating_sub(activity.last.elapsed())
            };
            drop(activity);
            match self.outputs.recv_timeout(wait) {
                Err(mpsc::RecvTimeoutError::Timeout)
                    if wait.is_zero() || deleted.load(Ordering::SeqCst) =>
                {
                    return false;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                _ => return true,
            }
        }
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
    // A terminal whose process has not started refuses, and stays open, as runc keeps a terminal
    // open when stdin ends.
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
        if closing.load(Ordering::SeqCst) && *left.get_or_insert_with(|| pending(fifo)) == 0 {
            break;
        }
        if !wait_readable(fifo) {
            continue;
        }
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

/// Copies an output to `sink` until its end, noting it in `activity`; a sink that fails, or
/// blocks once `deleted` is set, is dropped, and the rest drained, so that the process does not
/// block.
fn copy_output(
    client: &GuestServiceClient,
    guest_id: String,
    stderr: bool,
    mut sink: Option<Output>,
    activity: &Mutex<Activity>,
    deleted: &AtomicBool,
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
        activity.lock().expect("not poisoned").copying += 1;
        if let Some(output) = &sink
            && output.write_all(&response.data, deleted).is_err()
        {
            sink = None;
        }
        let mut activity = activity.lock().expect("not poisoned");
        activity.copying -= 1;
        activity.last = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;

    use containerd_shim::protos::ttrpc::{self, TtrpcContext};
    use litebox_guest_service_protocol::guest_service::{CloseStdinRequest, Empty};
    use litebox_guest_service_protocol::guest_service_ttrpc::{
        GuestService, GuestServiceClient, create_guest_service,
    };

    use super::Pumps;

    /// A guest service whose `CloseStdin` reports its exec ID, then answers once released.
    struct Gated {
        called: mpsc::Sender<String>,
        gate: Mutex<mpsc::Receiver<()>>,
    }

    impl GuestService for Gated {
        fn close_stdin(
            &self,
            _: &TtrpcContext,
            request: CloseStdinRequest,
        ) -> ttrpc::Result<Empty> {
            let _ = self.called.send(request.exec_id);
            let _ = self.gate.lock().unwrap().recv();
            Ok(Empty::new())
        }
    }

    #[test]
    fn closing_a_missing_stdin_does_not_wait_for_the_answer() {
        #[cfg(unix)]
        let (_dir, address) = {
            let dir = tempfile::tempdir().unwrap();
            let address = format!("unix://{}", dir.path().join("socket").display());
            (dir, address)
        };
        #[cfg(windows)]
        let address = format!(r"\\.\pipe\litebox-shim-stdio-test-{}", std::process::id());
        let (called, calls) = mpsc::channel();
        let (unblock, blocked) = mpsc::channel();
        let gate = Mutex::new(blocked);
        let service = Arc::new(Gated { called, gate });
        let mut server = ttrpc::Server::new()
            .bind(&address)
            .unwrap()
            .register_service(create_guest_service(service));
        server.start().unwrap();
        // On Windows, the server creates its pipe once it runs.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let client = loop {
            match ttrpc::Client::connect(&address) {
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                client => break client.unwrap(),
            }
        };
        let client = Arc::new(GuestServiceClient::new(client));
        let (done, returned) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let pumps = Pumps::start(
                &client,
                "1",
                super::Ends::default(),
                false,
                Arc::default(),
                Arc::default(),
            );
            let _ = done.send(());
            pumps
        });
        let returned = returned.recv_timeout(Duration::from_secs(5));
        let call = calls.recv_timeout(Duration::from_secs(5));
        unblock.send(()).unwrap();
        let pumps = thread.join().unwrap();
        // Read requests fail with `NOT_FOUND`, which ends the outputs.
        assert!(pumps.drain(Duration::from_secs(5)));
        server.shutdown();
        assert_eq!(returned, Ok(()), "`Pumps::start` waited for `CloseStdin`");
        assert_eq!(call.as_deref(), Ok("1"));
    }
}
