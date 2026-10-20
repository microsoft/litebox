// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The kernel's end of its [control channel](litebox_common_vm_control),
//! over virtio-vsock.
//!
//! The kernel listens on [`PORT`](protocol::PORT) and serves one connection
//! at a time, only from the host (the device ignores others), without
//! authentication: any host process that can connect controls the VM (see
//! the protocol's [trust model](litebox_common_vm_control#trust-model)). A
//! connection must say [`Request::Hello`] first; anything else gets a
//! best-effort [`Response::Error`], and the connection is closed. Once the
//! host disconnects, the kernel listens again, and the next connection must
//! say hello again. No host input panics the kernel: malformed or invalid
//! requests get [`Response::Error`] (a list longer than the protocol bounds
//! it to, see [`MAX_PROGRAMS`](protocol::MAX_PROGRAMS) and
//! [`MAX_STRINGS`](protocol::MAX_STRINGS), is a malformed message), and a
//! stream out of sync, or a host that stops reading its responses for
//! [`SEND_TIMEOUT`], loses its connection.
//!
//! Requests are served one at a time, on the boot CPU outside the
//! scheduler: a `Run` holds the channel until its programs end, and waiting
//! on the channel halts the CPU, so it happens only between requests.

use crate::devices::Vsock;
use crate::service::optee::{self, Optee};
use crate::service::program::Programs;
use crate::stdio::{Input, Stdio};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::ffi::CString;
use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::time::Duration;
use litebox_common_optee::{TeeLogin, TeeUuid};
use litebox_common_vm_abi::program::{ExitStatus, Program};
use litebox_common_vm_control::{
    self as protocol, Decoder, FrameError, Request, Response, RunResult, Service, Stdin, VERSION,
};
use litebox_hal::devices::VsockState;
use litebox_hal::{power, serial_println};
use litebox_shim_vm_kernel::optee::{Completion, EntryFunc, InParam, Invocation, OutParam};

/// How long a response may wait for the host to take it before the
/// connection is closed.
const SEND_TIMEOUT: Duration = Duration::from_mins(1);

/// How long the error before closing a connection may wait for the host.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(1);

/// How long [`Response::ShuttingDown`] may take to be queued to the device,
/// and then, again, to reach the host's socket, before the VM powers off
/// anyway: this phase takes up to twice this.
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

/// Then, how long the host may take to close the connection before the VM
/// powers off anyway.
const SHUTDOWN_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// What the kernel serves, as the payload decided.
pub enum Server {
    /// With the runs' standard streams.
    Programs(Box<Programs>, &'static Stdio),
    Optee(Optee),
}

/// Why no request was received.
enum ReceiveError {
    /// The host disconnected, or will send no more.
    Gone,
    Frame(FrameError),
}

/// The host disconnected, or stopped taking responses.
struct Gone;

/// Serves hosts on `vsock`, listening on [`PORT`](protocol::PORT) (see
/// [`Devices::vsock`](crate::devices::Devices::vsock)), until one shuts the
/// VM down.
pub fn serve(mut vsock: Vsock, mut server: Server) -> ! {
    litebox_util_log::info!(port:% = protocol::PORT; "control channel listening");
    loop {
        accept(&mut vsock);
        litebox_util_log::info!(
            peer_port:% = vsock.device.peer_port().unwrap_or_default();
            "control connection"
        );
        Connection {
            vsock: &mut vsock,
            decoder: Decoder::default(),
        }
        .serve(&mut server);
        vsock.device.close();
        litebox_util_log::info!("control connection closed");
    }
}

/// Waits for a connection.
fn accept(vsock: &mut Vsock) {
    loop {
        match vsock.device.state() {
            VsockState::Connected => return,
            // Gone before it was served.
            VsockState::Closed => vsock.device.close(),
            VsockState::Listening => vsock.wait(None),
        }
    }
}

struct Connection<'a> {
    vsock: &'a mut Vsock,
    decoder: Decoder,
}

impl Connection<'_> {
    /// Serves requests until the connection is to be closed.
    fn serve(&mut self, server: &mut Server) {
        let mut greeted = false;
        loop {
            let request = match self.receive() {
                Ok(request) => request,
                Err(ReceiveError::Gone) => return,
                Err(ReceiveError::Frame(error @ FrameError::Malformed)) if greeted => {
                    litebox_util_log::warn!(error:% = error; "control request malformed");
                    if self
                        .send(&Response::Error(error.to_string()), SEND_TIMEOUT)
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                Err(ReceiveError::Frame(error)) => return self.refuse(&error.to_string()),
            };
            let response = match request {
                Request::Hello { version } if version != VERSION => {
                    return self.refuse(&format!(
                        "version {version} unsupported: the kernel's is {VERSION}"
                    ));
                }
                Request::Hello { .. } => {
                    greeted = true;
                    Response::Hello {
                        version: VERSION,
                        service: match server {
                            Server::Programs(..) => Service::Programs,
                            Server::Optee(_) => Service::Optee,
                        },
                    }
                }
                request if !greeted => {
                    return self.refuse(&format!("{} before Hello", request.name()));
                }
                Request::Shutdown { success } => self.shut_down(success),
                request => serve_one(server, request),
            };
            if self.send(&response, SEND_TIMEOUT).is_err() {
                return;
            }
        }
    }

    /// Answers an error, best effort, before the connection is closed.
    fn refuse(&mut self, why: &str) {
        litebox_util_log::warn!(why:% = why; "control connection refused");
        let _ = self.send(&Response::Error(why.into()), REFUSAL_TIMEOUT);
    }

    /// The next request; waits for it.
    fn receive(&mut self) -> Result<Request, ReceiveError> {
        let mut buffer = [0u8; 4096];
        loop {
            if let Some(request) = self.decoder.next_message().map_err(ReceiveError::Frame)? {
                return Ok(request);
            }
            match self.vsock.device.read(&mut buffer) {
                None => return Err(ReceiveError::Gone),
                Some(0) => self.vsock.wait(None),
                Some(len) => self.decoder.push(&buffer[..len]),
            }
        }
    }

    /// Waits until all of `response` is queued to the device, within
    /// `timeout`, not until the host read it. A response too long for a
    /// frame becomes an error.
    fn send(&mut self, response: &Response, timeout: Duration) -> Result<(), Gone> {
        let frame = protocol::encode(response).unwrap_or_else(|error| {
            litebox_util_log::warn!(error:% = error; "response not sent");
            protocol::encode(&Response::Error(format!("response not sent: {error}")))
                .expect("an error fits a frame")
        });
        let deadline = self.vsock.deadline(timeout);
        let mut written = 0;
        loop {
            written += self.vsock.device.write(&frame[written..]).ok_or(Gone)?;
            if written == frame.len() {
                return Ok(());
            }
            if self.vsock.now() >= deadline {
                litebox_util_log::warn!("the host did not take a response");
                return Err(Gone);
            }
            self.vsock.wait(Some(deadline));
        }
    }

    /// Answers [`Response::ShuttingDown`], waits (bounded) for the host to
    /// have it and close the connection, then powers off. When QEMU tears
    /// the device down, the host's socket may end without what it still
    /// had queued, hence the wait for the host.
    fn shut_down(&mut self, success: bool) -> ! {
        if self
            .send(&Response::ShuttingDown, SHUTDOWN_FLUSH_TIMEOUT)
            .is_ok()
        {
            let deadline = self.vsock.deadline(SHUTDOWN_FLUSH_TIMEOUT);
            while !self.vsock.device.flushed() && self.vsock.now() < deadline {
                self.vsock.wait(Some(deadline));
            }
            let deadline = self.vsock.deadline(SHUTDOWN_CLOSE_TIMEOUT);
            let mut buffer = [0u8; 512];
            // Until the end of the stream, discarding anything sent before.
            while let Some(len) = self.vsock.device.read(&mut buffer) {
                if self.vsock.now() >= deadline {
                    litebox_util_log::warn!("the host did not close the control connection");
                    break;
                }
                if len == 0 {
                    self.vsock.wait(Some(deadline));
                }
            }
        }
        serial_println!("[litebox] the host shut the VM down (success: {success})");
        power::exit(success)
    }
}

fn serve_one(server: &mut Server, request: Request) -> Response {
    match (server, request) {
        (Server::Programs(programs, stdio), Request::Run { programs: runs }) => {
            run(programs, stdio, runs).unwrap_or_else(Response::Error)
        }
        (Server::Optee(optee), Request::Optee(call)) => {
            call_optee(optee, call).unwrap_or_else(Response::Error)
        }
        (Server::Optee(optee), Request::Processes) => Response::Processes(optee.processes()),
        // Programs' processes live only during a `Run`, which holds the
        // channel.
        (Server::Programs(..), Request::Processes) => Response::Processes(Vec::new()),
        (_, request) => Response::Error(format!("{} is not this kernel's service", request.name())),
    }
}

fn run(
    service: &mut Programs,
    stdio: &Stdio,
    runs: Vec<protocol::Program>,
) -> Result<Response, String> {
    // Decoding bounds the programs, to `MAX_PROGRAMS`, and their strings.
    if runs.is_empty() {
        return Err("a run has no programs".into());
    }
    let mut input = None;
    for run in &runs {
        let run_input = match &run.stdin {
            Stdin::Bytes(bytes) if bytes.is_empty() => continue,
            Stdin::Bytes(bytes) => Input::Given(bytes.iter().copied().collect()),
            Stdin::Console => Input::Console,
        };
        if input.replace(run_input).is_some() {
            return Err("programs run at once share standard input: one at most has input".into());
        }
    }
    let strings = |strings: &[String]| {
        strings
            .iter()
            .map(|string| CString::new(string.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| String::from("a string with NUL"))
    };
    let programs = runs
        .iter()
        .map(|run| {
            Ok(Program {
                path: run.argv.first().ok_or("an empty argv")?.clone(),
                argv: strings(&run.argv)?,
                envp: strings(&run.envp)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    for program in &programs {
        litebox_util_log::info!(path:% = program.path; "running");
    }
    stdio.start(input.unwrap_or(Input::Given(VecDeque::new())));
    let replies = service
        .run_concurrently(&programs)
        .map_err(|error| format!("failed to spawn a program runner: {error}"));
    let [stdout, stderr] = stdio.take();
    let runs = replies?
        .into_iter()
        .map(|reply| {
            litebox_util_log::info!(
                status:? = reply.status,
                reflected_syscalls:% = reply.reflected_syscalls;
                "ran"
            );
            RunResult {
                status: match reply.status {
                    Ok(ExitStatus::Exited { code }) => Ok(protocol::ExitStatus::Exited { code }),
                    Ok(ExitStatus::Signaled { signal }) => {
                        Ok(protocol::ExitStatus::Signaled { signal })
                    }
                    Ok(ExitStatus::Unknown) => Ok(protocol::ExitStatus::Unknown),
                    Err(error) => Err(format!("{error:?}")),
                },
                reflected_syscalls: reply.reflected_syscalls,
            }
        })
        .collect();
    Ok(Response::Ran {
        runs,
        stdout,
        stderr,
    })
}

fn call_optee(service: &mut Optee, call: protocol::OpteeCall) -> Result<Response, String> {
    let capacity = |capacity: u64| usize::try_from(capacity).map_err(|_| "a huge capacity");
    let mut params: [InParam; protocol::OPTEE_PARAMS] = Default::default();
    for (param, from) in params.iter_mut().zip(call.params) {
        *param = match from {
            protocol::InParam::None => InParam::None,
            protocol::InParam::ValueInput { a, b } => InParam::ValueInput { a, b },
            protocol::InParam::ValueOutput => InParam::ValueOutput,
            protocol::InParam::ValueInout { a, b } => InParam::ValueInout { a, b },
            protocol::InParam::MemrefInput(data) => InParam::MemrefInput(data),
            protocol::InParam::MemrefOutput { capacity: c } => InParam::MemrefOutput {
                capacity: capacity(c)?,
            },
            protocol::InParam::MemrefInout { data, capacity: c } => InParam::MemrefInout {
                data,
                capacity: capacity(c)?,
            },
        };
    }
    let invocation = Invocation {
        func: match call.func {
            protocol::EntryFunc::OpenSession => EntryFunc::OpenSession,
            protocol::EntryFunc::InvokeCommand => EntryFunc::InvokeCommand,
            protocol::EntryFunc::CloseSession => EntryFunc::CloseSession,
        },
        session: call.session,
        cmd_id: call.cmd_id,
        login: TeeLogin::try_from(call.login).map_err(|_| format!("login {}", call.login))?,
        client_uuid: TeeUuid::from_bytes(call.client_uuid),
        params,
    };
    let Completion {
        result,
        origin,
        session,
        params,
    } = service.call(optee::Request {
        ta: TeeUuid::from_bytes(call.ta),
        invocation,
    });
    Ok(Response::Optee(protocol::OpteeCompletion {
        result,
        origin,
        session,
        params: params.map(|param| match param {
            OutParam::None => protocol::OutParam::None,
            OutParam::Value { a, b } => protocol::OutParam::Value { a, b },
            OutParam::Memref { data, size } => protocol::OutParam::Memref { data, size },
        }),
    }))
}
