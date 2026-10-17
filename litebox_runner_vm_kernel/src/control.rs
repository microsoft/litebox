// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The kernel's end of its [control channel](litebox_common_vm_control).
//!
//! Requests are served one at a time, on the boot CPU outside the
//! scheduler: a `Run` holds the channel until its programs end, and waiting
//! on the channel halts the CPU, so it happens only between requests.

use crate::devices::Devices;
use crate::service::Service as _;
use crate::service::optee::{self, Optee};
use crate::service::program::Programs;
use crate::stdio::{Input, Stdio};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::ffi::CString;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;
use litebox_common_optee::{TeeLogin, TeeUuid};
use litebox_common_vm_abi::program::{ExitStatus, Program};
use litebox_common_vm_control::{
    self as protocol, Decoder, FrameError, Request, Response, RunResult, Service, Stdin, VERSION,
};
use litebox_hal::{power, serial_println};
use litebox_shim_vm_kernel::optee::{Completion, EntryFunc, InParam, Invocation, OutParam};

/// How long the [`Response::ShuttingDown`] may take to reach the host before
/// the VM powers off anyway.
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

/// What the kernel serves, as the payload decided.
pub enum Server {
    /// With the runs' standard streams.
    Programs(Box<Programs>, &'static Stdio),
    Optee(Optee),
}

struct Channel {
    devices: &'static Devices,
    decoder: Decoder,
}

/// Serves the host until it shuts the VM down. A missing or disconnected
/// host is not detected (see [`litebox_hal::virtio::console`]): it leaves
/// this waiting.
///
/// # Panics
///
/// If the console device does not support the control port (e.g., it is
/// not virtio, or lacks `MULTIPORT`), or the stream is out of sync (see
/// [`FrameError::TooLong`]).
pub fn serve(devices: &'static Devices, mut server: Server) -> ! {
    assert!(
        devices.has_control_port(),
        "no control channel: the console device lacks port {}",
        protocol::PORT
    );
    let mut channel = Channel {
        devices,
        decoder: Decoder::default(),
    };
    let mut greeted = false;
    loop {
        let response = match channel.receive() {
            Ok(Request::Hello { version }) if version == VERSION => {
                greeted = true;
                Response::Hello {
                    version: VERSION,
                    service: match server {
                        Server::Programs(..) => Service::Programs,
                        Server::Optee(_) => Service::Optee,
                    },
                }
            }
            Ok(Request::Hello { version }) => {
                greeted = false;
                Response::Error(format!(
                    "version {version} unsupported: the kernel's is {VERSION}"
                ))
            }
            Ok(_) if !greeted => Response::Error("no hello".into()),
            Ok(Request::Shutdown { success }) => channel.shut_down(success),
            Ok(request) => serve_one(&mut server, request),
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "malformed request");
                Response::Error(format!("{error}"))
            }
        };
        channel.send(&response);
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
        (Server::Optee(optee), Request::OpteeInstances) => {
            Response::OpteeInstances(optee.instance_count() as u64)
        }
        (_, request) => Response::Error(format!("{} is not this kernel's service", request.name())),
    }
}

fn run(
    service: &mut Programs,
    stdio: &Stdio,
    runs: Vec<protocol::Program>,
) -> Result<Response, String> {
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
    let replies = service.run_concurrently(&programs);
    let [stdout, stderr] = stdio.take();
    let runs = replies
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

impl Channel {
    /// # Panics
    ///
    /// If the stream is out of sync (see [`FrameError::TooLong`]).
    fn receive(&mut self) -> Result<Request, FrameError> {
        let mut buffer = [0u8; 512];
        loop {
            match self.decoder.next_message() {
                Ok(Some(request)) => return Ok(request),
                Ok(None) => {}
                Err(error @ FrameError::TooLong(_)) => panic!("control channel: {error}"),
                Err(error @ FrameError::Malformed(_)) => return Err(error),
            }
            let len = self.devices.control_read(&mut buffer);
            if len == 0 {
                self.devices.wait_for_console(None);
            } else {
                self.decoder.push(&buffer[..len]);
            }
        }
    }

    /// Waits until the device took all of `response`, which, for a
    /// `virtserialport`, is until the host read most of it.
    fn send(&mut self, response: &Response) {
        let frame = protocol::encode(response);
        let mut written = 0;
        loop {
            written += self.devices.control_write(&frame[written..]);
            if written == frame.len() {
                return;
            }
            self.devices.wait_for_console(None);
        }
    }

    fn shut_down(&mut self, success: bool) -> ! {
        self.send(&Response::ShuttingDown);
        if !self.devices.flush_control(SHUTDOWN_FLUSH_TIMEOUT) {
            litebox_util_log::warn!("the host did not take the shutdown response");
        }
        serial_println!("[litebox] the host shut the VM down (success: {success})");
        power::exit(success)
    }
}
