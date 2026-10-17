// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Drives the LiteBox VM kernel from the host over its control channel: runs
//! a test file's requests, checks each response, then shuts the VM down,
//! with success if every check passed. Exits with 0 if they did, 1 if not,
//! and 2 or more on an error, after which the VM may still be running.
//!
//! - `programs <runs.json>` (programs kernel): an array of runs, or of
//!   `{ "concurrent": [...] }` groups of runs started together. A run:
//!   - `argv`: `argv[0]` is the program's absolute path (e.g., in the
//!     payload's `rootfs.tar`).
//!   - `envp`: `KEY=VALUE` strings (default none).
//!   - `stdin`: the run's standard input, after which it ends (default: none,
//!     as `/dev/null`).
//!   - `console_stdin`: default false; if true (without `stdin`), the run's
//!     standard input is the console's: what the host sends it, when it
//!     sends it. It never ends.
//!   - `expect_exit_code` (default 0), or `expect_signal` for a signal death.
//!   - `expect_stdout`, `expect_stderr`: the exact output, if given.
//!   - `min_reflected_syscalls`: default 0; guest syscalls the runner did not
//!     take directly, so the kernel reflected them.
//!
//!   In a group, runs share standard input and output, so they take no
//!   `stdin`, `expect_stdout`, or `expect_stderr`, and at most one takes
//!   `console_stdin`.
//!
//! - `optee --tas <dir> [<cmds.json>]` (OP-TEE kernel): the TAs are
//!   `<dir>/<name>.elf`, as in the payload. `cmds.json` is the format of
//!   `litebox_runner_optee_on_linux_userland/tests/*-cmds.json` plus
//!   optional:
//!   - `ta`: the `open_session` target; required with more than one TA.
//!   - `session`: a label (default `default`).
//!   - `expect_result`: default success.
//!   - `expect_instances`: live instances after the command.
//!
//!   An entry may instead be `{ "kill": <TA>, "expect_instances": ... }`,
//!   which kills every live instance of the TA, as `pkill` would.
//!   - In output arguments: `expect_value_a`, `expect_value_b`,
//!     `expect_size`, `expect_data_base64`.
//!
//!   Without it, opens and closes a session to the only TA twice.

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use litebox_common_vm_control::{
    Captured, EntryFunc, ExitStatus, InParam, OPTEE_PARAMS, OpteeCall, OutParam, ProcessInfo,
    Program, Request, Response, Service, Stdin,
};
use litebox_vm_host::Connection;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
struct Cli {
    /// The Unix socket of the VM's control channel.
    #[arg(long)]
    socket: PathBuf,
    /// How long to retry connecting, in seconds (e.g., while QEMU starts).
    #[arg(long, default_value_t = 30)]
    connect_timeout: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Runs the programs of a runs file in order.
    Programs { runs: PathBuf },
    /// Runs OP-TEE client commands against the payload's TAs.
    Optee {
        /// The directory of the TAs, `<name>.elf`.
        #[arg(long)]
        tas: PathBuf,
        cmds: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("[host] error: {error:#}");
            std::process::exit(2);
        }
    }
}

/// Whether every check passed.
fn run(cli: &Cli) -> Result<bool> {
    let mut connection =
        Connection::connect(&cli.socket, Duration::from_secs(cli.connect_timeout))?;
    let service = match cli.command {
        Command::Programs { .. } => Service::Programs,
        Command::Optee { .. } => Service::Optee,
    };
    ensure!(
        connection.service() == service,
        "the kernel serves {:?}",
        connection.service()
    );
    let passed = match &cli.command {
        Command::Programs { runs } => programs(&mut connection, runs)?,
        Command::Optee { tas, cmds } => optee(&mut connection, tas, cmds.as_deref())?,
    };
    connection.shutdown(passed)?;
    Ok(passed)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Entry {
    Run(Run),
    Concurrent(Concurrent),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Concurrent {
    concurrent: Vec<Run>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    argv: Vec<String>,
    #[serde(default)]
    envp: Vec<String>,
    #[serde(default)]
    stdin: String,
    #[serde(default)]
    console_stdin: bool,
    expect_exit_code: Option<u32>,
    expect_signal: Option<u32>,
    expect_stdout: Option<String>,
    expect_stderr: Option<String>,
    #[serde(default)]
    min_reflected_syscalls: u64,
}

/// Runs a runs file's groups in order; returns whether all passed.
fn programs(connection: &mut Connection, path: &Path) -> Result<bool> {
    let json = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let entries: Vec<Entry> =
        serde_json::from_slice(&json).with_context(|| format!("parsing {}", path.display()))?;
    ensure!(!entries.is_empty(), "{} has no runs", path.display());
    let mut passed = true;
    let mut index = 0;
    for entry in entries {
        let group = match entry {
            Entry::Run(run) => vec![run],
            Entry::Concurrent(Concurrent { concurrent }) => {
                ensure!(
                    concurrent.iter().all(|run| run.stdin.is_empty()
                        && run.expect_stdout.is_none()
                        && run.expect_stderr.is_none()),
                    "runs {index}..: concurrent runs share standard streams, so they take no \
                     `stdin`, `expect_stdout`, or `expect_stderr`"
                );
                concurrent
            }
        };
        let programs = group
            .iter()
            .map(|run| {
                ensure!(
                    !run.console_stdin || run.stdin.is_empty(),
                    "`stdin` and `console_stdin` exclude each other"
                );
                Ok(Program {
                    argv: run.argv.clone(),
                    envp: run.envp.clone(),
                    stdin: if run.console_stdin {
                        Stdin::Console
                    } else {
                        Stdin::Bytes(run.stdin.clone().into_bytes())
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let Response::Ran {
            runs,
            stdout,
            stderr,
        } = connection.call(&Request::Run { programs })?
        else {
            bail!("unexpected response to a run");
        };
        ensure!(runs.len() == group.len(), "{} results", runs.len());
        for (run, result) in group.iter().zip(runs) {
            let path = &run.argv[0];
            match check_run(run, result, &stdout, &stderr) {
                Ok(()) => eprintln!("[host] PASS run {index} ({path})"),
                Err(why) => {
                    eprintln!("[host] FAIL run {index} ({path}): {why}");
                    passed = false;
                }
            }
            index += 1;
        }
    }
    Ok(passed)
}

/// Checks how a run ended; `stdout` and `stderr` are what its group wrote.
fn check_run(
    run: &Run,
    result: litebox_common_vm_control::RunResult,
    stdout: &Captured,
    stderr: &Captured,
) -> Result<(), String> {
    let expected = match (run.expect_exit_code, run.expect_signal) {
        (code, None) => ExitStatus::Exited {
            code: code.unwrap_or(0),
        },
        (None, Some(signal)) => ExitStatus::Signaled { signal },
        (Some(_), Some(_)) => {
            return Err("`expect_exit_code` and `expect_signal` exclude each other".into());
        }
    };
    let status = result
        .status
        .map_err(|error| format!("did not run: {error}"))?;
    if status != expected {
        return Err(format!("exit status {status:?}, expected {expected:?}"));
    }
    for (what, expected, actual) in [
        ("stdout", &run.expect_stdout, stdout),
        ("stderr", &run.expect_stderr, stderr),
    ] {
        if let Some(expected) = expected {
            if actual.truncated {
                return Err(format!("{what} exceeded what the kernel captures"));
            }
            if expected.as_bytes() != actual.bytes {
                return Err(format!(
                    "{what} was {:?}, expected {expected:?}",
                    String::from_utf8_lossy(&actual.bytes)
                ));
            }
        }
    }
    if result.reflected_syscalls < run.min_reflected_syscalls {
        return Err(format!(
            "{} reflected syscalls, expected at least {}",
            result.reflected_syscalls, run.min_reflected_syscalls
        ));
    }
    Ok(())
}

const DEFAULT_SESSION: &str = "default";

/// Runs `cmds` (or the default commands) against the TAs in `tas`; returns
/// whether all passed. A failure ends the run: later commands may depend on
/// it.
fn optee(connection: &mut Connection, tas: &Path, cmds: Option<&Path>) -> Result<bool> {
    // A client knows its TAs' UUIDs.
    let mut uuids: Vec<(String, [u8; 16])> = Vec::new();
    for entry in std::fs::read_dir(tas).with_context(|| format!("reading {}", tas.display()))? {
        let path = entry?.path();
        let Some(name) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".elf"))
        else {
            continue;
        };
        let image = std::fs::read(&path)?;
        let head = litebox_common_optee::parse_ta_head(&image)
            .with_context(|| format!("malformed TA header: {}", path.display()))?;
        uuids.push((name.into(), head.uuid.to_bytes()));
    }
    let commands: Vec<OpteeEntry> = match cmds {
        Some(path) => {
            let json =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_slice(&json).with_context(|| format!("parsing {}", path.display()))?
        }
        None => [
            TaEntryFunc::OpenSession,
            TaEntryFunc::CloseSession,
            TaEntryFunc::OpenSession,
            TaEntryFunc::CloseSession,
        ]
        .into_iter()
        .map(|func| OpteeEntry::Command(TaCommand::new(func)))
        .collect(),
    };
    let mut sessions: BTreeMap<String, u32> = BTreeMap::new();
    for (index, entry) in commands.iter().enumerate() {
        let (what, result) = match entry {
            OpteeEntry::Command(cmd) => (
                format!(
                    "{:?}, session {:?}",
                    cmd.func_id,
                    cmd.session.as_deref().unwrap_or(DEFAULT_SESSION)
                ),
                optee_command(connection, &uuids, &mut sessions, cmd),
            ),
            OpteeEntry::Kill(kill) => (
                format!("kill {}", kill.kill),
                kill_ta(connection, &uuids, kill),
            ),
        };
        if let Err(why) = result {
            eprintln!("[host] FAIL command {index} ({what}): {why:#}");
            return Ok(false);
        }
        eprintln!("[host] PASS command {index} ({what})");
    }
    Ok(true)
}

/// Kills every live instance of a TA, as `pkill` would.
fn kill_ta(connection: &mut Connection, tas: &[(String, [u8; 16])], kill: &Kill) -> Result<()> {
    let uuid = tas
        .iter()
        .find(|(ta, _)| *ta == kill.kill)
        .with_context(|| format!("no TA named {:?}", kill.kill))?
        .1;
    let name = ProcessInfo::ta_name(&uuid);
    let ids: Vec<u64> = processes(connection)?
        .into_iter()
        .filter(|process| process.name == name)
        .map(|process| process.id)
        .collect();
    ensure!(!ids.is_empty(), "no live instance");
    for id in ids {
        let Response::Killed = connection.call(&Request::Kill { id })? else {
            bail!("unexpected response to a kill");
        };
    }
    check_instances(connection, kill.expect_instances)
}

fn processes(connection: &mut Connection) -> Result<Vec<ProcessInfo>> {
    let Response::Processes(processes) = connection.call(&Request::Processes)? else {
        bail!("unexpected response to a process list");
    };
    Ok(processes)
}

fn check_instances(connection: &mut Connection, expected: Option<usize>) -> Result<()> {
    if let Some(expected) = expected {
        let live = processes(connection)?.len();
        ensure!(
            live == expected,
            "{live} live TA instances, expected {expected}"
        );
    }
    Ok(())
}

fn optee_command(
    connection: &mut Connection,
    tas: &[(String, [u8; 16])],
    sessions: &mut BTreeMap<String, u32>,
    cmd: &TaCommand,
) -> Result<()> {
    let label = cmd.session.as_deref().unwrap_or(DEFAULT_SESSION);
    let open = matches!(cmd.func_id, TaEntryFunc::OpenSession);
    let ta = if open {
        if let Some(name) = &cmd.ta {
            tas.iter()
                .find(|(ta, _)| ta == name)
                .with_context(|| format!("no TA named {name:?}"))?
                .1
        } else {
            ensure!(tas.len() == 1, "`ta` is required with several TAs");
            tas[0].1
        }
    } else {
        [0; 16]
    };
    ensure!(cmd.args.len() <= OPTEE_PARAMS, "more than four arguments");
    let mut params: [InParam; OPTEE_PARAMS] = Default::default();
    for (param, arg) in params.iter_mut().zip(&cmd.args) {
        *param = arg.to_in_param()?;
    }
    let call = OpteeCall {
        ta,
        func: cmd.func_id.into(),
        // An unknown label means an unknown session; 0 is never one.
        session: if open {
            0
        } else {
            sessions.get(label).copied().unwrap_or(0)
        },
        cmd_id: cmd.cmd_id,
        login: cmd
            .client_identity
            .as_ref()
            .map_or(ClientLoginJson::User, |id| id.login)
            .value(),
        client_uuid: cmd
            .client_identity
            .as_ref()
            .and_then(|id| id.uuid.as_deref())
            .map(parse_uuid)
            .transpose()?
            .unwrap_or([0; 16]),
        params,
    };
    let Response::Optee(completion) = connection.call(&Request::Optee(call))? else {
        bail!("unexpected response to an OP-TEE call");
    };
    let expected = cmd.expect_result.unwrap_or(0);
    ensure!(
        completion.result == expected,
        "result {:#x} (origin {}), expected {expected:#x}",
        completion.result,
        completion.origin
    );
    // A closed session keeps its label, so later commands send its stale ID.
    if open && completion.result == 0 {
        sessions.insert(label.into(), completion.session);
    }
    check_instances(connection, cmd.expect_instances)?;
    for (arg, (param, out)) in cmd.args.iter().zip(&completion.params).enumerate() {
        param
            .check(out)
            .with_context(|| format!("argument {arg}"))?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OpteeEntry {
    Kill(Kill),
    Command(TaCommand),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kill {
    /// A TA's name.
    kill: String,
    #[serde(default)]
    expect_instances: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct TaCommand {
    func_id: TaEntryFunc,
    #[serde(default)]
    cmd_id: u32,
    #[serde(default)]
    args: Vec<TaCommandParam>,
    #[serde(default)]
    client_identity: Option<ClientIdentityJson>,
    #[serde(default)]
    ta: Option<String>,
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    expect_result: Option<u32>,
    #[serde(default)]
    expect_instances: Option<usize>,
}

impl TaCommand {
    fn new(func_id: TaEntryFunc) -> Self {
        Self {
            func_id,
            cmd_id: 0,
            args: Vec::new(),
            client_identity: None,
            ta: None,
            session: None,
            expect_result: None,
            expect_instances: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClientIdentityJson {
    #[serde(default)]
    login: ClientLoginJson,
    #[serde(default)]
    uuid: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClientLoginJson {
    Public,
    #[default]
    User,
    Group,
    Application,
    ApplicationUser,
    ApplicationGroup,
    ReeKernel,
    TrustedApp,
}

impl ClientLoginJson {
    /// `TEE_LOGIN_*`.
    fn value(self) -> u32 {
        use litebox_common_optee::TeeLogin;
        (match self {
            Self::Public => TeeLogin::Public,
            Self::User => TeeLogin::User,
            Self::Group => TeeLogin::Group,
            Self::Application => TeeLogin::Application,
            Self::ApplicationUser => TeeLogin::ApplicationUser,
            Self::ApplicationGroup => TeeLogin::ApplicationGroup,
            Self::ReeKernel => TeeLogin::ReeKernel,
            Self::TrustedApp => TeeLogin::TrustedApp,
        }) as u32
    }
}

fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|&c| c != '-').collect();
    ensure!(
        hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "client uuid must be 32 hex digits: {s:?}"
    );
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TaEntryFunc {
    OpenSession,
    CloseSession,
    InvokeCommand,
}

impl From<TaEntryFunc> for EntryFunc {
    fn from(func: TaEntryFunc) -> Self {
        match func {
            TaEntryFunc::OpenSession => EntryFunc::OpenSession,
            TaEntryFunc::CloseSession => EntryFunc::CloseSession,
            TaEntryFunc::InvokeCommand => EntryFunc::InvokeCommand,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "param_type", rename_all = "snake_case")]
enum TaCommandParam {
    ValueInput {
        value_a: u64,
        value_b: u64,
    },
    ValueOutput {
        #[serde(flatten)]
        expect: ExpectValue,
    },
    ValueInout {
        value_a: u64,
        value_b: u64,
        #[serde(flatten)]
        expect: ExpectValue,
    },
    MemrefInput {
        data_base64: String,
    },
    MemrefOutput {
        buffer_size: u64,
        #[serde(flatten)]
        expect: ExpectMemref,
    },
    MemrefInout {
        data_base64: String,
        buffer_size: u64,
        #[serde(flatten)]
        expect: ExpectMemref,
    },
}

#[derive(Debug, Default, Deserialize)]
struct ExpectValue {
    expect_value_a: Option<u64>,
    expect_value_b: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct ExpectMemref {
    expect_size: Option<u64>,
    expect_data_base64: Option<String>,
}

impl TaCommandParam {
    fn to_in_param(&self) -> Result<InParam> {
        Ok(match self {
            Self::ValueInput { value_a, value_b } => InParam::ValueInput {
                a: *value_a,
                b: *value_b,
            },
            Self::ValueOutput { .. } => InParam::ValueOutput,
            Self::ValueInout {
                value_a, value_b, ..
            } => InParam::ValueInout {
                a: *value_a,
                b: *value_b,
            },
            Self::MemrefInput { data_base64 } => InParam::MemrefInput(decode_base64(data_base64)?),
            Self::MemrefOutput { buffer_size, .. } => InParam::MemrefOutput {
                capacity: *buffer_size,
            },
            Self::MemrefInout {
                data_base64,
                buffer_size,
                ..
            } => {
                let data = decode_base64(data_base64)?;
                ensure!(
                    *buffer_size >= data.len() as u64,
                    "buffer size is smaller than the input data"
                );
                InParam::MemrefInout {
                    data,
                    capacity: *buffer_size,
                }
            }
        })
    }

    /// Fails if `out` does not match the expectations.
    fn check(&self, out: &OutParam) -> Result<()> {
        match (self, out) {
            (
                Self::ValueOutput { expect } | Self::ValueInout { expect, .. },
                OutParam::Value { a, b },
            ) => {
                for (name, expected, actual) in [
                    ("value_a", expect.expect_value_a, a),
                    ("value_b", expect.expect_value_b, b),
                ] {
                    if let Some(expected) = expected {
                        ensure!(
                            expected == *actual,
                            "{name} {actual:#x}, expected {expected:#x}"
                        );
                    }
                }
            }
            (
                Self::MemrefOutput { expect, .. } | Self::MemrefInout { expect, .. },
                OutParam::Memref { data, size },
            ) => {
                if let Some(expected) = expect.expect_size {
                    ensure!(expected == *size, "size {size}, expected {expected}");
                }
                if let Some(expected) = &expect.expect_data_base64 {
                    ensure!(
                        *data == decode_base64(expected)?,
                        "data {}, expected {expected}",
                        base64::engine::general_purpose::STANDARD.encode(data)
                    );
                }
            }
            (Self::ValueOutput { expect } | Self::ValueInout { expect, .. }, OutParam::None) => {
                ensure!(
                    expect.expect_value_a.is_none() && expect.expect_value_b.is_none(),
                    "no output"
                );
            }
            (
                Self::MemrefOutput { expect, .. } | Self::MemrefInout { expect, .. },
                OutParam::None,
            ) => {
                ensure!(
                    expect.expect_size.is_none() && expect.expect_data_base64.is_none(),
                    "no output"
                );
            }
            _ => {}
        }
        Ok(())
    }
}

fn decode_base64(data_base64: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(data_base64)
        .context("malformed base64 data")
}
