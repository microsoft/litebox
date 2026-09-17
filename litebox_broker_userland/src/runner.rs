// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable ownership for one out-of-process LiteBox runner.

use std::ffi::{OsStr, OsString};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use litebox_broker_core::BrokerCore;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

#[cfg(target_os = "linux")]
use linux::PlatformRunnerEndpoint;
#[cfg(all(windows, target_arch = "x86_64"))]
use windows::PlatformRunnerEndpoint;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);

/// Configuration for starting one out-of-process runner.
pub struct RunnerConfig {
    executable: PathBuf,
    arguments: Vec<OsString>,
    proxy_url: Option<String>,
}

impl RunnerConfig {
    /// Creates runner configuration with opaque arguments passed after the
    /// broker transport arguments.
    #[must_use]
    pub fn new(executable: PathBuf, arguments: Vec<OsString>) -> Self {
        Self {
            executable,
            arguments,
            proxy_url: None,
        }
    }

    /// Configures the HTTP proxy URL passed to the runner.
    #[must_use]
    pub fn with_proxy_url(mut self, proxy_url: String) -> Self {
        self.proxy_url = Some(proxy_url);
        self
    }

    fn arguments(&self, control_channel: &OsStr) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("--unstable"),
            OsString::from("--broker-control-channel"),
            control_channel.to_os_string(),
        ];
        if let Some(proxy_url) = &self.proxy_url {
            arguments.push(OsString::from("--broker-proxy-url"));
            arguments.push(OsString::from(proxy_url));
        }
        arguments.extend(self.arguments.iter().cloned());
        arguments
    }
}

/// One out-of-process runner and its dedicated broker control endpoint.
///
/// Dropping an instance before [`Self::run_to_completion`] completes
/// terminates and reaps the runner.
pub struct RunnerInstance {
    runner: Child,
    endpoint: PlatformRunnerEndpoint,
}

impl RunnerInstance {
    /// Creates the runner's dedicated control endpoint and starts the runner.
    pub fn start(config: RunnerConfig) -> IoResult<Self> {
        let endpoint = PlatformRunnerEndpoint::create()?;
        let runner = Command::new(&config.executable)
            .args(config.arguments(endpoint.control_channel()))
            .spawn()?;
        Ok(Self { runner, endpoint })
    }

    /// Serves the runner's broker association and waits for its host process.
    ///
    /// Association failure terminates the runner before it is reaped. A
    /// non-successful runner exit is returned as ordinary instance data for the
    /// caller to interpret.
    pub fn run_to_completion(mut self, broker: &BrokerCore) -> IoResult<ExitStatus> {
        let association_result = self.endpoint.serve(broker, &mut self.runner);
        self.endpoint.close();
        if association_result.is_err() {
            let _ = self.runner.kill();
        }
        let runner_status = self.runner.wait()?;
        association_result?;
        Ok(runner_status)
    }
}

/// Runs every configured runner concurrently and waits for all of them.
///
/// Results retain configuration order. A runner's launch, association, or
/// exit does not stop the other runners.
pub fn run_all_to_completion(
    broker: BrokerCore,
    runners: Vec<RunnerConfig>,
) -> Vec<IoResult<ExitStatus>> {
    let workers = runners
        .into_iter()
        .enumerate()
        .map(|(runner_index, config)| {
            let broker = broker.clone();
            std::thread::Builder::new()
                .name(format!("litebox-runner-{runner_index}"))
                .spawn(move || RunnerInstance::start(config)?.run_to_completion(&broker))
        })
        .collect::<Vec<_>>();

    workers
        .into_iter()
        .map(|worker| match worker {
            Ok(worker) => worker
                .join()
                .unwrap_or_else(|_| Err(IoError::other("runner worker panicked"))),
            Err(error) => Err(IoError::new(
                error.kind(),
                format!("failed to start runner worker: {error}"),
            )),
        })
        .collect()
}

impl Drop for RunnerInstance {
    fn drop(&mut self) {
        self.endpoint.close();
        if !matches!(self.runner.try_wait(), Ok(Some(_status))) {
            let _ = self.runner.kill();
            let _ = self.runner.wait();
        }
    }
}

fn accept_runner_channel<Channel>(
    deadline: Instant,
    channel_name: &'static str,
    mut runner_status: impl FnMut() -> IoResult<Option<String>>,
    mut try_accept: impl FnMut() -> IoResult<Channel>,
) -> IoResult<Channel> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IoError::new(
                ErrorKind::TimedOut,
                format!("timed out waiting for runner {channel_name} channel"),
            ));
        }
        if let Some(status) = runner_status()? {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                format!("runner {status} before connecting its {channel_name} channel"),
            ));
        }
        match try_accept() {
            Ok(channel) => return Ok(channel),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(remaining.min(ACCEPT_RETRY_DELAY));
    }
}
