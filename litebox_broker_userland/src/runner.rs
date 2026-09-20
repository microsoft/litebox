// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable ownership for one out-of-process LiteBox runner.

use std::ffi::{OsStr, OsString};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use litebox_broker_core::BrokerCore;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

use crate::process_launcher::{PendingRunnerAssociation, UserlandProcessLauncher};
#[cfg(target_os = "linux")]
use linux::PlatformRunnerEndpoint;
#[cfg(all(windows, target_arch = "x86_64"))]
use windows::PlatformRunnerEndpoint;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_EXIT_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);

/// Configuration for starting one out-of-process runner.
///
/// Dynamically started descendants use the same executable without the root
/// arguments and derive their role from broker startup data.
#[derive(Clone)]
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

    pub(crate) fn without_initial_arguments(&self) -> Self {
        Self {
            executable: self.executable.clone(),
            arguments: Vec::new(),
            proxy_url: self.proxy_url.clone(),
        }
    }
}

/// One out-of-process runner and its dedicated broker control endpoint.
///
/// Dropping an instance before [`Self::run_process_to_completion`] completes
/// terminates and reaps the runner.
pub(crate) struct RunnerInstance {
    runner: Arc<Mutex<Child>>,
    shutdown: Arc<RunnerShutdown>,
    endpoint: PlatformRunnerEndpoint,
    setup_deadline: Instant,
}

struct RunnerShutdown {
    runner: Arc<Mutex<Child>>,
    state: Mutex<RunnerShutdownState>,
    changed: Condvar,
    termination_dispatched: AtomicBool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunnerShutdownState {
    Active,
    Terminating,
    Retired,
}

pub(crate) struct RunnerCompletion {
    result: IoResult<ExitStatus>,
    abnormal: bool,
    runner_signal: Option<i32>,
    runner_exit_code: Option<i32>,
    broker_termination: bool,
}

impl RunnerCompletion {
    pub(crate) fn panicked() -> Self {
        Self {
            result: Err(IoError::other("runner supervision thread panicked")),
            abnormal: true,
            runner_signal: None,
            runner_exit_code: None,
            broker_termination: false,
        }
    }

    pub(crate) fn is_abnormal(&self, thread_panicked: bool) -> bool {
        thread_panicked
            || self.abnormal
            || runner_signal_is_abnormal(self.runner_signal, self.broker_termination)
            || runner_exit_code_is_crash(self.runner_exit_code)
    }

    pub(crate) fn into_result(self) -> IoResult<ExitStatus> {
        self.result
    }
}

impl RunnerShutdown {
    fn shutdown(&self) {
        let mut state = self.state.lock().expect("runner shutdown mutex poisoned");
        loop {
            match *state {
                RunnerShutdownState::Active => {
                    *state = RunnerShutdownState::Terminating;
                    break;
                }
                RunnerShutdownState::Terminating => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("runner shutdown mutex poisoned");
                }
                RunnerShutdownState::Retired => return,
            }
        }
        drop(state);
        let termination_dispatched = {
            // Serialize observation and termination so collecting an exit
            // status can never expose a reusable PID between the check and
            // the kill request.
            let mut runner = self.runner.lock().expect("runner process mutex poisoned");
            match runner.try_wait() {
                Ok(Some(_)) => false,
                Ok(None) => runner.kill().is_ok(),
                Err(_) => {
                    let _ = runner.kill();
                    false
                }
            }
        };
        if termination_dispatched {
            self.termination_dispatched.store(true, Ordering::Release);
        }
        let mut state = self.state.lock().expect("runner shutdown mutex poisoned");
        debug_assert_eq!(*state, RunnerShutdownState::Terminating);
        *state = RunnerShutdownState::Retired;
        self.changed.notify_all();
    }

    fn retire(&self) {
        let mut state = self.state.lock().expect("runner shutdown mutex poisoned");
        while *state == RunnerShutdownState::Terminating {
            state = self
                .changed
                .wait(state)
                .expect("runner shutdown mutex poisoned");
        }
        *state = RunnerShutdownState::Retired;
        self.changed.notify_all();
    }

    fn has_exited(&self) -> IoResult<bool> {
        runner_has_exited(&self.runner)
    }

    fn termination_was_dispatched(&self) -> bool {
        self.termination_dispatched.load(Ordering::Acquire)
    }

    fn wait_for_exit(&self, timeout: Duration) -> IoResult<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.has_exited()? {
                return Ok(true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            std::thread::sleep(remaining.min(ACCEPT_RETRY_DELAY));
        }
    }
}

impl RunnerInstance {
    /// Creates the runner's dedicated control endpoint and starts the runner.
    pub(crate) fn start(config: RunnerConfig) -> IoResult<Self> {
        let setup_deadline = Instant::now() + SETUP_TIMEOUT;
        let endpoint = PlatformRunnerEndpoint::create()?;
        let runner = Arc::new(Mutex::new(
            Command::new(&config.executable)
                .args(config.arguments(endpoint.control_channel()))
                .spawn()?,
        ));
        let shutdown = Arc::new(RunnerShutdown {
            runner: Arc::clone(&runner),
            state: Mutex::new(RunnerShutdownState::Active),
            changed: Condvar::new(),
            termination_dispatched: AtomicBool::new(false),
        });
        Ok(Self {
            runner,
            shutdown,
            endpoint,
            setup_deadline,
        })
    }

    pub(crate) const fn setup_deadline(&self) -> Instant {
        self.setup_deadline
    }

    pub(crate) fn run_process_to_completion(
        mut self,
        association: PendingRunnerAssociation,
        broker: BrokerCore,
        launcher: Arc<UserlandProcessLauncher>,
    ) -> RunnerCompletion {
        let process = Arc::clone(&association.process);
        let shutdown = Arc::clone(&self.shutdown);
        process.install_shutdown(Arc::new(move || shutdown.shutdown()));
        let association_result = self.endpoint.serve(
            &self.runner,
            association,
            self.setup_deadline,
            broker,
            launcher,
        );
        self.endpoint.close();
        let shutdown_was_expected = process.shutdown_was_expected();
        let mut abnormal = association_result.abnormal;
        let runner_exited = if !shutdown_was_expected && !association_result.abnormal {
            self.shutdown
                .wait_for_exit(PROCESS_EXIT_OBSERVATION_TIMEOUT)
        } else {
            self.shutdown.has_exited()
        };
        match runner_exited {
            Ok(true) => {}
            Ok(false) => {
                if !shutdown_was_expected {
                    abnormal = true;
                }
                self.shutdown.shutdown();
            }
            Err(_) => {
                abnormal = true;
                self.shutdown.shutdown();
            }
        }
        self.shutdown.retire();
        let runner_status = wait_for_runner_exit(&self.runner);
        if runner_status.is_err() {
            abnormal = true;
        }
        let runner_signal = runner_status
            .as_ref()
            .ok()
            .copied()
            .and_then(runner_exit_signal);
        let runner_exit_code = runner_status.as_ref().ok().and_then(ExitStatus::code);
        let result = runner_status.and_then(|runner_status| {
            runner_exited.map(|_| ())?;
            association_result.result?;
            Ok(runner_status)
        });
        RunnerCompletion {
            result,
            abnormal,
            runner_signal,
            runner_exit_code,
            broker_termination: self.shutdown.termination_was_dispatched(),
        }
    }
}

/// Launches and supervises the initial runner process.
pub fn run_to_completion(config: RunnerConfig, broker: &BrokerCore) -> IoResult<ExitStatus> {
    UserlandProcessLauncher::run_root(config, broker)
}

impl Drop for RunnerInstance {
    fn drop(&mut self) {
        self.endpoint.close();
        self.shutdown.shutdown();
        self.shutdown.retire();
        let _ = wait_for_runner_exit(&self.runner);
    }
}

#[cfg(target_os = "linux")]
fn runner_exit_signal(status: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(target_os = "linux"))]
fn runner_exit_signal(_status: ExitStatus) -> Option<i32> {
    None
}

#[cfg(target_os = "linux")]
const LINUX_SIGKILL: i32 = 9;

#[cfg(target_os = "linux")]
const fn runner_signal_is_abnormal(signal: Option<i32>, broker_termination: bool) -> bool {
    matches!(signal, Some(signal) if signal != LINUX_SIGKILL || !broker_termination)
}

#[cfg(not(target_os = "linux"))]
const fn runner_signal_is_abnormal(_signal: Option<i32>, _broker_termination: bool) -> bool {
    false
}

#[cfg(target_os = "linux")]
const _: () = {
    assert!(runner_signal_is_abnormal(Some(LINUX_SIGKILL + 1), true));
    assert!(runner_signal_is_abnormal(Some(LINUX_SIGKILL), false));
    assert!(!runner_signal_is_abnormal(Some(LINUX_SIGKILL), true));
    assert!(!runner_signal_is_abnormal(None, false));
};

#[cfg(all(windows, target_arch = "x86_64"))]
const fn runner_exit_code_is_crash(exit_code: Option<i32>) -> bool {
    matches!(exit_code, Some(code) if code.cast_unsigned() >= 0x8000_0000)
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
const fn runner_exit_code_is_crash(_exit_code: Option<i32>) -> bool {
    false
}

#[cfg(all(windows, target_arch = "x86_64"))]
const _: () = {
    let access_violation = 0xc000_0005_u32.cast_signed();
    let breakpoint = 0x8000_0003_u32.cast_signed();
    assert!(runner_exit_code_is_crash(Some(access_violation)));
    assert!(runner_exit_code_is_crash(Some(breakpoint)));
};

fn accept_runner_channel<Channel>(
    deadline: Instant,
    channel_name: &'static str,
    mut runner_status: impl FnMut() -> IoResult<Option<String>>,
    mut try_accept: impl FnMut() -> IoResult<Channel>,
) -> IoResult<Channel> {
    loop {
        if let Some(status) = runner_status()? {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                format!("runner {status} before connecting its {channel_name} channel"),
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IoError::new(
                ErrorKind::TimedOut,
                format!("timed out waiting for runner {channel_name} channel"),
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

fn runner_has_exited(runner: &Arc<Mutex<Child>>) -> IoResult<bool> {
    // A pre-authentication caller stops accepting before acting on `true`;
    // post-authentication callers no longer rely on PID-based authentication.
    runner
        .lock()
        .expect("runner process mutex poisoned")
        .try_wait()
        .map(|status| status.is_some())
}

fn wait_for_runner_exit(runner: &Arc<Mutex<Child>>) -> IoResult<ExitStatus> {
    loop {
        if let Some(status) = runner
            .lock()
            .expect("runner process mutex poisoned")
            .try_wait()?
        {
            return Ok(status);
        }
        std::thread::sleep(ACCEPT_RETRY_DELAY);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Condvar, Mutex, atomic::AtomicBool, mpsc};
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    #[test]
    fn root_startup_preserves_runner_connection_error() {
        use litebox_broker_core::test_support::TestBrokerCoreBuilder;
        use litebox_broker_core::{ObjectRights, PolicyEngine};

        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_host_guaranteed_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let error = super::run_to_completion(
            super::RunnerConfig::new("/bin/false".into(), Vec::new()),
            &broker,
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(
            error
                .to_string()
                .contains("runner exited before connecting its control channel"),
            "unexpected root startup error: {error}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_can_terminate_while_runner_waits_for_exit() {
        use super::{RunnerShutdown, RunnerShutdownState, wait_for_runner_exit};
        use std::process::Command;

        let runner = Arc::new(Mutex::new(
            Command::new("sh")
                .args(["-c", "exec sleep 30"])
                .spawn()
                .unwrap(),
        ));
        let shutdown = RunnerShutdown {
            runner: Arc::clone(&runner),
            state: Mutex::new(RunnerShutdownState::Active),
            changed: Condvar::new(),
            termination_dispatched: AtomicBool::new(false),
        };
        let waiting = Arc::clone(&runner);
        let (finished, completion) = mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            let status = wait_for_runner_exit(&waiting).unwrap();
            finished.send(status).unwrap();
        });

        shutdown.shutdown();
        assert!(shutdown.termination_was_dispatched());
        assert!(
            !completion
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .success()
        );
        waiter.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_after_observed_exit_records_no_termination() {
        use super::{RunnerShutdown, RunnerShutdownState, wait_for_runner_exit};
        use std::process::Command;

        let runner = Arc::new(Mutex::new(
            Command::new("sh").args(["-c", "exit 1"]).spawn().unwrap(),
        ));
        let shutdown = RunnerShutdown {
            runner: Arc::clone(&runner),
            state: Mutex::new(RunnerShutdownState::Active),
            changed: Condvar::new(),
            termination_dispatched: AtomicBool::new(false),
        };
        assert!(shutdown.wait_for_exit(Duration::from_secs(1)).unwrap());

        shutdown.shutdown();
        shutdown.retire();

        assert!(!shutdown.termination_was_dispatched());
        assert!(!wait_for_runner_exit(&runner).unwrap().success());
    }
}
