// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    path::Path,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    thread::{self, JoinHandle, Thread},
    time::{Duration, Instant},
};

use alloc::sync::Arc;
use anyhow::{Context as _, Result};
use litebox_broker_client::BrokerClient;
use litebox_broker_protocol::{BrokerRequest, BrokerResponse};
use litebox_broker_unix_socket::UnixStreamClientControlChannel;
use litebox_shim_linux::{BrokerControl, BrokerControlError};

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_millis(20);
const PHASE_IDLE: u8 = 0;
const PHASE_RESERVED: u8 = 1;
const PHASE_REQUEST_READY: u8 = 2;
const PHASE_RESPONSE_READY: u8 = 3;
const PHASE_SHUTDOWN: u8 = 4;

type Client = BrokerClient<UnixStreamClientControlChannel>;

pub(crate) struct BrokerConnection {
    control: Arc<BrokerControlClient>,
}

struct BrokerControlClient {
    state: Arc<BrokerControlState>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

struct BrokerControlState {
    shutdown_requested: AtomicBool,
    phase: AtomicU8,
    request: Mutex<Option<BrokerRequest>>,
    response: Mutex<Option<core::result::Result<BrokerResponse, BrokerControlError>>>,
    requester_wait: Mutex<()>,
    requester_wakeup: Condvar,
    worker_thread: Mutex<Option<Thread>>,
}

pub(crate) fn connect(socket_path: Option<&Path>) -> Result<Option<BrokerConnection>> {
    match socket_path {
        Some(path) => connect_to_endpoint(path).map(Some),
        None => Ok(None),
    }
}

impl BrokerConnection {
    pub(crate) fn control(&self) -> Arc<dyn BrokerControl> {
        self.control.clone()
    }

    pub(crate) fn shutdown(self) {
        self.control.shutdown();
    }
}

impl Drop for BrokerConnection {
    fn drop(&mut self) {
        self.control.shutdown();
    }
}

impl BrokerControlClient {
    fn new(client: Client) -> Self {
        let state = Arc::new(BrokerControlState {
            shutdown_requested: AtomicBool::new(false),
            phase: AtomicU8::new(PHASE_IDLE),
            request: Mutex::new(None),
            response: Mutex::new(None),
            requester_wait: Mutex::new(()),
            requester_wakeup: Condvar::new(),
            worker_thread: Mutex::new(None),
        });
        let worker_state = state.clone();
        let worker = thread::spawn(move || run_broker_control_worker(client, worker_state));
        *state
            .worker_thread
            .lock()
            .expect("broker control worker-thread mutex poisoned") = Some(worker.thread().clone());
        Self {
            state,
            worker: Mutex::new(Some(worker)),
        }
    }

    fn shutdown(&self) {
        let mut worker = self
            .worker
            .lock()
            .expect("broker control worker mutex poisoned");
        if let Some(worker) = worker.take() {
            self.state.request_shutdown();
            worker.join().expect("broker control worker panicked");
        }
    }
}

impl BrokerControl for BrokerControlClient {
    fn request(
        &self,
        request: BrokerRequest,
    ) -> core::result::Result<BrokerResponse, BrokerControlError> {
        self.state.submit(request)
    }
}

impl BrokerControlState {
    fn submit(
        &self,
        request: BrokerRequest,
    ) -> core::result::Result<BrokerResponse, BrokerControlError> {
        // Guest syscall handling must not perform host socket I/O on the
        // rewritten thread, so this side publishes work to the dedicated worker.
        loop {
            if self.shutdown_requested.load(Ordering::Acquire) {
                return Err(BrokerControlError);
            }
            match self.phase.load(Ordering::Acquire) {
                PHASE_IDLE => {
                    if self
                        .phase
                        .compare_exchange(
                            PHASE_IDLE,
                            PHASE_RESERVED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        if self.shutdown_requested.load(Ordering::Acquire) {
                            self.store_phase_and_notify(PHASE_IDLE);
                            return Err(BrokerControlError);
                        }
                        break;
                    }
                }
                PHASE_SHUTDOWN => return Err(BrokerControlError),
                phase => self.wait_for_phase_change(phase, true),
            }
        }

        *self
            .request
            .lock()
            .expect("broker control request mutex poisoned") = Some(request);
        self.phase.store(PHASE_REQUEST_READY, Ordering::Release);
        self.wake_worker();

        loop {
            match self.phase.load(Ordering::Acquire) {
                PHASE_RESPONSE_READY => break,
                PHASE_SHUTDOWN => return Err(BrokerControlError),
                phase => self.wait_for_phase_change(phase, false),
            }
        }

        let response = self
            .response
            .lock()
            .expect("broker control response mutex poisoned")
            .take()
            .expect("broker control worker did not publish a response");
        self.store_phase_and_notify(PHASE_IDLE);
        response
    }

    fn request_shutdown(&self) {
        {
            let _guard = self
                .requester_wait
                .lock()
                .expect("broker control requester-wait mutex poisoned");
            self.shutdown_requested.store(true, Ordering::Release);
            self.requester_wakeup.notify_all();
        }
        loop {
            match self.phase.load(Ordering::Acquire) {
                PHASE_IDLE => {
                    if self
                        .phase
                        .compare_exchange(
                            PHASE_IDLE,
                            PHASE_SHUTDOWN,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.wake_worker();
                        return;
                    }
                }
                PHASE_SHUTDOWN => return,
                phase => self.wait_for_phase_change(phase, false),
            }
        }
    }

    fn store_phase_and_notify(&self, phase: u8) {
        let _guard = self
            .requester_wait
            .lock()
            .expect("broker control requester-wait mutex poisoned");
        self.phase.store(phase, Ordering::Release);
        self.requester_wakeup.notify_all();
    }

    fn wait_for_phase_change(&self, observed: u8, wake_on_shutdown: bool) {
        let mut guard = self
            .requester_wait
            .lock()
            .expect("broker control requester-wait mutex poisoned");
        while self.phase.load(Ordering::Acquire) == observed
            && !(wake_on_shutdown && self.shutdown_requested.load(Ordering::Acquire))
        {
            guard = self
                .requester_wakeup
                .wait(guard)
                .expect("broker control requester-wait mutex poisoned");
        }
    }

    fn wake_worker(&self) {
        if let Some(worker) = self
            .worker_thread
            .lock()
            .expect("broker control worker-thread mutex poisoned")
            .as_ref()
        {
            worker.unpark();
        }
    }
}

fn run_broker_control_worker(mut client: Client, state: Arc<BrokerControlState>) {
    loop {
        match state.phase.load(Ordering::Acquire) {
            PHASE_REQUEST_READY => {
                let request = state
                    .request
                    .lock()
                    .expect("broker control request mutex poisoned")
                    .take()
                    .expect("broker control request missing");
                let response = client
                    .active_raw_request(request)
                    .map_err(|_| BrokerControlError);
                *state
                    .response
                    .lock()
                    .expect("broker control response mutex poisoned") = Some(response);
                state.store_phase_and_notify(PHASE_RESPONSE_READY);
            }
            PHASE_SHUTDOWN => break,
            _ => thread::park(),
        }
    }
}

fn connect_to_endpoint(socket_path: &Path) -> Result<BrokerConnection> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let mut client = connect_with_retry(socket_path, setup_deadline)
        .with_context(|| format!("failed to connect to broker at {}", socket_path.display()))?;
    client
        .control_channel_mut()
        .set_io_deadline(None)
        .context("failed to clear broker setup deadline")?;
    Ok(BrokerConnection {
        control: Arc::new(BrokerControlClient::new(client)),
    })
}

fn connect_with_retry(socket_path: &Path, setup_deadline: Instant) -> Result<Client> {
    loop {
        match UnixStreamClientControlChannel::connect(socket_path) {
            Ok(mut channel) => {
                channel
                    .set_io_deadline(Some(setup_deadline))
                    .context("failed to configure broker setup deadline")?;
                let mut client = BrokerClient::new(channel);
                client.negotiate().context("broker negotiation failed")?;
                return Ok(client);
            }
            Err(error) => {
                if Instant::now() >= setup_deadline {
                    return Err(error).context("timed out connecting to broker");
                }
            }
        }
        let remaining = setup_deadline.saturating_duration_since(Instant::now());
        thread::sleep(RETRY_DELAY.min(remaining));
    }
}
