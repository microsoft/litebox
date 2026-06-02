// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;
use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    thread::{self, JoinHandle, Thread},
};

use litebox_broker_protocol::{BrokerRequest, BrokerResponse, ClientControlChannel};

use crate::{BrokerClient, ClientError};

const PHASE_IDLE: u8 = 0;
const PHASE_RESERVED: u8 = 1;
const PHASE_REQUEST_READY: u8 = 2;
const PHASE_RESPONSE_READY: u8 = 3;
const PHASE_SHUTDOWN: u8 = 4;

/// Error returned by [`BrokerClientWorker`].
#[derive(Debug)]
#[non_exhaustive]
pub enum BrokerClientWorkerError<E> {
    /// The wrapped broker client returned an error.
    Client(ClientError<E>),
    /// The worker is shutting down or has already shut down.
    Shutdown,
}

impl<E: fmt::Display> fmt::Display for BrokerClientWorkerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "broker client worker request failed: {error}"),
            Self::Shutdown => f.write_str("broker client worker is shut down"),
        }
    }
}

impl<E> core::error::Error for BrokerClientWorkerError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Shutdown => None,
        }
    }
}

type WorkerResult<E> = core::result::Result<BrokerResponse, BrokerClientWorkerError<E>>;

/// Dedicated worker for broker clients that must not run channel I/O on the caller thread.
///
/// The worker owns the [`BrokerClient`] and performs blocking channel operations
/// on a dedicated thread. Callers submit one raw broker request at a time and
/// block on an in-process condition variable until the worker publishes the
/// response. This preserves the serial control-channel contract while keeping
/// deployment-specific threads, such as rewritten guest syscall threads, away
/// from host IPC syscalls.
pub struct BrokerClientWorker<T>
where
    T: ClientControlChannel + Send + 'static,
    T::Error: Send + 'static,
{
    state: Arc<BrokerClientWorkerState<T::Error>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

struct BrokerClientWorkerState<E> {
    shutdown_requested: AtomicBool,
    phase: AtomicU8,
    request: Mutex<Option<BrokerRequest>>,
    response: Mutex<Option<WorkerResult<E>>>,
    requester_wait: Mutex<()>,
    requester_wakeup: Condvar,
    worker_thread: Mutex<Option<Thread>>,
}

impl<T> BrokerClientWorker<T>
where
    T: ClientControlChannel + Send + 'static,
    T::Error: Send + 'static,
{
    /// Starts a worker for an already-negotiated broker client.
    ///
    /// # Panics
    ///
    /// Panics if the worker-thread bookkeeping mutex is poisoned while the
    /// worker is being started.
    pub fn new(client: BrokerClient<T>) -> Self {
        let state = Arc::new(BrokerClientWorkerState {
            shutdown_requested: AtomicBool::new(false),
            phase: AtomicU8::new(PHASE_IDLE),
            request: Mutex::new(None),
            response: Mutex::new(None),
            requester_wait: Mutex::new(()),
            requester_wakeup: Condvar::new(),
            worker_thread: Mutex::new(None),
        });
        let worker_state = state.clone();
        let worker = thread::spawn(move || run_broker_client_worker(client, worker_state));
        *state
            .worker_thread
            .lock()
            .expect("broker client worker-thread mutex poisoned") = Some(worker.thread().clone());

        Self {
            state,
            worker: Mutex::new(Some(worker)),
        }
    }

    /// Sends one request on the active broker client and returns the raw protocol response.
    pub fn active_raw_request(
        &self,
        request: BrokerRequest,
    ) -> core::result::Result<BrokerResponse, BrokerClientWorkerError<T::Error>> {
        self.state.submit(request)
    }

    /// Shuts down the worker and waits for its thread to exit.
    ///
    /// # Panics
    ///
    /// Panics if the worker bookkeeping mutex is poisoned or if the worker
    /// thread panicked before shutdown completed.
    pub fn shutdown(&self) {
        let mut worker = self
            .worker
            .lock()
            .expect("broker client worker mutex poisoned");
        if let Some(worker) = worker.take() {
            self.state.request_shutdown();
            worker.join().expect("broker client worker panicked");
        }
    }
}

impl<T> Drop for BrokerClientWorker<T>
where
    T: ClientControlChannel + Send + 'static,
    T::Error: Send + 'static,
{
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl<E> BrokerClientWorkerState<E> {
    fn submit(&self, request: BrokerRequest) -> WorkerResult<E> {
        loop {
            if self.shutdown_requested.load(Ordering::Acquire) {
                return Err(BrokerClientWorkerError::Shutdown);
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
                            return Err(BrokerClientWorkerError::Shutdown);
                        }
                        break;
                    }
                }
                PHASE_SHUTDOWN => return Err(BrokerClientWorkerError::Shutdown),
                phase => self.wait_for_phase_change(phase, true),
            }
        }

        *self
            .request
            .lock()
            .expect("broker client worker request mutex poisoned") = Some(request);
        self.phase.store(PHASE_REQUEST_READY, Ordering::Release);
        self.wake_worker();

        loop {
            match self.phase.load(Ordering::Acquire) {
                PHASE_RESPONSE_READY => break,
                PHASE_SHUTDOWN => return Err(BrokerClientWorkerError::Shutdown),
                phase => self.wait_for_phase_change(phase, false),
            }
        }

        let response = self
            .response
            .lock()
            .expect("broker client worker response mutex poisoned")
            .take()
            .expect("broker client worker did not publish a response");
        self.store_phase_and_notify(PHASE_IDLE);
        response
    }

    fn request_shutdown(&self) {
        {
            let _guard = self
                .requester_wait
                .lock()
                .expect("broker client worker requester-wait mutex poisoned");
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
            .expect("broker client worker requester-wait mutex poisoned");
        self.phase.store(phase, Ordering::Release);
        self.requester_wakeup.notify_all();
    }

    fn wait_for_phase_change(&self, observed: u8, wake_on_shutdown: bool) {
        let mut guard = self
            .requester_wait
            .lock()
            .expect("broker client worker requester-wait mutex poisoned");
        while self.phase.load(Ordering::Acquire) == observed
            && !(wake_on_shutdown && self.shutdown_requested.load(Ordering::Acquire))
        {
            guard = self
                .requester_wakeup
                .wait(guard)
                .expect("broker client worker requester-wait mutex poisoned");
        }
    }

    fn wake_worker(&self) {
        if let Some(worker) = self
            .worker_thread
            .lock()
            .expect("broker client worker-thread mutex poisoned")
            .as_ref()
        {
            worker.unpark();
        }
    }
}

fn run_broker_client_worker<T>(
    mut client: BrokerClient<T>,
    state: Arc<BrokerClientWorkerState<T::Error>>,
) where
    T: ClientControlChannel,
{
    loop {
        match state.phase.load(Ordering::Acquire) {
            PHASE_REQUEST_READY => {
                let request = state
                    .request
                    .lock()
                    .expect("broker client worker request mutex poisoned")
                    .take()
                    .expect("broker client worker request missing");
                let response = client
                    .active_raw_request(request)
                    .map_err(BrokerClientWorkerError::Client);
                *state
                    .response
                    .lock()
                    .expect("broker client worker response mutex poisoned") = Some(response);
                state.store_phase_and_notify(PHASE_RESPONSE_READY);
            }
            PHASE_SHUTDOWN => break,
            _ => thread::park(),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        vec::Vec,
    };

    use litebox_broker_protocol::{
        BrokerRequest, BrokerResponse, ClientControlChannel, ErrorCode, ReceivedBrokerResponse,
    };

    use super::*;
    use crate::{BrokerClient, CLIENT_PROTOCOL_VERSION};

    #[test]
    fn worker_returns_raw_protocol_errors() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let channel = FakeControlChannel::new(
            sent.clone(),
            [
                BrokerResponse::Negotiated {
                    broker_protocol_version: CLIENT_PROTOCOL_VERSION,
                },
                BrokerResponse::Error(ErrorCode::WouldBlock),
            ],
        );
        let mut client = BrokerClient::new(channel);
        client.negotiate().unwrap();
        let worker = BrokerClientWorker::new(client);

        let response = worker
            .active_raw_request(BrokerRequest::Negotiate {
                protocol_version: CLIENT_PROTOCOL_VERSION,
            })
            .unwrap();

        assert_eq!(response, BrokerResponse::Error(ErrorCode::WouldBlock));
        assert_eq!(sent.lock().unwrap().len(), 2);
        worker.shutdown();
    }

    #[test]
    fn worker_rejects_requests_after_shutdown() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let channel = FakeControlChannel::new(
            sent,
            [BrokerResponse::Negotiated {
                broker_protocol_version: CLIENT_PROTOCOL_VERSION,
            }],
        );
        let mut client = BrokerClient::new(channel);
        client.negotiate().unwrap();
        let worker = BrokerClientWorker::new(client);

        worker.shutdown();

        assert!(matches!(
            worker.active_raw_request(BrokerRequest::Negotiate {
                protocol_version: CLIENT_PROTOCOL_VERSION,
            }),
            Err(BrokerClientWorkerError::Shutdown)
        ));
    }

    struct FakeControlChannel {
        sent: Arc<Mutex<Vec<BrokerRequest>>>,
        responses: VecDeque<BrokerResponse>,
    }

    impl FakeControlChannel {
        fn new<const N: usize>(
            sent: Arc<Mutex<Vec<BrokerRequest>>>,
            responses: [BrokerResponse; N],
        ) -> Self {
            Self {
                sent,
                responses: VecDeque::from(responses),
            }
        }
    }

    impl ClientControlChannel for FakeControlChannel {
        type Error = Infallible;

        fn send_request(&mut self, request: &BrokerRequest) -> Result<(), Self::Error> {
            self.sent.lock().unwrap().push(*request);
            Ok(())
        }

        fn recv_response(&mut self) -> Result<Option<ReceivedBrokerResponse>, Self::Error> {
            Ok(self
                .responses
                .pop_front()
                .map(ReceivedBrokerResponse::Response))
        }
    }
}
