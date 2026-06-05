// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;
use std::{
    boxed::Box,
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    thread::{self, JoinHandle, Thread},
    time::Duration,
};

use litebox_broker_protocol::{BrokerRequest, BrokerResponse, ClientControlChannel};

use crate::{BrokerLocalError, ControlClient};

const PHASE_IDLE: u8 = 0;
const PHASE_RESERVED: u8 = 1;
const PHASE_REQUEST_READY: u8 = 2;
const PHASE_RESPONSE_READY: u8 = 3;
const PHASE_SHUTDOWN: u8 = 4;
const DEFAULT_SHUTDOWN_WAIT: Duration = Duration::from_millis(100);

/// Error returned by [`ControlClientWorker`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ControlClientWorkerError<E> {
    /// The wrapped control client returned an error.
    Client(BrokerLocalError<E>),
    /// The worker is shutting down or has already shut down.
    Shutdown,
}

impl<E: fmt::Display> fmt::Display for ControlClientWorkerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "control client worker request failed: {error}"),
            Self::Shutdown => f.write_str("control client worker is shut down"),
        }
    }
}

impl<E> core::error::Error for ControlClientWorkerError<E>
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

type WorkerResult<E> = core::result::Result<BrokerResponse, ControlClientWorkerError<E>>;
type ShutdownHook = Box<dyn FnOnce() + Send + 'static>;

/// Dedicated worker for control clients that must not run channel I/O on the caller thread.
///
/// The worker owns the [`ControlClient`] and performs blocking channel operations
/// on a dedicated thread. Callers submit one raw broker request at a time and
/// block on an in-process condition variable until the worker publishes the
/// response. This preserves the serial control-channel contract while keeping
/// deployment-specific threads, such as rewritten guest syscall threads, away
/// from host IPC syscalls.
pub struct ControlClientWorker<T>
where
    T: ClientControlChannel + Send + 'static,
    T::Error: Send + 'static,
{
    state: Arc<ControlClientWorkerState<T::Error>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    finished: Mutex<Receiver<()>>,
}

struct ControlClientWorkerState<E> {
    shutdown_requested: AtomicBool,
    phase: AtomicU8,
    request: Mutex<Option<BrokerRequest>>,
    response: Mutex<Option<WorkerResult<E>>>,
    requester_wait: Mutex<()>,
    requester_wakeup: Condvar,
    worker_thread: Mutex<Option<Thread>>,
    shutdown_hook: Mutex<Option<ShutdownHook>>,
}

impl<T> ControlClientWorker<T>
where
    T: ClientControlChannel + Send + 'static,
    T::Error: Send + 'static,
{
    /// Starts a worker for an already-negotiated control client.
    ///
    /// # Panics
    ///
    /// Panics if the worker-thread bookkeeping mutex is poisoned while the
    /// worker is being started.
    pub fn new(client: ControlClient<T>) -> Self {
        Self::new_with_shutdown_hook(client, || {})
    }

    /// Starts a worker and registers a hook used to interrupt blocking channel I/O during shutdown.
    ///
    /// # Panics
    ///
    /// Panics if the worker-thread bookkeeping mutex is poisoned while the
    /// worker is being started.
    pub fn new_with_shutdown_hook<F>(client: ControlClient<T>, shutdown_hook: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        let state = Arc::new(ControlClientWorkerState {
            shutdown_requested: AtomicBool::new(false),
            phase: AtomicU8::new(PHASE_IDLE),
            request: Mutex::new(None),
            response: Mutex::new(None),
            requester_wait: Mutex::new(()),
            requester_wakeup: Condvar::new(),
            worker_thread: Mutex::new(None),
            shutdown_hook: Mutex::new(Some(Box::new(shutdown_hook))),
        });
        let worker_state = state.clone();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            run_control_client_worker(client, worker_state);
            let _ = finished_tx.send(());
        });
        *state
            .worker_thread
            .lock()
            .expect("control client worker-thread mutex poisoned") = Some(worker.thread().clone());

        Self {
            state,
            worker: Mutex::new(Some(worker)),
            finished: Mutex::new(finished_rx),
        }
    }

    /// Sends one request on the active control client and returns the raw protocol response.
    pub fn active_raw_request(
        &self,
        request: BrokerRequest,
    ) -> core::result::Result<BrokerResponse, ControlClientWorkerError<T::Error>> {
        self.state.submit(request)
    }

    /// Shuts down the worker.
    ///
    /// If an in-flight blocking channel operation does not exit promptly, the
    /// worker thread is detached after a short grace period so shutdown callers
    /// are not blocked indefinitely. Use [`Self::new_with_shutdown_hook`] for
    /// blocking channels that can be explicitly interrupted.
    ///
    /// # Panics
    ///
    /// Panics if the worker bookkeeping mutex is poisoned or if the worker
    /// thread panicked before shutdown completed.
    pub fn shutdown(&self) {
        let mut worker = self
            .worker
            .lock()
            .expect("control client worker mutex poisoned");
        if let Some(worker) = worker.take() {
            self.state.request_shutdown();
            match self
                .finished
                .lock()
                .expect("control client worker-finished mutex poisoned")
                .recv_timeout(DEFAULT_SHUTDOWN_WAIT)
            {
                Ok(()) => worker.join().expect("control client worker panicked"),
                Err(RecvTimeoutError::Disconnected) => {
                    worker.join().expect("control client worker panicked");
                }
                Err(RecvTimeoutError::Timeout) => {
                    drop(worker);
                }
            }
        }
    }
}

impl<T> Drop for ControlClientWorker<T>
where
    T: ClientControlChannel + Send + 'static,
    T::Error: Send + 'static,
{
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl<E> ControlClientWorkerState<E> {
    fn submit(&self, request: BrokerRequest) -> WorkerResult<E> {
        loop {
            if self.shutdown_requested.load(Ordering::Acquire) {
                return Err(ControlClientWorkerError::Shutdown);
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
                            self.cancel_reserved_request_on_shutdown();
                            return Err(ControlClientWorkerError::Shutdown);
                        }
                        break;
                    }
                }
                PHASE_SHUTDOWN => return Err(ControlClientWorkerError::Shutdown),
                phase => self.wait_for_phase_change(phase, true),
            }
        }

        *self
            .request
            .lock()
            .expect("control client worker request mutex poisoned") = Some(request);
        self.phase.store(PHASE_REQUEST_READY, Ordering::Release);
        self.wake_worker();

        loop {
            if self.shutdown_requested.load(Ordering::Acquire) {
                return Err(ControlClientWorkerError::Shutdown);
            }
            match self.phase.load(Ordering::Acquire) {
                PHASE_RESPONSE_READY => break,
                PHASE_SHUTDOWN => return Err(ControlClientWorkerError::Shutdown),
                phase => self.wait_for_phase_change(phase, true),
            }
        }

        let response = self
            .response
            .lock()
            .expect("control client worker response mutex poisoned")
            .take()
            .expect("control client worker did not publish a response");
        self.store_phase_and_notify(PHASE_IDLE);
        response
    }

    fn request_aborted_before_send(&self) -> bool {
        if self.shutdown_requested.load(Ordering::Acquire) {
            self.store_phase_and_notify(PHASE_SHUTDOWN);
            self.wake_worker();
            true
        } else {
            false
        }
    }

    fn publish_worker_response(&self, response: WorkerResult<E>) -> bool {
        if self.shutdown_requested.load(Ordering::Acquire) {
            self.store_phase_and_notify(PHASE_SHUTDOWN);
            false
        } else {
            *self
                .response
                .lock()
                .expect("control client worker response mutex poisoned") = Some(response);
            self.store_phase_and_notify(PHASE_RESPONSE_READY);
            true
        }
    }

    fn take_request(&self) -> Option<BrokerRequest> {
        if self.request_aborted_before_send() {
            return None;
        }
        let request = self
            .request
            .lock()
            .expect("control client worker request mutex poisoned")
            .take()
            .expect("control client worker request missing");
        if self.shutdown_requested.load(Ordering::Acquire) {
            self.store_phase_and_notify(PHASE_SHUTDOWN);
            None
        } else {
            Some(request)
        }
    }

    fn cancel_reserved_request_on_shutdown(&self) {
        if self
            .phase
            .compare_exchange(
                PHASE_RESERVED,
                PHASE_SHUTDOWN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.wake_worker();
            self.requester_wakeup.notify_all();
        }
    }

    fn worker_should_shutdown(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
            || self.phase.load(Ordering::Acquire) == PHASE_SHUTDOWN
    }

    fn wait_for_work_or_shutdown(&self) -> bool {
        if self.worker_should_shutdown() {
            return false;
        }
        thread::park();
        !self.worker_should_shutdown()
    }

    fn transition_idle_to_shutdown(&self) -> bool {
        self.phase
            .compare_exchange(
                PHASE_IDLE,
                PHASE_SHUTDOWN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn cancel_in_flight_request(&self) {
        self.store_phase_and_notify(PHASE_SHUTDOWN);
        self.wake_worker();
    }

    fn request_shutdown_without_waiting(&self) {
        if self.transition_idle_to_shutdown() {
            self.wake_worker();
        } else if self.phase.load(Ordering::Acquire) == PHASE_RESERVED {
            self.cancel_reserved_request_on_shutdown();
        } else {
            self.cancel_in_flight_request();
        }
    }

    fn request_shutdown(&self) {
        {
            let _guard = self
                .requester_wait
                .lock()
                .expect("control client worker requester-wait mutex poisoned");
            self.shutdown_requested.store(true, Ordering::Release);
            self.requester_wakeup.notify_all();
        }
        self.run_shutdown_hook();
        self.request_shutdown_without_waiting();
    }

    fn store_phase_and_notify(&self, phase: u8) {
        let _guard = self
            .requester_wait
            .lock()
            .expect("control client worker requester-wait mutex poisoned");
        self.phase.store(phase, Ordering::Release);
        self.requester_wakeup.notify_all();
    }

    fn wait_for_phase_change(&self, observed: u8, wake_on_shutdown: bool) {
        let mut guard = self
            .requester_wait
            .lock()
            .expect("control client worker requester-wait mutex poisoned");
        while self.phase.load(Ordering::Acquire) == observed
            && !(wake_on_shutdown && self.shutdown_requested.load(Ordering::Acquire))
        {
            guard = self
                .requester_wakeup
                .wait(guard)
                .expect("control client worker requester-wait mutex poisoned");
        }
    }

    fn wake_worker(&self) {
        if let Some(worker) = self
            .worker_thread
            .lock()
            .expect("control client worker-thread mutex poisoned")
            .as_ref()
        {
            worker.unpark();
        }
    }

    fn run_shutdown_hook(&self) {
        if let Some(hook) = self
            .shutdown_hook
            .lock()
            .expect("control client worker shutdown-hook mutex poisoned")
            .take()
        {
            hook();
        }
    }
}

fn run_control_client_worker<T>(
    mut client: ControlClient<T>,
    state: Arc<ControlClientWorkerState<T::Error>>,
) where
    T: ClientControlChannel,
{
    loop {
        match state.phase.load(Ordering::Acquire) {
            PHASE_REQUEST_READY => {
                let Some(request) = state.take_request() else {
                    break;
                };
                let response = client
                    .active_raw_request(request)
                    .map_err(ControlClientWorkerError::Client);
                if !state.publish_worker_response(response) {
                    break;
                }
            }
            PHASE_SHUTDOWN => break,
            _ => {
                if !state.wait_for_work_or_shutdown() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;
    use std::{
        collections::VecDeque,
        io,
        sync::{Arc, Condvar, Mutex},
        time::{Duration, Instant},
        vec::Vec,
    };

    use litebox_broker_protocol::{
        BrokerRequest, BrokerResponse, ClientControlChannel, ErrorCode, ReceivedBrokerResponse,
    };

    use super::*;
    use crate::{CLIENT_PROTOCOL_VERSION, ControlClient};

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
        let mut client = ControlClient::new(channel);
        client.negotiate().unwrap();
        let worker = ControlClientWorker::new(client);

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
        let mut client = ControlClient::new(channel);
        client.negotiate().unwrap();
        let worker = ControlClientWorker::new(client);

        worker.shutdown();

        assert!(matches!(
            worker.active_raw_request(BrokerRequest::Negotiate {
                protocol_version: CLIENT_PROTOCOL_VERSION,
            }),
            Err(ControlClientWorkerError::Shutdown)
        ));
    }

    #[test]
    fn worker_shutdown_interrupts_in_flight_channel_io() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let interrupted = Arc::new((Mutex::new(false), Condvar::new()));
        let channel = BlockingControlChannel::new(sent, interrupted.clone());
        let mut client = ControlClient::new(channel);
        client.negotiate().unwrap();
        let worker = Arc::new(ControlClientWorker::new_with_shutdown_hook(client, {
            let interrupted = interrupted.clone();
            move || {
                let (lock, wakeup) = &*interrupted;
                *lock.lock().unwrap() = true;
                wakeup.notify_all();
            }
        }));

        let requester = {
            let worker = worker.clone();
            thread::spawn(move || {
                worker.active_raw_request(BrokerRequest::Negotiate {
                    protocol_version: CLIENT_PROTOCOL_VERSION,
                })
            })
        };

        while worker.state.phase.load(Ordering::Acquire) != PHASE_REQUEST_READY {
            thread::yield_now();
        }
        worker.shutdown();

        assert!(matches!(
            requester.join().unwrap(),
            Err(ControlClientWorkerError::Shutdown
                | ControlClientWorkerError::Client(BrokerLocalError::Channel(_)))
        ));
    }

    #[test]
    fn worker_default_shutdown_does_not_wait_forever_for_in_flight_channel_io() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let interrupted = Arc::new((Mutex::new(false), Condvar::new()));
        let channel = BlockingControlChannel::new(sent, interrupted);
        let mut client = ControlClient::new(channel);
        client.negotiate().unwrap();
        let worker = Arc::new(ControlClientWorker::new(client));

        let requester = {
            let worker = worker.clone();
            thread::spawn(move || {
                worker.active_raw_request(BrokerRequest::Negotiate {
                    protocol_version: CLIENT_PROTOCOL_VERSION,
                })
            })
        };

        while worker.state.phase.load(Ordering::Acquire) != PHASE_REQUEST_READY {
            thread::yield_now();
        }
        let started = Instant::now();
        worker.shutdown();

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "default worker shutdown waited too long"
        );
        assert!(matches!(
            requester.join().unwrap(),
            Err(ControlClientWorkerError::Shutdown)
        ));
    }

    #[test]
    fn worker_shutdown_hook_interrupts_worker_thread() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let interrupted = Arc::new((Mutex::new(false), Condvar::new()));
        let channel = BlockingControlChannel::new(sent, interrupted.clone());
        let mut client = ControlClient::new(channel);
        client.negotiate().unwrap();
        let worker = Arc::new(ControlClientWorker::new_with_shutdown_hook(client, {
            let interrupted = interrupted.clone();
            move || {
                let (lock, wakeup) = &*interrupted;
                *lock.lock().unwrap() = true;
                wakeup.notify_all();
            }
        }));

        let requester = {
            let worker = worker.clone();
            thread::spawn(move || {
                worker.active_raw_request(BrokerRequest::Negotiate {
                    protocol_version: CLIENT_PROTOCOL_VERSION,
                })
            })
        };

        while worker.state.phase.load(Ordering::Acquire) != PHASE_REQUEST_READY {
            thread::yield_now();
        }
        worker.shutdown();

        let (lock, _) = &*interrupted;
        assert!(*lock.lock().unwrap(), "shutdown hook was not invoked");
        match requester.join().unwrap() {
            Err(ControlClientWorkerError::Shutdown) => {}
            Err(ControlClientWorkerError::Client(BrokerLocalError::Channel(error)))
                if error.kind() == io::ErrorKind::Interrupted => {}
            result => panic!("unexpected requester result: {result:?}"),
        }
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
            self.sent.lock().unwrap().push(request.clone());
            Ok(())
        }

        fn recv_response(&mut self) -> Result<Option<ReceivedBrokerResponse>, Self::Error> {
            Ok(self
                .responses
                .pop_front()
                .map(ReceivedBrokerResponse::Response))
        }
    }

    struct BlockingControlChannel {
        sent: Arc<Mutex<Vec<BrokerRequest>>>,
        interrupted: Arc<(Mutex<bool>, Condvar)>,
        negotiated: bool,
    }

    impl BlockingControlChannel {
        fn new(
            sent: Arc<Mutex<Vec<BrokerRequest>>>,
            interrupted: Arc<(Mutex<bool>, Condvar)>,
        ) -> Self {
            Self {
                sent,
                interrupted,
                negotiated: false,
            }
        }
    }

    impl ClientControlChannel for BlockingControlChannel {
        type Error = io::Error;

        fn send_request(&mut self, request: &BrokerRequest) -> Result<(), Self::Error> {
            self.sent.lock().unwrap().push(request.clone());
            Ok(())
        }

        fn recv_response(&mut self) -> Result<Option<ReceivedBrokerResponse>, Self::Error> {
            if !self.negotiated {
                self.negotiated = true;
                return Ok(Some(ReceivedBrokerResponse::Response(
                    BrokerResponse::Negotiated {
                        broker_protocol_version: CLIENT_PROTOCOL_VERSION,
                    },
                )));
            }

            let (lock, wakeup) = &*self.interrupted;
            let mut interrupted = lock.lock().unwrap();
            while !*interrupted {
                interrupted = wakeup.wait(interrupted).unwrap();
            }
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "interrupted by shutdown",
            ))
        }
    }
}
