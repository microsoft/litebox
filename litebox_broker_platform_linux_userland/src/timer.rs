// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned Linux timerfds driven by one epoll reactor.
//!
//! Each broker timerfd is a real host `timerfd` descriptor owned by a single
//! reactor thread. The reactor arms, disarms, reads, and epoll-watches the
//! descriptors; when a timer expires it publishes `READ` readiness through the
//! broker readiness path, exactly like [`crate::socket`]. All timekeeping is
//! delegated to the host kernel; the broker core stays time-free.

use std::collections::HashMap;
use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::mem::size_of;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::timer::{PlatformTimer, TimerProvider, TimerRead};
use litebox_broker_core::{BrokerError, Result as BrokerResult, SessionId};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::timer::{CreateTimerRequest, TimerSpec};
use rustix::event::{EventfdFlags, epoll, eventfd};
use rustix::io::{Errno, read, write};
use rustix::time::{
    Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec, timerfd_create,
    timerfd_gettime, timerfd_settime,
};

/// Epoll token reserved for the eventfd that wakes the reactor for commands.
const WAKE_TOKEN: u64 = 0;
const MAX_QUEUED_TIMERFD_COMMANDS: usize = 64;
const MAX_EPOLL_EVENTS: usize = 64;

/// Linux-userland timerfd provider.
///
/// One reactor thread owns every timer descriptor and all epoll state. Broker
/// request workers submit bounded commands and wait only for one immediate
/// nonblocking operation, never for a timer to expire.
pub struct LinuxTimerProvider {
    reactor: Arc<TimerReactorClient>,
}

impl LinuxTimerProvider {
    /// Starts a provider whose reactor tracks at most `max_timers` resources.
    pub fn new(max_timers: usize) -> IoResult<Self> {
        Ok(Self {
            reactor: Arc::new(TimerReactorClient::start(max_timers)?),
        })
    }
}

impl TimerProvider for LinuxTimerProvider {
    fn create(
        &self,
        _session_id: SessionId,
        request: CreateTimerRequest,
        readiness: ReadinessRegistration,
    ) -> BrokerResult<Arc<dyn PlatformTimer>> {
        let clock = clock_from_raw(request.clock_id)?;
        let id = self.reactor.allocate_timer_id()?;
        let snapshot = Arc::new(Mutex::new(ReadinessFlags::default()));
        // Allocate the provider object before the reactor creates an external
        // resource, so successful creation has no remaining Arc allocation.
        let timer = Arc::new(LinuxTimer {
            id,
            reactor: Arc::clone(&self.reactor),
            snapshot: Arc::clone(&snapshot),
        });
        self.reactor.request(|response| ReactorCommand::Create {
            id,
            clock,
            readiness,
            snapshot,
            response,
        })?;
        Ok(timer)
    }

    fn close_session(&self, _session_id: SessionId) {}
}

/// Broker-core-facing handle for a reactor-owned timerfd.
struct LinuxTimer {
    id: u64,
    reactor: Arc<TimerReactorClient>,
    snapshot: Arc<Mutex<ReadinessFlags>>,
}

impl PlatformTimer for LinuxTimer {
    fn set(&self, specification: TimerSpec, flags: u32) -> BrokerResult<TimerSpec> {
        let timer_flags = timer_flags_from_raw(flags)?;
        let new_value = itimerspec_from_spec(specification)?;
        self.reactor.request(|response| ReactorCommand::Set {
            id: self.id,
            new_value,
            flags: timer_flags,
            response,
        })
    }

    fn get(&self) -> BrokerResult<TimerSpec> {
        self.reactor.request(|response| ReactorCommand::Get {
            id: self.id,
            response,
        })
    }

    fn read(&self) -> BrokerResult<TimerRead> {
        self.reactor.request(|response| ReactorCommand::Read {
            id: self.id,
            response,
        })
    }

    fn readiness(&self) -> ReadinessFlags {
        *self
            .snapshot
            .lock()
            .expect("Linux timerfd snapshot mutex poisoned")
    }
}

impl Drop for LinuxTimer {
    fn drop(&mut self) {
        self.reactor.close_timer(self.id);
    }
}

/// Thread-safe command, wake, and lifecycle handle for the timerfd reactor.
struct TimerReactorClient {
    commands: SyncSender<ReactorCommand>,
    wake: Arc<OwnedFd>,
    next_timer_id: AtomicU64,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl TimerReactorClient {
    fn start(max_timers: usize) -> IoResult<Self> {
        let epoll_fd = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        let wake = Arc::new(eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?);
        epoll::add(
            &epoll_fd,
            wake.as_ref(),
            epoll::EventData::new_u64(WAKE_TOKEN),
            epoll::EventFlags::IN,
        )?;

        let mut timers = HashMap::new();
        timers
            .try_reserve(max_timers)
            .map_err(|_| Error::new(ErrorKind::OutOfMemory, "timer table allocation failed"))?;
        let (commands, receiver) = sync_channel(MAX_QUEUED_TIMERFD_COMMANDS);
        let (started, startup) = sync_channel(1);
        let reactor_wake = Arc::clone(&wake);
        let reactor_thread = thread::Builder::new()
            .name("litebox-broker-timerfd-reactor".into())
            .spawn(move || {
                let mut events = Vec::new();
                if events.try_reserve_exact(MAX_EPOLL_EVENTS).is_err() {
                    let _ = started.send(false);
                    return;
                }
                let mut reactor = TimerReactor {
                    epoll: epoll_fd,
                    wake: reactor_wake,
                    commands: receiver,
                    timers,
                    max_timers,
                    events,
                };
                if started.send(true).is_err() {
                    return;
                }
                if let Err(error) = reactor.run() {
                    reactor.fail_all_timers();
                    std::eprintln!("broker timerfd reactor failed: {error}");
                }
            })?;
        match startup.recv() {
            Ok(true) => {}
            Ok(false) => {
                let _ = reactor_thread.join();
                return Err(Error::new(
                    ErrorKind::OutOfMemory,
                    "epoll event allocation failed",
                ));
            }
            Err(_) => {
                let _ = reactor_thread.join();
                return Err(Error::other("timerfd reactor failed during startup"));
            }
        }

        Ok(Self {
            commands,
            wake,
            next_timer_id: AtomicU64::new(1),
            thread: Mutex::new(Some(reactor_thread)),
        })
    }

    fn allocate_timer_id(&self) -> BrokerResult<u64> {
        self.next_timer_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| BrokerError::ResourceExhausted)
    }

    fn request<T>(
        &self,
        make_command: impl FnOnce(SyncSender<BrokerResult<T>>) -> ReactorCommand,
    ) -> BrokerResult<T> {
        let (response, receive) = sync_channel(1);
        let command = make_command(response);
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(BrokerError::ResourceExhausted),
            Err(TrySendError::Disconnected(_)) => return Err(BrokerError::Internal),
        }
        self.signal().map_err(|_| BrokerError::Internal)?;
        receive.recv().map_err(|_| BrokerError::Internal)?
    }

    fn close_timer(&self, id: u64) {
        let (response, receive) = sync_channel(1);
        if self
            .commands
            .send(ReactorCommand::Close { id, response })
            .is_err()
        {
            return;
        }
        // Do not return until the reactor has dropped the descriptor, even if
        // the redundant wake write fails.
        let _ = self.signal();
        let _ = receive.recv();
    }

    fn signal(&self) -> IoResult<()> {
        let value = 1_u64.to_ne_bytes();
        loop {
            match write(self.wake.as_ref(), &value) {
                Ok(length) if length == value.len() => return Ok(()),
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "eventfd wake was truncated",
                    ));
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(Error::from_raw_os_error(error.raw_os_error())),
            }
        }
    }
}

impl Drop for TimerReactorClient {
    fn drop(&mut self) {
        let (response, receive) = sync_channel(1);
        if self
            .commands
            .send(ReactorCommand::Stop { response })
            .is_ok()
        {
            let _ = self.signal();
            let _ = receive.recv();
        }
        if let Some(thread) = self
            .thread
            .lock()
            .expect("timerfd reactor mutex poisoned")
            .take()
        {
            let _ = thread.join();
        }
    }
}

enum ReactorCommand {
    Create {
        id: u64,
        clock: TimerfdClockId,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<ReadinessFlags>>,
        response: SyncSender<BrokerResult<()>>,
    },
    Set {
        id: u64,
        new_value: Itimerspec,
        flags: TimerfdTimerFlags,
        response: SyncSender<BrokerResult<TimerSpec>>,
    },
    Get {
        id: u64,
        response: SyncSender<BrokerResult<TimerSpec>>,
    },
    Read {
        id: u64,
        response: SyncSender<BrokerResult<TimerRead>>,
    },
    Close {
        id: u64,
        response: SyncSender<()>,
    },
    Stop {
        response: SyncSender<()>,
    },
}

/// Reactor-owned descriptor and its broker-facing readiness state.
struct TimerEntry {
    timer: OwnedFd,
    readiness: ReadinessRegistration,
    snapshot: Arc<Mutex<ReadinessFlags>>,
}

/// Fatal failure that terminates the timerfd reactor.
#[derive(Debug)]
enum ReactorFailure {
    Io(Errno),
    Broker(BrokerError),
}

impl fmt::Display for ReactorFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Broker(error) => write!(formatter, "broker error: {error:?}"),
        }
    }
}

struct TimerReactor {
    epoll: OwnedFd,
    wake: Arc<OwnedFd>,
    commands: Receiver<ReactorCommand>,
    timers: HashMap<u64, TimerEntry>,
    max_timers: usize,
    events: Vec<epoll::Event>,
}

impl TimerReactor {
    fn run(&mut self) -> core::result::Result<(), ReactorFailure> {
        loop {
            let mut events = core::mem::take(&mut self.events);
            events.clear();
            match epoll::wait(
                &self.epoll,
                rustix::buffer::spare_capacity(&mut events),
                None,
            ) {
                Ok(_) => {}
                Err(Errno::INTR) => {
                    self.events = events;
                    continue;
                }
                Err(error) => return Err(ReactorFailure::Io(error)),
            }

            let mut wake = false;
            for event in events.drain(..) {
                let id = event.data.u64();
                let flags = event.flags;
                if id == WAKE_TOKEN {
                    wake = true;
                } else if let Some(timer) = self.timers.get(&id)
                    && flags.contains(epoll::EventFlags::IN)
                {
                    // The host timer expired: publish readable and cache it for
                    // subsequent readiness queries until the guest drains it.
                    *timer
                        .snapshot
                        .lock()
                        .expect("Linux timerfd snapshot mutex poisoned") = ReadinessFlags::READ;
                    timer
                        .readiness
                        .publish(ReadinessFlags::READ)
                        .map_err(ReactorFailure::Broker)?;
                }
            }
            self.events = events;
            if wake {
                self.drain_wake()?;
                if self.process_commands() {
                    return Ok(());
                }
            }
        }
    }

    fn drain_wake(&self) -> core::result::Result<(), ReactorFailure> {
        let mut value = [0_u8; size_of::<u64>()];
        loop {
            match read(self.wake.as_ref(), &mut value) {
                Ok(length) if length == value.len() => return Ok(()),
                Ok(_) => return Err(ReactorFailure::Io(Errno::IO)),
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(ReactorFailure::Io(error)),
            }
        }
    }

    fn process_commands(&mut self) -> bool {
        for _ in 0..MAX_QUEUED_TIMERFD_COMMANDS {
            let command = match self.commands.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            };
            match command {
                ReactorCommand::Create {
                    id,
                    clock,
                    readiness,
                    snapshot,
                    response,
                } => {
                    let outcome = self.create_timer(id, clock, readiness, snapshot);
                    let _ = response.send(outcome);
                }
                ReactorCommand::Set {
                    id,
                    new_value,
                    flags,
                    response,
                } => {
                    let _ = response.send(self.set_timer(id, &new_value, flags));
                }
                ReactorCommand::Get { id, response } => {
                    let _ = response.send(self.get_timer(id));
                }
                ReactorCommand::Read { id, response } => {
                    let _ = response.send(self.read_timer(id));
                }
                ReactorCommand::Close { id, response } => {
                    self.timers.remove(&id);
                    let _ = response.send(());
                }
                ReactorCommand::Stop { response } => {
                    self.timers.clear();
                    let _ = response.send(());
                    return true;
                }
            }
        }
        false
    }

    fn create_timer(
        &mut self,
        id: u64,
        clock: TimerfdClockId,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<ReadinessFlags>>,
    ) -> BrokerResult<()> {
        if self.timers.len() >= self.max_timers {
            return Err(BrokerError::ResourceExhausted);
        }
        if self.timers.contains_key(&id) {
            return Err(BrokerError::Internal);
        }
        let timer = timerfd_create(clock, TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK)
            .map_err(broker_error_from_errno)?;
        // Edge-triggered: each expiration is one edge, and a timerfd read drains
        // the entire accumulated count in a single call, so no expiration is
        // lost between the readiness publish and the guest's drain.
        epoll::add(
            &self.epoll,
            &timer,
            epoll::EventData::new_u64(id),
            epoll::EventFlags::IN | epoll::EventFlags::ET,
        )
        .map_err(broker_error_from_errno)?;
        self.timers.insert(
            id,
            TimerEntry {
                timer,
                readiness,
                snapshot,
            },
        );
        Ok(())
    }

    fn set_timer(
        &mut self,
        id: u64,
        new_value: &Itimerspec,
        flags: TimerfdTimerFlags,
    ) -> BrokerResult<TimerSpec> {
        let timer = self.timers.get(&id).ok_or(BrokerError::Internal)?;
        let previous =
            timerfd_settime(&timer.timer, flags, new_value).map_err(broker_error_from_errno)?;
        // A freshly (re)armed or disarmed timer has no pending expiration; the
        // reactor will publish readable again when it next expires.
        *timer
            .snapshot
            .lock()
            .expect("Linux timerfd snapshot mutex poisoned") = ReadinessFlags::default();
        Ok(spec_from_itimerspec(&previous))
    }

    fn get_timer(&self, id: u64) -> BrokerResult<TimerSpec> {
        let timer = self.timers.get(&id).ok_or(BrokerError::Internal)?;
        let current = timerfd_gettime(&timer.timer).map_err(broker_error_from_errno)?;
        Ok(spec_from_itimerspec(&current))
    }

    fn read_timer(&mut self, id: u64) -> BrokerResult<TimerRead> {
        let timer = self.timers.get(&id).ok_or(BrokerError::Internal)?;
        let mut buffer = [0_u8; size_of::<u64>()];
        match read(&timer.timer, &mut buffer) {
            Ok(length) if length == buffer.len() => {
                // The count is fully drained; cache not-readable until the next
                // expiration re-publishes readable.
                *timer
                    .snapshot
                    .lock()
                    .expect("Linux timerfd snapshot mutex poisoned") = ReadinessFlags::default();
                Ok(TimerRead {
                    expirations: u64::from_ne_bytes(buffer),
                    cancelled: false,
                })
            }
            Ok(_) => Err(BrokerError::Internal),
            Err(Errno::AGAIN) => Err(BrokerError::WouldBlock),
            // A CANCEL_ON_SET timer whose backing clock was set discontinuously
            // reports ECANCELED once and disarms. Consume the notification and
            // surface it so the guest read returns ECANCELED.
            Err(Errno::CANCELED) => {
                *timer
                    .snapshot
                    .lock()
                    .expect("Linux timerfd snapshot mutex poisoned") = ReadinessFlags::default();
                Ok(TimerRead {
                    expirations: 0,
                    cancelled: true,
                })
            }
            Err(error) => Err(broker_error_from_errno(error)),
        }
    }

    fn fail_all_timers(&mut self) {
        for timer in self.timers.values() {
            *timer
                .snapshot
                .lock()
                .expect("Linux timerfd snapshot mutex poisoned") = ReadinessFlags::ERROR;
            // The readiness path may itself be why the reactor is failing; the
            // cached terminal snapshot remains authoritative if publication is
            // no longer available.
            let _ = timer.readiness.publish(ReadinessFlags::ERROR);
        }
        self.timers.clear();
    }
}

/// Maps a raw Linux clock id to a supported timerfd clock.
fn clock_from_raw(clock_id: i32) -> BrokerResult<TimerfdClockId> {
    match clock_id {
        id if id == TimerfdClockId::Realtime as i32 => Ok(TimerfdClockId::Realtime),
        id if id == TimerfdClockId::Monotonic as i32 => Ok(TimerfdClockId::Monotonic),
        _ => Err(BrokerError::UnsupportedOperation),
    }
}

/// Maps raw set-time flags to supported timerfd timer flags.
///
/// `TimerfdTimerFlags::from_bits` accepts unknown bits (rustix models them as
/// external bits), so unknown flags are rejected explicitly here.
fn timer_flags_from_raw(flags: u32) -> BrokerResult<TimerfdTimerFlags> {
    let allowed = TimerfdTimerFlags::ABSTIME | TimerfdTimerFlags::CANCEL_ON_SET;
    if flags & !allowed.bits() != 0 {
        return Err(BrokerError::UnsupportedOperation);
    }
    Ok(TimerfdTimerFlags::from_bits_truncate(flags))
}

fn itimerspec_from_spec(spec: TimerSpec) -> BrokerResult<Itimerspec> {
    Ok(Itimerspec {
        it_interval: timespec_from_parts(spec.interval_seconds, spec.interval_nanoseconds)?,
        it_value: timespec_from_parts(spec.value_seconds, spec.value_nanoseconds)?,
    })
}

fn timespec_from_parts(seconds: u64, nanoseconds: u64) -> BrokerResult<Timespec> {
    Ok(Timespec {
        tv_sec: i64::try_from(seconds).map_err(|_| BrokerError::UnsupportedOperation)?,
        tv_nsec: i64::try_from(nanoseconds).map_err(|_| BrokerError::UnsupportedOperation)?,
    })
}

fn spec_from_itimerspec(value: &Itimerspec) -> TimerSpec {
    TimerSpec {
        value_seconds: value.it_value.tv_sec.unsigned_abs(),
        value_nanoseconds: value.it_value.tv_nsec.unsigned_abs(),
        interval_seconds: value.it_interval.tv_sec.unsigned_abs(),
        interval_nanoseconds: value.it_interval.tv_nsec.unsigned_abs(),
    }
}

const fn broker_error_from_errno(error: Errno) -> BrokerError {
    match error {
        Errno::NOMEM => BrokerError::OutOfMemory,
        Errno::MFILE | Errno::NFILE | Errno::NOBUFS | Errno::NOSPC => {
            BrokerError::ResourceExhausted
        }
        Errno::INVAL => BrokerError::UnsupportedOperation,
        _ => BrokerError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_mapping_accepts_supported_clocks_and_rejects_others() {
        assert!(matches!(clock_from_raw(0), Ok(TimerfdClockId::Realtime)));
        assert!(matches!(clock_from_raw(1), Ok(TimerfdClockId::Monotonic)));
        // CLOCK_PROCESS_CPUTIME_ID (2) is not a supported timerfd clock here.
        assert_eq!(clock_from_raw(2), Err(BrokerError::UnsupportedOperation));
        assert_eq!(clock_from_raw(-1), Err(BrokerError::UnsupportedOperation));
    }

    #[test]
    fn timer_flags_reject_unknown_bits() {
        assert_eq!(timer_flags_from_raw(0), Ok(TimerfdTimerFlags::empty()));
        assert_eq!(
            timer_flags_from_raw(TimerfdTimerFlags::ABSTIME.bits()),
            Ok(TimerfdTimerFlags::ABSTIME)
        );
        assert_eq!(
            timer_flags_from_raw(0x8000_0000),
            Err(BrokerError::UnsupportedOperation)
        );
    }

    #[test]
    fn itimerspec_round_trips_through_spec() {
        let spec = TimerSpec {
            value_seconds: 3,
            value_nanoseconds: 250_000_000,
            interval_seconds: 1,
            interval_nanoseconds: 500,
        };
        let itimerspec = itimerspec_from_spec(spec).unwrap();
        assert_eq!(itimerspec.it_value.tv_sec, 3);
        assert_eq!(itimerspec.it_value.tv_nsec, 250_000_000);
        assert_eq!(itimerspec.it_interval.tv_sec, 1);
        assert_eq!(itimerspec.it_interval.tv_nsec, 500);
        assert_eq!(spec_from_itimerspec(&itimerspec), spec);
    }

    #[test]
    fn oversized_spec_is_rejected() {
        let spec = TimerSpec {
            value_seconds: u64::MAX,
            ..TimerSpec::default()
        };
        assert_eq!(
            itimerspec_from_spec(spec).err(),
            Some(BrokerError::UnsupportedOperation)
        );
    }

    #[test]
    fn errno_mapping_matches_broker_errors() {
        assert_eq!(
            broker_error_from_errno(Errno::NOMEM),
            BrokerError::OutOfMemory
        );
        assert_eq!(
            broker_error_from_errno(Errno::MFILE),
            BrokerError::ResourceExhausted
        );
        assert_eq!(
            broker_error_from_errno(Errno::INVAL),
            BrokerError::UnsupportedOperation
        );
        assert_eq!(broker_error_from_errno(Errno::IO), BrokerError::Internal);
    }
}
