//! Crate-local test-only mock platform for easily running tests in the various modules.

#![expect(
    unused_variables,
    reason = "mock platform might ignore some parts / not yet implement them"
)]

// Pull in `std` for the test-only world, so that we have a nicer/easier time writing tests
extern crate std;

use core::sync::atomic::AtomicU32;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::vec::Vec;

use super::*;

/// A mock platform that is a [`platform::Provider`](Provider), useful purely for testing within
/// this crate.
///
/// Some great features of this mock platform are:
///
/// - Full determinism
///   + time moves at one millisecond per "now" call
///   + IP packets are placed into a deterministic ring buffer and spin back around
/// - Debuging output goes to stderr
/// - Can pre-fill stdin and check stdout easily between invocations (see [`Self::stdin_queue`],
///   [`Self::stdout_queue`], and [`Self::stderr_queue`])
/// - It will not mock you for using it during tests
pub(crate) struct MockPlatform {
    current_time: AtomicU64,
    ip_packets: RwLock<VecDeque<Vec<u8>>>,
    random: Mutex<crate::utils::rng::FastRng>,
    pub(crate) stdin_queue: RwLock<VecDeque<Vec<u8>>>,
    pub(crate) stdout_queue: RwLock<VecDeque<Vec<u8>>>,
    pub(crate) stderr_queue: RwLock<VecDeque<Vec<u8>>>,
}

impl MockPlatform {
    pub(crate) fn new() -> &'static Self {
        //  Since this is used entirely for tests, leaking a bit of memory is perfectly fine in
        //  order to give ourselves a statically lived platform easily.
        alloc::boxed::Box::leak(alloc::boxed::Box::new(MockPlatform {
            current_time: AtomicU64::new(0),
            ip_packets: RwLock::new(VecDeque::new()),
            random: Mutex::new(crate::utils::rng::FastRng::new_from_seed(
                core::num::NonZeroU64::new(0x4d595df4d0f33173).unwrap(),
            )),
            stdin_queue: RwLock::new(VecDeque::new()),
            stdout_queue: RwLock::new(VecDeque::new()),
            stderr_queue: RwLock::new(VecDeque::new()),
        }))
    }
}

impl Provider for MockPlatform {}

pub(crate) struct MockRawMutex {
    inner: AtomicU32,
    internal_state: std::sync::RwLock<MockRawMutexInternalState>,
}

struct MockRawMutexInternalState {
    number_to_wake_up: usize,
    number_blocked: usize,
}

impl MockRawMutex {
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // Before we can lose any wake-ups, we go and set the number blocked incremented by one.
        self.internal_state.write().unwrap().number_blocked += 1;

        // We then immediately wake up (without triggering anything else) if we can clearly see that
        // the value is different.
        if self.inner.load(core::sync::atomic::Ordering::SeqCst) != val {
            // We do need to make sure we reset the state, importantly, making sure that if a waker
            // showed up along the way, we actually reset that waker count by one, so we are not
            // leaving it impossible for wakers to handle things later.
            let mut internal_state = self.internal_state.write().unwrap();
            internal_state.number_blocked -= 1;
            if internal_state.number_to_wake_up > 0 {
                internal_state.number_to_wake_up -= 1;
            }
            return Err(ImmediatelyWokenUp);
        }

        // Track some initial information.
        let start = std::time::Instant::now();

        // We'll be looping unless we find a good reason to exit out of the loop, either due to a
        // wake-up or a time-out. We do a singular (only as a one-off) check for the
        // immediate-wake-up purely as an optimization, but otherwise, the only way to exit this
        // loop is to actually hit an `Ok` state out for this function.
        loop {
            core::hint::spin_loop();

            let remaining_time = match timeout {
                None => None,
                Some(timeout) => match timeout.checked_sub(start.elapsed()) {
                    None => {
                        break Ok(UnblockedOrTimedOut::TimedOut);
                    }
                    Some(remaining_time) => Some(remaining_time),
                },
            };

            // Fast-path check first
            if self.internal_state.read().unwrap().number_to_wake_up == 0 {
                continue;
            }

            // Seems like there may actually be stuff to wake up. We re-lock writably.
            let mut internal_state = self.internal_state.write().unwrap();

            // Now we can actually check and do things without anyone else interfering.
            if internal_state.number_to_wake_up == 0 {
                // Seems like someone else picked it up before us, go back to blocking
                continue;
            }

            internal_state.number_to_wake_up -= 1;
            internal_state.number_blocked -= 1;
            return Ok(UnblockedOrTimedOut::Unblocked);
        }
    }
}

impl RawMutex for MockRawMutex {
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        let mut internal_state = loop {
            let internal_state = self.internal_state.write().unwrap();
            if internal_state.number_to_wake_up > 0 {
                // Someone is already waking things up right now, let us not mess with it, and wait for our turn.
                drop(internal_state);
                continue;
            }
            break internal_state;
        };
        let num_to_wake_up = internal_state.number_blocked.min(n);
        internal_state.number_to_wake_up = num_to_wake_up;
        drop(internal_state); // actually allow the blocked things to wake up

        // we assume everyone we requested will actually wake up
        num_to_wake_up
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(timeout))
    }
}

impl RawMutexProvider for MockPlatform {
    type RawMutex = MockRawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        MockRawMutex {
            inner: AtomicU32::new(0),
            internal_state: std::sync::RwLock::new(MockRawMutexInternalState {
                number_to_wake_up: 0,
                number_blocked: 0,
            }),
        }
    }
}

impl IPInterfaceProvider for MockPlatform {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), SendError> {
        self.ip_packets.write().unwrap().push_back(packet.into());
        Ok(())
    }

    fn receive_ip_packet(&self, packet: &mut [u8]) -> Result<usize, ReceiveError> {
        if self.ip_packets.read().unwrap().is_empty() {
            Err(ReceiveError::WouldBlock)
        } else {
            let mut ipp = self.ip_packets.write().unwrap();
            let v = ipp.pop_front().unwrap();
            assert!(v.len() <= packet.len());
            packet[..v.len()].copy_from_slice(&v);
            Ok(v.len())
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MockInstant {
    time: u64,
}

impl Instant for MockInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        if earlier.time <= self.time {
            Some(core::time::Duration::from_millis(self.time - earlier.time))
        } else {
            None
        }
    }
    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        let duration_millis: u64 = duration.as_millis().try_into().ok()?;
        Some(MockInstant {
            time: self.time.checked_add(duration_millis)?,
        })
    }
}

pub(crate) struct MockSystemTime {
    time: u64,
}

impl SystemTime for MockSystemTime {
    const UNIX_EPOCH: Self = MockSystemTime { time: 0 };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        match self.time.cmp(&earlier.time) {
            core::cmp::Ordering::Less => {
                Err(core::time::Duration::from_millis(earlier.time - self.time))
            }
            core::cmp::Ordering::Equal => Ok(core::time::Duration::from_millis(0)),
            core::cmp::Ordering::Greater => {
                Ok(core::time::Duration::from_millis(self.time - earlier.time))
            }
        }
    }
}

impl TimeProvider for MockPlatform {
    type Instant = MockInstant;
    type SystemTime = MockSystemTime;

    fn now(&self) -> Self::Instant {
        MockInstant {
            time: self.current_time.fetch_add(1, Ordering::SeqCst),
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        MockSystemTime {
            time: self.current_time.load(Ordering::SeqCst),
        }
    }
}

impl PunchthroughProvider for MockPlatform {
    type PunchthroughToken = trivial_providers::ImpossiblePunchthroughToken;
    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        None
    }
}

impl DebugLogProvider for MockPlatform {
    fn debug_log_print(&self, msg: &str) {
        std::eprintln!("{msg}");
    }
}

impl RawPointerProvider for MockPlatform {
    type RawConstPointer<T: Clone> = super::trivial_providers::TransparentConstPtr<T>;
    type RawMutPointer<T: Clone> = super::trivial_providers::TransparentMutPtr<T>;
}

impl StdioProvider for MockPlatform {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, StdioReadError> {
        let Some(front) = self.stdin_queue.write().unwrap().pop_front() else {
            return Err(StdioReadError::Closed);
        };
        let len = front.len().min(buf.len());
        buf[..len].copy_from_slice(&front[..len]);
        if front.len() > len {
            self.stdin_queue
                .write()
                .unwrap()
                .push_front(front.into_iter().skip(len).collect());
        }
        Ok(len)
    }

    fn write_to(&self, stream: StdioOutStream, buf: &[u8]) -> Result<usize, StdioWriteError> {
        match stream {
            StdioOutStream::Stdout => &self.stdout_queue,
            StdioOutStream::Stderr => &self.stderr_queue,
        }
        .write()
        .unwrap()
        .push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn is_a_tty(&self, _stream: StdioStream) -> bool {
        false
    }
}

impl CrngProvider for MockPlatform {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        let mut random = self.random.lock().unwrap();
        let mut off = 0;
        while off < buf.len() {
            let bytes = random.next_u64();
            let max = core::cmp::min(buf.len() - off, 8);
            buf[off..off + max].copy_from_slice(&bytes.to_ne_bytes()[..max]);
            off += max;
        }
    }
}

std::thread_local! {
    static MOCK_TLS: core::cell::Cell<*mut()>  = const { core::cell::Cell::new(core::ptr::null_mut()) };
}

unsafe impl ThreadLocalStorageProvider for MockPlatform {
    fn get_thread_local_storage() -> *mut () {
        MOCK_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        MOCK_TLS.replace(value)
    }
}
