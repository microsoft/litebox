//! Crate-local test-only mock platform for easily running tests in the various modules.

// Pull in `std` for the test-only world, so that we have a nicer/easier time writing tests
extern crate std;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
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
    ip_packets: RefCell<VecDeque<Vec<u8>>>,
    pub(crate) stdin_queue: RefCell<VecDeque<Vec<u8>>>,
    pub(crate) stdout_queue: RefCell<VecDeque<Vec<u8>>>,
    pub(crate) stderr_queue: RefCell<VecDeque<Vec<u8>>>,
}

impl MockPlatform {
    pub(crate) fn new() -> Self {
        MockPlatform {
            current_time: AtomicU64::new(0),
            ip_packets: RefCell::new(VecDeque::new()),
            stdin_queue: RefCell::new(VecDeque::new()),
            stdout_queue: RefCell::new(VecDeque::new()),
            stderr_queue: RefCell::new(VecDeque::new()),
        }
    }
}

impl Provider for MockPlatform {}

pub(crate) struct MockRawMutex {
    atomic: core::sync::atomic::AtomicU32,
}

impl RawMutex for MockRawMutex {
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        &self.atomic
    }

    fn wake_many(&self, n: usize) -> usize {
        unimplemented!("raw mutex for MockPlatform")
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        unimplemented!("raw mutex for MockPlatform")
    }

    fn block_or_timeout(
        &self,
        val: u32,
        time: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        unimplemented!("raw mutex for MockPlatform")
    }
}

impl RawMutexProvider for MockPlatform {
    type RawMutex = MockRawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        MockRawMutex {
            atomic: core::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl IPInterfaceProvider for MockPlatform {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), SendError> {
        self.ip_packets.borrow_mut().push_back(packet.into());
        Ok(())
    }

    fn receive_ip_packet(&self, packet: &mut [u8]) -> Result<usize, ReceiveError> {
        if self.ip_packets.borrow().is_empty() {
            Err(ReceiveError::WouldBlock)
        } else {
            let mut ipp = self.ip_packets.borrow_mut();
            let v = ipp.pop_front().unwrap();
            assert!(v.len() <= packet.len());
            packet[..v.len()].copy_from_slice(&v);
            Ok(v.len())
        }
    }
}

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
}

impl TimeProvider for MockPlatform {
    type Instant = MockInstant;

    fn now(&self) -> Self::Instant {
        MockInstant {
            time: self.current_time.fetch_add(1, Ordering::SeqCst),
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
        let Some(front) = self.stdin_queue.borrow_mut().pop_front() else {
            return Err(StdioReadError::Closed);
        };
        let len = front.len().min(buf.len());
        buf[..len].copy_from_slice(&front[..len]);
        if front.len() > len {
            self.stdin_queue
                .borrow_mut()
                .push_front(front.into_iter().skip(len).collect());
        }
        Ok(len)
    }

    fn write_to(&self, stream: StdioOutStream, buf: &[u8]) -> Result<usize, StdioWriteError> {
        match stream {
            StdioOutStream::Stdout => &self.stdout_queue,
            StdioOutStream::Stderr => &self.stderr_queue,
        }
        .borrow_mut()
        .push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn is_a_tty(&self, _stream: StdioStream) -> bool {
        false
    }
}
