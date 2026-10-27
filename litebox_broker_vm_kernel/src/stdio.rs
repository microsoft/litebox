// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner processes' standard streams, on the runner's [`Console`]; both
//! output streams share it. Standard-input files are woken when input starts
//! to be pending, and output files once the device can take output again,
//! those of the processes whose write or readiness check found it full.

use crate::readiness::KernelReadiness;
use crate::serving;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use litebox_broker_core::BrokerError;
use litebox_broker_core::readiness::{ReadinessRegistration, ReadinessWatchers};
use litebox_broker_core::stdio::{
    StdioOutputStream, StdioProvider, StdioProviderError, StdioStream,
};
use litebox_broker_core::transfer::bounce_buffer;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_hal::virtio::console::TRANSMIT_CAPACITY;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::time::Instant as _;
use litebox_platform_vm_kernel::Instant;
use spin::Mutex;

/// How often a console that does not interrupt is polled while output waits
/// for it.
const OUTPUT_POLL: Duration = Duration::from_millis(1);

/// A byte-stream device behind the standard streams.
pub trait Console: Sync {
    /// Copies received bytes into `output`: how many (zero if none yet), or
    /// `None` at the end of input (e.g., a device without input).
    fn read(&self, output: &mut [u8]) -> Option<usize>;

    /// Whether [`Self::read`] would not return zero: input or its end.
    fn has_input(&self) -> bool;

    /// How much of `input`, for `stream`, the device takes now, without
    /// waiting: zero if it has no room.
    fn write(&self, stream: StdioOutputStream, input: &[u8]) -> usize;

    /// Whether [`Self::write`] would take something now.
    fn can_write(&self) -> bool;

    /// Whether the device interrupts once it can take output again; if not,
    /// the broker polls it while output waits for it.
    fn interrupts(&self) -> bool;
}

pub(crate) struct ConsoleStdio {
    console: &'static dyn Console,
    stdin: Mutex<Stdin>,
    /// Standard-output and standard-error files, to wake once the device can
    /// take output again (see [`Self::poll`]).
    output: Mutex<ReadinessWatchers>,
    writable: OutputLevel,
    waiters: Mutex<OutputWaiters>,
}

/// Whether output can go out, as far as the broker knows. Only a failure
/// lowers it, before it returns; the first poll that then finds room raises it
/// and publishes `WRITE` (see [`ConsoleStdio::poll`]): once per failure.
struct OutputLevel(AtomicBool);

impl OutputLevel {
    fn fail(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    /// Whether to publish `WRITE`: the level was down, and `can_write` found
    /// room; then it is up.
    fn poll(&self, can_write: impl FnOnce() -> bool) -> bool {
        !self.0.load(Ordering::SeqCst) && can_write() && !self.0.swap(true, Ordering::SeqCst)
    }

    fn is_up(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Whom the next `WRITE` publication wakes: the processes whose own write or
/// readiness check found the device full (only they wait for it, each through
/// its own registration), recorded before the level goes down and taken after
/// it comes up; everyone after a failure outside any request, or without
/// memory. Held weakly, so an ended process is not kept.
#[derive(Default)]
struct OutputWaiters {
    processes: Vec<Weak<KernelReadiness>>,
    everyone: bool,
}

impl OutputWaiters {
    /// Records `waiter`'s process, or, if `None`, everyone; forgets the
    /// processes that ended.
    fn add(&mut self, waiter: Option<Arc<KernelReadiness>>) {
        let Some(waiter) = waiter else {
            self.everyone = true;
            return;
        };
        self.processes.retain(|process| process.strong_count() != 0);
        let waiter = Arc::downgrade(&waiter);
        if self
            .processes
            .iter()
            .any(|process| Weak::ptr_eq(process, &waiter))
        {
            return;
        }
        if self.processes.try_reserve(1).is_ok() {
            self.processes.push(waiter);
        } else {
            self.everyone = true;
        }
    }
}

/// Locked as a whole, so that CPUs polling at once see input start to be
/// pending in turn (and one publishes it).
#[derive(Default)]
struct Stdin {
    /// Standard-input files, to wake when input arrives.
    watchers: ReadinessWatchers,
    /// Whether input was pending when last looked at.
    readable: bool,
}

impl ConsoleStdio {
    pub(crate) fn new(console: &'static dyn Console) -> Self {
        Self {
            console,
            stdin: Mutex::new(Stdin::default()),
            output: Mutex::new(ReadinessWatchers::default()),
            writable: OutputLevel(AtomicBool::new(true)),
            waiters: Mutex::new(OutputWaiters::default()),
        }
    }

    /// Wakes standard-input watchers if input started to be pending, and
    /// output watchers once the device can take output again after a failure
    /// (see [`OutputLevel`]).
    pub(crate) fn poll(&self) {
        {
            let mut stdin = self.stdin.lock();
            let readable = self.console.has_input();
            if readable && !stdin.readable {
                stdin.watchers.publish(ReadinessFlags::READ);
            }
            stdin.readable = readable;
        }
        if self.writable.poll(|| self.console.can_write()) {
            self.publish_writable(|| self.output.lock().publish(ReadinessFlags::WRITE));
        }
    }

    /// Runs `publish`, the `WRITE` publication, so that it wakes the recorded
    /// waiters alone, or everyone.
    fn publish_writable(&self, publish: impl FnOnce()) {
        let OutputWaiters {
            processes,
            everyone,
        } = core::mem::take(&mut *self.waiters.lock());
        if everyone {
            publish();
            return;
        }
        // The live ones, held until the publication ends, so that each mark is
        // undone.
        let processes: Vec<Arc<KernelReadiness>> = processes
            .into_iter()
            .filter_map(|process| process.upgrade())
            .collect();
        for process in &processes {
            process.wake_for_console(true);
        }
        serving::publish_console(publish);
        for process in &processes {
            process.wake_for_console(false);
        }
    }

    /// The device had no room for the caller, which may wait for `WRITE`:
    /// records `waiter` (see [`OutputWaiters`]), then lowers the level.
    fn full(&self, waiter: Option<Arc<KernelReadiness>>) {
        self.waiters.lock().add(waiter);
        self.writable.fail();
    }

    /// While output waits for a console that does not interrupt, when to poll
    /// it next.
    pub(crate) fn next_deadline(&self, now: Instant) -> Option<Instant> {
        (!self.writable.is_up() && !self.console.interrupts())
            .then(|| now.saturating_add(OUTPUT_POLL))
    }
}

impl StdioProvider for ConsoleStdio {
    fn read(&self, output: &mut dyn ReadBuffer) -> Result<usize, StdioProviderError> {
        let mut staged = bounce_buffer(output.len())?;
        match self.console.read(&mut staged) {
            None => Ok(0),
            Some(0) => Err(StdioProviderError::WouldBlock),
            Some(read) => {
                output.copy_from_slice_at(0, staged.get(..read).ok_or(BrokerError::Internal)?)?;
                Ok(read)
            }
        }
    }

    /// Stages at most what the device holds per attempt, so that a retry
    /// never stages the rest of a large write again; goes on while the device
    /// takes each chunk whole.
    fn write(
        &self,
        stream: StdioOutputStream,
        input: &dyn WriteBuffer,
    ) -> Result<usize, StdioProviderError> {
        let mut staged = bounce_buffer(input.len().min(TRANSMIT_CAPACITY))?;
        let mut written = 0;
        while written < input.len() {
            let chunk = &mut staged[..(input.len() - written).min(TRANSMIT_CAPACITY)];
            if let Err(fault) = input.copy_to_slice_at(written, chunk) {
                // What went out is reported, as a short write, so that a
                // retry does not write it again.
                if written == 0 {
                    return Err(fault.into());
                }
                break;
            }
            let taken = self.console.write(stream, chunk);
            written += taken;
            if taken < chunk.len() {
                break;
            }
        }
        if written == 0 {
            // For `Self::poll` to wake the writer, which may wait.
            self.full(serving::served());
            return Err(StdioProviderError::WouldBlock);
        }
        Ok(written)
    }

    fn readiness(&self, stream: StdioStream) -> ReadinessFlags {
        match stream {
            StdioStream::Stdin if !self.console.has_input() => ReadinessFlags(0),
            StdioStream::Stdin => ReadinessFlags::READ,
            StdioStream::Stdout | StdioStream::Stderr if self.console.can_write() => {
                ReadinessFlags::WRITE
            }
            StdioStream::Stdout | StdioStream::Stderr => {
                // For `Self::poll` to wake the caller, which may wait.
                self.full(serving::served());
                ReadinessFlags(0)
            }
        }
    }

    fn watch(
        &self,
        stream: StdioStream,
        registration: &ReadinessRegistration,
    ) -> litebox_broker_core::Result<()> {
        match stream {
            StdioStream::Stdin => {
                self.stdin.lock().watchers.watch(registration)?;
                if self.console.has_input() {
                    registration.publish(ReadinessFlags::READ);
                }
            }
            StdioStream::Stdout | StdioStream::Stderr => {
                self.output.lock().watch(registration)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::sync::atomic::AtomicUsize;
    use litebox_platform::buffer::{Buffer, Fault, RawBytes};

    /// A console with room for `room` more bytes of output, which tests set,
    /// that keeps what it takes.
    struct Device {
        room: AtomicUsize,
        taken: Mutex<Vec<u8>>,
        /// How many times [`Console::can_write`] looked at the room.
        looks: AtomicUsize,
        interrupts: bool,
    }

    impl Console for Device {
        fn read(&self, _output: &mut [u8]) -> Option<usize> {
            None
        }

        fn has_input(&self) -> bool {
            true
        }

        fn write(&self, _stream: StdioOutputStream, input: &[u8]) -> usize {
            let room = self.room.load(Ordering::Relaxed);
            let taken = input.len().min(room);
            self.room.store(room - taken, Ordering::Relaxed);
            self.taken.lock().extend_from_slice(&input[..taken]);
            taken
        }

        fn can_write(&self) -> bool {
            self.looks.fetch_add(1, Ordering::Relaxed);
            self.room.load(Ordering::Relaxed) != 0
        }

        fn interrupts(&self) -> bool {
            self.interrupts
        }
    }

    fn device(room: usize, interrupts: bool) -> &'static Device {
        Box::leak(Box::new(Device {
            room: AtomicUsize::new(room),
            taken: Mutex::new(Vec::new()),
            looks: AtomicUsize::new(0),
            interrupts,
        }))
    }

    /// `bytes`, of which a copy that reaches `fault_at` faults.
    struct Faulting<'a> {
        bytes: &'a [u8],
        fault_at: usize,
    }

    impl Faulting<'_> {
        fn reach(&self, end: usize) -> Result<(), Fault> {
            if end > self.fault_at {
                return Err(Fault);
            }
            Ok(())
        }
    }

    impl Buffer for Faulting<'_> {
        fn len(&self) -> usize {
            self.bytes.len()
        }
    }

    impl WriteBuffer for Faulting<'_> {
        fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
            self.reach(offset + destination.len())?;
            self.bytes.copy_to_slice_at(offset, destination)
        }

        fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
            self.reach(offset + destination.len())?;
            self.bytes.copy_to_raw_at(offset, destination)
        }
    }

    /// A write goes on while the device takes each chunk whole, and forwards
    /// the input in order, without gaps or repeats; only one that took
    /// nothing fails, and lowers the level.
    #[test]
    fn write_ends_at_the_first_chunk_taken_short() {
        // A period that divides no chunk.
        let input: Vec<u8> = (0..251).cycle().take(3 * TRANSMIT_CAPACITY).collect();
        for (room, written) in [
            // Whole, whole, then short.
            (
                2 * TRANSMIT_CAPACITY + 1000,
                Ok(2 * TRANSMIT_CAPACITY + 1000),
            ),
            // Whole, then nothing.
            (TRANSMIT_CAPACITY, Ok(TRANSMIT_CAPACITY)),
            // Nothing.
            (0, Err(StdioProviderError::WouldBlock)),
        ] {
            let device = device(room, true);
            let stdio = ConsoleStdio::new(device);
            assert_eq!(
                stdio.write(StdioOutputStream::Stdout, &input.as_slice()),
                written
            );
            assert_eq!(*device.taken.lock(), input[..room]);
            assert_eq!(stdio.writable.is_up(), room != 0);
        }
    }

    /// A fault copying the input fails a write only if no output went out
    /// yet; after some did, the write is short. Neither lowers the level.
    #[test]
    fn write_reports_what_went_out_before_a_fault() {
        let input: Vec<u8> = (0..251).cycle().take(2 * TRANSMIT_CAPACITY).collect();
        let device = device(usize::MAX, true);
        let stdio = ConsoleStdio::new(device);
        for (fault_at, written) in [
            // In the first chunk.
            (TRANSMIT_CAPACITY - 1, Err(StdioProviderError::from(Fault))),
            // In the second.
            (TRANSMIT_CAPACITY + 1, Ok(TRANSMIT_CAPACITY)),
        ] {
            device.taken.lock().clear();
            let input = Faulting {
                bytes: &input,
                fault_at,
            };
            assert_eq!(stdio.write(StdioOutputStream::Stdout, &input), written);
            assert_eq!(*device.taken.lock(), input.bytes[..written.unwrap_or(0)]);
            assert!(stdio.writable.is_up());
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Event {
        /// A write, which fails without room.
        Write,
        /// A readiness check (e.g., for `POLLOUT`), which fails without room.
        Check,
        /// The device takes output again.
        Drain,
        /// Other output fills the device.
        Fill,
        /// A poll of the broker's sources.
        Poll,
    }

    /// In every order of these, up to a length: a poll publishes `WRITE`
    /// (raises the level) exactly when a failure since the last publication
    /// left the level down and the device has room, and only then looks at
    /// the device. So does one after a drain between a waiting writer's
    /// retry (once its wait is registered) and its wait's first poll.
    #[test]
    fn output_level_publishes_once_per_failure() {
        const EVENTS: [Event; 5] = [
            Event::Write,
            Event::Check,
            Event::Drain,
            Event::Fill,
            Event::Poll,
        ];
        const LENGTH: u32 = 6;
        let device = device(0, true);
        for order in 0..EVENTS.len().pow(LENGTH) {
            let events: Vec<Event> = (0..LENGTH)
                .scan(order, |rest, _| {
                    let event = EVENTS[*rest % EVENTS.len()];
                    *rest /= EVENTS.len();
                    Some(event)
                })
                .collect();
            device.room.store(usize::MAX, Ordering::Relaxed);
            let stdio = ConsoleStdio::new(device);
            // A failure that no publication answered yet.
            let mut failed = false;
            for event in &events {
                let room = device.room.load(Ordering::Relaxed) != 0;
                match event {
                    Event::Write => {
                        failed |= stdio
                            .write(StdioOutputStream::Stdout, &[0u8].as_slice())
                            .is_err();
                    }
                    Event::Check => {
                        failed |= stdio.readiness(StdioStream::Stdout) != ReadinessFlags::WRITE;
                    }
                    Event::Drain => device.room.store(usize::MAX, Ordering::Relaxed),
                    Event::Fill => device.room.store(0, Ordering::Relaxed),
                    Event::Poll => {
                        let looks = device.looks.load(Ordering::Relaxed);
                        let was_up = stdio.writable.is_up();
                        stdio.poll();
                        assert_eq!(
                            !was_up && stdio.writable.is_up(),
                            failed && room,
                            "{events:?}: published"
                        );
                        assert_eq!(
                            device.looks.load(Ordering::Relaxed) != looks,
                            failed,
                            "{events:?}: looked at the device"
                        );
                        failed &= !room;
                    }
                }
                assert_eq!(stdio.writable.is_up(), !failed, "{events:?}: level");
            }
        }
    }

    /// Raises `stdio`'s level as a poll that finds room does, and publishes:
    /// which of `processes` the publication wakes, with `during` inside it.
    fn publish(
        stdio: &ConsoleStdio,
        device: &Device,
        processes: &[Arc<KernelReadiness>; 3],
        during: impl FnOnce(),
    ) -> [bool; 3] {
        device.room.store(usize::MAX, Ordering::Relaxed);
        assert!(stdio.writable.poll(|| device.can_write()));
        device.room.store(0, Ordering::Relaxed);
        let mut woken = None;
        stdio.publish_writable(|| {
            during();
            woken = Some(wakes(processes));
        });
        woken.expect("the publication ran")
    }

    /// Which of `processes` a console `WRITE` publication wakes now.
    fn wakes(processes: &[Arc<KernelReadiness>; 3]) -> [bool; 3] {
        processes
            .each_ref()
            .map(|process| process.wakes_for_console())
    }

    /// A publication wakes only the processes whose requests found the device
    /// full since the last one, each once, and only while it runs, even with
    /// another inside it; a failure outside any request wakes everyone.
    #[test]
    fn publication_wakes_the_processes_that_found_the_device_full() {
        let device = device(0, true);
        let stdio = ConsoleStdio::new(device);
        let processes = [(); 3].map(|()| Arc::new(KernelReadiness::new()));
        let [writer, checker, _bystander] = &processes;
        let full = |process: Option<&Arc<KernelReadiness>>| stdio.full(process.cloned());
        full(Some(writer));
        full(Some(checker));
        full(Some(writer));
        let woken = publish(&stdio, device, &processes, || ());
        assert_eq!(woken, [true, true, false]);
        assert_eq!(wakes(&processes), [false; 3], "after a publication");
        full(Some(checker));
        assert_eq!(
            publish(&stdio, device, &processes, || ()),
            [false, true, false]
        );
        full(Some(writer));
        full(None);
        assert!(stdio.waiters.lock().everyone);
        assert_eq!(publish(&stdio, device, &processes, || ()), [false; 3]);
        assert!(!stdio.waiters.lock().everyone, "once");
        full(Some(writer));
        let woken = publish(&stdio, device, &processes, || {
            full(Some(writer));
            let woken = publish(&stdio, device, &processes, || ());
            assert_eq!(woken, [true, false, false], "inside");
        });
        assert_eq!(woken, [true, false, false]);
        assert_eq!(wakes(&processes), [false; 3], "after both");
    }

    /// The record keeps no process that ended: its readiness is dropped while
    /// the device stays full, and the next record forgets it.
    #[test]
    fn the_record_keeps_no_ended_process() {
        let stdio = ConsoleStdio::new(device(0, true));
        let ended = Arc::new(KernelReadiness::new());
        let readiness = Arc::downgrade(&ended);
        stdio.full(Some(ended));
        assert_eq!(readiness.strong_count(), 0, "dropped");
        let live = Arc::new(KernelReadiness::new());
        stdio.full(Some(live.clone()));
        assert_eq!(stdio.waiters.lock().processes.len(), 1, "forgotten");
        assert_eq!(Arc::strong_count(&live), 1, "held weakly");
    }

    /// Only a console that does not interrupt is polled, while the level is
    /// down.
    #[test]
    fn next_deadline_is_a_poll_while_output_waits_without_interrupts() {
        let now = Instant::from_nanos(1_000_000);
        for interrupts in [false, true] {
            let device = device(0, interrupts);
            let stdio = ConsoleStdio::new(device);
            assert_eq!(stdio.next_deadline(now), None);
            assert!(
                stdio
                    .write(StdioOutputStream::Stdout, &[0u8].as_slice())
                    .is_err()
            );
            let poll = (!interrupts).then(|| now.saturating_add(OUTPUT_POLL));
            assert_eq!(stdio.next_deadline(now), poll);
            stdio.poll();
            assert_eq!(stdio.next_deadline(now), poll);
            device.room.store(1, Ordering::Relaxed);
            stdio.poll();
            assert_eq!(stdio.next_deadline(now), None);
        }
    }
}
