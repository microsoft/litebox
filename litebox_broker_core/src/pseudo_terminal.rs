// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned pseudo-terminal pairs.
//!
//! A pair joins a manager, through which a program such as a terminal
//! emulator plays the terminal's hardware, and a subsidiary, which other
//! programs use as their terminal. Bytes written to the manager are the
//! subsidiary's input, and pass through the pair's line discipline, as does
//! output written to the subsidiary, which the manager reads along with any
//! echo. Both sides share the line discipline's settings and the window size.
//!
//! An index, unique among existing pairs, names each pair's subsidiary. The
//! subsidiary starts locked against opening, so that the manager's opener can
//! prepare it first. Closing the manager hangs up the subsidiary and retires
//! its name. The index becomes free once nothing refers to the pair.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use litebox_broker_protocol::fs::FileError;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::{
    ChangeTiming, TerminalEvents, TerminalOperation, TerminalResponse, WindowSize,
};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::{Mutex, MutexGuard};

use crate::fs::FileResult;
use crate::fs::errors::{OpenError, PathError, ReadError, WriteError};
use crate::readiness::{ReadinessRegistration, ReadinessSource, ReadinessWatchers};
use crate::terminal::{
    ATOMIC_WRITE_SIZE, INPUT_CAPACITY, OUTPUT_CAPACITY, TerminalEndpoint, TerminalEngine,
    TerminalEventSink,
};
use crate::transfer::{bounce_buffer, take_from_queue};

/// Most pseudo-terminal pairs that may exist at once.
pub(crate) const MAX_PSEUDO_TERMINALS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Manager,
    Subsidiary,
}

struct State {
    engine: TerminalEngine,
    /// Output written to the subsidiary, and echo, for the manager to read.
    output: VecDeque<u8>,
    size: WindowSize,
    sink: Option<Arc<dyn TerminalEventSink>>,
    /// Whether the subsidiary refuses to open.
    locked: bool,
    /// Whether the manager is open. Closing it hangs up the subsidiary.
    manager_open: bool,
    /// Files open on the subsidiary.
    subsidiary_files: usize,
    /// Whether every file opened on the subsidiary has closed since the last
    /// one opened.
    subsidiary_closed: bool,
    manager_watchers: ReadinessWatchers,
    subsidiary_watchers: ReadinessWatchers,
}

impl State {
    fn manager_readiness(&self) -> ReadinessFlags {
        let mut flags = ReadinessFlags::default();
        if !self.output.is_empty() {
            flags = flags | ReadinessFlags::READ;
        }
        if self.engine.accepts_input() {
            flags = flags | ReadinessFlags::WRITE;
        }
        // Reads fail once output is drained, but report no end-of-file, since
        // the subsidiary may open again.
        if self.subsidiary_closed {
            flags = flags | ReadinessFlags::CLOSED;
        }
        flags
    }

    fn subsidiary_readiness(&self) -> ReadinessFlags {
        if !self.manager_open {
            return ReadinessFlags::READ
                | ReadinessFlags::WRITE
                | ReadinessFlags::ERROR
                | ReadinessFlags::CLOSED;
        }
        let mut flags = ReadinessFlags::default();
        if self.engine.readable() {
            flags = flags | ReadinessFlags::READ;
        }
        if !self.engine.output_stopped()
            && self.output.len()
                <= OUTPUT_CAPACITY - self.engine.output_expansion() * ATOMIC_WRITE_SIZE
        {
            flags = flags | ReadinessFlags::WRITE;
        }
        flags
    }

    /// Wakes both sides' watchers.
    fn publish(&self) {
        self.manager_watchers.publish(self.manager_readiness());
        self.subsidiary_watchers
            .publish(self.subsidiary_readiness());
    }
}

/// A pseudo-terminal pair, which is also its subsidiary's endpoint, so every
/// file open on the subsidiary shares one endpoint.
pub(crate) struct PseudoTerminal {
    index: u32,
    state: Mutex<State>,
}

impl PseudoTerminal {
    fn new(index: u32) -> Self {
        Self {
            index,
            state: Mutex::new(State {
                engine: TerminalEngine::default(),
                output: VecDeque::new(),
                size: WindowSize::default(),
                sink: None,
                locked: true,
                manager_open: true,
                subsidiary_files: 0,
                subsidiary_closed: false,
                manager_watchers: ReadinessWatchers::default(),
                subsidiary_watchers: ReadinessWatchers::default(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock()
    }

    /// Opens a file on the subsidiary. Fails if the manager has closed, or
    /// with [`OpenError::Io`] if the subsidiary is locked.
    pub(crate) fn open_subsidiary(self: &Arc<Self>) -> Result<SubsidiaryFile, OpenError> {
        let mut state = self.lock();
        if !state.manager_open {
            return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory));
        }
        if state.locked {
            return Err(OpenError::Io);
        }
        state.subsidiary_files += 1;
        if state.subsidiary_closed {
            state.subsidiary_closed = false;
            state.publish();
        }
        Ok(SubsidiaryFile(Arc::clone(self)))
    }

    fn attach(&self, sink: Arc<dyn TerminalEventSink>) {
        let sink = {
            let mut state = self.lock();
            let sink = Arc::clone(state.sink.get_or_insert(sink));
            if state.manager_open {
                return;
            }
            sink
        };
        sink.hang_up();
    }

    fn manager_read(&self, output: &mut dyn ReadBuffer) -> Result<usize, ReadError> {
        let mut state = self.lock();
        if output.is_empty() {
            return Ok(0);
        }
        if state.output.is_empty() {
            return Err(if state.subsidiary_closed {
                ReadError::Io
            } else {
                ReadError::WouldBlock
            });
        }
        let count = output.len().min(state.output.len());
        take_from_queue(&mut state.output, count, output)?;
        state.publish();
        Ok(count)
    }

    fn manager_write(&self, input: &dyn WriteBuffer) -> Result<usize, WriteError> {
        if input.is_empty() {
            return Ok(0);
        }
        let mut staged = bounce_buffer(input.len().min(INPUT_CAPACITY))?;
        input.copy_to_slice_at(0, &mut staged)?;
        let state = &mut *self.lock();
        let result = state.engine.receive(&staged);
        if result.consumed == 0 {
            return Err(WriteError::WouldBlock);
        }
        // Signal characters' discarding of queued output is ignored: the
        // manager may already have read it, and its reads are not output that
        // a terminal could still be transmitting.
        //
        // Echo is best-effort under output backpressure, as with a bounded
        // terminal-driver echo buffer.
        let available = OUTPUT_CAPACITY - state.output.len();
        state.output.extend(result.echo.into_iter().take(available));
        if let Some(sink) = &state.sink
            && !result.events.is_empty()
        {
            sink.post(result.events);
        }
        state.publish();
        Ok(result.consumed)
    }

    fn subsidiary_read(&self, output: &mut dyn ReadBuffer) -> Result<usize, ReadError> {
        let mut state = self.lock();
        if !state.manager_open {
            return Ok(0);
        }
        let Some(count) = state.engine.read(output)? else {
            return Err(ReadError::WouldBlock);
        };
        state.publish();
        Ok(count)
    }

    fn subsidiary_write(&self, input: &dyn WriteBuffer) -> Result<usize, WriteError> {
        let state = &mut *self.lock();
        if !state.manager_open {
            return Err(WriteError::Io);
        }
        if input.is_empty() {
            return Ok(0);
        }
        let available = (OUTPUT_CAPACITY - state.output.len()) / state.engine.output_expansion();
        if state.engine.output_stopped()
            || available == 0
            || (input.len() <= ATOMIC_WRITE_SIZE && input.len() > available)
        {
            return Err(WriteError::WouldBlock);
        }
        // Output processing rewrites bytes, so stage them first.
        let mut staged = bounce_buffer(input.len().min(available))?;
        input.copy_to_slice_at(0, &mut staged)?;
        state.engine.output(&staged, &mut state.output);
        state.publish();
        Ok(staged.len())
    }

    fn control(&self, side: Side, operation: TerminalOperation) -> FileResult<TerminalResponse> {
        let mut state = self.lock();
        if side == Side::Subsidiary && !state.manager_open {
            return Err(FileError::Io);
        }
        let response = match operation {
            TerminalOperation::GetSettings => TerminalResponse::Settings(state.engine.settings()),
            TerminalOperation::SetSettings { settings, timing } => {
                if !settings.is_supported() {
                    return Err(FileError::InvalidTerminalControl);
                }
                // The manager reads output directly, so none waits to drain.
                if timing == ChangeTiming::AfterOutputAndFlushInput {
                    state.engine.flush_input();
                }
                state.engine.configure(settings)?;
                TerminalResponse::Done
            }
            TerminalOperation::GetWindowSize => TerminalResponse::WindowSize(state.size),
            TerminalOperation::SetWindowSize(window) => {
                if state.size != window {
                    state.size = window;
                    if let Some(sink) = &state.sink {
                        sink.post(TerminalEvents::RESIZE);
                    }
                }
                TerminalResponse::Done
            }
            TerminalOperation::Flush { input, output } => {
                if !input && !output {
                    return Err(FileError::InvalidTerminalControl);
                }
                // Each side discards what it has yet to read. Neither holds
                // output that has yet to reach the other side's queue.
                if input {
                    match side {
                        Side::Manager => state.output.clear(),
                        Side::Subsidiary => state.engine.flush_input(),
                    }
                }
                TerminalResponse::Done
            }
            TerminalOperation::Drain => TerminalResponse::Done,
            TerminalOperation::GetSubsidiaryIndex
            | TerminalOperation::GetSubsidiaryLock
            | TerminalOperation::SetSubsidiaryLock(_)
                if side == Side::Subsidiary =>
            {
                return Err(FileError::InvalidTerminalControl);
            }
            TerminalOperation::GetSubsidiaryIndex => TerminalResponse::SubsidiaryIndex(self.index),
            TerminalOperation::GetSubsidiaryLock => TerminalResponse::SubsidiaryLock(state.locked),
            TerminalOperation::SetSubsidiaryLock(locked) => {
                state.locked = locked;
                TerminalResponse::Done
            }
        };
        state.publish();
        Ok(response)
    }
}

impl ReadinessSource for PseudoTerminal {
    fn readiness(&self) -> ReadinessFlags {
        self.lock().subsidiary_readiness()
    }

    fn watch(&self, registration: &ReadinessRegistration) -> crate::Result<()> {
        self.lock().subsidiary_watchers.watch(registration)
    }
}

impl TerminalEndpoint for PseudoTerminal {
    fn read(&self, output: &mut dyn ReadBuffer) -> Result<usize, ReadError> {
        self.subsidiary_read(output)
    }

    fn write(&self, input: &dyn WriteBuffer) -> Result<usize, WriteError> {
        self.subsidiary_write(input)
    }

    fn control(&self, operation: TerminalOperation) -> crate::Result<FileResult<TerminalResponse>> {
        Ok(self.control(Side::Subsidiary, operation))
    }

    fn attach(&self, sink: Arc<dyn TerminalEventSink>) {
        PseudoTerminal::attach(self, sink);
    }

    fn reopen(self: Arc<Self>) -> Result<Box<dyn Send + Sync>, OpenError> {
        // Like Linux, a subsidiary that is hung up or locked fails to reopen
        // with `Io`, even though its path is gone once hung up.
        self.open_subsidiary()
            .map(|file| Box::new(file) as Box<dyn Send + Sync>)
            .map_err(|_| OpenError::Io)
    }
}

/// A pseudo-terminal pair's manager endpoint.
pub(crate) struct PseudoTerminalManager(Arc<PseudoTerminal>);

impl ReadinessSource for PseudoTerminalManager {
    fn readiness(&self) -> ReadinessFlags {
        self.0.lock().manager_readiness()
    }

    fn watch(&self, registration: &ReadinessRegistration) -> crate::Result<()> {
        self.0.lock().manager_watchers.watch(registration)
    }
}

impl TerminalEndpoint for PseudoTerminalManager {
    fn read(&self, output: &mut dyn ReadBuffer) -> Result<usize, ReadError> {
        self.0.manager_read(output)
    }

    fn write(&self, input: &dyn WriteBuffer) -> Result<usize, WriteError> {
        self.0.manager_write(input)
    }

    fn control(&self, operation: TerminalOperation) -> crate::Result<FileResult<TerminalResponse>> {
        Ok(self.0.control(Side::Manager, operation))
    }

    fn attach(&self, sink: Arc<dyn TerminalEventSink>) {
        self.0.attach(sink);
    }

    fn subsidiary(&self) -> Option<Arc<dyn TerminalEndpoint>> {
        Some(self.0.clone())
    }
}

/// The open manager of a pseudo-terminal pair. Dropping it closes the
/// manager, apart from its endpoint, which only performs I/O.
pub(crate) struct ManagerFile(Arc<PseudoTerminalManager>);

impl ManagerFile {
    /// The manager's endpoint, shared by every holder of this file.
    pub(crate) fn endpoint(&self) -> &Arc<PseudoTerminalManager> {
        &self.0
    }
}

impl Drop for ManagerFile {
    fn drop(&mut self) {
        let sink = {
            let mut state = self.0.0.lock();
            state.manager_open = false;
            // A hung-up subsidiary reads nothing, and nothing reads its output.
            state.output = VecDeque::new();
            state.engine.flush_input();
            state.publish();
            state.sink.clone()
        };
        if let Some(sink) = sink {
            sink.hang_up();
        }
    }
}

/// One open file on a pseudo-terminal pair's subsidiary. Dropping the last
/// one reports the subsidiary closed to the manager.
pub(crate) struct SubsidiaryFile(Arc<PseudoTerminal>);

impl SubsidiaryFile {
    /// The subsidiary's endpoint, shared by every file open on it.
    pub(crate) fn endpoint(&self) -> &Arc<PseudoTerminal> {
        &self.0
    }
}

impl Drop for SubsidiaryFile {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.subsidiary_files -= 1;
        if state.subsidiary_files == 0 {
            state.subsidiary_closed = true;
            state.publish();
        }
    }
}

/// Every pseudo-terminal pair of one device namespace, by index.
pub(crate) struct PseudoTerminals(Mutex<Vec<Weak<PseudoTerminal>>>);

impl PseudoTerminals {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(Vec::with_capacity(MAX_PSEUDO_TERMINALS)))
    }

    /// Creates a pair with the lowest free index and opens its manager. Fails
    /// with [`OpenError::NoSpace`] if every index is in use.
    pub(crate) fn open_manager(&self) -> Result<ManagerFile, OpenError> {
        let mut pairs = self.0.lock();
        let index = match pairs.iter().position(|pair| pair.strong_count() == 0) {
            Some(index) => index,
            None if pairs.len() < MAX_PSEUDO_TERMINALS => {
                pairs.push(Weak::new());
                pairs.len() - 1
            }
            None => return Err(OpenError::NoSpace),
        };
        let pair = Arc::new(PseudoTerminal::new(
            u32::try_from(index).expect("pseudo-terminal limit fits in u32"),
        ));
        pairs[index] = Arc::downgrade(&pair);
        Ok(ManagerFile(Arc::new(PseudoTerminalManager(pair))))
    }

    /// The pair whose subsidiary `index` names, unless its manager has closed.
    pub(crate) fn get(&self, index: u32) -> Option<Arc<PseudoTerminal>> {
        let pair = self.0.lock().get(usize::try_from(index).ok()?)?.upgrade()?;
        let manager_open = pair.lock().manager_open;
        manager_open.then_some(pair)
    }

    /// The indices naming subsidiaries whose managers are open, in order.
    pub(crate) fn indices(&self) -> Vec<u32> {
        // Pairs drop outside the registry lock.
        let pairs: Vec<_> = self.0.lock().iter().filter_map(Weak::upgrade).collect();
        pairs
            .into_iter()
            .filter(|pair| pair.lock().manager_open)
            .map(|pair| pair.index)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::terminal::{LocalFlags, TerminalSettings};

    use super::*;
    use crate::readiness::tests::TestReadinessSink;

    const R: ReadinessFlags = ReadinessFlags::READ;
    const W: ReadinessFlags = ReadinessFlags::WRITE;

    #[derive(Default)]
    struct TestEventSink(StdMutex<Vec<TerminalEvents>>);

    impl TerminalEventSink for TestEventSink {
        fn post(&self, events: TerminalEvents) {
            self.0.lock().unwrap().push(events);
        }

        /// Records a hang-up as [`TerminalEvents::HANGUP`].
        fn hang_up(&self) {
            self.0.lock().unwrap().push(TerminalEvents::HANGUP);
        }
    }

    /// An unlocked pair with one open subsidiary file.
    fn open_pair(terminals: &PseudoTerminals) -> (ManagerFile, SubsidiaryFile) {
        let manager = terminals.open_manager().unwrap();
        let pair = Arc::clone(&manager.endpoint().0);
        assert_eq!(
            manager
                .endpoint()
                .control(TerminalOperation::SetSubsidiaryLock(false)),
            Ok(Ok(TerminalResponse::Done))
        );
        let subsidiary = pair.open_subsidiary().unwrap();
        (manager, subsidiary)
    }

    fn read(endpoint: &dyn TerminalEndpoint) -> Result<Vec<u8>, ReadError> {
        let mut buffer = [0; 256];
        let count = endpoint.read(&mut buffer)?;
        Ok(buffer[..count].to_vec())
    }

    fn write(endpoint: &dyn TerminalEndpoint, bytes: &[u8]) -> Result<usize, WriteError> {
        endpoint.write(&bytes)
    }

    fn control(
        endpoint: &dyn TerminalEndpoint,
        operation: TerminalOperation,
    ) -> FileResult<TerminalResponse> {
        endpoint.control(operation).unwrap()
    }

    fn raw() -> TerminalSettings {
        TerminalSettings {
            local: LocalFlags::empty(),
            ..TerminalSettings::default()
        }
    }

    #[test]
    fn bytes_pass_through_the_line_discipline_both_ways() {
        let terminals = PseudoTerminals::new();
        let (manager, subsidiary) = open_pair(&terminals);
        let manager = manager.endpoint().as_ref();
        let subsidiary = subsidiary.endpoint().as_ref();

        assert!(matches!(write(manager, b"hi"), Ok(2)));
        assert!(matches!(read(subsidiary), Err(ReadError::WouldBlock)));
        assert_eq!(read(manager).unwrap(), b"hi");
        assert!(matches!(write(manager, b"\r"), Ok(1)));
        assert_eq!(read(subsidiary).unwrap(), b"hi\n");
        assert_eq!(read(manager).unwrap(), b"\r\n");

        assert!(matches!(write(subsidiary, b"ok\n"), Ok(3)));
        assert_eq!(read(manager).unwrap(), b"ok\r\n");
        assert!(matches!(read(manager), Err(ReadError::WouldBlock)));
        assert!(matches!(write(subsidiary, b""), Ok(0)));
        assert!(matches!(write(manager, b""), Ok(0)));
        assert!(matches!(manager.read(&mut [0u8; 0]), Ok(0)));
    }

    #[test]
    fn subsidiary_opens_only_when_unlocked_and_managed() {
        let terminals = PseudoTerminals::new();
        let manager = terminals.open_manager().unwrap();
        let pair = terminals.get(0).unwrap();
        let endpoint = manager.endpoint().as_ref();
        assert_eq!(
            control(endpoint, TerminalOperation::GetSubsidiaryLock),
            Ok(TerminalResponse::SubsidiaryLock(true))
        );
        assert!(matches!(pair.open_subsidiary(), Err(OpenError::Io)));
        control(endpoint, TerminalOperation::SetSubsidiaryLock(false)).unwrap();
        assert_eq!(
            control(endpoint, TerminalOperation::GetSubsidiaryLock),
            Ok(TerminalResponse::SubsidiaryLock(false))
        );
        assert_eq!(
            control(endpoint, TerminalOperation::GetSubsidiaryIndex),
            Ok(TerminalResponse::SubsidiaryIndex(0))
        );
        let subsidiary = pair.open_subsidiary().unwrap();
        for operation in [
            TerminalOperation::GetSubsidiaryIndex,
            TerminalOperation::GetSubsidiaryLock,
            TerminalOperation::SetSubsidiaryLock(true),
        ] {
            assert_eq!(
                control(subsidiary.endpoint().as_ref(), operation),
                Err(FileError::InvalidTerminalControl)
            );
        }

        drop(manager);
        assert!(terminals.get(0).is_none());
        assert!(matches!(
            pair.open_subsidiary(),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }

    #[test]
    fn indices_are_bounded_and_reused_once_unreferenced() {
        let terminals = PseudoTerminals::new();
        let mut managers: Vec<_> = (0..MAX_PSEUDO_TERMINALS)
            .map(|_| Some(terminals.open_manager().unwrap()))
            .collect();
        assert!(matches!(terminals.open_manager(), Err(OpenError::NoSpace)));
        assert_eq!(terminals.indices().len(), MAX_PSEUDO_TERMINALS);

        // An open subsidiary keeps its index, but not its name.
        let pair = terminals.get(5).unwrap();
        control(
            managers[5].as_ref().unwrap().endpoint().as_ref(),
            TerminalOperation::SetSubsidiaryLock(false),
        )
        .unwrap();
        let subsidiary = pair.open_subsidiary().unwrap();
        drop(pair);
        managers[5] = None;
        assert!(terminals.get(5).is_none());
        assert!(!terminals.indices().contains(&5));
        assert!(matches!(terminals.open_manager(), Err(OpenError::NoSpace)));

        drop(subsidiary);
        let manager = terminals.open_manager().unwrap();
        assert_eq!(manager.endpoint().0.index, 5);
        managers[2] = None;
        managers[9] = None;
        assert_eq!(terminals.open_manager().unwrap().endpoint().0.index, 2);
    }

    #[test]
    fn manager_reads_fail_only_while_the_subsidiary_is_closed() {
        let terminals = PseudoTerminals::new();
        let manager_file = terminals.open_manager().unwrap();
        let manager = manager_file.endpoint().as_ref();
        let pair = terminals.get(0).unwrap();
        control(manager, TerminalOperation::SetSubsidiaryLock(false)).unwrap();

        // Before the subsidiary first opens, reads wait.
        assert!(matches!(read(manager), Err(ReadError::WouldBlock)));
        assert_eq!(manager.readiness(), W);

        let subsidiary = pair.open_subsidiary().unwrap();
        write(subsidiary.endpoint().as_ref(), b"bye").unwrap();
        drop(subsidiary);
        assert_eq!(manager.readiness(), R | W | ReadinessFlags::CLOSED);
        assert_eq!(read(manager).unwrap(), b"bye");
        assert!(matches!(read(manager), Err(ReadError::Io)));
        assert_eq!(manager.readiness(), W | ReadinessFlags::CLOSED);

        // Input still reaches a later subsidiary.
        control(
            manager,
            TerminalOperation::SetSettings {
                settings: raw(),
                timing: ChangeTiming::Now,
            },
        )
        .unwrap();
        assert!(matches!(write(manager, b"again"), Ok(5)));
        let subsidiary = pair.open_subsidiary().unwrap();
        assert!(matches!(read(manager), Err(ReadError::WouldBlock)));
        assert_eq!(read(subsidiary.endpoint().as_ref()).unwrap(), b"again");
    }

    #[test]
    fn closing_the_manager_hangs_up_the_subsidiary() {
        let terminals = PseudoTerminals::new();
        let (manager, subsidiary) = open_pair(&terminals);
        let events = Arc::new(TestEventSink::default());
        manager.endpoint().attach(events.clone());
        write(manager.endpoint().as_ref(), b"line\r").unwrap();
        let sink = Arc::new(TestReadinessSink::default());
        let registration = ReadinessRegistration::new(ObjectHandle(1), sink.clone());
        let subsidiary = subsidiary.endpoint().as_ref();
        subsidiary.watch(&registration).unwrap();

        drop(manager);
        assert_eq!(*events.0.lock().unwrap(), [TerminalEvents::HANGUP]);
        let hung_up = R | W | ReadinessFlags::ERROR | ReadinessFlags::CLOSED;
        assert_eq!(
            sink.republished.lock().unwrap().as_slice(),
            [(ObjectHandle(1), hung_up)]
        );
        assert_eq!(subsidiary.readiness(), hung_up);
        assert_eq!(read(subsidiary).unwrap(), b"");
        assert!(matches!(write(subsidiary, b"x"), Err(WriteError::Io)));
        assert_eq!(
            control(subsidiary, TerminalOperation::GetSettings),
            Err(FileError::Io)
        );
        assert!(terminals.get(0).is_none());
        assert_eq!(terminals.indices(), Vec::<u32>::new());
    }

    #[test]
    fn readiness_follows_each_queue() {
        let terminals = PseudoTerminals::new();
        let (manager, subsidiary) = open_pair(&terminals);
        let sink = Arc::new(TestReadinessSink::default());
        let manager_registration = ReadinessRegistration::new(ObjectHandle(1), sink.clone());
        let subsidiary_registration = ReadinessRegistration::new(ObjectHandle(2), sink.clone());
        let manager = manager.endpoint().as_ref();
        let subsidiary = subsidiary.endpoint().as_ref();
        manager.watch(&manager_registration).unwrap();
        subsidiary.watch(&subsidiary_registration).unwrap();
        assert_eq!(manager.readiness(), W);
        assert_eq!(subsidiary.readiness(), W);

        write(manager, b"x\r").unwrap();
        assert_eq!(
            sink.republished.lock().unwrap().as_slice(),
            [(ObjectHandle(1), R | W), (ObjectHandle(2), R | W)]
        );
        read(subsidiary).unwrap();
        read(manager).unwrap();
        assert_eq!(manager.readiness(), W);
        assert_eq!(subsidiary.readiness(), W);

        // Software flow control stops subsidiary output, but not echo.
        write(manager, &[0x13]).unwrap();
        assert_eq!(subsidiary.readiness(), ReadinessFlags::default());
        assert!(matches!(
            write(subsidiary, b"x"),
            Err(WriteError::WouldBlock)
        ));
        assert!(matches!(write(manager, b"y"), Ok(1)));
        assert_eq!(read(manager).unwrap(), b"y");
        write(manager, &[0x11]).unwrap();
        assert_eq!(subsidiary.readiness(), W);
        assert!(matches!(write(subsidiary, b"x"), Ok(1)));
    }

    #[test]
    fn full_queues_apply_backpressure() {
        let terminals = PseudoTerminals::new();
        let (manager, subsidiary) = open_pair(&terminals);
        let manager = manager.endpoint().as_ref();
        let subsidiary = subsidiary.endpoint().as_ref();
        control(
            manager,
            TerminalOperation::SetSettings {
                settings: raw(),
                timing: ChangeTiming::Now,
            },
        )
        .unwrap();

        let bytes = alloc::vec![b'a'; INPUT_CAPACITY + 1];
        let accepted = write(manager, &bytes).unwrap();
        assert!(accepted < bytes.len());
        assert!(matches!(write(manager, b"b"), Err(WriteError::WouldBlock)));
        assert_eq!(manager.readiness(), ReadinessFlags::default());
        assert_eq!(read(subsidiary).unwrap().len(), 256);
        assert_eq!(manager.readiness(), W);

        let bytes = alloc::vec![b'c'; OUTPUT_CAPACITY];
        let mut written = 0;
        while let Ok(count) = write(subsidiary, &bytes) {
            written += count;
        }
        assert!(written > OUTPUT_CAPACITY / 4);
        assert!(!subsidiary.readiness().contains(W));
        // A small write is all-or-nothing.
        assert!(matches!(
            write(subsidiary, &bytes[..2]),
            Err(WriteError::WouldBlock)
        ));
    }

    #[test]
    fn settings_and_size_are_shared() {
        let terminals = PseudoTerminals::new();
        let (manager, subsidiary) = open_pair(&terminals);
        let manager = manager.endpoint().as_ref();
        let subsidiary = subsidiary.endpoint().as_ref();
        let events = Arc::new(TestEventSink::default());
        subsidiary.attach(events.clone());

        control(
            manager,
            TerminalOperation::SetSettings {
                settings: raw(),
                timing: ChangeTiming::AfterOutput,
            },
        )
        .unwrap();
        assert_eq!(
            control(subsidiary, TerminalOperation::GetSettings),
            Ok(TerminalResponse::Settings(raw()))
        );
        let settings = TerminalSettings {
            minimum_read: 2,
            ..raw()
        };
        assert_eq!(
            control(
                subsidiary,
                TerminalOperation::SetSettings {
                    settings,
                    timing: ChangeTiming::Now,
                }
            ),
            Err(FileError::InvalidTerminalControl)
        );

        let size = WindowSize {
            rows: 24,
            columns: 80,
            x_pixels: 0,
            y_pixels: 0,
        };
        for _ in 0..2 {
            control(subsidiary, TerminalOperation::SetWindowSize(size)).unwrap();
        }
        assert_eq!(
            control(manager, TerminalOperation::GetWindowSize),
            Ok(TerminalResponse::WindowSize(size))
        );
        assert_eq!(*events.0.lock().unwrap(), [TerminalEvents::RESIZE]);

        // Input generates events through the attached sink.
        control(
            manager,
            TerminalOperation::SetSettings {
                settings: TerminalSettings::default(),
                timing: ChangeTiming::Now,
            },
        )
        .unwrap();
        write(manager, &[3]).unwrap();
        assert_eq!(events.0.lock().unwrap().len(), 2);
    }

    #[test]
    fn flushing_discards_each_sides_unread_input() {
        let terminals = PseudoTerminals::new();
        let (manager, subsidiary) = open_pair(&terminals);
        let manager = manager.endpoint().as_ref();
        let subsidiary = subsidiary.endpoint().as_ref();
        write(manager, b"in\r").unwrap();
        write(subsidiary, b"out").unwrap();

        for endpoint in [manager as &dyn TerminalEndpoint, subsidiary] {
            assert_eq!(
                control(
                    endpoint,
                    TerminalOperation::Flush {
                        input: false,
                        output: false,
                    }
                ),
                Err(FileError::InvalidTerminalControl)
            );
            control(
                endpoint,
                TerminalOperation::Flush {
                    input: false,
                    output: true,
                },
            )
            .unwrap();
        }
        control(
            manager,
            TerminalOperation::Flush {
                input: true,
                output: false,
            },
        )
        .unwrap();
        assert!(matches!(read(manager), Err(ReadError::WouldBlock)));
        assert_eq!(read(subsidiary).unwrap(), b"in\n");

        write(manager, b"more\r").unwrap();
        write(subsidiary, b"kept").unwrap();
        control(
            subsidiary,
            TerminalOperation::Flush {
                input: true,
                output: true,
            },
        )
        .unwrap();
        assert!(matches!(read(subsidiary), Err(ReadError::WouldBlock)));
        assert_eq!(read(manager).unwrap(), b"more\r\nkept");

        write(manager, b"gone\r").unwrap();
        control(
            manager,
            TerminalOperation::SetSettings {
                settings: TerminalSettings::default(),
                timing: ChangeTiming::AfterOutputAndFlushInput,
            },
        )
        .unwrap();
        assert!(matches!(read(subsidiary), Err(ReadError::WouldBlock)));
    }
}
