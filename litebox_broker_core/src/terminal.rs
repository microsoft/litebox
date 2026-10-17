// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared, transport-independent terminal processing.
//!
//! A provider serializes a terminal's engine with its transport queues. The
//! engine never calls host APIs or knows guest ioctl or signal numbers.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use litebox_broker_protocol::process_group::ProcessGroupMembership;
use litebox_broker_protocol::terminal::{
    InputFlags as I, LocalFlags as L, OutputFlags as O, TerminalError, TerminalEvent,
    TerminalOperation, TerminalResponse, TerminalSettings,
};
use spin::Mutex;

use crate::id::IdAllocator;
use crate::readiness::ReadinessSource;
use crate::{BrokerCore, BrokerProcess};

/// Maximum queued input bytes and canonical record boundaries per terminal.
pub const INPUT_CAPACITY: usize = 64 * 1024;
/// Maximum editable canonical line, including its terminating newline.
pub const LINE_CAPACITY: usize = 4096;

/// Receives ABI-neutral terminal actions.
pub trait TerminalEventSink: Send + Sync {
    /// Posts an action without blocking on guest execution.
    fn post(&self, event: TerminalEvent);
}

/// A shared terminal endpoint implemented over a platform transport.
pub trait TerminalEndpoint: ReadinessSource {
    /// Controls the endpoint without blocking. Output-draining operations may
    /// return `WouldBlock` and later publish writable readiness.
    fn control(
        &self,
        operation: TerminalOperation,
    ) -> crate::Result<Result<TerminalResponse, TerminalError>>;

    /// Attaches the initial process group once. Later opens must not replace
    /// this association.
    fn attach(&self, sink: Arc<dyn TerminalEventSink>);
}

struct ProcessGroupSink {
    processes: Weak<
        spin::rwlock::RwLock<
            hashbrown::HashMap<litebox_broker_protocol::ProcessId, Weak<BrokerProcess>>,
        >,
    >,
    tree_lock: Arc<Mutex<()>>,
    ids: Arc<Mutex<IdAllocator>>,
    membership: ProcessGroupMembership,
}

impl TerminalEventSink for ProcessGroupSink {
    fn post(&self, event: TerminalEvent) {
        let targets = {
            let _tree = self.tree_lock.lock();
            let Some(processes) = self.processes.upgrade() else {
                return;
            };
            let processes = processes
                .read()
                .values()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            processes
                .into_iter()
                .filter(|process| process.membership() == self.membership)
                .collect::<Vec<_>>()
        };
        for process in targets {
            process.signals.post_terminal_event(event);
        }
    }
}

impl Drop for ProcessGroupSink {
    fn drop(&mut self) {
        let mut ids = self.ids.lock();
        ids.release(self.membership.process_group.0);
        ids.release(self.membership.session.0);
    }
}

pub(crate) fn attach(endpoint: &dyn TerminalEndpoint, process: &BrokerProcess) {
    let core: &BrokerCore = &process.core;
    let tree = core.process_tree_lock.lock();
    let membership = process.membership();
    {
        let mut ids = core.ids.lock();
        ids.retain(membership.process_group.0);
        ids.retain(membership.session.0);
    }
    let sink = Arc::new(ProcessGroupSink {
        processes: Arc::downgrade(&core.processes),
        tree_lock: Arc::clone(&core.process_tree_lock),
        ids: Arc::clone(&core.ids),
        membership,
    });
    drop(tree);
    endpoint.attach(sink);
}

/// Effects of processing incoming transport bytes.
#[derive(Default)]
pub struct InputResult {
    /// Bytes consumed; the transport must retain the unconsumed suffix.
    pub consumed: usize,
    /// Echo to append to the transport's output queue in order.
    pub echo: Vec<u8>,
    /// Coalescible actions to publish to the attached process group.
    pub events: Vec<TerminalEvent>,
    /// A signal-generating character discarded previously queued output.
    pub flush_output: bool,
    /// Input was discarded because a control-enabled terminal's queue was full.
    pub input_overrun: bool,
}

struct LineByte {
    byte: u8,
    echo_width: u8,
}

/// One terminal's line discipline. Access must be serialized by its owner.
#[derive(Default)]
pub struct TerminalEngine {
    settings: TerminalSettings,
    input: VecDeque<u8>,
    records: VecDeque<usize>,
    line: Vec<LineByte>,
    quoted: bool,
    output_stopped: bool,
    column: usize,
}

impl TerminalEngine {
    #[must_use]
    /// Returns the shared terminal settings.
    pub fn settings(&self) -> TerminalSettings {
        self.settings
    }

    /// Changes settings without discarding buffered input.
    pub fn configure(&mut self, settings: TerminalSettings) -> Result<(), TerminalError> {
        if settings.minimum_read > 1 {
            return Err(TerminalError::InvalidSettings);
        }
        let was_canonical = self.settings.local.contains(L::CANONICAL);
        let canonical = settings.local.contains(L::CANONICAL);
        if was_canonical && !canonical {
            self.input
                .extend(self.line.drain(..).map(|entry| entry.byte));
            self.records.clear();
        } else if !was_canonical && canonical && !self.input.is_empty() {
            self.records.push_back(self.input.len());
        }
        if !settings.input.contains(I::SOFTWARE_FLOW_CONTROL) {
            self.output_stopped = false;
        }
        self.quoted = false;
        self.settings = settings;
        Ok(())
    }

    /// Discards both complete records and the line currently being edited.
    pub fn flush_input(&mut self) {
        self.input.clear();
        self.records.clear();
        self.line.clear();
        self.quoted = false;
    }

    #[must_use]
    /// Remaining bounded input capacity, including record boundaries.
    pub fn input_space(&self) -> usize {
        INPUT_CAPACITY.saturating_sub(self.input.len() + self.line.len() + self.records.len())
    }

    /// Whether the transport should continue receiving. Control-enabled
    /// terminals must still recognize interrupt and flow-control characters
    /// when their ordinary input queue is full.
    #[must_use]
    pub fn accepts_input(&self) -> bool {
        self.input_space() >= 2
            || self
                .settings
                .local
                .intersects(L::CANONICAL | L::GENERATE_EVENTS)
            || self.settings.input.contains(I::SOFTWARE_FLOW_CONTROL)
    }

    #[must_use]
    /// Whether input or a canonical EOF can be consumed without waiting.
    pub fn readable(&self) -> bool {
        if self.settings.local.contains(L::CANONICAL) {
            !self.records.is_empty()
        } else {
            !self.input.is_empty()
        }
    }

    #[must_use]
    /// Whether software flow control has stopped transport output.
    pub fn output_stopped(&self) -> bool {
        self.output_stopped
    }

    /// Reads one canonical record, or available noncanonical bytes. `None`
    /// means the caller must wait; `Some(0)` is a single canonical EOF or an
    /// immediate noncanonical read.
    pub fn read(&mut self, output: &mut [u8]) -> Option<usize> {
        if output.is_empty() {
            return Some(0);
        }
        let count = if self.settings.local.contains(L::CANONICAL) {
            let record = self.records.front_mut()?;
            let count = (*record).min(output.len());
            *record -= count;
            if *record == 0 {
                self.records.pop_front();
            }
            count
        } else {
            if self.input.is_empty() && self.settings.minimum_read != 0 {
                return None;
            }
            output.len().min(self.input.len())
        };
        for (out, byte) in output.iter_mut().zip(self.input.drain(..count)) {
            *out = byte;
        }
        Some(count)
    }

    fn matches(byte: u8, character: u8) -> bool {
        character != 0 && byte == character
    }

    /// Feeds raw transport input, applying editing, echo, and control actions.
    pub fn receive(&mut self, bytes: &[u8]) -> InputResult {
        let mut result = InputResult::default();
        for &byte in bytes {
            if !self.accepts_input() || result.echo.len() > INPUT_CAPACITY - 6 * LINE_CAPACITY {
                break;
            }
            result.consumed += 1;
            let mut byte = byte;
            let i = self.settings.input;
            let l = self.settings.local;
            let cc = self.settings.characters;
            if i.contains(I::STRIP_HIGH_BIT) {
                byte &= 0x7f;
            }
            let quoted = core::mem::take(&mut self.quoted);
            // A CR mapped to NL echoes raw even outside canonical mode.
            let newline_is_control = byte != b'\r';
            if !quoted {
                if i.contains(I::SOFTWARE_FLOW_CONTROL) {
                    if Self::matches(byte, cc.start) {
                        self.output_stopped = false;
                        continue;
                    }
                    if Self::matches(byte, cc.stop) {
                        self.output_stopped = true;
                        continue;
                    }
                    if i.contains(I::RESTART_OUTPUT_ON_INPUT) {
                        self.output_stopped = false;
                    }
                }
                if l.contains(L::GENERATE_EVENTS) {
                    let event = if Self::matches(byte, cc.interrupt) {
                        Some(TerminalEvent::Interrupt)
                    } else if Self::matches(byte, cc.quit) {
                        Some(TerminalEvent::Quit)
                    } else {
                        None
                    };
                    if let Some(event) = event {
                        if i.contains(I::SOFTWARE_FLOW_CONTROL) {
                            self.output_stopped = false;
                        }
                        if !l.contains(L::NO_FLUSH_ON_EVENT) {
                            self.flush_input();
                            result.echo.clear();
                            result.flush_output = true;
                        }
                        self.echo(byte, true, &mut result.echo);
                        result.events.push(event);
                        continue;
                    }
                }
                if byte == b'\r' {
                    if i.contains(I::IGNORE_CARRIAGE_RETURN) {
                        continue;
                    }
                    if i.contains(I::CARRIAGE_RETURN_TO_NEWLINE) {
                        byte = b'\n';
                    }
                } else if byte == b'\n' && i.contains(I::NEWLINE_TO_CARRIAGE_RETURN) {
                    byte = b'\r';
                }
                if l.contains(L::CANONICAL) {
                    if Self::matches(byte, cc.erase) {
                        self.erase(&mut result.echo, false);
                        continue;
                    }
                    if Self::matches(byte, cc.kill) {
                        if self.line.is_empty() {
                            continue;
                        }
                        if l.contains(L::ECHO | L::ECHO_KILL | L::ECHO_KILL_ERASE | L::ECHO_ERASE) {
                            while !self.line.is_empty() {
                                self.erase(&mut result.echo, true);
                            }
                        } else {
                            self.line.clear();
                            self.echo(byte, true, &mut result.echo);
                            if l.contains(L::ECHO | L::ECHO_KILL) {
                                self.output_byte(b'\n', &mut result.echo);
                            }
                        }
                        continue;
                    }
                    if Self::matches(byte, cc.end_of_file) {
                        if self.input_space() != 0 {
                            self.commit_line();
                        } else {
                            result.input_overrun = true;
                        }
                        continue;
                    }
                    if l.contains(L::EXTENDED_EDITING) {
                        if Self::matches(byte, cc.literal_next) {
                            self.quoted = true;
                            continue;
                        }
                        if Self::matches(byte, cc.word_erase) {
                            let mut seen_word = false;
                            while let Some(start) = self.last_character_start() {
                                let byte = self.line[start].byte;
                                // Terminal byte word classes include Latin-1 letters;
                                // UTF-8-aware editing classifies the leading byte.
                                let word = byte.is_ascii_alphanumeric()
                                    || byte == b'_'
                                    || matches!(byte, 0xc0..=0xd6 | 0xd8..=0xf6 | 0xf8..=0xff);
                                if seen_word && !word {
                                    break;
                                }
                                seen_word |= word;
                                self.erase(&mut result.echo, true);
                            }
                            continue;
                        }
                        if l.contains(L::ECHO) && Self::matches(byte, cc.reprint) {
                            self.echo(byte, true, &mut result.echo);
                            self.output_byte(b'\n', &mut result.echo);
                            for index in 0..self.line.len() {
                                self.line[index] = self.echo_line_byte(
                                    self.line[index].byte,
                                    true,
                                    &mut result.echo,
                                );
                            }
                            continue;
                        }
                    }
                }
            }
            if self.input_space() < 2 {
                result.input_overrun = true;
                continue;
            }
            if l.contains(L::CANONICAL) {
                let delimiter = !quoted
                    && (byte == b'\n'
                        || Self::matches(byte, cc.end_of_line)
                        || (l.contains(L::EXTENDED_EDITING)
                            && Self::matches(byte, cc.end_of_line2)));
                if self.line.len() < LINE_CAPACITY - 1 || delimiter {
                    let entry = self.echo_line_byte(byte, quoted, &mut result.echo);
                    self.line.push(entry);
                }
                if delimiter {
                    self.commit_line();
                }
            } else {
                self.input.push_back(byte);
                self.echo(byte, newline_is_control, &mut result.echo);
            }
        }
        result
    }

    fn commit_line(&mut self) {
        self.records.push_back(self.line.len());
        self.input
            .extend(self.line.drain(..).map(|entry| entry.byte));
    }

    fn erase(&mut self, echo: &mut Vec<u8>, force_visual: bool) {
        let Some(start) = self.last_character_start() else {
            return;
        };
        let width: usize = self
            .line
            .drain(start..)
            .map(|entry| usize::from(entry.echo_width))
            .sum();
        let l = self.settings.local;
        if l.contains(L::ECHO) && (force_visual || l.contains(L::ECHO_ERASE)) {
            for _ in 0..width {
                self.output_byte(b'\x08', echo);
                self.output_byte(b' ', echo);
                self.output_byte(b'\x08', echo);
            }
        } else {
            self.echo(self.settings.characters.erase, true, echo);
        }
    }

    fn last_character_start(&self) -> Option<usize> {
        let mut start = self.line.len().checked_sub(1)?;
        if self.settings.input.contains(I::UTF8_ERASE) {
            while start > 0 && self.line[start].byte & 0xc0 == 0x80 {
                start -= 1;
            }
        }
        Some(start)
    }

    fn echo_line_byte(&mut self, byte: u8, quoted: bool, output: &mut Vec<u8>) -> LineByte {
        let column = self.column;
        self.echo(byte, quoted, output);
        LineByte {
            byte,
            // Remember the actual expansion, including prompt-relative tab stops.
            echo_width: self
                .column
                .saturating_sub(column)
                .min(8)
                .try_into()
                .expect("echo width is bounded by a tab stop"),
        }
    }

    fn echo(&mut self, byte: u8, newline_is_control: bool, output: &mut Vec<u8>) {
        let l = self.settings.local;
        if !l.contains(L::ECHO) {
            if byte == b'\n' && !newline_is_control && l.contains(L::CANONICAL | L::ECHO_NEWLINE) {
                self.output_byte(byte, output);
            }
            return;
        }
        if l.contains(L::ECHO_CONTROL)
            && byte.is_ascii_control()
            && (byte != b'\n' || newline_is_control)
            && byte != b'\t'
        {
            self.output_byte(b'^', output);
            self.output_byte(if byte == 127 { b'?' } else { byte + b'@' }, output);
        } else {
            self.output_byte(byte, output);
        }
    }

    fn output_byte(&mut self, mut byte: u8, output: &mut Vec<u8>) {
        let flags = self.settings.output;
        if flags.contains(O::PROCESS) {
            if byte == b'\r' {
                if self.column == 0 && flags.contains(O::OMIT_CARRIAGE_RETURN_AT_COLUMN_ZERO) {
                    return;
                }
                if flags.contains(O::CARRIAGE_RETURN_TO_NEWLINE) {
                    byte = b'\n';
                }
            } else if byte == b'\n' && flags.contains(O::NEWLINE_TO_CRLF) {
                output.push(b'\r');
                self.column = 0;
            }
        }
        output.push(byte);
        match byte {
            b'\r' => self.column = 0,
            b'\n' if flags.contains(O::PROCESS | O::NEWLINE_RETURNS_CARRIAGE) => self.column = 0,
            b'\x08' => self.column = self.column.saturating_sub(1),
            b'\t' => self.column = self.column.saturating_add(8) & !7,
            b' '..=b'~' => self.column = self.column.saturating_add(1),
            0x80..=0xff if !self.settings.input.contains(I::UTF8_ERASE) || byte & 0xc0 != 0x80 => {
                self.column = self.column.saturating_add(1);
            }
            _ => {}
        }
    }

    /// Transforms a bounded prefix of a guest write. Returns consumed input
    /// bytes and transport output; at most twice `limit` bytes are generated.
    pub fn output(&mut self, input: &[u8], limit: usize) -> (usize, Vec<u8>) {
        let count = input.len().min(limit);
        let mut output = Vec::with_capacity(count * 2);
        for &byte in &input[..count] {
            self.output_byte(byte, &mut output);
        }
        (count, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Endpoint(Mutex<Option<Arc<dyn TerminalEventSink>>>);

    impl ReadinessSource for Endpoint {
        fn readiness(&self) -> litebox_broker_protocol::readiness::ReadinessFlags {
            litebox_broker_protocol::readiness::ReadinessFlags::default()
        }

        fn watch(
            &self,
            _registration: &crate::readiness::ReadinessRegistration,
        ) -> crate::Result<()> {
            Ok(())
        }
    }

    impl TerminalEndpoint for Endpoint {
        fn control(
            &self,
            _operation: TerminalOperation,
        ) -> crate::Result<Result<TerminalResponse, TerminalError>> {
            Ok(Err(TerminalError::Unsupported))
        }

        fn attach(&self, sink: Arc<dyn TerminalEventSink>) {
            let mut existing = self.0.lock();
            if existing.is_none() {
                *existing = Some(sink);
            }
        }
    }

    #[test]
    fn terminal_events_target_only_the_initial_group_and_coalesce() {
        use crate::readiness::tests::TestReadinessSink;
        use crate::test_support::TestBrokerCoreBuilder;
        use crate::{BrokerError, CallerCredential, ObjectRights, PolicyEngine};
        use litebox_broker_protocol::readiness::ReadinessFlags;
        use litebox_broker_protocol::signal::SignalEvent;
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let child = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        let background = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        crate::process_group::set(&root, background.id(), background.id().into()).unwrap();
        let handles = [&root, &child, &background].map(|process| {
            crate::signal::open(process, Arc::new(TestReadinessSink::default())).unwrap()
        });
        let endpoint = Endpoint(Mutex::new(None));
        attach(&endpoint, &root);
        attach(&endpoint, &background);
        let sink = endpoint.0.lock().clone().unwrap();
        sink.post(TerminalEvent::Interrupt);
        sink.post(TerminalEvent::Interrupt);
        sink.post(TerminalEvent::Resize);
        for (process, handle) in [(&root, handles[0]), (&child, handles[1])] {
            assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::READ));
            assert_eq!(
                crate::signal::take(process, handle),
                Ok(SignalEvent::Terminal(TerminalEvent::Interrupt))
            );
            assert_eq!(
                crate::signal::take(process, handle),
                Ok(SignalEvent::Terminal(TerminalEvent::Resize))
            );
            assert_eq!(
                crate::signal::take(process, handle),
                Err(BrokerError::WouldBlock)
            );
        }
        assert_eq!(
            crate::signal::take(&background, handles[2]),
            Err(BrokerError::WouldBlock)
        );
    }

    #[test]
    fn canonical_editing_and_record_boundaries() {
        let mut tty = TerminalEngine::default();
        let mut output = [0; 32];
        assert_eq!(tty.receive(b"hellx\x7fo").echo, b"hellx\x08 \x08o");
        assert_eq!(tty.read(&mut output), None);
        tty.receive(b"\rsecond\n");
        assert_eq!(tty.read(&mut output), Some(6));
        assert_eq!(&output[..6], b"hello\n");
        assert_eq!(tty.read(&mut output[..3]), Some(3));
        assert_eq!(&output[..3], b"sec");
        assert_eq!(tty.read(&mut output), Some(4));
        assert_eq!(&output[..4], b"ond\n");
    }

    #[test]
    fn eof_ends_one_read_and_does_not_discard_later_input() {
        let mut tty = TerminalEngine::default();
        tty.receive(b"abc\x04\x04next\n");
        let mut output = [0; 32];
        assert_eq!(tty.read(&mut output), Some(3));
        assert_eq!(tty.read(&mut output), Some(0));
        assert_eq!(tty.read(&mut output), Some(5));
        assert_eq!(&output[..5], b"next\n");
        assert_eq!(tty.read(&mut output), None);
    }

    #[test]
    fn raw_transition_exposes_pending_line_and_disables_processing() {
        let mut tty = TerminalEngine::default();
        tty.receive(b"pending");
        tty.configure(TerminalSettings {
            input: I::empty(),
            output: O::empty(),
            local: L::empty(),
            ..tty.settings()
        })
        .unwrap();
        let mut output = [0; 32];
        assert_eq!(tty.read(&mut output), Some(7));
        let input = tty.receive(b"\x03\x04\r\n");
        assert!(input.echo.is_empty() && input.events.is_empty());
        assert_eq!(tty.read(&mut output), Some(4));
        assert_eq!(&output[..4], b"\x03\x04\r\n");
        assert_eq!(tty.output(b"x\n", 2).1, b"x\n");
    }

    #[test]
    fn interrupt_flushes_input_and_emits_an_abi_neutral_event() {
        let mut tty = TerminalEngine::default();
        tty.receive(b"queued\npending");
        let result = tty.receive(b"\x03");
        assert_eq!(result.events, [TerminalEvent::Interrupt]);
        assert_eq!(result.echo, b"^C");
        assert!(result.flush_output);
        assert!(!tty.readable());
    }

    #[test]
    fn flow_control_and_output_processing() {
        let mut tty = TerminalEngine::default();
        assert_eq!(tty.output(b"a\n", 2).1, b"a\r\n");
        tty.receive(b"\x13");
        assert!(tty.output_stopped());
        tty.receive(b"\x11");
        assert!(!tty.output_stopped());
    }

    #[test]
    fn signal_characters_resume_output_with_or_without_flushing() {
        for no_flush in [false, true] {
            for (byte, event) in [(3, TerminalEvent::Interrupt), (28, TerminalEvent::Quit)] {
                let mut tty = TerminalEngine::default();
                let mut settings = tty.settings();
                settings.local.set(L::NO_FLUSH_ON_EVENT, no_flush);
                tty.configure(settings).unwrap();
                tty.receive(b"\x13");
                assert!(tty.output_stopped());
                let result = tty.receive(&[byte]);
                assert!(!tty.output_stopped());
                assert_eq!(result.events, [event]);
                assert_eq!(result.flush_output, !no_flush);
            }
        }
    }

    #[test]
    fn literal_next_bypasses_newline_translation_but_not_high_bit_stripping() {
        for (byte, input, expected, echo) in [
            (b'\r', I::CARRIAGE_RETURN_TO_NEWLINE, b'\r', b"^M"),
            (b'\r', I::IGNORE_CARRIAGE_RETURN, b'\r', b"^M"),
            (b'\n', I::NEWLINE_TO_CARRIAGE_RETURN, b'\n', b"^J"),
            (
                0x8d,
                I::STRIP_HIGH_BIT | I::CARRIAGE_RETURN_TO_NEWLINE,
                b'\r',
                b"^M",
            ),
        ] {
            let mut tty = TerminalEngine::default();
            tty.configure(TerminalSettings {
                input,
                ..tty.settings()
            })
            .unwrap();
            let result = tty.receive(&[22, byte, 4]);
            assert_eq!(result.echo, echo);
            assert_eq!(result.events, []);
            let mut bytes = [0; 2];
            assert_eq!(tty.read(&mut bytes), Some(1));
            assert_eq!(bytes[0], expected);
        }
        let mut tty = TerminalEngine::default();
        tty.configure(TerminalSettings {
            input: I::IGNORE_CARRIAGE_RETURN,
            ..tty.settings()
        })
        .unwrap();
        assert_eq!(
            tty.receive(b"\x16\r\x03").events,
            [TerminalEvent::Interrupt]
        );
    }

    #[test]
    fn control_characters_precede_cr_nl_mapping_and_suppression() {
        for (byte, flags) in [
            (b'\r', I::CARRIAGE_RETURN_TO_NEWLINE),
            (b'\r', I::IGNORE_CARRIAGE_RETURN),
            (b'\n', I::NEWLINE_TO_CARRIAGE_RETURN),
        ] {
            let mut tty = TerminalEngine::default();
            let mut settings = tty.settings();
            settings.input = flags | I::SOFTWARE_FLOW_CONTROL;
            settings.characters.start = byte;
            tty.configure(settings).unwrap();
            tty.receive(b"\x13");
            assert!(tty.output_stopped());
            tty.receive(&[byte]);
            assert!(!tty.output_stopped());
            assert!(!tty.readable());
            for event in [TerminalEvent::Interrupt, TerminalEvent::Quit] {
                let mut tty = TerminalEngine::default();
                let mut settings = tty.settings();
                settings.input = flags;
                match event {
                    TerminalEvent::Interrupt => settings.characters.interrupt = byte,
                    TerminalEvent::Quit => settings.characters.quit = byte,
                    TerminalEvent::Resize => unreachable!(),
                }
                tty.configure(settings).unwrap();
                let result = tty.receive(&[byte]);
                assert_eq!(result.events, [event]);
                assert_eq!(result.echo, if byte == b'\n' { b"^J" } else { b"^M" });
            }
        }
        let mut tty = TerminalEngine::default();
        tty.configure(TerminalSettings {
            input: I::SOFTWARE_FLOW_CONTROL
                | I::RESTART_OUTPUT_ON_INPUT
                | I::IGNORE_CARRIAGE_RETURN,
            ..tty.settings()
        })
        .unwrap();
        tty.receive(b"\x13\r");
        assert!(!tty.output_stopped());
    }

    #[test]
    fn word_erase_preserves_punctuation_before_the_erased_word() {
        for (input, expected) in [
            (b"foo/bar".as_slice(), b"foo/\n".as_slice()),
            (b"foo.bar_", b"foo.\n"),
            (b"foo bar///", b"foo \n"),
            (b"foo bar   ", b"foo \n"),
            (b"foo \xc3\xa9bar", b"foo \n"),
            (b"foo \xc3\xa9", b"foo \n"),
        ] {
            let mut tty = TerminalEngine::default();
            tty.receive(input);
            tty.receive(b"\x17\n");
            let mut bytes = [0; 32];
            assert_eq!(tty.read(&mut bytes), Some(expected.len()));
            assert_eq!(&bytes[..expected.len()], expected);
        }
    }

    #[test]
    fn newline_echo_without_echo_only_applies_to_delimiters() {
        let mut tty = TerminalEngine::default();
        tty.configure(TerminalSettings {
            local: L::CANONICAL | L::EXTENDED_EDITING | L::ECHO_NEWLINE,
            ..tty.settings()
        })
        .unwrap();
        assert_eq!(tty.receive(b"\x16\n\x04").echo, b"");
        assert_eq!(tty.receive(b"\n").echo, b"\r\n");
    }

    #[test]
    fn editing_echo_respects_erase_and_kill_flags() {
        for erase in [false, true] {
            for kill in [false, true] {
                for kill_erase in [false, true] {
                    let mut tty = TerminalEngine::default();
                    let mut settings = tty.settings();
                    settings.local.set(L::ECHO_ERASE, erase);
                    settings.local.set(L::ECHO_KILL, kill);
                    settings.local.set(L::ECHO_KILL_ERASE, kill_erase);
                    tty.configure(settings).unwrap();
                    assert_eq!(tty.receive(b"\x15").echo, b"");
                    tty.receive(b"foo");
                    let expected = if erase && kill && kill_erase {
                        b"\x08 \x08".repeat(3)
                    } else if kill {
                        b"^U\r\n".to_vec()
                    } else {
                        b"^U".to_vec()
                    };
                    assert_eq!(tty.receive(b"\x15").echo, expected);
                    assert_eq!(tty.receive(b"\x15").echo, b"");
                    tty.receive(b"foo");
                    assert_eq!(tty.receive(b"\x17").echo, b"\x08 \x08".repeat(3));
                    tty.receive(b"foo");
                    assert_eq!(
                        tty.receive(b"\x7f").echo,
                        if erase {
                            b"\x08 \x08".as_slice()
                        } else {
                            b"^?"
                        }
                    );
                    tty.receive(b"\n");
                    assert_eq!(tty.receive(b"\x15").echo, b"");
                    tty.receive(b"\x04");
                    assert_eq!(tty.receive(b"\x15").echo, b"");
                    let mut bytes = [0; 8];
                    assert_eq!(tty.read(&mut bytes), Some(3));
                    assert_eq!(&bytes[..3], b"fo\n");
                    assert_eq!(tty.read(&mut bytes), Some(0));
                }
            }
        }
    }

    #[test]
    fn noncanonical_echo_distinguishes_literal_and_translated_newlines() {
        for (input, byte, expected, echo) in [
            (
                I::CARRIAGE_RETURN_TO_NEWLINE,
                b'\n',
                b'\n',
                b"^J".as_slice(),
            ),
            (I::CARRIAGE_RETURN_TO_NEWLINE, b'\r', b'\n', b"\r\n"),
            (I::empty(), b'\n', b'\n', b"^J"),
            (I::empty(), b'\r', b'\r', b"^M"),
            (I::NEWLINE_TO_CARRIAGE_RETURN, b'\n', b'\r', b"^M"),
            (I::NEWLINE_TO_CARRIAGE_RETURN, b'\r', b'\r', b"^M"),
        ] {
            let mut tty = TerminalEngine::default();
            let mut settings = tty.settings();
            settings.input = input;
            settings.local.remove(L::CANONICAL);
            tty.configure(settings).unwrap();
            assert_eq!(tty.receive(&[byte]).echo, echo);
            let mut bytes = [0; 1];
            assert_eq!(tty.read(&mut bytes), Some(1));
            assert_eq!(bytes[0], expected);
        }
    }

    #[test]
    fn reprint_is_ordinary_input_when_echo_is_disabled() {
        let mut tty = TerminalEngine::default();
        let mut settings = tty.settings();
        settings.local.remove(L::ECHO);
        tty.configure(settings).unwrap();
        assert_eq!(tty.receive(b"a\x12b\n").echo, b"");
        let mut bytes = [0; 8];
        assert_eq!(tty.read(&mut bytes), Some(4));
        assert_eq!(&bytes[..4], b"a\x12b\n");

        settings.characters.reprint = b'\n';
        tty.configure(settings).unwrap();
        assert_eq!(tty.receive(b"abc\n").echo, b"");
        assert_eq!(tty.read(&mut bytes), Some(4));
        assert_eq!(&bytes[..4], b"abc\n");

        settings.local.insert(L::ECHO_NEWLINE);
        tty.configure(settings).unwrap();
        assert_eq!(tty.receive(b"xyz\n").echo, b"\r\n");
        assert_eq!(tty.read(&mut bytes), Some(4));
        assert_eq!(&bytes[..4], b"xyz\n");
    }

    #[test]
    fn tab_erasure_uses_its_echoed_width_after_prompts_and_reprints() {
        for (prefix, width) in [(b"a".as_slice(), 5), (b"\x01", 4), (b"\xc3\xa9", 5)] {
            let mut tty = TerminalEngine::default();
            tty.output(b"$ ", 2);
            tty.receive(prefix);
            tty.receive(b"\t");
            assert_eq!(tty.receive(b"\x7f").echo, b"\x08 \x08".repeat(width));
            tty.receive(b"\n");
            let mut bytes = [0; 8];
            assert_eq!(tty.read(&mut bytes), Some(prefix.len() + 1));
            assert_eq!(&bytes[..prefix.len()], prefix);
        }
        let mut tty = TerminalEngine::default();
        tty.output(b"$ ", 2);
        tty.receive(b"a\t\x12");
        assert_eq!(tty.receive(b"\x7f").echo, b"\x08 \x08".repeat(7));
    }

    #[test]
    fn mode_flags_do_not_enable_raw_newline_echo_or_suppress_quoted_input() {
        let mut tty = TerminalEngine::default();
        tty.receive(b"\x16\x03\n");
        let mut bytes = [0; 32];
        assert_eq!(tty.read(&mut bytes), Some(2));
        assert_eq!(&bytes[..2], b"\x03\n");
        tty.configure(TerminalSettings {
            local: L::ECHO_NEWLINE,
            minimum_read: 0,
            ..tty.settings()
        })
        .unwrap();
        assert_eq!(tty.receive(b"\n").echo, b"");
        assert_eq!(tty.read(&mut bytes), Some(1));
        assert_eq!(tty.read(&mut bytes), Some(0));
        tty.configure(TerminalSettings {
            local: L::CANONICAL,
            ..tty.settings()
        })
        .unwrap();
        tty.receive(b"partial");
        tty.flush_input();
        assert_eq!(tty.read(&mut bytes), None);
    }

    #[test]
    fn input_and_empty_eof_records_are_bounded() {
        let mut tty = TerminalEngine::default();
        let eof = alloc::vec![4; INPUT_CAPACITY * 2];
        let result = tty.receive(&eof);
        assert!(result.input_overrun);
        assert!(tty.records.len() <= INPUT_CAPACITY);
        tty.flush_input();
        tty.receive(&alloc::vec![b'x'; LINE_CAPACITY * 2]);
        tty.receive(b"\n");
        assert_eq!(
            tty.read(&mut alloc::vec![0; LINE_CAPACITY * 2]),
            Some(LINE_CAPACITY)
        );
    }

    #[test]
    fn editing_cannot_amplify_one_input_batch_without_bound() {
        let mut tty = TerminalEngine::default();
        tty.receive(&alloc::vec![b'x'; LINE_CAPACITY - 1]);
        let result = tty.receive(&alloc::vec![18; INPUT_CAPACITY]);
        assert!(result.consumed < INPUT_CAPACITY);
        assert!(result.echo.len() <= INPUT_CAPACITY);
        tty.flush_input();
        tty.output(&alloc::vec![b'x'; INPUT_CAPACITY], INPUT_CAPACITY);
        let result = tty.receive(b"\t\x7f");
        assert!(result.echo.len() <= 25);
    }

    #[test]
    fn full_input_does_not_block_interrupts_but_raw_input_is_backpressured() {
        let mut tty = TerminalEngine::default();
        tty.configure(TerminalSettings {
            local: L::CANONICAL | L::GENERATE_EVENTS,
            ..tty.settings()
        })
        .unwrap();
        tty.receive(&alloc::vec![b'\n'; INPUT_CAPACITY]);
        assert!(tty.input_space() < 2);
        assert!(tty.receive(b"x").input_overrun);
        assert_eq!(tty.receive(b"\x03").events, [TerminalEvent::Interrupt]);
        assert_eq!(tty.input_space(), INPUT_CAPACITY);
        tty.configure(TerminalSettings {
            input: I::empty(),
            local: L::empty(),
            ..tty.settings()
        })
        .unwrap();
        tty.receive(&alloc::vec![b'x'; INPUT_CAPACITY]);
        assert!(!tty.accepts_input());
        assert_eq!(tty.receive(b"more").consumed, 0);
    }
}
