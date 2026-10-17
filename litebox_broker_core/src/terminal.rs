// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared, transport-independent terminal processing.
//!
//! A provider serializes a terminal's engine with its transport queues. The
//! engine never calls host APIs or knows guest ioctl or signal numbers.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use litebox_broker_protocol::fs::FileError;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::{
    InputFlags as I, LocalFlags as L, OutputFlags as O, TerminalEvents, TerminalOperation,
    TerminalResponse, TerminalSettings, WindowSize,
};

use crate::fs::FileResult;
use crate::readiness::ReadinessSource;
use crate::transfer::{Copier, lend_from_queue};

/// Maximum queued input bytes and canonical record boundaries per terminal.
pub const INPUT_CAPACITY: usize = 64 * 1024;
/// Maximum editable canonical line, including its terminating newline.
pub const LINE_CAPACITY: usize = 4096;

/// Receives ABI-neutral terminal actions.
pub trait TerminalEventSink: Send + Sync {
    /// Posts actions without blocking on guest execution.
    fn post(&self, events: TerminalEvents);
}

/// A shared terminal endpoint implemented over a platform transport.
pub trait TerminalEndpoint: ReadinessSource {
    /// Controls the endpoint without blocking. Output-draining operations may
    /// return `WouldBlock` and later publish writable readiness.
    fn control(&self, operation: TerminalOperation) -> crate::Result<FileResult<TerminalResponse>>;

    /// Attaches the initial process group once. Later opens must not replace
    /// this association.
    fn attach(&self, sink: Arc<dyn TerminalEventSink>);
}

/// Why a host terminal transport operation did not complete.
#[derive(Debug)]
pub enum TerminalTransportError {
    /// The operation cannot complete now. Retry after
    /// [`TerminalTransport::wait`].
    WouldBlock,
    /// The host side of the terminal hung up.
    HungUp,
    /// The transport failed and cannot continue.
    Failed(Box<dyn core::error::Error + Send + Sync>),
}

impl core::fmt::Display for TerminalTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WouldBlock => f.write_str("terminal operation would block"),
            Self::HungUp => f.write_str("terminal hung up"),
            Self::Failed(error) => write!(f, "terminal transport failed: {error}"),
        }
    }
}

impl core::error::Error for TerminalTransportError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Failed(error) => Some(&**error),
            Self::WouldBlock | Self::HungUp => None,
        }
    }
}

/// Raw I/O with one host terminal, which a platform provides beneath a
/// [`TerminalEndpoint`].
///
/// A transport performs no line processing; the endpoint's
/// [`TerminalEngine`] interprets every byte. Acquiring a transport switches
/// the host terminal to raw mode, and [`restore`](Self::restore) returns it to
/// its original state.
pub trait TerminalTransport: Send + Sync {
    /// Reads available input without blocking. `Ok(0)` means the host side
    /// hung up.
    fn read(&self, buffer: &mut [u8]) -> Result<usize, TerminalTransportError>;

    /// Writes output without blocking and returns the bytes written.
    fn write(&self, buffer: &[u8]) -> Result<usize, TerminalTransportError>;

    /// Blocks until the terminal has readiness in `interest`, `timeout`
    /// elapses, or [`wake`](Self::wake) is called, and returns the readiness
    /// found, which may be empty.
    ///
    /// `interest` may contain [`READ`](ReadinessFlags::READ),
    /// [`WRITE`](ReadinessFlags::WRITE), and
    /// [`HANGUP`](ReadinessFlags::HANGUP). An empty interest waits only for a
    /// wake or the timeout.
    fn wait(
        &self,
        interest: ReadinessFlags,
        timeout: Option<Duration>,
    ) -> Result<ReadinessFlags, TerminalTransportError>;

    /// Ends the current or next [`wait`](Self::wait) early.
    fn wake(&self) -> Result<(), TerminalTransportError>;

    /// Returns the host terminal's window size.
    fn get_window_size(&self) -> Result<WindowSize, TerminalTransportError>;

    /// Sets the host terminal's window size.
    fn set_window_size(&self, size: WindowSize) -> Result<(), TerminalTransportError>;

    /// Discards host input not yet read, output not yet transmitted, or both.
    fn flush(&self, input: bool, output: bool) -> Result<(), TerminalTransportError>;

    /// Blocks until all written output has been transmitted.
    fn drain(&self) -> Result<(), TerminalTransportError>;

    /// Restores the host terminal's original state. Later calls do nothing.
    fn restore(&self) -> Result<(), TerminalTransportError>;
}

/// Effects of processing incoming transport bytes.
#[derive(Default)]
pub struct InputResult {
    /// Bytes consumed; the transport must retain the unconsumed suffix.
    pub consumed: usize,
    /// Echo to append to the transport's output queue in order.
    pub echo: Vec<u8>,
    /// Actions to publish to the attached process group.
    pub events: TerminalEvents,
    /// A signal-generating character discarded previously queued output.
    pub flush_output: bool,
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
    ///
    /// Fails with [`FileError::InvalidTerminalControl`] if the settings need
    /// more than one byte to satisfy a noncanonical read.
    pub fn configure(&mut self, settings: TerminalSettings) -> FileResult<()> {
        if settings.minimum_read > 1 {
            return Err(FileError::InvalidTerminalControl);
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

    /// Whether the transport should continue receiving. A full queue holds
    /// readable input, so control characters behind it wait for the reader
    /// rather than discarding ordinary input.
    #[must_use]
    pub fn accepts_input(&self) -> bool {
        self.input_space() >= 2
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

    /// Reads up to `length` bytes of one canonical record, or of the available
    /// noncanonical bytes, lending them to `copy` (see [`crate::transfer`]).
    /// `None` means the caller must wait; `Some(0)` is a single canonical EOF
    /// or an immediate noncanonical read. If `copy` fails, nothing is read.
    pub fn read(&mut self, length: usize, copy: &mut Copier<'_>) -> crate::Result<Option<usize>> {
        if length == 0 {
            return Ok(Some(0));
        }
        let canonical = self.settings.local.contains(L::CANONICAL);
        let count = if canonical {
            let Some(&record) = self.records.front() else {
                return Ok(None);
            };
            record.min(length)
        } else {
            if self.input.is_empty() && self.settings.minimum_read != 0 {
                return Ok(None);
            }
            length.min(self.input.len())
        };
        lend_from_queue(&self.input, 0..count, copy)?;
        if canonical && let Some(record) = self.records.front_mut() {
            *record -= count;
            if *record == 0 {
                self.records.pop_front();
            }
        }
        self.input.drain(..count);
        Ok(Some(count))
    }

    fn matches(byte: u8, character: u8) -> bool {
        character != 0 && byte == character
    }

    /// Feeds raw transport input, applying editing, echo, and control actions.
    pub fn receive(&mut self, bytes: &[u8]) -> InputResult {
        let mut result = InputResult::default();
        for &byte in bytes {
            // One byte echoes at most eight bytes per line entry, when killing
            // a line of tabs, so a batch's echo stays within `INPUT_CAPACITY`.
            if !self.accepts_input() || result.echo.len() > INPUT_CAPACITY - 8 * LINE_CAPACITY {
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
                        Some(TerminalEvents::INTERRUPT)
                    } else if Self::matches(byte, cc.quit) {
                        Some(TerminalEvents::QUIT)
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
                        result.events |= event;
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
                        self.commit_line();
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
        let tab = self.line[start].byte == b'\t';
        let width: usize = self
            .line
            .drain(start..)
            .map(|entry| usize::from(entry.echo_width))
            .sum();
        let l = self.settings.local;
        if l.contains(L::ECHO) && (force_visual || l.contains(L::ECHO_ERASE)) {
            for _ in 0..width {
                self.output_byte(b'\x08', echo);
                // Like Linux, erase a tab by only moving back over its columns.
                if !tab {
                    self.output_byte(b' ', echo);
                    self.output_byte(b'\x08', echo);
                }
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
            } else if byte == b'\t' && flags.contains(O::EXPAND_TABS) {
                let spaces = 8 - (self.column & 7);
                output.resize(output.len() + spaces, b' ');
                self.column = self.column.saturating_add(spaces);
                return;
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

    #[must_use]
    /// Most transport bytes that [`Self::output`] can generate per input byte
    /// under the current settings.
    pub fn output_expansion(&self) -> usize {
        if self.settings.output.contains(O::PROCESS | O::EXPAND_TABS) {
            8
        } else {
            2
        }
    }

    /// Transforms a bounded prefix of a guest write. Returns consumed input
    /// bytes and transport output; at most [`Self::output_expansion`] times
    /// `limit` bytes are generated.
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
    use crate::transfer::copy_to_slice;

    impl TerminalEngine {
        /// Reads into `output`, for tests that are not about lending.
        fn read_slice(&mut self, output: &mut [u8]) -> Option<usize> {
            self.read(output.len(), &mut copy_to_slice(output)).unwrap()
        }
    }

    #[test]
    fn canonical_editing_and_record_boundaries() {
        let mut tty = TerminalEngine::default();
        let mut output = [0; 32];
        assert_eq!(tty.receive(b"hellx\x7fo").echo, b"hellx\x08 \x08o");
        assert_eq!(tty.read_slice(&mut output), None);
        tty.receive(b"\rsecond\n");
        assert_eq!(tty.read_slice(&mut output), Some(6));
        assert_eq!(&output[..6], b"hello\n");
        assert_eq!(tty.read_slice(&mut output[..3]), Some(3));
        assert_eq!(&output[..3], b"sec");
        assert_eq!(tty.read_slice(&mut output), Some(4));
        assert_eq!(&output[..4], b"ond\n");
    }

    #[test]
    fn failed_copies_read_nothing() {
        let mut tty = TerminalEngine::default();
        tty.receive(b"line\n");
        assert_eq!(
            tty.read(5, &mut |_| Err(crate::BrokerError::Internal)),
            Err(crate::BrokerError::Internal)
        );
        let mut output = [0; 8];
        assert_eq!(tty.read_slice(&mut output), Some(5));
        assert_eq!(&output[..5], b"line\n");
        assert_eq!(tty.read_slice(&mut output), None);
    }

    #[test]
    fn eof_ends_one_read_and_does_not_discard_later_input() {
        let mut tty = TerminalEngine::default();
        tty.receive(b"abc\x04\x04next\n");
        let mut output = [0; 32];
        assert_eq!(tty.read_slice(&mut output), Some(3));
        assert_eq!(tty.read_slice(&mut output), Some(0));
        assert_eq!(tty.read_slice(&mut output), Some(5));
        assert_eq!(&output[..5], b"next\n");
        assert_eq!(tty.read_slice(&mut output), None);
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
        assert_eq!(tty.read_slice(&mut output), Some(7));
        let input = tty.receive(b"\x03\x04\r\n");
        assert!(input.echo.is_empty() && input.events.is_empty());
        assert_eq!(tty.read_slice(&mut output), Some(4));
        assert_eq!(&output[..4], b"\x03\x04\r\n");
        assert_eq!(tty.output(b"x\n", 2).1, b"x\n");
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
    fn tabs_expand_to_the_next_stop_only_when_processed() {
        let mut tty = TerminalEngine::default();
        tty.configure(TerminalSettings {
            output: tty.settings().output | O::EXPAND_TABS,
            ..tty.settings()
        })
        .unwrap();
        assert_eq!(tty.output_expansion(), 8);
        assert_eq!(tty.output(b"ab\tc\t\n", 6).1, b"ab      c       \r\n");
        assert_eq!(tty.receive(b"\t").echo, b" ".repeat(8));
        assert_eq!(tty.receive(b"\x7f").echo, b"\x08".repeat(8));
        tty.configure(TerminalSettings {
            output: O::EXPAND_TABS,
            ..tty.settings()
        })
        .unwrap();
        assert_eq!(tty.output_expansion(), 2);
        assert_eq!(tty.output(b"\t", 1).1, b"\t");
    }

    #[test]
    fn signal_characters_resume_output_with_or_without_flushing() {
        for no_flush in [false, true] {
            for (byte, event) in [(3, TerminalEvents::INTERRUPT), (28, TerminalEvents::QUIT)] {
                let mut tty = TerminalEngine::default();
                let mut settings = tty.settings();
                settings.local.set(L::NO_FLUSH_ON_EVENT, no_flush);
                tty.configure(settings).unwrap();
                tty.receive(b"\x13");
                assert!(tty.output_stopped());
                let result = tty.receive(&[byte]);
                assert!(!tty.output_stopped());
                assert_eq!(result.events, event);
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
            assert_eq!(result.events, TerminalEvents::empty());
            let mut bytes = [0; 2];
            assert_eq!(tty.read_slice(&mut bytes), Some(1));
            assert_eq!(bytes[0], expected);
        }
        let mut tty = TerminalEngine::default();
        tty.configure(TerminalSettings {
            input: I::IGNORE_CARRIAGE_RETURN,
            ..tty.settings()
        })
        .unwrap();
        assert_eq!(tty.receive(b"\x16\r\x03").events, TerminalEvents::INTERRUPT);
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
            for event in [TerminalEvents::INTERRUPT, TerminalEvents::QUIT] {
                let mut tty = TerminalEngine::default();
                let mut settings = tty.settings();
                settings.input = flags;
                if event == TerminalEvents::INTERRUPT {
                    settings.characters.interrupt = byte;
                } else {
                    settings.characters.quit = byte;
                }
                tty.configure(settings).unwrap();
                let result = tty.receive(&[byte]);
                assert_eq!(result.events, event);
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
            assert_eq!(tty.read_slice(&mut bytes), Some(expected.len()));
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
                    assert_eq!(tty.read_slice(&mut bytes), Some(3));
                    assert_eq!(&bytes[..3], b"fo\n");
                    assert_eq!(tty.read_slice(&mut bytes), Some(0));
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
            assert_eq!(tty.read_slice(&mut bytes), Some(1));
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
        assert_eq!(tty.read_slice(&mut bytes), Some(4));
        assert_eq!(&bytes[..4], b"a\x12b\n");

        settings.characters.reprint = b'\n';
        tty.configure(settings).unwrap();
        assert_eq!(tty.receive(b"abc\n").echo, b"");
        assert_eq!(tty.read_slice(&mut bytes), Some(4));
        assert_eq!(&bytes[..4], b"abc\n");

        settings.local.insert(L::ECHO_NEWLINE);
        tty.configure(settings).unwrap();
        assert_eq!(tty.receive(b"xyz\n").echo, b"\r\n");
        assert_eq!(tty.read_slice(&mut bytes), Some(4));
        assert_eq!(&bytes[..4], b"xyz\n");
    }

    #[test]
    fn tab_erasure_uses_its_echoed_width_after_prompts_and_reprints() {
        for (prefix, width) in [(b"a".as_slice(), 5), (b"\x01", 4), (b"\xc3\xa9", 5)] {
            let mut tty = TerminalEngine::default();
            tty.output(b"$ ", 2);
            tty.receive(prefix);
            tty.receive(b"\t");
            assert_eq!(tty.receive(b"\x7f").echo, b"\x08".repeat(width));
            tty.receive(b"\n");
            let mut bytes = [0; 8];
            assert_eq!(tty.read_slice(&mut bytes), Some(prefix.len() + 1));
            assert_eq!(&bytes[..prefix.len()], prefix);
        }
        let mut tty = TerminalEngine::default();
        tty.output(b"$ ", 2);
        tty.receive(b"a\t\x12");
        assert_eq!(tty.receive(b"\x7f").echo, b"\x08".repeat(7));
    }

    #[test]
    fn mode_flags_do_not_enable_raw_newline_echo_or_suppress_quoted_input() {
        let mut tty = TerminalEngine::default();
        tty.receive(b"\x16\x03\n");
        let mut bytes = [0; 32];
        assert_eq!(tty.read_slice(&mut bytes), Some(2));
        assert_eq!(&bytes[..2], b"\x03\n");
        tty.configure(TerminalSettings {
            local: L::ECHO_NEWLINE,
            minimum_read: 0,
            ..tty.settings()
        })
        .unwrap();
        assert_eq!(tty.receive(b"\n").echo, b"");
        assert_eq!(tty.read_slice(&mut bytes), Some(1));
        assert_eq!(tty.read_slice(&mut bytes), Some(0));
        tty.configure(TerminalSettings {
            local: L::CANONICAL,
            ..tty.settings()
        })
        .unwrap();
        tty.receive(b"partial");
        tty.flush_input();
        assert_eq!(tty.read_slice(&mut bytes), None);
    }

    #[test]
    fn input_and_empty_eof_records_are_bounded() {
        let mut tty = TerminalEngine::default();
        let eof = alloc::vec![4; INPUT_CAPACITY * 2];
        assert!(tty.receive(&eof).consumed < eof.len());
        assert!(tty.records.len() <= INPUT_CAPACITY);
        tty.flush_input();
        tty.receive(&alloc::vec![b'x'; LINE_CAPACITY * 2]);
        tty.receive(b"\n");
        assert_eq!(
            tty.read_slice(&mut alloc::vec![0; LINE_CAPACITY * 2]),
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
        for erase in [21, 23] {
            let mut input = alloc::vec![b'\t'; LINE_CAPACITY - 1];
            input.push(erase);
            let result = tty.receive(&input);
            assert_eq!(result.consumed, input.len());
            assert!(tty.line.is_empty());
            assert!(result.echo.len() <= INPUT_CAPACITY);
        }
    }

    #[test]
    fn full_input_is_backpressured_without_loss() {
        let paste: Vec<u8> = (0..INPUT_CAPACITY * 2)
            .map(|index| if index % 64 == 63 { b'\n' } else { b'x' })
            .collect();
        for local in [L::CANONICAL | L::GENERATE_EVENTS, L::GENERATE_EVENTS] {
            let mut tty = TerminalEngine::default();
            tty.configure(TerminalSettings {
                local,
                ..tty.settings()
            })
            .unwrap();
            let mut offset = tty.receive(&paste).consumed;
            assert!(offset < paste.len());
            assert!(!tty.accepts_input());
            assert_eq!(tty.receive(b"\x03").consumed, 0);
            let mut received = Vec::new();
            let mut bytes = alloc::vec![0; INPUT_CAPACITY];
            while received.len() < paste.len() {
                match tty.read_slice(&mut bytes) {
                    Some(count) if count != 0 => received.extend_from_slice(&bytes[..count]),
                    _ => {
                        let consumed = tty.receive(&paste[offset..]).consumed;
                        assert_ne!(consumed, 0);
                        offset += consumed;
                    }
                }
            }
            assert_eq!(received, paste);
        }
    }
}
