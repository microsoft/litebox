// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-ABI-independent controls for shared terminal endpoints.

use crate::ObjectHandle;

bitflags::bitflags! {
    /// Transformations applied to incoming bytes.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct InputFlags: u16 {
        const STRIP_HIGH_BIT = 1 << 0;
        const IGNORE_CARRIAGE_RETURN = 1 << 1;
        const CARRIAGE_RETURN_TO_NEWLINE = 1 << 2;
        const NEWLINE_TO_CARRIAGE_RETURN = 1 << 3;
        const SOFTWARE_FLOW_CONTROL = 1 << 4;
        const RESTART_OUTPUT_ON_INPUT = 1 << 5;
        const UTF8_ERASE = 1 << 6;
    }
}

bitflags::bitflags! {
    /// Transformations applied to outgoing bytes, including echo.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct OutputFlags: u16 {
        const PROCESS = 1 << 0;
        const NEWLINE_TO_CRLF = 1 << 1;
        const CARRIAGE_RETURN_TO_NEWLINE = 1 << 2;
        const OMIT_CARRIAGE_RETURN_AT_COLUMN_ZERO = 1 << 3;
        const NEWLINE_RETURNS_CARRIAGE = 1 << 4;
    }
}

bitflags::bitflags! {
    /// Shared terminal input and echo behavior.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct LocalFlags: u16 {
        const CANONICAL = 1 << 0;
        const ECHO = 1 << 1;
        const ECHO_ERASE = 1 << 2;
        const ECHO_KILL = 1 << 3;
        const ECHO_NEWLINE = 1 << 4;
        const ECHO_CONTROL = 1 << 5;
        const ECHO_KILL_ERASE = 1 << 6;
        const EXTENDED_EDITING = 1 << 7;
        const GENERATE_EVENTS = 1 << 8;
        const NO_FLUSH_ON_EVENT = 1 << 9;
    }
}

/// Named editing characters. Zero disables a character.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlCharacters {
    /// Request an interrupt action.
    pub interrupt: u8,
    /// Request a quit action.
    pub quit: u8,
    /// Erase the preceding character in a canonical line.
    pub erase: u8,
    /// Erase the current canonical line.
    pub kill: u8,
    /// End the current record without appending a byte.
    pub end_of_file: u8,
    /// Additional canonical record delimiter.
    pub end_of_line: u8,
    /// Additional delimiter enabled by extended editing.
    pub end_of_line2: u8,
    /// Resume transport output.
    pub start: u8,
    /// Stop transport output.
    pub stop: u8,
    /// Erase the preceding word.
    pub word_erase: u8,
    /// Quote the next input character.
    pub literal_next: u8,
    /// Echo the current editable line again.
    pub reprint: u8,
}

/// Settings shared by every descriptor referring to one terminal.
///
/// This initial interface supports canonical reads and immediate or one-byte
/// noncanonical reads. Timed reads and serial-port configuration are not
/// emulated; shims must reject those requests rather than silently accepting
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalSettings {
    /// Incoming byte transformations and flow control.
    pub input: InputFlags,
    /// Outgoing byte transformations.
    pub output: OutputFlags,
    /// Line editing, echo, and action generation.
    pub local: LocalFlags,
    /// Named control characters, independent of guest array indices.
    pub characters: ControlCharacters,
    /// Zero permits an empty noncanonical read; one waits for input.
    pub minimum_read: u8,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        Self {
            input: InputFlags::CARRIAGE_RETURN_TO_NEWLINE
                | InputFlags::SOFTWARE_FLOW_CONTROL
                | InputFlags::UTF8_ERASE,
            output: OutputFlags::PROCESS | OutputFlags::NEWLINE_TO_CRLF,
            local: LocalFlags::CANONICAL
                | LocalFlags::ECHO
                | LocalFlags::ECHO_ERASE
                | LocalFlags::ECHO_KILL
                | LocalFlags::ECHO_CONTROL
                | LocalFlags::ECHO_KILL_ERASE
                | LocalFlags::EXTENDED_EDITING
                | LocalFlags::GENERATE_EVENTS,
            characters: ControlCharacters {
                interrupt: 3,
                quit: 28,
                erase: 127,
                kill: 21,
                end_of_file: 4,
                end_of_line: 0,
                end_of_line2: 0,
                start: 17,
                stop: 19,
                word_erase: 23,
                literal_next: 22,
                reprint: 18,
            },
            minimum_read: 1,
        }
    }
}

/// Terminal dimensions, independent of a guest's structure layout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowSize {
    /// Text rows.
    pub rows: u16,
    /// Text columns.
    pub columns: u16,
    /// Horizontal pixel dimension, or zero if unknown.
    pub x_pixels: u16,
    /// Vertical pixel dimension, or zero if unknown.
    pub y_pixels: u16,
}

/// When to change terminal settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeTiming {
    /// Apply immediately, without changing already queued output.
    Now,
    /// Apply once accepted output reaches the transport.
    AfterOutput,
    /// Drain output, discard buffered input, and then apply.
    AfterOutputAndFlushInput,
}

/// One typed operation on the terminal backing an open file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalOperation {
    /// Read the shared settings.
    GetSettings,
    /// Change the shared settings.
    SetSettings {
        /// New settings.
        settings: TerminalSettings,
        /// Ordering relative to queued I/O.
        timing: ChangeTiming,
    },
    /// Read transport geometry.
    GetWindowSize,
    /// Change transport geometry.
    SetWindowSize(WindowSize),
    /// Discard the selected queues; at least one direction must be selected.
    Flush {
        /// Discard input.
        input: bool,
        /// Discard output.
        output: bool,
    },
    /// Wait for accepted output to reach the transport.
    Drain,
}

/// A terminal control addressed through an existing file capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalRequest {
    /// Existing file capability.
    pub handle: ObjectHandle,
    /// Typed operation.
    pub operation: TerminalOperation,
}

/// Result of a terminal control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalResponse {
    /// Current settings.
    Settings(TerminalSettings),
    /// Current geometry.
    WindowSize(WindowSize),
    /// Mutation or drain completed.
    Done,
}

/// A terminal failure that a shim translates to its own ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalError {
    /// The file does not expose a terminal endpoint.
    NotTerminal,
    /// The endpoint does not implement this capability.
    Unsupported,
    /// The requested configuration is invalid or unsupported.
    InvalidSettings,
    /// The transport failed.
    Io,
}

/// Terminal actions delivered to the initially attached process group.
///
/// These are not guest signal numbers. Foreground-group switching and
/// stop/continue are deliberately outside this initial terminal interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalEvent {
    /// The interrupt character was received with action generation enabled.
    Interrupt,
    /// The quit character was received with action generation enabled.
    Quit,
    /// Transport geometry changed.
    Resize,
}
