// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trace event definitions

use std::fmt;
use std::time::SystemTime;

/// Category of traced API
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiCategory {
    /// File I/O operations
    FileIo,
    /// Console I/O operations
    ConsoleIo,
    /// Memory management operations
    Memory,
    /// Threading operations
    Threading,
    /// Synchronization operations
    Synchronization,
    /// Environment variables
    Environment,
    /// Process information
    Process,
    /// Registry operations
    Registry,
    /// DLL loading operations
    Dll,
    /// Unknown/uncategorized
    Unknown,
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiCategory::FileIo => write!(f, "file_io"),
            ApiCategory::ConsoleIo => write!(f, "console_io"),
            ApiCategory::Memory => write!(f, "memory"),
            ApiCategory::Threading => write!(f, "threading"),
            ApiCategory::Synchronization => write!(f, "synchronization"),
            ApiCategory::Environment => write!(f, "environment"),
            ApiCategory::Process => write!(f, "process"),
            ApiCategory::Registry => write!(f, "registry"),
            ApiCategory::Dll => write!(f, "dll"),
            ApiCategory::Unknown => write!(f, "unknown"),
        }
    }
}

/// Trace event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Function call started
    Call,
    /// Function call returned
    Return,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::Call => write!(f, "CALL"),
            EventType::Return => write!(f, "RETURN"),
        }
    }
}

/// A traced API call event
#[derive(Debug, Clone)]
pub struct TraceEvent {
    /// Timestamp of the event
    pub timestamp: SystemTime,
    /// Thread ID (if available)
    pub thread_id: Option<u64>,
    /// Event type (call or return)
    pub event_type: EventType,
    /// API category
    pub category: ApiCategory,
    /// Function name
    pub function: String,
    /// Function arguments (formatted as string)
    pub args: Option<String>,
    /// Return value (formatted as string)
    pub return_value: Option<String>,
}

impl TraceEvent {
    /// Create a new call event
    pub fn call(function: &str, category: ApiCategory) -> Self {
        Self {
            timestamp: SystemTime::now(),
            thread_id: None,
            event_type: EventType::Call,
            category,
            function: function.to_string(),
            args: None,
            return_value: None,
        }
    }

    /// Create a new return event
    pub fn return_event(function: &str, category: ApiCategory) -> Self {
        Self {
            timestamp: SystemTime::now(),
            thread_id: None,
            event_type: EventType::Return,
            category,
            function: function.to_string(),
            args: None,
            return_value: None,
        }
    }

    /// Set the arguments for this event
    #[must_use]
    pub fn with_args(mut self, args: String) -> Self {
        self.args = Some(args);
        self
    }

    /// Set the return value for this event
    #[must_use]
    pub fn with_return_value(mut self, return_value: String) -> Self {
        self.return_value = Some(return_value);
        self
    }

    /// Set the thread ID for this event
    #[must_use]
    pub fn with_thread_id(mut self, thread_id: u64) -> Self {
        self.thread_id = Some(thread_id);
        self
    }
}
