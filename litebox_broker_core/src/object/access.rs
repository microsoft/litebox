// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The operations that can be delegated on an individual reference. Deployment policy classes
//! bound issuance; they are not descriptor grants and cannot restore a bit lost on transfer.

use super::{ObjectEntry, ObjectRights};
use crate::{BrokerError, Result};
use litebox_broker_protocol::fs::FileAccessMode;

bitflags::bitflags! {
    /// Operations a holder may attempt. Object type, open mode, and any descriptor checks still
    /// apply. In particular, waiting for readiness does not grant permission to consume data.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct HandleOperations: u32 {
        /// Observe or subscribe to readiness.
        const WAIT = 1 << 0;
        /// Read data, or consume an event, expiration, or ready notification.
        const READ = 1 << 1;
        /// Write data or add event credits.
        const WRITE = 1 << 2;
        /// Query handle metadata, including names and status flags.
        const QUERY = 1 << 3;
        /// Modify shared status flags.
        const SET_FLAGS = 1 << 4;
        /// Enumerate a directory.
        const LIST = 1 << 5;
        /// Change the shared file offset.
        const SEEK = 1 << 6;
        /// Change file length.
        const TRUNCATE = 1 << 7;
        /// Change a file's timestamps, subject to its descriptor.
        const SET_TIMES = 1 << 8;
        /// Apply an advisory file lock.
        const LOCK = 1 << 9;
        /// Request a shared mapping; also requires data access in the mapped directions.
        const MAP = 1 << 10;
        /// Operate on a terminal through a file.
        const TERMINAL = 1 << 11;
        /// Bind a socket.
        const BIND = 1 << 12;
        /// Listen for connections.
        const LISTEN = 1 << 13;
        /// Start, check or cancel a socket connection.
        const CONNECT = 1 << 14;
        /// Accept a new connection.
        const ACCEPT = 1 << 15;
        /// Shut down a socket.
        const SHUTDOWN = 1 << 16;
        /// Set socket options.
        const SET_OPTION = 1 << 17;
        /// Consume or replace a socket's pending error.
        const SOCKET_ERROR = 1 << 18;
        /// Set a timer's schedule.
        const ARM_TIMER = 1 << 19;
        /// Change the entries watched by a readiness queue.
        const WATCH_SET = 1 << 20;
        /// Use a process handle to select a child exit.
        const WAIT_CHILD = 1 << 21;
        /// Signal through a process handle. Only references between processes without a
        /// file-system profile carry it, since no descriptor check applies to them; see
        /// `ProcessObject`.
        const SIGNAL = 1 << 22;
        /// Arm or disarm a private futex waiter.
        const ARM_WAITER = 1 << 23;
        /// Query the current state of a timer or transport.
        const READ_STATE = 1 << 24;
        /// Select a private registered subject. These references cannot be transferred.
        const USE_SUBJECT = 1 << 25;
    }
}

impl HandleOperations {
    fn for_classes(classes: ObjectRights) -> Self {
        let mut ops = Self::empty();
        if !classes.is_empty() {
            ops |= Self::QUERY
                | Self::SET_FLAGS
                | Self::SEEK
                | Self::SET_TIMES
                | Self::LOCK
                | Self::TERMINAL
                | Self::SOCKET_ERROR;
        }
        if classes.contains(ObjectRights::WAIT) {
            ops |= Self::WAIT
                | Self::READ
                | Self::LIST
                | Self::MAP
                | Self::ACCEPT
                | Self::WAIT_CHILD
                | Self::SIGNAL
                | Self::ARM_WAITER
                | Self::READ_STATE;
        }
        if classes.contains(ObjectRights::WRITE) {
            ops |= Self::WRITE
                | Self::TRUNCATE
                | Self::BIND
                | Self::LISTEN
                | Self::CONNECT
                | Self::SHUTDOWN
                | Self::SET_OPTION
                | Self::ARM_TIMER
                | Self::WATCH_SET;
        }
        ops
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ReferenceAccess {
    pub(crate) classes: ObjectRights,
    pub(crate) operations: HandleOperations,
}

impl ReferenceAccess {
    pub(crate) fn issue(object: &ObjectEntry, classes: ObjectRights) -> Self {
        use HandleOperations as Op;
        let common = Op::WAIT | Op::QUERY | Op::SET_FLAGS;
        let kind = match object {
            ObjectEntry::File(file) if file.profile.is_some() => file.operations,
            ObjectEntry::File(_) => {
                // Legacy unattenuated uses still return file-specific errors for the wrong mode
                // (e.g. NotForReading). An explicit delegation cannot promise such an operation.
                common
                    | Op::READ
                    | Op::WRITE
                    | Op::LIST
                    | Op::SEEK
                    | Op::TRUNCATE
                    | Op::SET_TIMES
                    | Op::LOCK
                    | Op::MAP
                    | Op::TERMINAL
            }
            ObjectEntry::Event(_) => common | Op::READ | Op::WRITE,
            ObjectEntry::Pipe(pipe) => {
                common
                    | match pipe.get_status_flags().access {
                        FileAccessMode::ReadOnly => Op::READ,
                        FileAccessMode::WriteOnly => Op::WRITE,
                        _ => Op::empty(),
                    }
            }
            ObjectEntry::Socket(_) | ObjectEntry::VsockSocket(_) | ObjectEntry::UnixSocket(_) => {
                common
                    | Op::READ
                    | Op::WRITE
                    | Op::BIND
                    | Op::LISTEN
                    | Op::CONNECT
                    | Op::ACCEPT
                    | Op::SHUTDOWN
                    | Op::SET_OPTION
                    | Op::SOCKET_ERROR
                    | Op::READ_STATE
            }
            ObjectEntry::Timer(_) => common | Op::READ | Op::READ_STATE | Op::ARM_TIMER,
            ObjectEntry::ReadinessQueue(_) => common | Op::READ | Op::WATCH_SET,
            ObjectEntry::Process(process) => process.operations(),
            ObjectEntry::Signals(_) => Op::WAIT | Op::READ,
            ObjectEntry::FutexWaiter(_) => Op::WAIT | Op::ARM_WAITER,
            // Subject registration and use are bounded by process authority, not by the
            // deployment's data I/O classes.
            ObjectEntry::Subject(_) => {
                return Self {
                    classes: ObjectRights::empty(),
                    operations: Op::USE_SUBJECT,
                };
            }
        };
        Self {
            classes,
            operations: kind & Op::for_classes(classes),
        }
    }

    pub(crate) fn restrict(
        self,
        classes: ObjectRights,
        requested: Option<HandleOperations>,
    ) -> Result<Self> {
        if classes.is_empty() || !self.classes.contains(classes) {
            return Err(BrokerError::InvalidRights);
        }
        let remaining = self.operations & HandleOperations::for_classes(classes);
        let operations = requested.unwrap_or(remaining);
        if operations.is_empty() || !remaining.contains(operations) {
            return Err(BrokerError::InvalidRights);
        }
        Ok(Self {
            classes,
            operations,
        })
    }
}
