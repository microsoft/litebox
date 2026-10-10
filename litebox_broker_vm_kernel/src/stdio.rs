// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner processes' standard streams, on the runner's [`Console`]; both
//! output streams share it. Standard-input files are woken when input starts
//! to be pending.

use core::sync::atomic::{AtomicBool, Ordering};
use litebox_broker_core::readiness::{ReadinessRegistration, ReadinessWatchers};
use litebox_broker_core::stdio::{
    StdioOutputStream, StdioProvider, StdioProviderError, StdioStream,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::Mutex;

/// A byte-stream device behind the standard streams.
pub trait Console: Sync {
    /// Copies received bytes into `output`: how many (zero if none yet), or
    /// `None` at the end of input (e.g., a device without input).
    fn read(&self, output: &mut [u8]) -> Option<usize>;

    /// Whether [`Self::read`] would not return zero: input or its end.
    fn has_input(&self) -> bool;

    /// How much of `input` the device took; less if it stays full.
    fn write(&self, input: &[u8]) -> usize;
}

pub(crate) struct ConsoleStdio {
    console: &'static dyn Console,
    /// Standard-input files, to wake when input arrives.
    watchers: Mutex<ReadinessWatchers>,
    /// Whether input was pending when last looked at.
    readable: AtomicBool,
}

impl ConsoleStdio {
    pub(crate) fn new(console: &'static dyn Console) -> Self {
        Self {
            console,
            watchers: Mutex::new(ReadinessWatchers::default()),
            readable: AtomicBool::new(false),
        }
    }

    /// Wakes standard-input watchers if input started to be pending.
    pub(crate) fn poll(&self) {
        let readable = self.console.has_input();
        if readable && !self.readable.swap(true, Ordering::Relaxed) {
            self.watchers.lock().publish(ReadinessFlags::READ);
        } else if !readable {
            self.readable.store(false, Ordering::Relaxed);
        }
    }
}

/// Never a terminal.
impl StdioProvider for ConsoleStdio {
    fn read(&self, output: &mut [u8]) -> Result<usize, StdioProviderError> {
        match self.console.read(output) {
            None => Ok(0),
            Some(0) => Err(StdioProviderError::WouldBlock),
            Some(read) => Ok(read),
        }
    }

    fn write(&self, _stream: StdioOutputStream, input: &[u8]) -> Result<usize, StdioProviderError> {
        match self.console.write(input) {
            0 => Err(StdioProviderError::WouldBlock),
            written => Ok(written),
        }
    }

    fn is_terminal(&self, _stream: StdioStream) -> bool {
        false
    }

    fn readiness(&self, stream: StdioStream) -> ReadinessFlags {
        match stream {
            StdioStream::Stdin if !self.console.has_input() => ReadinessFlags(0),
            StdioStream::Stdin => ReadinessFlags::READ,
            StdioStream::Stdout | StdioStream::Stderr => ReadinessFlags::WRITE,
        }
    }

    fn watch(
        &self,
        stream: StdioStream,
        registration: &ReadinessRegistration,
    ) -> litebox_broker_core::Result<()> {
        if stream == StdioStream::Stdin {
            self.watchers.lock().watch(registration)?;
            if self.console.has_input() {
                registration.publish(ReadinessFlags::READ)?;
            }
        }
        Ok(())
    }
}
