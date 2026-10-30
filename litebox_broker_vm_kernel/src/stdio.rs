// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner processes' standard streams, on the runner's [`Console`]; both
//! output streams share it. Standard-input files are woken when input starts
//! to be pending, and output files once the device may take output again
//! after a write found it full.

use core::sync::atomic::{AtomicBool, Ordering};
use litebox_broker_core::BrokerError;
use litebox_broker_core::readiness::{ReadinessRegistration, ReadinessWatchers};
use litebox_broker_core::stdio::{
    StdioOutputStream, StdioProvider, StdioProviderError, StdioStream,
};
use litebox_broker_core::transfer::bounce_buffer;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::Mutex;

/// A byte-stream device behind the standard streams.
pub trait Console: Sync {
    /// Copies received bytes into `output`: how many (zero if none yet), or
    /// `None` at the end of input (e.g., a device without input).
    fn read(&self, output: &mut [u8]) -> Option<usize>;

    /// Whether [`Self::read`] would not return zero: input or its end.
    fn has_input(&self) -> bool;

    /// How much of `input`, for `stream`, the device took; less if it stays
    /// full.
    fn write(&self, stream: StdioOutputStream, input: &[u8]) -> usize;
}

pub(crate) struct ConsoleStdio {
    console: &'static dyn Console,
    stdin: Mutex<Stdin>,
    /// Standard-output and standard-error files, to wake once the device may
    /// take output again (see [`Self::poll`]).
    output: Mutex<ReadinessWatchers>,
    /// A write found the device full since the last [`Self::poll`].
    output_blocked: AtomicBool,
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
            output_blocked: AtomicBool::new(false),
        }
    }

    /// Wakes standard-input watchers if input started to be pending, and
    /// output watchers if a write found the device full since the last call.
    pub(crate) fn poll(&self) {
        {
            let mut stdin = self.stdin.lock();
            let readable = self.console.has_input();
            if readable && !stdin.readable {
                stdin.watchers.publish(ReadinessFlags::READ);
            }
            stdin.readable = readable;
        }
        if self.output_blocked.load(Ordering::Relaxed)
            && self.output_blocked.swap(false, Ordering::AcqRel)
        {
            self.output.lock().publish(ReadinessFlags::WRITE);
        }
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

    fn write(
        &self,
        stream: StdioOutputStream,
        input: &dyn WriteBuffer,
    ) -> Result<usize, StdioProviderError> {
        let mut staged = bounce_buffer(input.len())?;
        input.copy_to_slice_at(0, &mut staged)?;
        match self.console.write(stream, &staged) {
            0 => {
                // For `Self::poll` to wake the writer, which may wait.
                self.output_blocked.store(true, Ordering::Release);
                Err(StdioProviderError::WouldBlock)
            }
            written => Ok(written),
        }
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
