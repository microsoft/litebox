// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Standard streams of a [`Request::Run`]'s programs, which share them: the
//! console's, but with the request's input unless it asks for the console's,
//! and output also captured (bounded) for the response.
//!
//! [`Request::Run`]: litebox_common_vm_control::Request::Run

use alloc::collections::VecDeque;
use litebox_broker_core::stdio::StdioOutputStream;
use litebox_broker_vm_kernel::stdio::Console;
use litebox_common_vm_control::Captured;
use spin::Mutex;

/// Captures at most this much of each stream per run; the console gets all.
const MAX_CAPTURED: usize = 64 * 1024;

/// A run's standard input.
pub enum Input {
    /// What is left of it, then its end.
    Given(VecDeque<u8>),
    Console,
}

/// The current run's [`Console`].
pub struct Stdio {
    device: &'static dyn Console,
    input: Mutex<Input>,
    /// Standard output, then standard error.
    captured: Mutex<[Captured; 2]>,
}

impl Stdio {
    pub fn new(device: &'static dyn Console) -> Self {
        Self {
            device,
            input: Mutex::new(Input::Given(VecDeque::new())),
            captured: Mutex::new(Default::default()),
        }
    }

    /// Starts a run with `input`, forgetting what was captured.
    pub fn start(&self, input: Input) {
        *self.input.lock() = input;
        self.take();
    }

    /// Standard output and standard error since the last call.
    pub fn take(&self) -> [Captured; 2] {
        core::mem::take(&mut *self.captured.lock())
    }
}

impl Console for Stdio {
    fn read(&self, output: &mut [u8]) -> Option<usize> {
        let mut input = self.input.lock();
        let input = match &mut *input {
            Input::Given(input) => input,
            Input::Console => return self.device.read(output),
        };
        if input.is_empty() {
            return None;
        }
        let len = output.len().min(input.len());
        for (byte, input) in output.iter_mut().zip(input.drain(..len)) {
            *byte = input;
        }
        Some(len)
    }

    /// Given input, or its end, never waits.
    fn has_input(&self) -> bool {
        match *self.input.lock() {
            Input::Given(_) => true,
            Input::Console => self.device.has_input(),
        }
    }

    /// Captures what the device took.
    fn write(&self, stream: StdioOutputStream, input: &[u8]) -> usize {
        let written = self.device.write(stream, input);
        let index = match stream {
            StdioOutputStream::Stdout => 0,
            StdioOutputStream::Stderr => 1,
        };
        let captured = &mut self.captured.lock()[index];
        let room = MAX_CAPTURED.saturating_sub(captured.bytes.len());
        let kept = written.min(room);
        captured.bytes.extend_from_slice(&input[..kept]);
        captured.truncated |= kept < written;
        written
    }
}
