// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Standard streams of a [`Request::Run`]'s programs, which share them: the
//! console's, but with the request's input unless it asks for the console's,
//! and output also recorded (bounded) for the response.
//!
//! [`Request::Run`]: litebox_common_vm_control::Request::Run

use alloc::collections::VecDeque;
use litebox_broker_core::stdio::StdioOutputStream;
use litebox_broker_vm_kernel::stdio::Console;
use litebox_common_vm_control::Captured;
use spin::Mutex;

/// Keeps at most this much of each stream per run; the console gets all.
const MAX_RECORDED: usize = 64 * 1024;

/// A run's standard input.
pub enum Input {
    /// What is left of it, then its end.
    Given(VecDeque<u8>),
    /// The device's.
    Console,
}

/// The runs' [`Console`]: serves each run's standard input, and records what
/// each output stream wrote to `device`.
pub struct Stdio {
    device: &'static dyn Console,
    /// The current run's.
    input: Mutex<Input>,
    /// Standard output, then standard error.
    recorded: Mutex<[Captured; 2]>,
}

impl Stdio {
    pub fn new(device: &'static dyn Console) -> Self {
        Self {
            device,
            input: Mutex::new(Input::Given(VecDeque::new())),
            recorded: Mutex::new(Default::default()),
        }
    }

    /// Starts a run with `input`, forgetting what was recorded.
    pub fn start(&self, input: Input) {
        self.take();
        *self.input.lock() = input;
    }

    /// Standard output and standard error since the last call.
    pub fn take(&self) -> [Captured; 2] {
        core::mem::take(&mut *self.recorded.lock())
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

    /// Records what the device took.
    fn write(&self, stream: StdioOutputStream, input: &[u8]) -> usize {
        let written = self.device.write(stream, input);
        let index = match stream {
            StdioOutputStream::Stdout => 0,
            StdioOutputStream::Stderr => 1,
        };
        let recorded = &mut self.recorded.lock()[index];
        let room = MAX_RECORDED.saturating_sub(recorded.bytes.len());
        let kept = written.min(room);
        recorded.bytes.extend_from_slice(&input[..kept]);
        recorded.truncated |= kept < written;
        written
    }
}
