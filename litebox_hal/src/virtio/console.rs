// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio console (device type 3): QEMU's `virtio-serial-pci` with a
//! `virtconsole` on port 0, e.g.:
//!
//! ```text
//! -device virtio-serial-pci,id=vs0,disable-legacy=on
//! -chardev file,id=con0,path=out.txt,input-path=in.txt
//! -device virtconsole,chardev=con0,bus=vs0.0
//! ```
//!
//! Without `VIRTIO_CONSOLE_F_MULTIPORT` (not negotiated), the device is a
//! single port (port 0, where a `virtconsole` attaches) on queues 0
//! (receive) and 1 (transmit), open without control-queue traffic.
//!
//! Neither direction blocks: [`VirtioConsole::write`] takes what free
//! transmit buffers hold, and [`VirtioConsole::read`] what has arrived. The
//! device interrupts as input arrives, and as it returns a transmit buffer
//! while output waits for room: once the driver found every one with the
//! device, until it finds one free.

use super::Error;
use super::buffers::Buffers;
use super::pci::PciTransport;
use super::queue::VirtQueue;
use crate::dma::Hal;
use crate::interrupt::MsiMessage;
use alloc::collections::VecDeque;

const DEVICE_TYPE: u16 = 3;
const RECEIVE_QUEUE: u16 = 0;
const TRANSMIT_QUEUE: u16 = 1;

const RECEIVE_BUFFERS: u16 = 16;
const RECEIVE_BUFFER_SIZE: usize = 256;
/// As many as QEMU's virtio-serial queues hold. `PciTransport::setup_queue`
/// and `Buffers::new` cap them at the device's queue size, so
/// [`TRANSMIT_CAPACITY`] is an upper bound. They set how much output a broker
/// call can hand the device at once.
const TRANSMIT_BUFFERS: u16 = 128;
const TRANSMIT_BUFFER_SIZE: usize = 512;

/// The most output the device holds at once.
pub const TRANSMIT_CAPACITY: usize = TRANSMIT_BUFFERS as usize * TRANSMIT_BUFFER_SIZE;

/// A live console. Not internally synchronized.
pub struct VirtioConsole {
    transport: PciTransport,
    receive: VirtQueue,
    receive_buffers: Buffers,
    transmit: VirtQueue,
    transmit_buffers: Buffers,
    /// Filled receive buffers not yet read, as (buffer, length), oldest
    /// first; `received_offset` bytes of the first are read.
    received: VecDeque<(u16, usize)>,
    received_offset: usize,
}

impl VirtioConsole {
    /// The first virtio console on bus 0, brought up, interrupting with
    /// `interrupt` (if it can; see [`PciTransport::interrupts`]); `None` if
    /// there is none.
    ///
    /// # Errors
    ///
    /// The device cannot be driven.
    pub fn probe(
        hal: &'static dyn Hal,
        interrupt: Option<MsiMessage>,
    ) -> Option<Result<Self, Error>> {
        let function = super::find_pci_devices(DEVICE_TYPE).next()?;
        Some(
            PciTransport::new(hal, function, interrupt)
                .and_then(|transport| Self::bring_up(hal, transport)),
        )
    }

    fn bring_up(hal: &'static dyn Hal, transport: PciTransport) -> Result<Self, Error> {
        transport.init(0)?;
        let setup = || -> Result<_, Error> {
            let receive = transport.setup_queue(hal, RECEIVE_QUEUE, RECEIVE_BUFFERS)?;
            let transmit = transport.setup_queue(hal, TRANSMIT_QUEUE, TRANSMIT_BUFFERS)?;
            let receive_buffers =
                Buffers::new(hal, &receive, RECEIVE_BUFFERS, RECEIVE_BUFFER_SIZE)?;
            let transmit_buffers =
                Buffers::new(hal, &transmit, TRANSMIT_BUFFERS, TRANSMIT_BUFFER_SIZE)?;
            Ok((receive, receive_buffers, transmit, transmit_buffers))
        };
        let (receive, receive_buffers, transmit, transmit_buffers) =
            setup().inspect_err(|_| transport.fail())?;
        Ok(Self::start(
            transport,
            (receive, receive_buffers),
            (transmit, transmit_buffers),
        ))
    }

    /// Turns the transmit interrupt off, lends the device every receive
    /// buffer, and starts it.
    fn start(
        transport: PciTransport,
        (mut receive, mut receive_buffers): (VirtQueue, Buffers),
        (mut transmit, transmit_buffers): (VirtQueue, Buffers),
    ) -> Self {
        transmit.disable_interrupts();
        while let Some(buffer) = receive_buffers.free.pop() {
            receive_buffers.post(&mut receive, buffer, RECEIVE_BUFFER_SIZE, true);
        }
        transport.start();
        transport.notify(&receive);
        Self {
            transport,
            receive,
            receive_buffers,
            transmit,
            transmit_buffers,
            received: VecDeque::with_capacity(usize::from(RECEIVE_BUFFERS)),
            received_offset: 0,
        }
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    /// Takes back the transmit buffers the device returned: whether one is
    /// free, and if so, turns the transmit interrupt off.
    fn reclaim_transmitted(&mut self) -> bool {
        while let Some((buffer, _)) = self.transmit_buffers.take_used(&mut self.transmit) {
            self.transmit_buffers.free.push(buffer);
        }
        let room = !self.transmit_buffers.free.is_empty();
        if room {
            self.transmit.disable_interrupts();
        }
        room
    }

    /// With every transmit buffer with the device: asks it to interrupt as it
    /// returns one, and takes back any it returned meanwhile: whether one is
    /// free, in which case the interrupt is off again (see
    /// [`Self::reclaim_transmitted`]).
    fn arm_room_interrupt(&mut self) -> bool {
        self.transmit.enable_interrupts() && self.reclaim_transmitted()
    }

    /// Whether [`Self::write`] would take output now; if not, the device
    /// interrupts as it returns a buffer, unless a later call finds it first.
    pub fn can_write(&mut self) -> bool {
        self.reclaim_transmitted() || self.arm_room_interrupt()
    }

    /// Queues as much of `bytes` as free transmit buffers hold; returns how
    /// much. A short count, zero included, means every buffer is with the
    /// device, which then interrupts as it returns one, unless a later call
    /// finds it first.
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        self.reclaim_transmitted();
        let mut written = 0;
        while written < bytes.len() {
            let Some(buffer) = self.transmit_buffers.free.pop() else {
                // Arms the interrupt; goes on if the device returned a buffer
                // meanwhile.
                if self.arm_room_interrupt() {
                    continue;
                }
                break;
            };
            let chunk = &bytes[written..];
            let chunk = &chunk[..chunk.len().min(TRANSMIT_BUFFER_SIZE)];
            let destination = self.transmit_buffers.ptr(buffer, 0, chunk.len());
            // Safety: a free buffer, which the device does not access.
            unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), destination, chunk.len()) };
            self.transmit_buffers
                .post(&mut self.transmit, buffer, chunk.len(), false);
            written += chunk.len();
        }
        if written != 0 {
            self.transport.notify(&self.transmit);
        }
        written
    }

    /// Whether [`Self::read`] would return data.
    pub fn has_input(&mut self) -> bool {
        self.collect_received();
        !self.received.is_empty()
    }

    /// Copies received bytes into `output`; returns how many.
    pub fn read(&mut self, output: &mut [u8]) -> usize {
        self.collect_received();
        let mut read = 0;
        let mut reposted = false;
        while read < output.len() {
            let Some(&(buffer, len)) = self.received.front() else {
                break;
            };
            let n = (len - self.received_offset).min(output.len() - read);
            let source = self.receive_buffers.ptr(buffer, self.received_offset, n);
            // Safety: the device returned the buffer; `n` bytes are in it.
            unsafe { core::ptr::copy_nonoverlapping(source, output[read..].as_mut_ptr(), n) };
            read += n;
            self.received_offset += n;
            if self.received_offset == len {
                self.received.pop_front();
                self.received_offset = 0;
                self.receive_buffers
                    .post(&mut self.receive, buffer, RECEIVE_BUFFER_SIZE, true);
                reposted = true;
            }
        }
        if reposted {
            self.transport.notify(&self.receive);
        }
        read
    }

    fn collect_received(&mut self) {
        let mut reposted = false;
        while let Some((buffer, len)) = self.receive_buffers.take_used(&mut self.receive) {
            if len == 0 {
                self.receive_buffers
                    .post(&mut self.receive, buffer, RECEIVE_BUFFER_SIZE, true);
                reposted = true;
            } else {
                self.received.push_back((buffer, len));
            }
        }
        if reposted {
            self.transport.notify(&self.receive);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::queue::testing::{HeapHal, Registers, device_returns};

    /// A console on `registers` with 4 transmit buffers, started.
    fn console(registers: &Registers) -> VirtioConsole {
        let queue = |index, size| {
            let queue = VirtQueue::new(&HeapHal, index, 4, 0).unwrap();
            let buffers = Buffers::new(&HeapHal, &queue, 4, size).unwrap();
            (queue, buffers)
        };
        VirtioConsole::start(
            registers.transport(),
            queue(RECEIVE_QUEUE, RECEIVE_BUFFER_SIZE),
            queue(TRANSMIT_QUEUE, TRANSMIT_BUFFER_SIZE),
        )
    }

    /// Output interrupts only while it waits for room: the console asks for
    /// the interrupt once it finds every transmit buffer with the device,
    /// looks again after, and stops asking once it finds one free.
    #[test]
    fn output_interrupts_only_while_it_waits_for_room() {
        let registers = Registers::new();
        let mut console = console(&registers);
        let output = [b'x'; 4 * TRANSMIT_BUFFER_SIZE];
        assert!(!console.transmit.asks_to_interrupt(), "as started");
        assert!(console.can_write());
        assert_eq!(console.write(&output), output.len());
        assert!(!console.transmit.asks_to_interrupt(), "output that fits");
        // Heads 0 to 3 have the buffers, in turn; the device returns them in
        // used slots 0 on.
        device_returns(&console.transmit, 0, 0, 0);
        assert!(console.can_write());
        assert_eq!(console.write(&output), TRANSMIT_BUFFER_SIZE);
        assert!(
            console.transmit.asks_to_interrupt(),
            "output waits for room"
        );
        assert!(!console.can_write());
        // Full, then a buffer comes back, then a write, which finds room.
        device_returns(&console.transmit, 1, 1, 0);
        assert_eq!(console.write(&output[..1]), 1);
        assert!(
            !console.transmit.asks_to_interrupt(),
            "output that found room"
        );
        // A buffer that comes back unannounced, before the interrupt is asked
        // for, is found then.
        device_returns(&console.transmit, 2, 2, 0);
        assert!(console.arm_room_interrupt());
        assert!(!console.transmit.asks_to_interrupt());
    }

    /// A full queue that `can_write` finds first, before any write fails: it
    /// says no room, and asks the device to interrupt as it returns a buffer,
    /// which the next `can_write` finds.
    #[test]
    fn can_write_without_room_asks_for_the_interrupt() {
        let registers = Registers::new();
        let mut console = console(&registers);
        let output = [b'x'; 4 * TRANSMIT_BUFFER_SIZE];
        assert_eq!(console.write(&output), output.len());
        assert!(!console.transmit.asks_to_interrupt(), "output that fits");
        assert!(!console.can_write());
        assert!(console.transmit.asks_to_interrupt(), "no room");
        device_returns(&console.transmit, 0, 0, 0);
        assert!(console.can_write());
        assert!(!console.transmit.asks_to_interrupt(), "room");
    }
}
