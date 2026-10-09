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
//! device interrupts when it returns buffers in either direction.

use super::Error;
use super::pci::PciTransport;
use super::queue::{Buffer, VirtQueue};
use crate::dma::{DmaRegion, Hal};
use crate::pci::MsiMessage;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

const DEVICE_TYPE: u16 = 3;
const RECEIVE_QUEUE: u16 = 0;
const TRANSMIT_QUEUE: u16 = 1;

const RECEIVE_BUFFERS: u16 = 16;
const RECEIVE_BUFFER_SIZE: usize = 256;
const TRANSMIT_BUFFERS: u16 = 32;
const TRANSMIT_BUFFER_SIZE: usize = 512;

/// Fixed-size buffers in one DMA region, each a one-descriptor chain while
/// the device has it.
struct Buffers {
    memory: DmaRegion,
    size: usize,
    /// By queue head: the buffer the device has.
    by_head: Vec<Option<u16>>,
    free: Vec<u16>,
}

impl Buffers {
    fn new(
        hal: &'static dyn Hal,
        queue: &VirtQueue,
        count: u16,
        size: usize,
    ) -> Result<Self, Error> {
        let count = count.min(queue.size());
        Ok(Self {
            memory: DmaRegion::new(hal, usize::from(count) * size).ok_or(Error::OutOfMemory)?,
            size,
            by_head: vec![None; usize::from(queue.size())],
            free: (0..count).rev().collect(),
        })
    }

    fn ptr(&self, buffer: u16, offset: usize, len: usize) -> *mut u8 {
        assert!(offset + len <= self.size);
        self.memory
            .ptr(usize::from(buffer) * self.size + offset, len)
    }

    /// Gives a free buffer (`len` bytes of it) to the device.
    fn post(&mut self, queue: &mut VirtQueue, buffer: u16, len: usize, device_writes: bool) {
        let chain = [Buffer {
            pa: self.memory.pa() + (usize::from(buffer) * self.size) as u64,
            len: u32::try_from(len.min(self.size)).expect("buffers are small"),
            device_writes,
        }];
        // Safety: the buffer is ours (free) and DMA memory that lives as
        // long as the console; it is not accessed until the device returns
        // it.
        let head = unsafe { queue.add(&chain) }.expect("a descriptor per buffer");
        self.by_head[usize::from(head)] = Some(buffer);
    }

    /// The next buffer the device returned, with its length clamped.
    fn take_used(&mut self, queue: &mut VirtQueue) -> Option<(u16, usize)> {
        let (head, len) = queue.pop_used()?;
        let buffer = self.by_head[usize::from(head)]
            .take()
            .expect("in-flight chains are posted buffers");
        Some((
            buffer,
            usize::try_from(len).map_or(self.size, |len| len.min(self.size)),
        ))
    }
}

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
        let function = super::find_pci_device(DEVICE_TYPE)?;
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
        let (mut receive, mut receive_buffers, transmit, transmit_buffers) =
            setup().inspect_err(|_| transport.fail())?;
        while let Some(buffer) = receive_buffers.free.pop() {
            receive_buffers.post(&mut receive, buffer, RECEIVE_BUFFER_SIZE, true);
        }
        transport.start();
        transport.notify(&receive);
        Ok(Self {
            transport,
            receive,
            receive_buffers,
            transmit,
            transmit_buffers,
            received: VecDeque::with_capacity(usize::from(RECEIVE_BUFFERS)),
            received_offset: 0,
        })
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    /// Queues as much of `bytes` as free transmit buffers hold; returns how
    /// much. Zero means every buffer is still with the device.
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        while let Some((buffer, _)) = self.transmit_buffers.take_used(&mut self.transmit) {
            self.transmit_buffers.free.push(buffer);
        }
        let mut written = 0;
        while written < bytes.len() {
            let Some(buffer) = self.transmit_buffers.free.pop() else {
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
