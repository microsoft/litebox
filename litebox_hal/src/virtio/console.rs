// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio console (device type 3): QEMU's `virtio-serial-pci`, driving its
//! ports below [`MAX_PORTS`], e.g.:
//!
//! ```text
//! -device virtio-serial-pci,id=vs0,disable-legacy=on
//! -chardev file,id=con0,path=out.txt,input-path=in.txt
//! -device virtconsole,chardev=con0,bus=vs0.0
//! -chardev socket,id=ch1,path=ch1.sock,server=on,wait=on
//! -device virtserialport,chardev=ch1,bus=vs0.0,nr=1
//! ```
//!
//! With `VIRTIO_CONSOLE_F_MULTIPORT`, port `n` is on queues `2n + 2` and
//! `2n + 3`, but port 0 on 0 and 1, and the control queues are 2 and 3. The
//! driver answers each `PORT_ADD` with `PORT_READY` and `PORT_OPEN`, as it
//! next looks at the device; QEMU sends a port no input until then. Other
//! control messages, including the device's `PORT_OPEN` and `PORT_REMOVE`,
//! are ignored, so the driver cannot tell whether a port has a connected
//! backend: one without takes output (QEMU discards it) and receives
//! nothing. Without `MULTIPORT`, the device is port 0 alone.
//!
//! QEMU drops output a `virtconsole`'s backend cannot take at once (e.g., a
//! full socket), but holds a `virtserialport`'s until it does: only the
//! latter is a reliable byte stream.
//!
//! Neither direction blocks: [`VirtioConsole::write`] takes what free
//! transmit buffers hold, and [`VirtioConsole::read`] what has arrived. The
//! device interrupts when it returns buffers in any queue.

use super::Error;
use super::buffers::Buffers;
use super::pci::PciTransport;
use super::queue::VirtQueue;
use crate::dma::Hal;
use crate::interrupt::MsiMessage;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

const DEVICE_TYPE: u16 = 3;
const F_MULTIPORT: u64 = 1 << 1;
/// `max_nr_ports` in the device configuration, with `MULTIPORT`.
const CONFIG_MAX_NR_PORTS: usize = 4;

/// Ports beyond these are not driven.
pub const MAX_PORTS: u32 = 2;

const RECEIVE_BUFFERS: u16 = 16;
const RECEIVE_BUFFER_SIZE: usize = 256;
const TRANSMIT_BUFFERS: u16 = 32;
const TRANSMIT_BUFFER_SIZE: usize = 512;

const CONTROL_RECEIVE_QUEUE: u16 = 2;
const CONTROL_TRANSMIT_QUEUE: u16 = 3;
const CONTROL_BUFFERS: u16 = 8;
/// Longer control messages (e.g., `PORT_NAME`) are truncated; none that the
/// driver reads are.
const CONTROL_BUFFER_SIZE: usize = 64;

/// `struct virtio_console_control`: `id` (le32), `event` (le16), `value`
/// (le16).
mod control {
    pub const LEN: usize = 8;
    pub const DEVICE_READY: u16 = 0;
    pub const PORT_ADD: u16 = 1;
    pub const PORT_READY: u16 = 3;
    pub const PORT_OPEN: u16 = 6;

    pub fn encode(id: u32, event: u16, value: u16) -> [u8; LEN] {
        let mut message = [0; LEN];
        message[..4].copy_from_slice(&id.to_le_bytes());
        message[4..6].copy_from_slice(&event.to_le_bytes());
        message[6..].copy_from_slice(&value.to_le_bytes());
        message
    }

    /// `(id, event)`.
    pub fn decode(message: [u8; LEN]) -> (u32, u16) {
        let [id @ .., event0, event1, _, _] = message;
        (u32::from_le_bytes(id), u16::from_le_bytes([event0, event1]))
    }
}

/// Gives `bytes` (at most a buffer) to the device in a free buffer of
/// `buffers`, if any; returns whether it did.
fn send(buffers: &mut Buffers, queue: &mut VirtQueue, bytes: &[u8]) -> bool {
    let Some(buffer) = buffers.free.pop() else {
        return false;
    };
    let destination = buffers.ptr(buffer, 0, bytes.len());
    // Safety: a free buffer, which the device does not access.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
    buffers.post(queue, buffer, bytes.len(), false);
    true
}

/// Frees the transmit buffers the device returned.
fn recycle(buffers: &mut Buffers, queue: &mut VirtQueue) {
    while let Some((buffer, _)) = buffers.take_used(queue) {
        buffers.free.push(buffer);
    }
}

/// A port's queues.
struct Port {
    receive: VirtQueue,
    receive_buffers: Buffers,
    transmit: VirtQueue,
    transmit_buffers: Buffers,
    /// All transmit buffers, as free when none is with the device.
    transmit_count: usize,
    /// Filled receive buffers not yet read, as (buffer, length), oldest
    /// first; `received_offset` bytes of the first are read.
    received: VecDeque<(u16, usize)>,
    received_offset: usize,
}

impl Port {
    fn setup(hal: &'static dyn Hal, transport: &PciTransport, index: u16) -> Result<Self, Error> {
        let (receive_queue, transmit_queue) = match index {
            0 => (0, 1),
            index => (2 * index + 2, 2 * index + 3),
        };
        let receive = transport.setup_queue(hal, receive_queue, RECEIVE_BUFFERS)?;
        let transmit = transport.setup_queue(hal, transmit_queue, TRANSMIT_BUFFERS)?;
        let receive_buffers = Buffers::new(hal, &receive, RECEIVE_BUFFERS, RECEIVE_BUFFER_SIZE)?;
        let transmit_buffers =
            Buffers::new(hal, &transmit, TRANSMIT_BUFFERS, TRANSMIT_BUFFER_SIZE)?;
        Ok(Self {
            receive,
            receive_buffers,
            transmit,
            transmit_count: transmit_buffers.free.len(),
            transmit_buffers,
            received: VecDeque::with_capacity(usize::from(RECEIVE_BUFFERS)),
            received_offset: 0,
        })
    }

    /// Lends the device every receive buffer; before the device starts.
    fn post_receive_buffers(&mut self) {
        while let Some(buffer) = self.receive_buffers.free.pop() {
            self.receive_buffers
                .post(&mut self.receive, buffer, RECEIVE_BUFFER_SIZE, true);
        }
    }

    fn write(&mut self, transport: &PciTransport, bytes: &[u8]) -> usize {
        recycle(&mut self.transmit_buffers, &mut self.transmit);
        let mut written = 0;
        for chunk in bytes.chunks(TRANSMIT_BUFFER_SIZE) {
            if !send(&mut self.transmit_buffers, &mut self.transmit, chunk) {
                break;
            }
            written += chunk.len();
        }
        if written != 0 {
            transport.notify(&self.transmit);
        }
        written
    }

    fn flushed(&mut self) -> bool {
        recycle(&mut self.transmit_buffers, &mut self.transmit);
        self.transmit_buffers.free.len() == self.transmit_count
    }

    fn read(&mut self, transport: &PciTransport, output: &mut [u8]) -> usize {
        self.collect_received(transport);
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
            transport.notify(&self.receive);
        }
        read
    }

    fn collect_received(&mut self, transport: &PciTransport) {
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
            transport.notify(&self.receive);
        }
    }
}

/// The control queues, with `MULTIPORT`.
struct Control {
    receive: VirtQueue,
    receive_buffers: Buffers,
    transmit: VirtQueue,
    transmit_buffers: Buffers,
    /// Messages waiting for a free transmit buffer, oldest first.
    pending: VecDeque<[u8; control::LEN]>,
}

impl Control {
    fn setup(hal: &'static dyn Hal, transport: &PciTransport) -> Result<Self, Error> {
        let receive = transport.setup_queue(hal, CONTROL_RECEIVE_QUEUE, CONTROL_BUFFERS)?;
        let transmit = transport.setup_queue(hal, CONTROL_TRANSMIT_QUEUE, CONTROL_BUFFERS)?;
        let receive_buffers = Buffers::new(hal, &receive, CONTROL_BUFFERS, CONTROL_BUFFER_SIZE)?;
        let transmit_buffers = Buffers::new(hal, &transmit, CONTROL_BUFFERS, control::LEN)?;
        let mut control = Self {
            receive,
            receive_buffers,
            transmit,
            transmit_buffers,
            pending: VecDeque::from([control::encode(0, control::DEVICE_READY, 1)]),
        };
        while let Some(buffer) = control.receive_buffers.free.pop() {
            control
                .receive_buffers
                .post(&mut control.receive, buffer, CONTROL_BUFFER_SIZE, true);
        }
        Ok(control)
    }

    /// Handles what the device sent about the first `ports` ports, and
    /// sends what is pending.
    fn poll(&mut self, transport: &PciTransport, ports: usize) {
        let mut reposted = false;
        while let Some((buffer, len)) = self.receive_buffers.take_used(&mut self.receive) {
            if len >= control::LEN {
                let mut message = [0; control::LEN];
                let source = self.receive_buffers.ptr(buffer, 0, control::LEN);
                // Safety: the device returned the buffer, with `len` bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(source, message.as_mut_ptr(), control::LEN);
                };
                let (id, event) = control::decode(message);
                if event == control::PORT_ADD && usize::try_from(id).is_ok_and(|id| id < ports) {
                    self.pending
                        .push_back(control::encode(id, control::PORT_READY, 1));
                    self.pending
                        .push_back(control::encode(id, control::PORT_OPEN, 1));
                }
            }
            self.receive_buffers
                .post(&mut self.receive, buffer, CONTROL_BUFFER_SIZE, true);
            reposted = true;
        }
        if reposted {
            transport.notify(&self.receive);
        }
        recycle(&mut self.transmit_buffers, &mut self.transmit);
        let mut sent = false;
        while let Some(message) = self.pending.front() {
            if !send(&mut self.transmit_buffers, &mut self.transmit, message) {
                break;
            }
            self.pending.pop_front();
            sent = true;
        }
        if sent {
            transport.notify(&self.transmit);
        }
    }
}

/// A live console. Not internally synchronized. Methods taking a port panic
/// if it is not driven ([`Self::ports`]).
pub struct VirtioConsole {
    transport: PciTransport,
    /// By port number.
    ports: Vec<Port>,
    control: Option<Control>,
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
        let multiport = transport.init(F_MULTIPORT)? & F_MULTIPORT != 0;
        let setup = || -> Result<_, Error> {
            let count = if multiport {
                let max_ports = transport
                    .device_config()
                    .filter(|config| config.len() >= CONFIG_MAX_NR_PORTS + 4)
                    .map_or(1, |config| config.read_u32(CONFIG_MAX_NR_PORTS));
                max_ports.clamp(1, MAX_PORTS)
            } else {
                1
            };
            let ports = (0..u16::try_from(count).expect("few ports"))
                .map(|index| Port::setup(hal, &transport, index))
                .collect::<Result<Vec<_>, _>>()?;
            let control = multiport
                .then(|| Control::setup(hal, &transport))
                .transpose()?;
            Ok((ports, control))
        };
        let (mut ports, control) = setup().inspect_err(|_| transport.fail())?;
        for port in &mut ports {
            port.post_receive_buffers();
        }
        transport.start();
        for port in &ports {
            transport.notify(&port.receive);
        }
        let mut console = Self {
            transport,
            ports,
            control,
        };
        if let Some(control) = &console.control {
            console.transport.notify(&control.receive);
        }
        // Says `DEVICE_READY`.
        console.poll_control();
        Ok(console)
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    /// The ports driven: `0..ports()`.
    #[expect(clippy::cast_possible_truncation, reason = "at most `MAX_PORTS`")]
    pub fn ports(&self) -> u32 {
        self.ports.len() as u32
    }

    fn poll_control(&mut self) {
        if let Some(control) = &mut self.control {
            control.poll(&self.transport, self.ports.len());
        }
    }

    /// Port `port`, after handling control messages.
    fn port(&mut self, port: u32) -> (&mut Port, &PciTransport) {
        self.poll_control();
        let port = usize::try_from(port)
            .ok()
            .and_then(|port| self.ports.get_mut(port))
            .expect("a driven port");
        (port, &self.transport)
    }

    /// Queues as much of `bytes` as free transmit buffers of `port` hold;
    /// returns how much. Zero means every buffer is still with the device.
    pub fn write(&mut self, port: u32, bytes: &[u8]) -> usize {
        let (port, transport) = self.port(port);
        port.write(transport, bytes)
    }

    /// Whether the device returned all of `port`'s output: for a
    /// `virtserialport`, its backend took it.
    pub fn flushed(&mut self, port: u32) -> bool {
        self.port(port).0.flushed()
    }

    /// Whether [`Self::read`] would return data.
    pub fn has_input(&mut self, port: u32) -> bool {
        let (port, transport) = self.port(port);
        port.collect_received(transport);
        !port.received.is_empty()
    }

    /// Copies bytes received on `port` into `output`; returns how many.
    pub fn read(&mut self, port: u32, output: &mut [u8]) -> usize {
        let (port, transport) = self.port(port);
        port.read(transport, output)
    }
}
