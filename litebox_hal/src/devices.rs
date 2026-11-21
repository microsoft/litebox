// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices behind device-neutral types ([`ConsoleDevice`],
//! [`NetworkDevice`], [`NinePDevice`], [`FuseDevice`], [`VsockDevice`]),
//! each probing the drivers the HAL has for its kind. Runners choose which
//! devices to probe, where they interrupt, and what to do without one.

use crate::dma::Hal;
use crate::interrupt::InterruptTarget;
use crate::virtio::console::VirtioConsole;
use crate::virtio::fs::{Shared, VirtioFs};
use crate::virtio::net::VirtioNet;
use crate::virtio::nine_p::Virtio9p;
use crate::virtio::vsock::VirtioVsock;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

/// A console: output, and input if the device receives any. Not internally
/// synchronized.
pub struct ConsoleDevice(Backend);

enum Backend {
    Virtio(Box<VirtioConsole>),
    /// The kernel's UART ([`crate::serial`]): output only.
    Serial,
}

impl ConsoleDevice {
    /// The VM's console device, interrupting `interrupt` if it can (see
    /// [`Self::interrupts`]); `None` if there is none.
    ///
    /// # Errors
    ///
    /// The device cannot be driven.
    pub fn probe(
        hal: &'static dyn Hal,
        interrupt: InterruptTarget,
    ) -> Result<Option<Self>, crate::virtio::Error> {
        // Virtio over PCI.
        let device = VirtioConsole::probe(hal, interrupt.msi_message()).transpose()?;
        Ok(device.map(|device| Self(Backend::Virtio(Box::new(device)))))
    }

    /// Output to the kernel's UART; receives nothing.
    pub fn serial() -> Self {
        Self(Backend::Serial)
    }

    /// Whether the device receives input at all.
    pub fn receives(&self) -> bool {
        match &self.0 {
            Backend::Virtio(_) => true,
            Backend::Serial => false,
        }
    }

    /// Whether the device raises its interrupt; else it must be polled.
    pub fn interrupts(&self) -> bool {
        match &self.0 {
            Backend::Virtio(device) => device.transport().interrupts(),
            Backend::Serial => false,
        }
    }

    /// Whether [`Self::write`] would take output now. If not, a device that
    /// interrupts (see [`Self::interrupts`]) does so once room comes, unless
    /// a later call finds it first.
    pub fn can_write(&mut self) -> bool {
        match &mut self.0 {
            Backend::Virtio(device) => device.can_write(),
            Backend::Serial => true,
        }
    }

    /// Queues as much of `bytes` as the device takes now; returns how much.
    /// After a short count, a device that interrupts (see [`Self::interrupts`])
    /// does so once room comes, unless a later call finds it first.
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        match &mut self.0 {
            Backend::Virtio(device) => device.write(bytes),
            Backend::Serial => {
                crate::serial::print_bytes(bytes);
                bytes.len()
            }
        }
    }

    /// Whether the device took all output queued so far.
    pub fn is_drained(&mut self) -> bool {
        match &mut self.0 {
            Backend::Virtio(device) => device.is_drained(),
            Backend::Serial => true,
        }
    }

    /// Whether received input is waiting.
    pub fn has_input(&mut self) -> bool {
        match &mut self.0 {
            Backend::Virtio(device) => device.has_input(),
            Backend::Serial => false,
        }
    }

    /// Copies received input into `output`; returns how much (zero if none
    /// is waiting).
    pub fn read(&mut self, output: &mut [u8]) -> usize {
        match &mut self.0 {
            Backend::Virtio(device) => device.read(output),
            Backend::Serial => 0,
        }
    }
}

impl fmt::Display for ConsoleDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Backend::Virtio(device) => write!(
                f,
                "virtio (pci {}, interrupts {})",
                device.transport().function(),
                device.transport().interrupts()
            ),
            Backend::Serial => f.write_str("serial (output only)"),
        }
    }
}

/// An Ethernet network interface. Not internally synchronized.
pub struct NetworkDevice(Box<VirtioNet>);

impl NetworkDevice {
    /// The longest frame (without FCS) sent or received.
    pub const MAX_FRAME_SIZE: usize = crate::virtio::net::MAX_FRAME_SIZE;

    /// The VM's network device, interrupting `interrupt` if it can (see
    /// [`Self::interrupts`]); `None` if there is none.
    ///
    /// # Errors
    ///
    /// The device cannot be driven.
    pub fn probe(
        hal: &'static dyn Hal,
        interrupt: InterruptTarget,
    ) -> Result<Option<Self>, crate::virtio::Error> {
        // Virtio over PCI.
        let device = VirtioNet::probe(hal, interrupt.msi_message()).transpose()?;
        Ok(device.map(|device| Self(Box::new(device))))
    }

    /// Whether the device raises its interrupt; else it must be polled.
    pub fn interrupts(&self) -> bool {
        self.0.transport().interrupts()
    }

    pub fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }

    /// Whether [`Self::transmit`] would take a frame now.
    pub fn can_transmit(&mut self) -> bool {
        self.0.can_transmit()
    }

    /// Queues `frame`, at most [`Self::MAX_FRAME_SIZE`] bytes; false if the
    /// device has no room for it now.
    pub fn transmit(&mut self, frame: &[u8]) -> bool {
        self.0.transmit(frame)
    }

    /// The next frame's length, its bytes copied into `frame` (truncated);
    /// 0 for a malformed one, which the device dropped.
    pub fn receive(&mut self, frame: &mut [u8]) -> Option<usize> {
        self.0.receive(frame)
    }
}

impl fmt::Display for NetworkDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mac = self.mac();
        write!(
            f,
            "virtio (pci {}, interrupts {}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            self.0.transport().function(),
            self.interrupts(),
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
        )
    }
}

/// A host directory served over 9P, one request at a time. Not internally
/// synchronized.
pub struct NinePDevice(Box<Virtio9p>);

impl NinePDevice {
    /// The largest message either way: the most a 9P client may negotiate.
    pub const MAX_MESSAGE_SIZE: usize = crate::virtio::nine_p::MAX_MESSAGE_SIZE;

    /// The VM's 9P devices, interrupting `interrupt` if they can (see
    /// [`Self::interrupts`]), or why one cannot be driven.
    pub fn probe_all(
        hal: &'static dyn Hal,
        interrupt: InterruptTarget,
    ) -> Vec<Result<Self, crate::virtio::Error>> {
        // Virtio over PCI.
        Virtio9p::probe_all(hal, interrupt.msi_message())
            .into_iter()
            .map(|device| device.map(|device| Self(Box::new(device))))
            .collect()
    }

    /// Whether the device raises its interrupt; else it must be polled.
    pub fn interrupts(&self) -> bool {
        self.0.transport().interrupts()
    }

    /// The share's name, if it has one: untrusted bytes from the host.
    pub fn mount_tag(&self) -> Option<&[u8]> {
        self.0.mount_tag()
    }

    /// Queues `message`, one whole 9P request; false if one is in flight.
    ///
    /// # Panics
    ///
    /// If `message` is empty or longer than [`Self::MAX_MESSAGE_SIZE`].
    pub fn transmit(&mut self, message: &[u8]) -> bool {
        self.0.transmit(message)
    }

    /// The response's length, once the device answered, its bytes copied
    /// into `response` (truncated); unchecked as 9P.
    pub fn receive(&mut self, response: &mut [u8]) -> Option<usize> {
        self.0.receive(response)
    }
}

impl fmt::Display for NinePDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "virtio (pci {}, interrupts {})",
            self.0.transport().function(),
            self.interrupts()
        )
    }
}

/// A host directory served over FUSE, one request at a time (see
/// [`crate::virtio::fs`]), through bytes shared with the device ([`Shared`]).
/// Not internally synchronized.
pub struct FuseDevice(Box<VirtioFs>);

impl FuseDevice {
    /// The longest request header and arguments.
    pub const MAX_REQUEST_SIZE: usize = crate::virtio::fs::MAX_REQUEST_SIZE;
    /// The largest payload either way: a request's, or a reply's body.
    pub const MAX_PAYLOAD_SIZE: usize = crate::virtio::fs::MAX_PAYLOAD_SIZE;
    /// The largest reply body of a request with a payload.
    pub const MAX_SMALL_REPLY_SIZE: usize = crate::virtio::fs::MAX_SMALL_REPLY_SIZE;
    /// The longest request without a reply.
    pub const MAX_ONEWAY_SIZE: usize = crate::virtio::fs::MAX_ONEWAY_SIZE;
    /// A reply's header, before its body.
    pub const OUT_HEADER_SIZE: usize = crate::virtio::fs::OUT_HEADER_SIZE;

    /// The VM's FUSE devices, interrupting `interrupt` if they can (see
    /// [`Self::interrupts`]), or why one cannot be driven.
    pub fn probe_all(
        hal: &'static dyn Hal,
        interrupt: InterruptTarget,
    ) -> Vec<Result<Self, crate::virtio::Error>> {
        // Virtio over PCI.
        VirtioFs::probe_all(hal, interrupt.msi_message())
            .into_iter()
            .map(|device| device.map(|device| Self(Box::new(device))))
            .collect()
    }

    /// Whether the device raises its interrupt; else it must be polled.
    pub fn interrupts(&self) -> bool {
        self.0.transport().interrupts()
    }

    /// The file system's name: untrusted bytes from the host.
    pub fn tag(&self) -> &[u8] {
        self.0.tag()
    }

    /// See [`VirtioFs::request`].
    pub fn request(&mut self) -> Option<Shared<'_>> {
        self.0.request()
    }

    /// See [`VirtioFs::payload`].
    pub fn payload(&mut self) -> Option<Shared<'_>> {
        self.0.payload()
    }

    /// See [`VirtioFs::transmit`].
    pub fn transmit(&mut self, request: usize, payload: usize, room: usize) -> bool {
        self.0.transmit(request, payload, room)
    }

    /// See [`VirtioFs::receive`].
    pub fn receive(&mut self) -> Option<usize> {
        self.0.receive()
    }

    /// See [`VirtioFs::reply_header`].
    pub fn reply_header(&self) -> Option<Shared<'_>> {
        self.0.reply_header()
    }

    /// See [`VirtioFs::reply_body`].
    pub fn reply_body(&self) -> Option<Shared<'_>> {
        self.0.reply_body()
    }

    /// See [`VirtioFs::oneway`].
    pub fn oneway(&mut self) -> Option<Shared<'_>> {
        self.0.oneway()
    }

    /// See [`VirtioFs::transmit_oneway`].
    pub fn transmit_oneway(&mut self, len: usize) -> bool {
        self.0.transmit_oneway(len)
    }

    /// See [`VirtioFs::oneway_done`].
    pub fn oneway_done(&mut self) -> bool {
        self.0.oneway_done()
    }
}

impl fmt::Display for FuseDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "virtio (pci {}, interrupts {})",
            self.0.transport().function(),
            self.interrupts()
        )
    }
}

/// A socket device's connection, by its ends' ports, whichever end
/// connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId {
    pub guest_port: u32,
    pub host_port: u32,
}

/// What became of a connection the user asked the host for
/// ([`VsockDevice::connect`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectState {
    /// The host has yet to answer.
    Connecting,
    /// The host accepted it; it is live, or gone since.
    Established,
    /// The host refused it, or it was reset (e.g., the host sent anything
    /// but its answer, or the transport reset), or it is unknown, or the
    /// host requested it (the user's was forgotten).
    Failed,
}

/// What reads and writes on a connection would do now
/// ([`VsockDevice::status`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionStatus {
    /// Received data waits to be read.
    pub readable: bool,
    /// The host sends no more: it shut down sending, or the connection is
    /// gone or unknown. Data already received can still be read.
    pub host_sending_ended: bool,
    /// A write takes data now (the host has credit for it, and a transmit
    /// buffer is free), or fails: the connection takes no more.
    pub writable: bool,
}

/// The VM's socket device (vsock): stream connections the host makes to any
/// guest port, which its user accepts or refuses, and those its user makes to
/// the host's ports (see [`VirtioVsock`]). Not internally synchronized.
pub struct VsockDevice(Box<VirtioVsock>);

impl VsockDevice {
    /// The VM's socket device, interrupting `interrupt` if it can (see
    /// [`Self::interrupts`]); `None` if there is none.
    ///
    /// # Errors
    ///
    /// The device cannot be driven.
    pub fn probe(
        hal: &'static dyn Hal,
        interrupt: InterruptTarget,
    ) -> Result<Option<Self>, crate::virtio::Error> {
        // Virtio over PCI.
        let device = VirtioVsock::probe(hal, interrupt.msi_message()).transpose()?;
        Ok(device.map(|device| Self(Box::new(device))))
    }

    /// Whether the device raises its interrupt; else it must be polled.
    pub fn interrupts(&self) -> bool {
        self.0.transport().interrupts()
    }

    /// See [`VirtioVsock::take_request`].
    pub fn take_request(&mut self) -> Option<ConnectionId> {
        self.0.take_request()
    }

    /// See [`VirtioVsock::accept`].
    pub fn accept(&mut self, id: ConnectionId) -> bool {
        self.0.accept(id)
    }

    /// See [`VirtioVsock::refuse`].
    pub fn refuse(&mut self, id: ConnectionId) {
        self.0.refuse(id);
    }

    /// See [`VirtioVsock::connect`].
    pub fn connect(&mut self, id: ConnectionId) -> bool {
        self.0.connect(id)
    }

    /// See [`VirtioVsock::connect_state`].
    pub fn connect_state(&mut self, id: ConnectionId) -> ConnectState {
        self.0.connect_state(id)
    }

    /// See [`VirtioVsock::read`].
    pub fn read(&mut self, id: ConnectionId, output: &mut [u8]) -> Option<usize> {
        self.0.read(id, output)
    }

    /// See [`VirtioVsock::write`].
    pub fn write(&mut self, id: ConnectionId, bytes: &[u8]) -> Option<usize> {
        self.0.write(id, bytes)
    }

    /// See [`VirtioVsock::shutdown_sending`].
    pub fn shutdown_sending(&mut self, id: ConnectionId) {
        self.0.shutdown_sending(id);
    }

    /// See [`VirtioVsock::shutdown_receiving`].
    pub fn shutdown_receiving(&mut self, id: ConnectionId) {
        self.0.shutdown_receiving(id);
    }

    /// See [`VirtioVsock::close`].
    pub fn close(&mut self, id: ConnectionId) {
        self.0.close(id);
    }

    /// See [`VirtioVsock::guest_cid`].
    pub fn guest_cid(&self) -> u64 {
        self.0.guest_cid()
    }

    /// See [`VirtioVsock::status`].
    pub fn status(&self, id: ConnectionId) -> ConnectionStatus {
        self.0.status(id)
    }

    /// See [`VirtioVsock::is_closed`].
    pub fn is_closed(&mut self, id: ConnectionId) -> bool {
        self.0.is_closed(id)
    }

    /// See [`VirtioVsock::forget`].
    pub fn forget(&mut self, id: ConnectionId) {
        self.0.forget(id);
    }

    /// See [`VirtioVsock::take_backlog`].
    pub fn take_backlog(&mut self) -> bool {
        self.0.take_backlog()
    }
}

impl fmt::Display for VsockDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "virtio (pci {}, interrupts {}, cid {})",
            self.0.transport().function(),
            self.interrupts(),
            self.0.guest_cid()
        )
    }
}
