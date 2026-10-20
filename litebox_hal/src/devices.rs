// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices behind device-neutral types ([`ConsoleDevice`],
//! [`NetworkDevice`], [`NinePDevice`], [`VsockDevice`]), each probing
//! the drivers the HAL has for its kind. Runners choose which devices to
//! probe, where they interrupt, and what to do without one.

use crate::dma::Hal;
use crate::interrupt::InterruptTarget;
use crate::virtio::console::VirtioConsole;
use crate::virtio::net::VirtioNet;
use crate::virtio::nine_p::Virtio9p;
use crate::virtio::vsock::{self, VirtioVsock};
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

    /// Queues as much of `bytes` as the device takes now; returns how much.
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        match &mut self.0 {
            Backend::Virtio(device) => device.write(bytes),
            Backend::Serial => {
                crate::serial::print_bytes(bytes);
                bytes.len()
            }
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

/// A [`VsockDevice`]'s state, as its user sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VsockState {
    /// No connection: the next request from the host is accepted.
    Listening,
    /// A connection, which may still have data to read after the host shut
    /// down its sending side, or after the connection is gone (see
    /// [`Self::Closed`]), until its data is read.
    Connected,
    /// The connection is gone (reset, shut down both ways, or lost to a
    /// transport reset), and its data read; [`VsockDevice::close`] it to
    /// listen again. Requests are refused meanwhile.
    Closed,
}

/// A stream listener on one port of the VM's socket device, which the host
/// connects to: at most one connection at a time, only from the host. Not
/// internally synchronized.
pub struct VsockDevice(Box<VirtioVsock>);

impl VsockDevice {
    /// The VM's socket device, interrupting `interrupt` if it can (see
    /// [`Self::interrupts`]), listening on `port`; `None` if there is none.
    ///
    /// # Errors
    ///
    /// The device cannot be driven.
    pub fn probe(
        hal: &'static dyn Hal,
        interrupt: InterruptTarget,
        port: u32,
    ) -> Result<Option<Self>, crate::virtio::Error> {
        // Virtio over PCI.
        let device = VirtioVsock::probe(hal, interrupt.msi_message(), port).transpose()?;
        Ok(device.map(|device| Self(Box::new(device))))
    }

    /// Whether the device raises its interrupt; else it must be polled.
    pub fn interrupts(&self) -> bool {
        self.0.transport().interrupts()
    }

    /// The host's port of the connection, if any.
    pub fn peer_port(&self) -> Option<u32> {
        self.0.peer_port()
    }

    /// The listener's state, once what the device returned is taken.
    pub fn state(&mut self) -> VsockState {
        match self.0.state() {
            vsock::State::Listening => VsockState::Listening,
            vsock::State::Connected => VsockState::Connected,
            vsock::State::Closed => VsockState::Closed,
        }
    }

    /// Copies received data into `output`: how much (zero if none is
    /// waiting), or `None` at the end of the stream (no connection, or the
    /// host sends no more).
    pub fn read(&mut self, output: &mut [u8]) -> Option<usize> {
        self.0.read(output)
    }

    /// Queues as much of `bytes` as the device and host take now: how much,
    /// or `None` if the stream takes no more (no live connection, or the
    /// host receives no more).
    pub fn write(&mut self, bytes: &[u8]) -> Option<usize> {
        self.0.write(bytes)
    }

    /// Ends the connection, if any, and listens again.
    pub fn close(&mut self) {
        self.0.close();
    }

    /// Whether everything written reached the host's socket.
    pub fn flushed(&mut self) -> bool {
        self.0.flushed()
    }
}

impl fmt::Display for VsockDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "virtio (pci {}, interrupts {}, cid {}, port {})",
            self.0.transport().function(),
            self.interrupts(),
            self.0.guest_cid(),
            self.0.port()
        )
    }
}
