// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices behind device-neutral types ([`ConsoleDevice`],
//! [`NetworkDevice`]), each probing
//! the drivers the HAL has for its kind. Runners choose which devices to
//! probe, where they interrupt, and what to do without one.

use crate::dma::Hal;
use crate::interrupt::InterruptTarget;
use crate::virtio::console::VirtioConsole;
use crate::virtio::net::VirtioNet;
use alloc::boxed::Box;
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
