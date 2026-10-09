// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio 1.x devices over PCI ([`pci::PciTransport`]): the modern
//! interface, with its structures in memory BARs (mapped through
//! [`crate::dma::Hal`]) and INTx interrupts (routed to a legacy PIC IRQ by
//! firmware; MSI-X is left disabled). Split virtqueues ([`queue`]).
//!
//! Devices: [`console`]. The transport and queues are device-independent,
//! for further devices (e.g., file systems and networking for the broker).
//!
//! Devices are not trusted: the capability list, BAR ranges, queue sizes and
//! used-ring entries are checked, and lengths the device reports are clamped
//! by the driver before use.

pub mod console;
pub mod pci;
pub mod queue;

const PCI_VENDOR: u16 = 0x1af4;

/// The first virtio function of type `device_type` on bus 0. Modern-only
/// device IDs are 0x1040 + type; transitional ones (0x1000..=0x103f) give
/// the type in the subsystem ID.
pub fn find_pci_device(device_type: u16) -> Option<crate::pci::Function> {
    crate::pci::find(|function| {
        let device_id = function.device_id();
        function.vendor_id() == PCI_VENDOR
            && (device_id == 0x1040 + device_type
                || ((0x1000..=0x103f).contains(&device_id)
                    && function.subsystem_id() == device_type))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The device lacks a required structure (common, notify, or ISR).
    MissingStructure(&'static str),
    /// A structure is outside its BAR, too short, or not in a memory BAR.
    BadStructure(&'static str),
    /// The platform could not map a structure.
    MapFailed,
    ResetTimedOut,
    /// No `VIRTIO_F_VERSION_1`.
    NotModern,
    /// The device cleared `FEATURES_OK`.
    FeaturesRejected,
    QueueUnavailable(u16),
    /// The queue's notification address is outside the notify structure.
    BadNotifyOffset(u16),
    OutOfMemory,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingStructure(what) => write!(f, "no {what} structure"),
            Self::BadStructure(what) => write!(f, "malformed {what} structure"),
            Self::MapFailed => f.write_str("cannot map device registers"),
            Self::ResetTimedOut => f.write_str("reset timed out"),
            Self::NotModern => f.write_str("VIRTIO_F_VERSION_1 not offered"),
            Self::FeaturesRejected => f.write_str("features rejected"),
            Self::QueueUnavailable(queue) => write!(f, "queue {queue} unavailable"),
            Self::BadNotifyOffset(queue) => write!(f, "queue {queue} notify offset out of range"),
            Self::OutOfMemory => f.write_str("out of DMA memory"),
        }
    }
}
