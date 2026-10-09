// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The modern virtio-PCI transport: structures located by vendor-specific
//! capabilities, in memory BARs.

use super::Error;
use super::queue::VirtQueue;
use crate::dma::{Hal, Mmio};
use crate::pci::{self, Function, MemoryBar};

const CAP_VENDOR_SPECIFIC: u8 = 0x09;

/// `VIRTIO_F_VERSION_1`: the modern interface; always negotiated.
const F_VERSION_1: u64 = 1 << 32;

/// `virtio_pci_cap` fields, from the capability's offset.
mod cap {
    pub const CFG_TYPE: u8 = 3;
    pub const BAR: u8 = 4;
    pub const OFFSET: u8 = 8;
    pub const LENGTH: u8 = 12;
    /// `virtio_pci_notify_cap` only.
    pub const NOTIFY_OFF_MULTIPLIER: u8 = 16;
    /// Of a `virtio_pci_notify_cap`, the longest one read.
    pub const LEN: u8 = 20;

    pub const COMMON: u8 = 1;
    pub const NOTIFY: u8 = 2;
    pub const ISR: u8 = 3;
    pub const DEVICE: u8 = 4;
}

/// `virtio_pci_common_cfg` fields.
mod common {
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    pub const DEVICE_FEATURE: usize = 0x04;
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    pub const DRIVER_FEATURE: usize = 0x0c;
    pub const DEVICE_STATUS: usize = 0x14;
    pub const QUEUE_SELECT: usize = 0x16;
    pub const QUEUE_SIZE: usize = 0x18;
    pub const QUEUE_ENABLE: usize = 0x1c;
    pub const QUEUE_NOTIFY_OFF: usize = 0x1e;
    pub const QUEUE_DESC: usize = 0x20;
    pub const QUEUE_DRIVER: usize = 0x28;
    pub const QUEUE_DEVICE: usize = 0x30;
    pub const LEN: usize = 0x38;
}

mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const FAILED: u8 = 0x80;
}

const RESET_POLL_LIMIT: u32 = 1_000_000;

/// A structure's location, from its capability.
#[derive(Clone, Copy)]
struct Location {
    bar: u8,
    offset: u32,
    length: u32,
}

/// The device's capabilities: the first of each structure type, as the
/// specification asks drivers to prefer.
#[derive(Default)]
struct Locations {
    common: Option<Location>,
    notify: Option<(Location, u32)>,
    isr: Option<Location>,
    device: Option<Location>,
}

impl Locations {
    fn read(function: Function) -> Self {
        let mut found = Self::default();
        function.for_each_capability(|offset, id| {
            // Every field read must be inside configuration space.
            if id != CAP_VENDOR_SPECIFIC || offset.checked_add(cap::LEN).is_none() {
                return;
            }
            let location = Location {
                bar: function.read_u8(offset + cap::BAR),
                offset: function.read_u32(offset + cap::OFFSET),
                length: function.read_u32(offset + cap::LENGTH),
            };
            match function.read_u8(offset + cap::CFG_TYPE) {
                cap::COMMON => {
                    found.common.get_or_insert(location);
                }
                cap::NOTIFY => {
                    let multiplier = function.read_u32(offset + cap::NOTIFY_OFF_MULTIPLIER);
                    found.notify.get_or_insert((location, multiplier));
                }
                cap::ISR => {
                    found.isr.get_or_insert(location);
                }
                cap::DEVICE => {
                    found.device.get_or_insert(location);
                }
                _ => {}
            }
        });
        found
    }
}

/// A virtio PCI function's mapped structures.
pub struct PciTransport {
    function: Function,
    common: Mmio,
    notify: Mmio,
    notify_off_multiplier: u32,
    isr: Mmio,
    device: Option<Mmio>,
    irq: Option<u8>,
}

impl PciTransport {
    /// Maps `function`'s structures and enables its memory decoding, bus
    /// mastering, and INTx.
    ///
    /// # Errors
    ///
    /// A missing or malformed structure, or one that cannot be mapped.
    pub fn new(hal: &dyn Hal, function: Function) -> Result<Self, Error> {
        let locations = Locations::read(function);
        let mut bars = [None::<MemoryBar>; 6];
        let mut map = |location: Location, what, min_len: usize| -> Result<Mmio, Error> {
            let bad = Error::BadStructure(what);
            let slot = bars.get_mut(usize::from(location.bar)).ok_or(bad)?;
            let bar = match *slot {
                Some(bar) => bar,
                // Safety: the driver does not access the BARs yet.
                None => *slot.insert(unsafe { function.memory_bar(location.bar) }.ok_or(bad)?),
            };
            let (offset, length) = (u64::from(location.offset), u64::from(location.length));
            if length < min_len as u64 || offset + length > bar.size {
                return Err(bad);
            }
            let length = usize::try_from(length).map_err(|_| bad)?;
            // Safety: within the BAR, so device registers.
            unsafe { hal.map_mmio(bar.address + offset, length) }.ok_or(Error::MapFailed)
        };
        let common = locations.common.ok_or(Error::MissingStructure("common"))?;
        let (notify, notify_off_multiplier) =
            locations.notify.ok_or(Error::MissingStructure("notify"))?;
        let isr = locations.isr.ok_or(Error::MissingStructure("ISR"))?;
        let transport = Self {
            function,
            common: map(common, "common", common::LEN)?,
            notify: map(notify, "notify", 2)?,
            notify_off_multiplier,
            isr: map(isr, "ISR", 1)?,
            device: locations
                .device
                .map(|device| map(device, "device", 0))
                .transpose()?,
            irq: function.legacy_irq(),
        };
        let command = (function.command() | pci::COMMAND_MEMORY_SPACE | pci::COMMAND_BUS_MASTER)
            & !pci::COMMAND_INTX_DISABLE;
        // Safety: decodes the BARs firmware assigned; DMA only goes where the
        // driver points the queues.
        unsafe { function.set_command(command) };
        Ok(transport)
    }

    pub fn function(&self) -> Function {
        self.function
    }

    /// The PIC IRQ of the device's INTx, if firmware routed one.
    pub fn irq(&self) -> Option<u8> {
        self.irq
    }

    /// The device-specific configuration, if any.
    pub fn device_config(&self) -> Option<Mmio> {
        self.device
    }

    fn status(&self) -> u8 {
        self.common.read_u8(common::DEVICE_STATUS)
    }

    fn set_status(&self, status: u8) {
        self.common.write_u8(common::DEVICE_STATUS, status);
    }

    fn add_status(&self, bits: u8) {
        self.set_status(self.status() | bits);
    }

    /// Marks the device `FAILED`, e.g., after a failed initialization.
    pub fn fail(&self) {
        self.add_status(status::FAILED);
    }

    /// Resets the device and negotiates `wanted` features (plus
    /// `VIRTIO_F_VERSION_1`) as far as it offers them; returns those. Set up
    /// queues next, then [`Self::start`].
    ///
    /// # Errors
    ///
    /// The device did not reset, is not modern, or rejected the features. It
    /// is left `FAILED`, except after a reset timeout.
    pub fn init(&self, wanted: u64) -> Result<u64, Error> {
        self.set_status(0);
        if !(0..RESET_POLL_LIMIT).any(|_| self.status() == 0) {
            return Err(Error::ResetTimedOut);
        }
        self.add_status(status::ACKNOWLEDGE);
        self.add_status(status::DRIVER);
        let offered = (0..2u32).fold(0, |features, word| {
            self.common.write_u32(common::DEVICE_FEATURE_SELECT, word);
            features | u64::from(self.common.read_u32(common::DEVICE_FEATURE)) << (32 * word)
        });
        if offered & F_VERSION_1 == 0 {
            self.fail();
            return Err(Error::NotModern);
        }
        let accepted = offered & (wanted | F_VERSION_1);
        for word in 0..2u32 {
            self.common.write_u32(common::DRIVER_FEATURE_SELECT, word);
            #[expect(clippy::cast_possible_truncation, reason = "one 32-bit word")]
            self.common
                .write_u32(common::DRIVER_FEATURE, (accepted >> (32 * word)) as u32);
        }
        self.add_status(status::FEATURES_OK);
        if self.status() & status::FEATURES_OK == 0 {
            self.fail();
            return Err(Error::FeaturesRejected);
        }
        Ok(accepted)
    }

    /// Sets up and enables queue `index`, with at most `max_size` entries.
    ///
    /// # Errors
    ///
    /// The device lacks the queue, its notification address is out of
    /// range, or memory ran out.
    pub fn setup_queue(
        &self,
        hal: &'static dyn Hal,
        index: u16,
        max_size: u16,
    ) -> Result<VirtQueue, Error> {
        self.common.write_u16(common::QUEUE_SELECT, index);
        let device_max = self.common.read_u16(common::QUEUE_SIZE);
        // Split queues of a power-of-two size work with every device.
        let size = device_max.min(max_size);
        if size == 0 {
            return Err(Error::QueueUnavailable(index));
        }
        let size = 1 << size.ilog2();
        let notify_offset = usize::from(self.common.read_u16(common::QUEUE_NOTIFY_OFF))
            .checked_mul(usize::try_from(self.notify_off_multiplier).unwrap_or(usize::MAX))
            .filter(|&offset| offset.is_multiple_of(2) && offset + 2 <= self.notify.len())
            .ok_or(Error::BadNotifyOffset(index))?;
        let queue = VirtQueue::new(hal, index, size, notify_offset)?;
        let [desc, driver, device] = queue.addresses();
        self.common.write_u16(common::QUEUE_SIZE, size);
        for (field, address) in [
            (common::QUEUE_DESC, desc),
            (common::QUEUE_DRIVER, driver),
            (common::QUEUE_DEVICE, device),
        ] {
            #[expect(clippy::cast_possible_truncation, reason = "split into words")]
            {
                self.common.write_u32(field, address as u32);
                self.common.write_u32(field + 4, (address >> 32) as u32);
            }
        }
        self.common.write_u16(common::QUEUE_ENABLE, 1);
        Ok(queue)
    }

    /// Lets the device use its queues.
    pub fn start(&self) {
        self.add_status(status::DRIVER_OK);
    }

    /// Tells the device that `queue` has new available buffers.
    pub fn notify(&self, queue: &VirtQueue) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.notify.write_u16(queue.notify_offset(), queue.index());
    }

    /// Acknowledges the device's interrupt (deasserting INTx); returns the
    /// ISR status (bit 0: a queue, bit 1: configuration). Process the queues
    /// afterwards, so nothing that arrived before goes unnoticed.
    pub fn acknowledge_interrupt(&self) -> u8 {
        self.isr.read_u8(0)
    }
}
