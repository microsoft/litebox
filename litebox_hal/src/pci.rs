// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PCI: configuration space through the legacy mechanism #1 ports
//! (`0xCF8`/`0xCFC`), on bus 0, and MSI-X. Firmware (SeaBIOS under QEMU) has
//! already assigned BARs.

use crate::dma::Hal;
use crate::interrupt::MsiMessage;
use x86_64::instructions::port::Port;

const CONFIG_ADDRESS: u16 = 0xcf8;
const CONFIG_DATA: u16 = 0xcfc;

const VENDOR_ID: u8 = 0x00;
const DEVICE_ID: u8 = 0x02;
const SUBSYSTEM_ID: u8 = 0x2e;
const COMMAND: u8 = 0x04;
const STATUS: u8 = 0x06;
const HEADER_TYPE: u8 = 0x0e;
const CAPABILITIES_POINTER: u8 = 0x34;
const STATUS_CAPABILITIES: u16 = 1 << 4;
/// Capabilities live past the standard header.
const FIRST_CAPABILITY: u8 = 0x40;
const BAR0: u8 = 0x10;

const CAP_MSIX: u8 = 0x11;
const MSIX_CONTROL_ENABLE: u16 = 1 << 15;
const MSIX_CONTROL_FUNCTION_MASK: u16 = 1 << 14;
const MSIX_ENTRY_SIZE: usize = 16;

/// `COMMAND` bits.
pub const COMMAND_IO_SPACE: u16 = 1 << 0;
pub const COMMAND_MEMORY_SPACE: u16 = 1 << 1;
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;
pub const COMMAND_INTX_DISABLE: u16 = 1 << 10;

/// A function on bus 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub device: u8,
    pub function: u8,
}

impl core::fmt::Display for Function {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "00:{:02x}.{}", self.device, self.function)
    }
}

impl Function {
    fn select(self, offset: u8) {
        let address = 0x8000_0000
            | (u32::from(self.device & 0x1f) << 11)
            | (u32::from(self.function & 0x7) << 8)
            | u32::from(offset & 0xfc);
        // Safety: selects a configuration register; no memory side effects.
        // Nothing else in the kernel accesses PCI configuration space, and
        // callers run with interrupts disabled, so the address/data pair is
        // not interleaved.
        unsafe { Port::<u32>::new(CONFIG_ADDRESS).write(address) };
    }

    pub fn read_u32(self, offset: u8) -> u32 {
        self.select(offset);
        // Safety: see `select`.
        unsafe { Port::<u32>::new(CONFIG_DATA).read() }
    }

    pub fn read_u16(self, offset: u8) -> u16 {
        self.select(offset);
        // Safety: see `select`.
        unsafe { Port::<u16>::new(CONFIG_DATA + u16::from(offset & 2)).read() }
    }

    pub fn read_u8(self, offset: u8) -> u8 {
        self.select(offset);
        // Safety: see `select`.
        unsafe { Port::<u8>::new(CONFIG_DATA + u16::from(offset & 3)).read() }
    }

    /// # Safety
    ///
    /// The write must not move a BAR or enable DMA into memory the caller
    /// does not own.
    pub unsafe fn write_u32(self, offset: u8, value: u32) {
        self.select(offset);
        // Safety: forwarded to the caller.
        unsafe { Port::<u32>::new(CONFIG_DATA).write(value) };
    }

    pub fn vendor_id(self) -> u16 {
        self.read_u16(VENDOR_ID)
    }

    pub fn device_id(self) -> u16 {
        self.read_u16(DEVICE_ID)
    }

    pub fn subsystem_id(self) -> u16 {
        self.read_u16(SUBSYSTEM_ID)
    }

    pub fn command(self) -> u16 {
        self.read_u16(COMMAND)
    }

    /// A 16-bit write, leaving the neighboring register (e.g., `STATUS`,
    /// write-1-to-clear) alone.
    ///
    /// # Safety
    ///
    /// As for [`Self::write_u32`].
    pub unsafe fn write_u16(self, offset: u8, value: u16) {
        self.select(offset);
        // Safety: forwarded to the caller.
        unsafe { Port::<u16>::new(CONFIG_DATA + u16::from(offset & 2)).write(value) };
    }

    /// # Safety
    ///
    /// Enabling bus mastering lets the device DMA wherever the driver points
    /// it.
    pub unsafe fn set_command(self, command: u16) {
        // Safety: forwarded to the caller.
        unsafe { self.write_u16(COMMAND, command) };
    }

    /// Memory BAR `index` (with its upper half, if 64-bit), sized; `None` if
    /// it is not a memory BAR or is unassigned. Sizing briefly disables the
    /// function's decoding.
    ///
    /// # Safety
    ///
    /// Nothing may access the function's BARs meanwhile.
    pub unsafe fn memory_bar(self, index: u8) -> Option<MemoryBar> {
        if index >= 6 {
            return None;
        }
        let offset = BAR0 + 4 * index;
        let low = self.read_u32(offset);
        let wide = (low >> 1) & 3 == 2;
        if low & 1 != 0 || (wide && index == 5) {
            return None;
        }
        let high = if wide { self.read_u32(offset + 4) } else { 0 };
        let command = self.command();
        // Safety: decoding is off while the BAR reads back its size mask, and
        // both halves are restored before it is turned back on.
        let (low_mask, high_mask) = unsafe {
            self.set_command(command & !(COMMAND_IO_SPACE | COMMAND_MEMORY_SPACE));
            self.write_u32(offset, u32::MAX);
            let low_mask = self.read_u32(offset);
            self.write_u32(offset, low);
            let high_mask = if wide {
                self.write_u32(offset + 4, u32::MAX);
                let mask = self.read_u32(offset + 4);
                self.write_u32(offset + 4, high);
                mask
            } else {
                u32::MAX
            };
            self.set_command(command);
            (low_mask, high_mask)
        };
        let mask = (u64::from(high_mask) << 32) | u64::from(low_mask & !0xf);
        let size = (!mask).wrapping_add(1);
        let address = (u64::from(high) << 32) | u64::from(low & !0xf);
        (size != 0 && address != 0 && address.checked_add(size).is_some())
            .then_some(MemoryBar { address, size })
    }

    /// Calls `f` with the offset and ID of each capability. The list comes
    /// from the device: a malformed or cyclic one ends the walk.
    pub fn for_each_capability(self, mut f: impl FnMut(u8, u8)) {
        if self.read_u16(STATUS) & STATUS_CAPABILITIES == 0 {
            return;
        }
        let mut offset = self.read_u8(CAPABILITIES_POINTER) & 0xfc;
        // At most this many fit in configuration space.
        for _ in 0..(256 - usize::from(FIRST_CAPABILITY)) / 4 {
            if offset < FIRST_CAPABILITY {
                return;
            }
            f(offset, self.read_u8(offset));
            offset = self.read_u8(offset + 1) & 0xfc;
        }
    }

    /// Routes every MSI-X vector of the function to `message` and enables
    /// MSI-X (which disables INTx); `false` if it has no usable MSI-X.
    ///
    /// # Safety
    ///
    /// Nothing may access the function's BARs meanwhile, and `message` must
    /// raise an interrupt the kernel handles.
    pub unsafe fn enable_msix(self, hal: &dyn Hal, message: MsiMessage) -> bool {
        let mut msix = None;
        self.for_each_capability(|offset, id| {
            if id == CAP_MSIX && offset <= 0xf4 {
                msix.get_or_insert(offset);
            }
        });
        let Some(cap) = msix else {
            return false;
        };
        let control = self.read_u16(cap + 2);
        let entries = usize::from(control & 0x7ff) + 1;
        let table = self.read_u32(cap + 4);
        // Safety: the caller does not access the BARs meanwhile.
        let Some(bar) = (unsafe { self.memory_bar(table.to_le_bytes()[0] & 7) }) else {
            return false;
        };
        let (offset, len) = (u64::from(table & !7), (entries * MSIX_ENTRY_SIZE) as u64);
        if offset + len > bar.size {
            return false;
        }
        // Safety: the table is within the BAR, so device registers.
        let Some(table) =
            (unsafe { hal.map_mmio(bar.address + offset, entries * MSIX_ENTRY_SIZE) })
        else {
            return false;
        };
        // Safety: decodes the BAR firmware assigned, so the table writes
        // below reach the device.
        unsafe { self.set_command(self.command() | COMMAND_MEMORY_SPACE) };
        #[expect(clippy::cast_possible_truncation, reason = "split into words")]
        for entry in (0..entries).map(|entry| entry * MSIX_ENTRY_SIZE) {
            table.write_u32(entry, message.address as u32);
            table.write_u32(entry + 4, (message.address >> 32) as u32);
            table.write_u32(entry + 8, message.data);
            table.write_u32(entry + 12, 0); // unmasked
        }
        // Safety: the vectors raise the caller's interrupt.
        unsafe {
            self.write_u16(
                cap + 2,
                (control | MSIX_CONTROL_ENABLE) & !MSIX_CONTROL_FUNCTION_MASK,
            );
        }
        true
    }
}

/// A memory BAR's physical range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryBar {
    pub address: u64,
    pub size: u64,
}

/// The first function on bus 0 that `matches`.
pub fn find(matches: impl Fn(Function) -> bool) -> Option<Function> {
    for device in 0..32 {
        let first = Function {
            device,
            function: 0,
        };
        if first.vendor_id() == 0xffff {
            continue;
        }
        let multifunction = first.read_u8(HEADER_TYPE) & 0x80 != 0;
        for function in 0..if multifunction { 8 } else { 1 } {
            let candidate = Function { device, function };
            if matches(candidate) {
                return Some(candidate);
            }
        }
    }
    None
}
