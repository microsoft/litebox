// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A one-shot timer: the legacy PIT's channel 0 in mode 0 (interrupt on
//! terminal count), through the 8259's IRQ0. Works under both TCG and KVM,
//! unlike the local APIC's TSC-deadline mode, which TCG lacks. A shot lasts at
//! most [`MAX_DELAY`]; a longer delay fires then.

use core::time::Duration;
use x86_64::instructions::port::Port;

/// IRQ0 of the legacy PICs as [`crate::interrupt::init_legacy_pics`] maps
/// them.
pub const VECTOR: u8 = crate::interrupt::LEGACY_PIC_VECTOR_BASE;

const PIT_HZ: u64 = 1_193_182;
const PIT_CH0: u16 = 0x40;
const PIT_CMD: u16 = 0x43;
/// Channel 0, low then high byte, mode 0, binary.
const CH0_ONE_SHOT: u8 = 0x30;
const MAX_COUNT: u64 = 0xffff;

/// About 55 ms.
pub const MAX_DELAY: Duration = Duration::from_nanos(MAX_COUNT * 1_000_000_000 / PIT_HZ);

/// Owns PIT channel 0 and IRQ0.
///
/// IRQ0 stays masked until the first [`Self::arm`]: the PIT runs from reset,
/// and a fire it raised while masked is still pending in the PIC, so a kernel
/// that never arms the timer must not see it. After the first arm, that stale
/// fire may arrive early.
pub struct PitTimer {
    unmasked: core::sync::atomic::AtomicBool,
}

impl PitTimer {
    /// Disarmed, IRQ0 masked.
    ///
    /// # Safety
    ///
    /// At most one, after [`crate::interrupt::init_legacy_pics`]: it owns PIT
    /// channel 0 and IRQ0.
    pub unsafe fn init() -> Self {
        let timer = Self {
            unmasked: core::sync::atomic::AtomicBool::new(false),
        };
        timer.disarm();
        timer
    }

    /// Fires once after `delay`, at most [`MAX_DELAY`]; replaces any armed
    /// shot. Rounds up, so it does not fire before `delay`.
    pub fn arm(&self, delay: Duration) {
        if !self
            .unmasked
            .swap(true, core::sync::atomic::Ordering::Relaxed)
        {
            crate::interrupt::unmask_legacy_irq(0);
        }
        let ticks = (delay.as_nanos() * u128::from(PIT_HZ)).div_ceil(1_000_000_000);
        let count = u16::try_from(ticks.clamp(1, u128::from(MAX_COUNT))).unwrap_or(u16::MAX);
        let [lo, hi] = count.to_le_bytes();
        // Safety: this timer owns channel 0; the write sequence programs it.
        unsafe {
            Port::<u8>::new(PIT_CMD).write(CH0_ONE_SHOT);
            Port::<u8>::new(PIT_CH0).write(lo);
            Port::<u8>::new(PIT_CH0).write(hi);
        }
    }

    /// A control word without a count stops the channel, its output low.
    pub fn disarm(&self) {
        // Safety: as in `arm`.
        unsafe { Port::<u8>::new(PIT_CMD).write(CH0_ONE_SHOT) };
    }

    pub fn end_of_interrupt(&self) {
        crate::interrupt::end_of_legacy_irq(0);
    }
}
