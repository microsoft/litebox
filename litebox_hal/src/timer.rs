// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Timer: PIT channel 0 in one-shot mode (mode 0), on PIC IRQ 0. Enough to
//! bound a halt; the TSC tells the time (see [`crate::clock`]).

use x86_64::instructions::port::Port;

/// The PIC IRQ the timer raises.
pub const IRQ: u8 = 0;

const PIT_HZ: u64 = 1_193_182;
const PIT_CMD: u16 = 0x43;
const PIT_CH0: u16 = 0x40;
/// Channel 0, lobyte/hibyte, mode 0 (interrupt on terminal count), binary.
const CH0_ONESHOT: u8 = 0x30;

/// Stops channel 0 without an interrupt; firmware may have left it
/// periodic. Call before unmasking [`IRQ`].
pub fn disarm() {
    // Safety: in mode 0, a control word holds OUT low and stops counting
    // until a count is written. Nothing else uses channel 0.
    unsafe { Port::<u8>::new(PIT_CMD).write(CH0_ONESHOT) };
}

/// Raises [`IRQ`] once, after `nanos`, clamped to about 55 ms (longer waits
/// re-arm). Replaces a pending shot.
pub fn arm_oneshot(nanos: u64) {
    let ticks = u128::from(nanos) * u128::from(PIT_HZ) / 1_000_000_000;
    let ticks = u16::try_from(ticks.clamp(1, 0xffff)).unwrap_or(u16::MAX);
    let [lo, hi] = ticks.to_le_bytes();
    // Safety: programs channel 0 only; see `disarm`.
    unsafe {
        Port::<u8>::new(PIT_CMD).write(CH0_ONESHOT);
        let mut ch0 = Port::<u8>::new(PIT_CH0);
        ch0.write(lo);
        ch0.write(hi);
    }
}
