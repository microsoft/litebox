// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The kernel must install a [`ClockSource`] before reading platform time.

use x86_64::instructions::port::Port;

pub trait ClockSource: Sync {
    /// Nanoseconds since an arbitrary origin that is fixed for the kernel's
    /// lifetime. Never decreases.
    fn monotonic_nanos(&self) -> u64;
}

static SOURCE: spin::Once<&'static dyn ClockSource> = spin::Once::new();

/// Call once, before the platform reads time.
///
/// # Panics
///
/// Panics if a clock source is already installed.
pub fn init(source: &'static dyn ClockSource) {
    let mut installed = false;
    SOURCE.call_once(|| {
        installed = true;
        source
    });
    assert!(installed, "the clock source is already set");
}

/// # Panics
///
/// Panics if called before [`init`].
pub(crate) fn monotonic_nanos() -> u64 {
    SOURCE
        .get()
        .expect("clock used before clock::init")
        .monotonic_nanos()
}

/// Requires a single CPU and a constant TSC rate; neither is checked.
pub struct TscClock {
    khz: u64,
}

impl TscClock {
    /// # Panics
    ///
    /// Panics if `khz` is zero.
    pub fn new(khz: u64) -> Self {
        assert!(khz != 0, "TSC frequency must not be zero");
        Self { khz }
    }
}

impl ClockSource for TscClock {
    fn monotonic_nanos(&self) -> u64 {
        // Safety: RDTSC has no side effects.
        let tsc = u128::from(unsafe { core::arch::x86_64::_rdtsc() });
        u64::try_from(tsc * 1_000_000 / u128::from(self.khz)).unwrap_or(u64::MAX)
    }
}

const PIT_HZ: u64 = 1_193_182;
const CALIBRATION_MS: u64 = 50;
/// Bounds the calibration wait, so a missing PIT panics instead of hanging.
const CALIBRATION_TIMEOUT_CYCLES: u64 = 1 << 36;

/// Measure the TSC frequency, in kHz, against legacy PIT channel 2. Takes
/// ~50 ms.
///
/// # Panics
///
/// Panics if the machine has no legacy PIT, or the measurement is zero.
pub fn calibrate_tsc_khz_with_pit() -> u64 {
    const PORT_B: u16 = 0x61; // bit 0: channel 2 gate, bit 1: speaker, bit 5: OUT2
    const PIT_CMD: u16 = 0x43;
    const PIT_CH2: u16 = 0x42;
    let latch = u16::try_from(PIT_HZ * CALIBRATION_MS / 1000).expect("PIT latch fits in 16 bits");

    // In mode 0 the count starts on the first PIT clock after the MSB write,
    // so the start TSC is read right after it.
    //
    // Safety: legacy PIT/port-B programming; nothing else uses channel 2.
    unsafe {
        let mut port_b = Port::<u8>::new(PORT_B);
        let v = port_b.read();
        port_b.write((v & !0x02) | 0x01);
        // Channel 2, lobyte/hibyte, mode 0, binary.
        Port::<u8>::new(PIT_CMD).write(0xb0);
        let mut ch2 = Port::<u8>::new(PIT_CH2);
        let [lo, hi] = latch.to_le_bytes();
        ch2.write(lo);
        ch2.write(hi);

        let start = core::arch::x86_64::_rdtsc();
        let mut now = start;
        while port_b.read() & 0x20 == 0 {
            now = core::arch::x86_64::_rdtsc();
            assert!(
                now - start < CALIBRATION_TIMEOUT_CYCLES,
                "TSC calibration: the legacy PIT (channel 2) never signalled"
            );
        }
        // Bits 4-7 are read-only.
        port_b.write(v & 0x0f);
        let khz = (now - start) / CALIBRATION_MS;
        assert!(khz != 0, "TSC calibration measured a zero frequency");
        khz
    }
}
