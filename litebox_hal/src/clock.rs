// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Clocks: TSC frequency, calibrated against the legacy PIT.

const PIT_HZ: u64 = 1_193_182;
const CALIBRATION_MS: u64 = 50;
const CALIBRATION_TIMEOUT_CYCLES: u64 = 1 << 36;

/// Uses PIT channel 2 exclusively for ~50 ms.
///
/// # Panics
///
/// Panics if calibration fails.
pub fn calibrate_tsc_khz() -> u64 {
    use x86_64::instructions::port::Port;

    const PORT_B: u16 = 0x61; // gate: bit 0, speaker: bit 1, OUT2: bit 5
    const PIT_CMD: u16 = 0x43;
    const PIT_CH2: u16 = 0x42;
    let latch = u16::try_from(PIT_HZ * CALIBRATION_MS / 1000).expect("PIT latch fits in 16 bits");

    // Safety: during boot, nothing else uses PIT channel 2 or port B.
    unsafe {
        let mut port_b = Port::<u8>::new(PORT_B);
        let v = port_b.read();
        port_b.write((v & !0x02) | 0x01);
        Port::<u8>::new(PIT_CMD).write(0xb0); // channel 2, lobyte/hibyte, mode 0
        let mut ch2 = Port::<u8>::new(PIT_CH2);
        let [lo, hi] = latch.to_le_bytes();
        ch2.write(lo);
        ch2.write(hi);

        // Mode 0 starts counting on the PIT clock after the MSB write.
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
