// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The CPU's clock: a free-running counter ([`now`], in ticks) and its
//! frequency ([`Clock`]). On x86-64, the counter is the TSC, which ring 3
//! reads too: the kernel clock of `litebox_common_vm_abi` is [`Clock::nanos`],
//! with `StartupInfo::clock_khz` being [`Clock::khz`]. Its frequency comes
//! from the most authoritative source the machine has: CPUID, the
//! hypervisor, or else calibration against the legacy PIT (which, e.g.,
//! Firecracker and Cloud Hypervisor lack).

use core::arch::x86_64::__cpuid_count as cpuid;

const PIT_HZ: u64 = 1_193_182;
const CALIBRATION_MS: u64 = 50;
const CALIBRATION_TIMEOUT_CYCLES: u64 = 1 << 36;

/// Frequencies outside this range are not believed.
const PLAUSIBLE_KHZ: core::ops::RangeInclusive<u64> = 100_000..=100_000_000;

/// The counter: the TSC, as ring 3 reads it (see the module docs). Never
/// decreases (one CPU, constant rate).
pub fn now() -> u64 {
    // Safety: RDTSC has no side effects.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// The counter's frequency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    khz: u64,
}

impl Clock {
    /// Finds the frequency (logged, with its source). Call once, at boot;
    /// calibration takes a while.
    ///
    /// # Panics
    ///
    /// If no source works.
    pub fn measure() -> Self {
        let (khz, source) = tsc_khz();
        litebox_util_log::info!(mhz:% = khz / 1000, source:? = source; "clock frequency");
        Self { khz }
    }

    /// Ticks per millisecond: the TSC frequency in kHz, as ring 3 gets it.
    pub fn khz(self) -> u64 {
        self.khz
    }

    /// [`now`] in nanoseconds.
    pub fn nanos(self) -> u64 {
        u64::try_from(u128::from(now()) * 1_000_000 / u128::from(self.khz)).unwrap_or(u64::MAX)
    }

    /// The first tick [`now`] reaches where [`Self::nanos`] is at least
    /// `nanos`, e.g., to program a timer for a deadline in nanoseconds.
    pub fn ticks_at(self, nanos: u64) -> u64 {
        let ticks = (u128::from(nanos) * u128::from(self.khz)).div_ceil(1_000_000);
        u64::try_from(ticks).unwrap_or(u64::MAX)
    }
}

/// Where [`tsc_khz`] got the frequency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TscSource {
    /// CPUID leaf 0x15: the core crystal and its ratio (Intel).
    Cpuid,
    /// The hypervisor's timing leaf 0x40000010 (KVM via QEMU, VMware).
    Hypervisor,
    /// Calibration against the PIT.
    Pit,
}

/// The TSC frequency in kHz, and its source.
fn tsc_khz() -> (u64, TscSource) {
    if let Some(khz) = cpuid_khz().filter(|khz| PLAUSIBLE_KHZ.contains(khz)) {
        return (khz, TscSource::Cpuid);
    }
    if let Some(khz) = hypervisor_khz().filter(|khz| PLAUSIBLE_KHZ.contains(khz)) {
        return (khz, TscSource::Hypervisor);
    }
    (calibrate_tsc_khz(), TscSource::Pit)
}

fn cpuid_khz() -> Option<u64> {
    if cpuid(0, 0).eax < 0x15 {
        return None;
    }
    let leaf = cpuid(0x15, 0);
    let (denominator, numerator, crystal_hz) = (leaf.eax, leaf.ebx, leaf.ecx);
    (denominator != 0 && numerator != 0 && crystal_hz != 0)
        .then(|| u64::from(crystal_hz) * u64::from(numerator) / u64::from(denominator) / 1000)
}

fn hypervisor_khz() -> Option<u64> {
    const KVM: [u32; 3] = [0x4b4d_564b, 0x564b_4d56, 0x0000_004d]; // "KVMKVMKVM\0\0\0"
    const VMWARE: [u32; 3] = [0x6177_4d56, 0x4d56_6572, 0x6572_6177]; // "VMwareVMware"
    if cpuid(1, 0).ecx & (1 << 31) == 0 {
        return None;
    }
    let leaf = cpuid(0x4000_0000, 0);
    let signature = [leaf.ebx, leaf.ecx, leaf.edx];
    if signature != KVM && signature != VMWARE || leaf.eax < 0x4000_0010 {
        return None;
    }
    Some(u64::from(cpuid(0x4000_0010, 0).eax))
}

/// Uses PIT channel 2 exclusively for ~50 ms.
fn calibrate_tsc_khz() -> u64 {
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
        let start = now();
        let mut end = start;
        while port_b.read() & 0x20 == 0 {
            end = now();
            assert!(
                end - start < CALIBRATION_TIMEOUT_CYCLES,
                "TSC calibration: the legacy PIT (channel 2) never signalled"
            );
        }
        // Bits 4-7 are read-only.
        port_b.write(v & 0x0f);
        let khz = (end - start) / CALIBRATION_MS;
        assert!(khz != 0, "TSC calibration measured a zero frequency");
        khz
    }
}
