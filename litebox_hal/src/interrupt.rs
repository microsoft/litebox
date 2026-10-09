// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Interrupt controllers: the local APIC, for device interrupts (MSI) and
//! the timer, in x2APIC mode (as on LVBS) where the CPU has it, else in
//! xAPIC mode (e.g., QEMU's TCG); the legacy 8259 PICs are only masked.

use crate::dma::{Hal, Mmio};
use crate::pci::MsiMessage;
use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;

const LEGACY_PIC_VECTOR_BASE: u8 = 0x20;

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xa0;
const SLAVE_DATA: u16 = 0xa1;

const IA32_APIC_BASE: u32 = 0x1b;
const IA32_APIC_BASE_EN: u64 = 1 << 11;
const IA32_APIC_BASE_EXTD: u64 = 1 << 10;
const IA32_TSC_DEADLINE: u32 = 0x6e0;

/// Local APIC registers, as xAPIC offsets; x2APIC MSR `0x800 + offset / 16`.
mod reg {
    pub const ID: usize = 0x20;
    pub const EOI: usize = 0xb0;
    pub const SVR: usize = 0xf0;
    pub const LVT_TIMER: usize = 0x320;
    pub const TIMER_INITIAL_COUNT: usize = 0x380;
    pub const TIMER_CURRENT_COUNT: usize = 0x390;
    pub const TIMER_DIVIDE: usize = 0x3e0;
}

const SVR_ENABLE: u32 = 1 << 8;
const LVT_TIMER_MASKED: u32 = 1 << 16;
const LVT_TIMER_TSC_DEADLINE: u32 = 0b10 << 17;
/// Divide the timer's clock by 16.
const TIMER_DIVIDE_BY_16: u32 = 0b0011;
const TIMER_CALIBRATION_MS: u64 = 10;

/// The local APIC's spurious vector; needs no EOI.
const APIC_SPURIOUS_VECTOR: u8 = 0xff;

/// PIC IRQ7/IRQ15 can arrive while masked, and the local APIC raises its
/// spurious vector.
pub const SPURIOUS_VECTORS: [u8; 3] = [
    LEGACY_PIC_VECTOR_BASE + 7,
    LEGACY_PIC_VECTOR_BASE + 15,
    APIC_SPURIOUS_VECTOR,
];

/// Must precede user entry (IF=1). PVH's PIC vectors overlap CPU exceptions.
pub fn init_legacy_pics() {
    const ICW1_INIT_ICW4: u8 = 0x11; // edge-triggered, cascade, ICW4 follows
    const ICW4_8086: u8 = 0x01;
    // Safety: the standard 8259 initialization sequence; nothing else drives
    // the PICs, and interrupts are still disabled.
    unsafe {
        Port::<u8>::new(MASTER_CMD).write(ICW1_INIT_ICW4);
        Port::<u8>::new(SLAVE_CMD).write(ICW1_INIT_ICW4);
        Port::<u8>::new(MASTER_DATA).write(LEGACY_PIC_VECTOR_BASE); // ICW2: vector base
        Port::<u8>::new(SLAVE_DATA).write(LEGACY_PIC_VECTOR_BASE + 8);
        Port::<u8>::new(MASTER_DATA).write(1 << 2); // ICW3: slave on IRQ2
        Port::<u8>::new(SLAVE_DATA).write(2); // ICW3: cascade identity
        Port::<u8>::new(MASTER_DATA).write(ICW4_8086);
        Port::<u8>::new(SLAVE_DATA).write(ICW4_8086);
        Port::<u8>::new(MASTER_DATA).write(0xff);
        Port::<u8>::new(SLAVE_DATA).write(0xff);
    }
}

/// This CPU's local APIC, enabled, with its timer raising a vector when
/// armed.
pub struct LocalApic {
    /// The xAPIC registers; `None` in x2APIC mode.
    xapic: Option<Mmio>,
    /// Timer ticks per TSC cycle, as (ticks, cycles); `None` for the
    /// TSC-deadline timer.
    one_shot: Option<(u64, u64)>,
}

fn has_cpu_feature(ecx_bit: u32) -> bool {
    core::arch::x86_64::__cpuid_count(1, 0).ecx & (1 << ecx_bit) != 0
}

fn rdtsc() -> u64 {
    // Safety: RDTSC has no side effects.
    unsafe { core::arch::x86_64::_rdtsc() }
}

impl LocalApic {
    /// Enables the local APIC and sets its timer to raise `timer_vector`,
    /// disarmed. Calibrates the timer against the TSC (`tsc_khz`) if it has
    /// no TSC-deadline mode.
    ///
    /// # Panics
    ///
    /// If the xAPIC registers cannot be mapped.
    pub fn init(hal: &dyn Hal, timer_vector: u8, tsc_khz: u64) -> Self {
        // The local APIC belongs to this kernel, and interrupts are disabled.
        // The SDM requires enabling xAPIC before x2APIC.
        let mut base = Msr::new(IA32_APIC_BASE);
        // Safety: see above.
        let value = unsafe { base.read() } | IA32_APIC_BASE_EN;
        let xapic = if has_cpu_feature(21) {
            // Safety: see above.
            unsafe {
                base.write(value);
                base.write(value | IA32_APIC_BASE_EXTD);
            }
            None
        } else {
            // Safety: see above.
            unsafe { base.write(value) };
            // Safety: the APIC base names the local APIC's registers.
            let registers = unsafe { hal.map_mmio(value & 0xf_ffff_f000, 0x1000) };
            Some(registers.expect("the local APIC's registers can be mapped"))
        };
        let mut apic = Self {
            xapic,
            one_shot: None,
        };
        let svr = apic.read(reg::SVR);
        apic.write(reg::SVR, svr | SVR_ENABLE | u32::from(APIC_SPURIOUS_VECTOR));
        if has_cpu_feature(24) {
            apic.write(
                reg::LVT_TIMER,
                LVT_TIMER_TSC_DEADLINE | u32::from(timer_vector),
            );
        } else {
            apic.write(reg::TIMER_DIVIDE, TIMER_DIVIDE_BY_16);
            apic.write(reg::LVT_TIMER, LVT_TIMER_MASKED | u32::from(timer_vector));
            apic.write(reg::TIMER_INITIAL_COUNT, u32::MAX);
            let start = rdtsc();
            let cycles = TIMER_CALIBRATION_MS * tsc_khz;
            while rdtsc() - start < cycles {}
            let ticks = u64::from(u32::MAX - apic.read(reg::TIMER_CURRENT_COUNT));
            apic.write(reg::TIMER_INITIAL_COUNT, 0);
            apic.write(reg::LVT_TIMER, u32::from(timer_vector));
            apic.one_shot = Some((ticks.max(1), cycles));
        }
        litebox_util_log::info!(
            mode:% = if apic.xapic.is_some() { "xAPIC" } else { "x2APIC" },
            timer:% = if apic.one_shot.is_some() { "one-shot" } else { "TSC-deadline" };
            "local APIC"
        );
        apic
    }

    /// x2APIC register `register`'s MSR.
    fn msr(register: usize) -> Msr {
        Msr::new(0x800 + u32::try_from(register >> 4).expect("small offsets"))
    }

    fn read(&self, register: usize) -> u32 {
        match self.xapic {
            Some(registers) => registers.read_u32(register),
            // Safety: reading a local APIC register has no side effects; the
            // registers used are 32 bits.
            #[expect(clippy::cast_possible_truncation, reason = "32-bit registers")]
            None => unsafe { Self::msr(register).read() as u32 },
        }
    }

    fn write(&self, register: usize, value: u32) {
        match self.xapic {
            Some(registers) => registers.write_u32(register, value),
            // Safety: callers program the local APIC, which this kernel owns.
            None => unsafe { Self::msr(register).write(u64::from(value)) },
        }
    }

    /// For interrupt handlers: ends the interrupt.
    pub fn end_of_interrupt(&self) {
        self.write(reg::EOI, 0);
    }

    /// The MSI message that raises `vector` on this CPU (fixed delivery,
    /// edge).
    ///
    /// # Panics
    ///
    /// If the APIC ID does not fit an MSI address (above 255).
    pub fn msi_message(&self, vector: u8) -> MsiMessage {
        let id = match self.xapic {
            Some(_) => self.read(reg::ID) >> 24,
            None => self.read(reg::ID),
        };
        // Without interrupt remapping, MSI addresses an 8-bit APIC ID.
        assert!(id <= 0xff, "APIC ID {id} beyond MSI's reach");
        MsiMessage {
            address: 0xfee0_0000 | (u64::from(id) << 12),
            data: u32::from(vector),
        }
    }

    /// Raises the timer's vector once, when the TSC reaches `deadline` (at
    /// once if it has; without TSC-deadline mode, a distant deadline may come
    /// early); replaces a pending deadline.
    pub fn arm_timer(&self, deadline: u64) {
        match self.one_shot {
            // Safety: programs this CPU's timer; zero would disarm.
            None => unsafe { Msr::new(IA32_TSC_DEADLINE).write(deadline.max(1)) },
            Some((ticks, cycles)) => {
                let delta = u128::from(deadline.saturating_sub(rdtsc()));
                let count = delta * u128::from(ticks) / u128::from(cycles);
                self.write(
                    reg::TIMER_INITIAL_COUNT,
                    u32::try_from(count.max(1)).unwrap_or(u32::MAX),
                );
            }
        }
    }

    pub fn disarm_timer(&self) {
        match self.one_shot {
            // Safety: programs this CPU's timer.
            None => unsafe { Msr::new(IA32_TSC_DEADLINE).write(0) },
            Some(_) => self.write(reg::TIMER_INITIAL_COUNT, 0),
        }
    }
}
