// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Interrupt controllers: the local APICs, one per CPU, for device
//! interrupts (MSI), the timer, and IPIs between CPUs, in x2APIC mode (as on
//! LVBS) where the CPUs have it, else in xAPIC mode (e.g., QEMU's TCG); the
//! legacy 8259 PICs are only masked.

use crate::clock::{Clock, now};
use crate::dma::{Hal, Mmio};
use core::sync::atomic::{Ordering, compiler_fence};
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
/// Bits 51:12, the registers' physical address (bits from MAXPHYADDR up are
/// reserved, so 0).
const IA32_APIC_BASE_ADDRESS: u64 = 0xf_ffff_ffff_f000;
const IA32_TSC_DEADLINE: u32 = 0x6e0;

/// Local APIC registers, as xAPIC offsets; x2APIC MSR `0x800 + offset / 16`.
mod reg {
    pub const ID: usize = 0x20;
    pub const EOI: usize = 0xb0;
    pub const SVR: usize = 0xf0;
    /// In x2APIC mode, one 64-bit register, with the destination in the high
    /// half.
    pub const ICR_LOW: usize = 0x300;
    pub const ICR_HIGH: usize = 0x310;
    pub const LVT_TIMER: usize = 0x320;
    pub const TIMER_INITIAL_COUNT: usize = 0x380;
    pub const TIMER_CURRENT_COUNT: usize = 0x390;
    pub const TIMER_DIVIDE: usize = 0x3e0;
}

const SVR_ENABLE: u32 = 1 << 8;
const ICR_INIT: u32 = 0b101 << 8;
const ICR_STARTUP: u32 = 0b110 << 8;
const ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// xAPIC only: the last IPI is not sent yet.
const ICR_SEND_PENDING: u32 = 1 << 12;
/// Where an xAPIC ID is in the ID register and in `ICR_HIGH`: bits 31:24.
const XAPIC_ID_SHIFT: u32 = 24;
/// The broadcast local APIC IDs, which no one CPU has: xAPIC's (also in MSI
/// addresses), and x2APIC's.
pub(crate) const XAPIC_BROADCAST: u32 = 0xff;
pub(crate) const X2APIC_BROADCAST: u32 = u32::MAX;
/// VGA memory, below 1 MiB: not RAM, and its pages are reserved for startup
/// IPIs by Intel's MP initialization.
pub const VGA_MEMORY: core::ops::Range<u64> = 0xa_0000..0xc_0000;
/// How long an IPI waits for the last one to go, in xAPIC mode, before it is
/// sent anyway.
const ICR_SEND_TIMEOUT_CYCLES: u64 = 1 << 30;
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

/// An MSI message: a write of `data` to `address` raises the interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiMessage {
    pub address: u64,
    pub data: u32,
}

/// Where a device interrupt goes: `vector` on the CPU with local APIC ID
/// `apic_id`. Each delivery mechanism derives its own form (e.g., an MSI
/// message).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptTarget {
    pub apic_id: u32,
    pub vector: u8,
}

impl InterruptTarget {
    /// As an MSI message (fixed delivery, edge); `None` if the APIC ID does
    /// not fit an MSI address, which without interrupt remapping holds 8
    /// bits, 0xff broadcasting.
    pub fn msi_message(self) -> Option<MsiMessage> {
        let id = u8::try_from(self.apic_id)
            .ok()
            .filter(|_| self.apic_id != XAPIC_BROADCAST)?;
        Some(MsiMessage {
            address: 0xfee0_0000 | (u64::from(id) << 12),
            data: u32::from(self.vector),
        })
    }
}

/// An interprocessor interrupt that resets or starts a CPU; see
/// [`LocalApic::send_startup_ipi`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupIpi {
    /// Resets the CPU to wait for a startup IPI.
    Init,
    /// Starts a CPU that waits for one, in real mode at physical address
    /// `page << 12`; not in [`VGA_MEMORY`].
    Startup { page: u8 },
}

/// The calling CPU's local APIC ID, as the MADT lists it and IPIs target
/// it: in x2APIC mode, from the APIC ID register; else from CPUID, its x2APIC
/// ID where CPUID has it (leaf 0xb), else its 8-bit initial xAPIC ID, which
/// the register keeps unless firmware changed it, as is assumed. Usable
/// before the local APIC is set up.
pub fn initial_apic_id() -> u32 {
    use core::arch::x86_64::__cpuid_count as cpuid;
    let x2apic_mode = IA32_APIC_BASE_EN | IA32_APIC_BASE_EXTD;
    // Safety: reads only.
    if unsafe { Msr::new(IA32_APIC_BASE).read() } & x2apic_mode == x2apic_mode {
        // Safety: reads the APIC ID register, in x2APIC mode.
        #[expect(clippy::cast_possible_truncation, reason = "a 32-bit register")]
        let id = unsafe { LocalApic::msr(reg::ID).read() } as u32;
        return id;
    }
    if cpuid(0, 0).eax >= 0xb && cpuid(0xb, 0).ebx != 0 {
        cpuid(0xb, 0).edx
    } else {
        cpuid(1, 0).ebx >> 24
    }
}

/// The local APIC: methods act on the calling CPU's. [`Self::init`] enables
/// the boot CPU's, and [`Self::init_cpu`] then each other CPU's alike,
/// each with its timer raising a vector when armed.
pub struct LocalApic {
    /// The xAPIC registers (each CPU's at the same address); `None` in x2APIC
    /// mode.
    xapic: Option<Mmio>,
    /// Their physical address, in xAPIC mode.
    xapic_base: u64,
    /// Timer ticks per TSC cycle, as (ticks, cycles); `None` for the
    /// TSC-deadline timer. The same for every CPU.
    one_shot: Option<(u64, u64)>,
    timer_vector: u8,
}

/// CPUID leaf 1's ECX bits.
const CPUID_X2APIC: u32 = 21;
const CPUID_TSC_DEADLINE: u32 = 24;

fn has_cpu_feature(ecx_bit: u32) -> bool {
    core::arch::x86_64::__cpuid_count(1, 0).ecx & (1 << ecx_bit) != 0
}

/// Enables the calling CPU's local APIC, in x2APIC mode if `x2apic`;
/// returns its registers' physical address (for xAPIC mode). The SDM
/// requires enabling xAPIC before x2APIC.
fn enable(x2apic: bool) -> u64 {
    // The local APIC belongs to this kernel, and interrupts are disabled.
    let mut base = Msr::new(IA32_APIC_BASE);
    // Safety: see above.
    let value = unsafe { base.read() } | IA32_APIC_BASE_EN;
    // Safety: see above.
    unsafe {
        base.write(value);
        if x2apic {
            base.write(value | IA32_APIC_BASE_EXTD);
        }
    }
    value & IA32_APIC_BASE_ADDRESS
}

impl LocalApic {
    /// Enables the calling CPU's local APIC and sets its timer to raise
    /// `timer_vector`, disarmed. Calibrates the timer against `clock` if it
    /// has no TSC-deadline mode.
    ///
    /// # Panics
    ///
    /// If the xAPIC registers cannot be mapped.
    pub fn init(hal: &dyn Hal, timer_vector: u8, clock: Clock) -> Self {
        let in_x2apic_mode = has_cpu_feature(CPUID_X2APIC);
        let xapic_base = enable(in_x2apic_mode);
        let xapic = (!in_x2apic_mode).then(|| {
            // Safety: the APIC base names the local APIC's registers.
            let registers = unsafe { hal.map_mmio(xapic_base, 0x1000) };
            registers.expect("the local APIC's registers can be mapped")
        });
        let mut apic = Self {
            xapic,
            xapic_base,
            one_shot: None,
            timer_vector,
        };
        apic.enable_vectors();
        if !has_cpu_feature(CPUID_TSC_DEADLINE) {
            apic.write(reg::TIMER_DIVIDE, TIMER_DIVIDE_BY_16);
            apic.write(reg::LVT_TIMER, LVT_TIMER_MASKED | u32::from(timer_vector));
            apic.write(reg::TIMER_INITIAL_COUNT, u32::MAX);
            let start = now();
            let cycles = TIMER_CALIBRATION_MS * clock.khz();
            while now() - start < cycles {}
            let ticks = u64::from(u32::MAX - apic.read(reg::TIMER_CURRENT_COUNT));
            apic.one_shot = Some((ticks.max(1), cycles));
        }
        apic.init_timer();
        litebox_util_log::info!(
            mode:% = if apic.xapic.is_some() { "xAPIC" } else { "x2APIC" },
            timer:% = if apic.one_shot.is_some() { "one-shot" } else { "TSC-deadline" };
            "local APIC"
        );
        apic
    }

    /// On a CPU other than [`Self::init`]'s: enables its local APIC as that
    /// one's (mode, spurious vector, and timer, with that calibration: the
    /// CPUs' timers run at the same rate), its timer disarmed.
    ///
    /// # Panics
    ///
    /// If it lacks x2APIC mode or the TSC-deadline timer, as the first uses,
    /// or, in xAPIC mode, if its registers are elsewhere than the first's.
    pub fn init_cpu(&self) {
        assert!(
            (self.xapic.is_some() || has_cpu_feature(CPUID_X2APIC))
                && (self.one_shot.is_some() || has_cpu_feature(CPUID_TSC_DEADLINE)),
            "this CPU's local APIC lacks the first's x2APIC mode or TSC-deadline timer"
        );
        let base = enable(self.xapic.is_none());
        assert!(
            self.xapic.is_none() || base == self.xapic_base,
            "the CPUs' local APICs are at different addresses"
        );
        self.enable_vectors();
        self.init_timer();
    }

    /// Sets the calling CPU's timer to raise its vector, in its mode,
    /// disarmed first (even of a deadline left from before, e.g., by
    /// firmware: switching modes disarms it too).
    fn init_timer(&self) {
        self.disarm_timer();
        let vector = u32::from(self.timer_vector);
        if self.one_shot.is_none() {
            self.write(reg::LVT_TIMER, LVT_TIMER_TSC_DEADLINE | vector);
            // The SDM orders the xAPIC's memory-mapped write before later
            // WRMSRs to `IA32_TSC_DEADLINE` (ignored outside TSC-deadline
            // mode) with MFENCE, as Linux does.
            // Safety: a fence only.
            unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)) };
        } else {
            self.write(reg::TIMER_DIVIDE, TIMER_DIVIDE_BY_16);
            self.write(reg::LVT_TIMER, vector);
        }
    }

    /// Software-enables the local APIC, with its spurious vector.
    fn enable_vectors(&self) {
        let svr = self.read(reg::SVR);
        self.write(reg::SVR, svr | SVR_ENABLE | u32::from(APIC_SPURIOUS_VECTOR));
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

    /// Interrupts raising `vector` on this CPU.
    pub fn target(&self, vector: u8) -> InterruptTarget {
        InterruptTarget {
            apic_id: self.id(),
            vector,
        }
    }

    /// The calling CPU's local APIC ID, from its APIC ID register.
    fn id(&self) -> u32 {
        match self.xapic {
            Some(_) => self.read(reg::ID) >> XAPIC_ID_SHIFT,
            None => self.read(reg::ID),
        }
    }

    /// Raises `vector` (fixed delivery, edge) on the CPU with local APIC ID
    /// `apic_id`, as a device's interrupt may (see [`InterruptTarget`]);
    /// false if it cannot be addressed alone: a broadcast ID (0xff in xAPIC
    /// mode, `u32::MAX` in x2APIC mode), or, in xAPIC mode, above. Only a
    /// doorbell: it is sent after the caller's earlier writes, but what it is
    /// for, the receiver reads through atomics. Takes no lock: usable in
    /// interrupt handlers. In xAPIC mode, it first waits for the last IPI to
    /// be sent, for at most 2^30 TSC cycles (about 0.3-1 s), then sends
    /// anyway (as Linux does starting CPUs): an APIC that never sends would
    /// lose one of the two. Emulated APICs (QEMU's, KVM's) send at once.
    ///
    /// # Panics
    ///
    /// If `vector` is below 32, an exception's, or one of
    /// [`SPURIOUS_VECTORS`], which need no EOI: as their handlers send none,
    /// it would stay in service on that CPU, masking the interrupts of its
    /// priority class and below for good.
    #[must_use]
    pub fn send_fixed_ipi(&self, apic_id: u32, vector: u8) -> bool {
        assert!(vector >= 32, "vectors below 32 are the CPU's exceptions");
        assert!(
            !SPURIOUS_VECTORS.contains(&vector),
            "spurious vectors' handlers end no interrupt"
        );
        // Safety: a fixed interrupt, with an interrupt's vector.
        unsafe { self.send(apic_id, u32::from(vector)) }
    }

    /// Sends `ipi` to the CPU with local APIC ID `apic_id`, as
    /// [`Self::send_fixed_ipi`] sends its interrupt; false for the calling
    /// CPU's own ID too (e.g., misidentified), which INIT would reset. One
    /// command: the caller sequences a start (INIT, ~10 ms, startup IPI,
    /// ~200 µs, startup IPI, as in Intel's MP initialization protocol), and
    /// any retries.
    ///
    /// # Safety
    ///
    /// The CPU must be one the caller starts, running nothing anything still
    /// needs (INIT resets it). For [`StartupIpi::Startup`], the page must
    /// hold the code it is to run in real mode, with its data, until the CPU
    /// is known to be done with it, so for good if that may never be known
    /// (e.g., once the caller gave up waiting for it).
    ///
    /// # Panics
    ///
    /// For a [`StartupIpi::Startup`] page in [`VGA_MEMORY`].
    #[must_use]
    pub unsafe fn send_startup_ipi(&self, apic_id: u32, ipi: StartupIpi) -> bool {
        let command = match ipi {
            StartupIpi::Init => ICR_INIT,
            StartupIpi::Startup { page } => {
                assert!(
                    !VGA_MEMORY.contains(&(u64::from(page) << 12)),
                    "reserved startup page"
                );
                ICR_STARTUP | u32::from(page)
            }
        };
        if apic_id == self.id() {
            return false;
        }
        // Safety: the caller's.
        unsafe { self.send(apic_id, command) }
    }

    /// Sends the IPI with ICR command `command` (but its level) to `apic_id`;
    /// see [`Self::send_fixed_ipi`].
    ///
    /// # Safety
    ///
    /// As for [`Self::send_startup_ipi`], unless `command` is a fixed
    /// interrupt with an interrupt's vector (32 and up).
    unsafe fn send(&self, apic_id: u32, command: u32) -> bool {
        let broadcast = if self.xapic.is_some() {
            XAPIC_BROADCAST
        } else {
            X2APIC_BROADCAST
        };
        if apic_id >= broadcast {
            return false;
        }
        let command = ICR_LEVEL_ASSERT | command;
        if let Some(registers) = self.xapic {
            // Uninterrupted, as in Linux: an interrupt handler's IPI would
            // replace the destination between the writes.
            x86_64::instructions::interrupts::without_interrupts(|| {
                let start = now();
                while registers.read_u32(reg::ICR_LOW) & ICR_SEND_PENDING != 0
                    && now() - start < ICR_SEND_TIMEOUT_CYCLES
                {
                    core::hint::spin_loop();
                }
                // After the caller's earlier writes, which the compiler may
                // otherwise move past these volatile ones (the hardware keeps
                // them in order: the MMIO is uncached).
                compiler_fence(Ordering::SeqCst);
                registers.write_u32(reg::ICR_HIGH, apic_id << XAPIC_ID_SHIFT);
                registers.write_u32(reg::ICR_LOW, command);
            });
        } else {
            // The ICR's WRMSR is not ordered after earlier stores, which the
            // receiver may rely on (Linux's `weak_wrmsr_fence`).
            // Safety: fences only.
            unsafe { core::arch::asm!("mfence", "lfence", options(nostack, preserves_flags)) };
            // Safety: the ICR, which sends `command`, as the caller may.
            unsafe {
                Self::msr(reg::ICR_LOW).write((u64::from(apic_id) << 32) | u64::from(command));
            }
        }
        true
    }

    /// Raises the timer's vector once, when [`now`] reaches `deadline` (at
    /// once if it has; without TSC-deadline mode, a distant deadline may come
    /// early); replaces a pending deadline.
    pub fn arm_timer(&self, deadline: u64) {
        match self.one_shot {
            // Safety: programs this CPU's timer; zero would disarm.
            None => unsafe { Msr::new(IA32_TSC_DEADLINE).write(deadline.max(1)) },
            Some((ticks, cycles)) => {
                let delta = u128::from(deadline.saturating_sub(now()));
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
