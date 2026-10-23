// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The trampoline a startup IPI starts a CPU in: from real mode, through
//! protected mode, to long mode in a page table that maps it at its physical
//! address, then `entry(arg)` on `stack` (see [`Args`]). Copied to a page
//! below 1 MiB, it is position independent: the code uses only offsets from
//! its start, and the boot CPU patches its data ([`Data`]).
//!
//! Each start claims the trampoline in real mode, before anything it patched
//! is used; once [`Trampoline::park`]ed, a CPU that starts late halts there
//! for good instead.

use core::sync::atomic::{AtomicU32, Ordering};
use litebox_common_linux::PAGE_SIZE;
use litebox_hal::interrupt::VGA_MEMORY;
use x86_64::PhysAddr;

/// [`Data::state`]: patched for one start, and not claimed yet.
const ARMED: u32 = 1;
/// [`Data::state`]: a CPU took the patched data.
const CLAIMED: u32 = 2;
/// [`Data::state`]: a CPU that starts halts for good.
const PARKED: u32 = 0;

const CR0_PE: u32 = 1 << 0;
/// Hardwired on CPUs since the 486; set as they report it.
const CR0_ET: u32 = 1 << 4;
const CR0_PG: u32 = 1 << 31;
const CR4_PAE: u32 = 1 << 5;
const IA32_EFER: u32 = 0xc000_0080;
const EFER_LME: u32 = 1 << 8;
const EFER_NXE: u32 = 1 << 11;

/// Selectors of [`Data::gdt`].
const CODE32: u16 = 0x08;
const DATA: u16 = 0x10;
const CODE64: u16 = 0x18;

/// The trampoline's data, at its `data` label; all addresses physical but
/// `stack` and `entry`.
#[repr(C)]
struct Data {
    state: u32,
    /// The page table's, which must be below 4 GiB for 32-bit code to load it.
    cr3: u32,
    /// Limit 0: an exception before the kernel's IDT is a triple fault.
    idtr: [u16; 4],
    /// Limit, then the 32-bit base, as `lgdtl` reads them.
    gdtr: [u16; 4],
    /// Far pointers (offset, then selector) to the 32- and 64-bit code.
    far32: [u32; 2],
    far64: [u32; 2],
    stack: u64,
    entry: u64,
    arg: u64,
    /// Flat 32-bit code, data, and 64-bit code.
    gdt: [u64; 4],
}

core::arch::global_asm!(
    r#"
    .pushsection .rodata.litebox_cpu_trampoline, "a"
    .balign 16
    .globl litebox_cpu_trampoline
    .code16
litebox_cpu_trampoline:
    /* CS:IP is page:0; CS's base is the page, and so DS's. */
    cli
    cld
    mov %cs, %ax
    mov %ax, %ds
    mov ${armed}, %eax
    mov ${claimed}, %ecx
    lock cmpxchgl %ecx, (.Ltrampoline_data - litebox_cpu_trampoline + {state})
    jne .Ltrampoline_park
    xor %ebx, %ebx
    mov %cs, %bx
    shl $4, %ebx                /* the page's physical address, from here on */
    lidtl (.Ltrampoline_data - litebox_cpu_trampoline + {idtr})
    lgdtl (.Ltrampoline_data - litebox_cpu_trampoline + {gdtr})
    /* Protected mode, with caching: clears CR0.CD and NW, which power-up
       sets, and INIT keeps. */
    mov ${cr0}, %eax
    mov %eax, %cr0
    ljmpl *(.Ltrampoline_data - litebox_cpu_trampoline + {far32})
.Ltrampoline_park:
    cli
    hlt
    jmp .Ltrampoline_park

    .code32
    .globl litebox_cpu_trampoline_32
litebox_cpu_trampoline_32:
    mov ${data}, %eax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs
    mov %cr4, %eax
    or ${cr4_pae}, %eax
    mov %eax, %cr4
    mov (.Ltrampoline_data - litebox_cpu_trampoline + {cr3})(%ebx), %eax
    mov %eax, %cr3
    /* NX before paging: kernel PTEs use it. */
    mov ${efer}, %ecx
    rdmsr
    or ${efer_bits}, %eax
    wrmsr
    mov %cr0, %eax
    or ${cr0_pg}, %eax
    mov %eax, %cr0
    ljmpl *(.Ltrampoline_data - litebox_cpu_trampoline + {far64})(%ebx)

    .code64
    .globl litebox_cpu_trampoline_64
litebox_cpu_trampoline_64:
    /* The upper halves of registers are undefined after the switch. */
    mov %ebx, %ebx
    mov (.Ltrampoline_data - litebox_cpu_trampoline + {stack})(%rbx), %rsp
    mov (.Ltrampoline_data - litebox_cpu_trampoline + {arg})(%rbx), %rdi
    xor %ebp, %ebp
    call *(.Ltrampoline_data - litebox_cpu_trampoline + {entry})(%rbx)
    ud2

    .balign 8
    .globl litebox_cpu_trampoline_data
litebox_cpu_trampoline_data:
.Ltrampoline_data:
    .skip {data_size}
    .globl litebox_cpu_trampoline_end
litebox_cpu_trampoline_end:
    .popsection
    "#,
    armed = const ARMED,
    claimed = const CLAIMED,
    cr0 = const CR0_PE | CR0_ET,
    cr0_pg = const CR0_PG,
    cr4_pae = const CR4_PAE,
    efer = const IA32_EFER,
    efer_bits = const EFER_LME | EFER_NXE,
    data = const DATA,
    state = const core::mem::offset_of!(Data, state),
    cr3 = const core::mem::offset_of!(Data, cr3),
    idtr = const core::mem::offset_of!(Data, idtr),
    gdtr = const core::mem::offset_of!(Data, gdtr),
    far32 = const core::mem::offset_of!(Data, far32),
    far64 = const core::mem::offset_of!(Data, far64),
    stack = const core::mem::offset_of!(Data, stack),
    entry = const core::mem::offset_of!(Data, entry),
    arg = const core::mem::offset_of!(Data, arg),
    data_size = const size_of::<Data>(),
    options(att_syntax)
);

/// Where the trampoline is in the image, and its labels' offsets in it.
struct Labels {
    start: *const u8,
    code32: usize,
    code64: usize,
    data: usize,
    end: usize,
}

fn labels() -> Labels {
    let (start, code32, code64, data, end): (usize, usize, usize, usize, usize);
    // Safety: only takes the addresses of the labels above.
    unsafe {
        core::arch::asm!(
            "lea {start}, [rip + litebox_cpu_trampoline]",
            "lea {code32}, [rip + litebox_cpu_trampoline_32]",
            "lea {code64}, [rip + litebox_cpu_trampoline_64]",
            "lea {data}, [rip + litebox_cpu_trampoline_data]",
            "lea {end}, [rip + litebox_cpu_trampoline_end]",
            start = out(reg) start,
            code32 = out(reg) code32,
            code64 = out(reg) code64,
            data = out(reg) data,
            end = out(reg) end,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    Labels {
        start: start as *const u8,
        code32: code32 - start,
        code64: code64 - start,
        data: data - start,
        end: end - start,
    }
}

/// What a start runs: `entry(arg)` on `stack`, in the page table at `cr3`,
/// which must map the trampoline's page at its physical address.
pub(crate) struct Args {
    pub(crate) cr3: u32,
    pub(crate) stack: u64,
    pub(crate) entry: unsafe extern "C" fn(u64) -> !,
    pub(crate) arg: u64,
}

/// The trampoline, installed in its page.
pub(crate) struct Trampoline {
    /// Its physical address.
    pa: PhysAddr,
    /// Its kernel address.
    va: *mut u8,
}

impl Trampoline {
    /// Copies the trampoline, parked, into the page at `pa`, at `va` in the
    /// kernel.
    ///
    /// # Safety
    ///
    /// The page must be RAM below [`VGA_MEMORY`] (as startup IPIs' pages are)
    /// that nothing else uses, for good: a CPU may start in it at any time
    /// after a startup IPI.
    pub(crate) unsafe fn install(pa: PhysAddr, va: *mut u8) -> Self {
        let labels = labels();
        let len = labels.end;
        assert!(len <= PAGE_SIZE, "the CPU trampoline exceeds a page");
        debug_assert!(pa.is_aligned(PAGE_SIZE as u64) && pa.as_u64() < VGA_MEMORY.start);
        // Safety: the code is `len` bytes, and the page (the caller's) holds
        // them; the copy's data is all zero, parked.
        unsafe { core::ptr::copy_nonoverlapping(labels.start, va, len) };
        Self { pa, va }
    }

    /// Its page, as a startup IPI names it.
    pub(crate) fn page(&self) -> u8 {
        u8::try_from(self.pa.as_u64() >> 12).expect("the trampoline is below 1 MiB")
    }

    fn data(&self) -> *mut Data {
        // Safety: within the page (`install`); aligned to 8 (`.balign`).
        unsafe { self.va.add(labels().data).cast() }
    }

    fn state(&self) -> &AtomicU32 {
        // Safety: an aligned `u32` in the page, which only CPUs that start
        // there access otherwise, atomically.
        unsafe { AtomicU32::from_ptr(&raw mut (*self.data()).state) }
    }

    /// Patches the data for the next start: `args`.
    ///
    /// # Panics
    ///
    /// Unless parked.
    pub(crate) fn arm(&self, args: &Args) {
        assert_eq!(
            self.state().load(Ordering::SeqCst),
            PARKED,
            "the trampoline is in use"
        );
        let base = u32::try_from(self.pa.as_u64()).expect("the trampoline is below 1 MiB");
        let labels = labels();
        let at = |offset: usize| base + u32::try_from(offset).expect("small offsets");
        let gdt = at(labels.data + core::mem::offset_of!(Data, gdt));
        let data = Data {
            state: PARKED,
            cr3: args.cr3,
            idtr: [0; 4],
            #[expect(clippy::cast_possible_truncation, reason = "halves of a u32")]
            gdtr: [
                u16::try_from(size_of::<[u64; 4]>() - 1).expect("a small GDT"),
                gdt as u16,
                (gdt >> 16) as u16,
                0,
            ],
            far32: [at(labels.code32), CODE32.into()],
            far64: [at(labels.code64), CODE64.into()],
            stack: args.stack,
            entry: args.entry as usize as u64,
            arg: args.arg,
            // Accessed, so that loading them writes nothing (the page is
            // mapped read-only once paging is on).
            gdt: [
                0,
                0x00cf_9b00_0000_ffff, // 32-bit code, flat
                0x00cf_9300_0000_ffff, // data, flat
                0x00af_9b00_0000_ffff, // 64-bit code
            ],
        };
        // Safety: the data, which no CPU uses while parked.
        unsafe { self.data().write(data) };
        // Publishes the data to the CPU that claims it.
        self.state().store(ARMED, Ordering::SeqCst);
    }

    /// Whether a CPU took the data [`Self::arm`] patched.
    pub(crate) fn claimed(&self) -> bool {
        self.state().load(Ordering::SeqCst) == CLAIMED
    }

    /// Parks the trampoline for the next [`Self::arm`], unless a CPU took the
    /// data meanwhile ([`Self::claimed`]): it then runs it, so it must stay
    /// valid.
    pub(crate) fn park(&self) {
        let _ = self
            .state()
            .compare_exchange(ARMED, PARKED, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Readies the trampoline for the next [`Self::arm`] after a start that
    /// claimed it ([`Self::claimed`]) and no longer needs the data.
    pub(crate) fn reset(&self) {
        let _ = self
            .state()
            .compare_exchange(CLAIMED, PARKED, Ordering::SeqCst, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4096))]
    struct Page([u8; PAGE_SIZE]);

    unsafe extern "C" fn entry(_arg: u64) -> ! {
        unreachable!()
    }

    #[test]
    fn arm_patches_the_copy() {
        let mut page = alloc::boxed::Box::new(Page([0xcc; PAGE_SIZE]));
        let pa = PhysAddr::new(0x9e000);
        // Safety: the page is this test's.
        let trampoline = unsafe { Trampoline::install(pa, page.0.as_mut_ptr()) };
        assert_eq!(trampoline.page(), 0x9e);
        assert_eq!(page.0[0], 0xfa, "starts with `cli`");
        assert_eq!(
            trampoline.state().load(Ordering::SeqCst),
            PARKED,
            "installed parked"
        );

        trampoline.arm(&Args {
            cr3: 0x1234_5000,
            stack: 0xffff_e200_0001_0000,
            entry,
            arg: 42,
        });
        // Safety: the page's data, which no CPU uses.
        let data = unsafe { trampoline.data().read() };
        let labels = labels();
        let at = |offset: usize| 0x9e000 + u32::try_from(offset).unwrap();
        assert_eq!(data.state, ARMED);
        assert_eq!(data.cr3, 0x1234_5000);
        assert_eq!(data.idtr, [0; 4]);
        let gdt = at(labels.data + core::mem::offset_of!(Data, gdt));
        assert_eq!(
            data.gdtr,
            [31, (gdt & 0xffff) as u16, (gdt >> 16) as u16, 0]
        );
        assert_eq!(data.far32, [at(labels.code32), CODE32.into()]);
        assert_eq!(data.far64, [at(labels.code64), CODE64.into()]);
        assert_eq!(
            data.gdt,
            [
                0,
                0x00cf_9b00_0000_ffff,
                0x00cf_9300_0000_ffff,
                0x00af_9b00_0000_ffff
            ],
            "accessed"
        );
        assert_eq!(
            (data.stack, data.entry, data.arg),
            (0xffff_e200_0001_0000, entry as *const () as u64, 42)
        );

        // A CPU claims it, as the code does in real mode.
        assert!(!trampoline.claimed());
        trampoline
            .state()
            .compare_exchange(ARMED, CLAIMED, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap();
        assert!(trampoline.claimed());
        trampoline.park();
        assert!(trampoline.claimed(), "a claimed start keeps its data");
        trampoline.reset();
        assert!(!trampoline.claimed());

        // Armed, then parked before any CPU claims it.
        trampoline.arm(&Args {
            cr3: 0,
            stack: 0,
            entry,
            arg: 0,
        });
        trampoline.park();
        assert_eq!(trampoline.state().load(Ordering::SeqCst), PARKED);
    }
}
