// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Experimental QEMU runner policy. Intentionally UP, no scheduler, no device
//! interrupts, no services yet. Boot checks run in ring 0, followed by finite
//! ring-3 payloads in `user_smoke` using the shared execution machinery.

mod user_smoke;

use alloc::{boxed::Box, vec::Vec};
use core::{
    alloc::Layout,
    fmt::{self, Write},
    sync::atomic::AtomicU32,
};
use litebox::mm::allocator::SafeZoneAllocator;
use litebox_common_linux::errno::Errno;
use litebox_platform_lvbs::{
    HostInterface, KERNEL_OFFSET, LinuxKernel,
    arch::{self, ioport::ComPort},
    mm::{MemoryProvider, tlb::TlbInvalidation},
    per_cpu_variables::{PerCpuVariables, PerCpuVariablesAsm},
    serial_println,
};
use litebox_runner_optee_on_kvm::memory_map::{self, Error, MAPPED_LIMIT};
use spin::{Mutex, Once};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{Page, PhysFrame, Size4KiB},
};

pub struct QemuHost;
pub struct QemuMemory;
pub struct SingleCpuTlb;
type Platform = LinuxKernel<QemuHost>;

#[global_allocator]
static HEAP: SafeZoneAllocator<'static, 30, QemuHost> = SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for QemuHost {
    fn alloc(_layout: &Layout) -> Option<(usize, usize)> {
        None
    }
    unsafe fn free(_addr: usize) {
        unreachable!("QEMU heap has no dynamic rescue regions");
    }
}

impl MemoryProvider for QemuMemory {
    fn print(args: fmt::Arguments<'_>) {
        console(args);
    }

    type Tlb = SingleCpuTlb;
    const GVA_OFFSET: VirtAddr = VirtAddr::new(litebox_platform_lvbs::GVA_OFFSET);
    const PRIVATE_PTE_MASK: u64 = 0;
    fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
        HEAP.allocate_pages(order)
    }
    unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
        unsafe {
            HEAP.free_pages(ptr, order);
        }
    }
    unsafe fn mem_fill_pages(start: usize, size: usize) {
        unsafe {
            HEAP.fill_pages(start, size);
        }
    }
}

// SAFETY: boot rejects a multi-vCPU configuration, never starts APs, and
// disables PCID/global mappings. Thus local completion covers every possible
// user of these mappings. A scheduler/SMP implementation must replace this.
unsafe impl TlbInvalidation for SingleCpuTlb {
    fn invalidate(start: Page<Size4KiB>, page_count: usize) {
        unsafe {
            arch::mm::tlb::invalidate_local(start, page_count);
        }
    }
}

impl HostInterface for QemuHost {
    type Memory = QemuMemory;
    fn alloc(_layout: &Layout) -> Option<(usize, usize)> {
        None
    }
    unsafe fn free(_addr: usize) {
        unreachable!("no host allocations");
    }
    fn exit() -> ! {
        exit(true)
    }
    fn terminate(_reason_set: u64, _reason_code: u64) -> ! {
        exit(false)
    }
    fn log(msg: &str) {
        console(format_args!("{msg}"));
    }
    fn send_ip_packet(_packet: &[u8]) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }
    fn receive_ip_packet(_packet: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }
    fn wake_many(_mutex: &AtomicU32, _n: usize) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }
    fn block_or_maybe_timeout(
        _mutex: &AtomicU32,
        _val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn switch(_result: u64) -> ! {
        panic!("plain guest has no VTL peer");
    }
}

fn console(args: fmt::Arguments<'_>) {
    static SERIAL: Once<Mutex<ComPort>> = Once::new();
    let serial = SERIAL.call_once(|| {
        let mut port = ComPort::new(0x3f8);
        port.init();
        Mutex::new(port)
    });
    let _ = serial.lock().write_fmt(args);
}

/// QEMU isa-debug-exit reports `(value << 1) | 1`: 33=pass, 35=failure.
/// If the device is missing, halt; never fall through to unrelated memory.
pub fn exit(success: bool) -> ! {
    let value = if success { 0x10u32 } else { 0x11u32 };
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xf4u16, in("eax") value, options(nostack, nomem));
    }
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nostack, nomem));
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    console(format_args!("QEMU-BOOT: FAIL {info}\n"));
    exit(false)
}

pub extern "C" fn early_entry() -> ! {
    unsafe {
        crate::boot::relocate();
    }
    boot_main()
}

#[inline(never)]
fn boot_main() -> ! {
    serial_println!(console; "QEMU-BOOT: long-mode relocated");
    configure_cpu();
    let info_pa = crate::boot::start_info_pa();
    let memory = memory_map::parse(info_pa, |pa, out| {
        let end = pa.checked_add(out.len() as u64).ok_or(Error::Overflow)?;
        if end > MAPPED_LIMIT {
            return Err(Error::BadPointer);
        }
        // SAFETY: PVH supplies these read-only boot structures in the low 1 GiB,
        // mapped by boot.S. Parse bounds every read and validates before seeding.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (KERNEL_OFFSET + pa) as *const u8,
                out.as_mut_ptr(),
                out.len(),
            );
        }
        Ok(())
    })
    .expect("unsupported PVH boot memory");
    assert!(
        memory
            .heap
            .iter()
            .map(|range| range.end - range.start)
            .sum::<u64>()
            >= 32 * 1024 * 1024,
        "at least 32 MiB allocatable guest RAM required"
    );
    serial_println!(console;
        "QEMU-BOOT: ram {:#x}..{:#x}",
        memory.ram.start,
        memory.ram.end
    );
    for range in &memory.heap {
        serial_println!(console; "QEMU-BOOT: heap {:#x}..{:#x}", range.start, range.end);
        // SAFETY: parser returned disjoint usable RAM excluding boot/image and
        // firmware storage. The whole range is mapped and not yet allocated.
        unsafe {
            QemuMemory::mem_fill_pages(
                usize::try_from(KERNEL_OFFSET + range.start).unwrap(),
                usize::try_from(range.end - range.start).unwrap(),
            );
        }
    }
    // Only scalar bounds must cross the stack switch; keep them in registers.
    let start = memory.ram.start;
    let end = memory.ram.end;
    let mut storage = Box::<PerCpuVariables>::new_uninit();
    let cpu = unsafe {
        PerCpuVariables::initialize_at(storage.as_mut_ptr());
        storage.assume_init()
    };
    let cpu = Box::leak(cpu);
    cpu.init_stacks();
    unsafe {
        litebox_common_linux::wrgsbase(core::ptr::from_mut(cpu) as usize);
    }
    // Like LVBS: switch to a permanent aligned kernel stack, then CALL so the
    // Rust entry sees RSP % 16 == 8. Nothing on the former stack is used again.
    unsafe {
        core::arch::asm!(
            "mov rsp, gs:[{stack}]",
            "xor rbp, rbp",
            "call {entry}",
            stack = const PerCpuVariablesAsm::kernel_stack_ptr_offset(),
            entry = sym kernel_main,
            in("rdi") start, in("rsi") end,
            options(noreturn),
        );
    }
}

fn qemu_cpu_count() -> u16 {
    fn select(key: u16) {
        unsafe {
            core::arch::asm!("out dx, ax", in("dx") 0x510u16, in("ax") key, options(nostack, nomem));
        }
    }
    fn read() -> u8 {
        let byte: u8;
        unsafe {
            core::arch::asm!("in al, dx", in("dx") 0x511u16, out("al") byte, options(nostack, nomem));
        }
        byte
    }
    select(0); // FW_CFG_SIGNATURE
    assert_eq!(
        [read(), read(), read(), read()],
        *b"QEMU",
        "QEMU fw_cfg required"
    );
    select(5); // FW_CFG_NB_CPUS, little endian
    u16::from_le_bytes([read(), read()])
}

fn configure_cpu() {
    use core::arch::x86_64::__cpuid_count as cpuid;
    let features = cpuid(1, 0);
    // QEMU's fw_cfg reports the configured CPU count across sockets. CPUID's
    // package-local logical count may be zero when HTT is absent, and cannot
    // enforce a VM-wide UP restriction by itself.
    assert_eq!(qemu_cpu_count(), 1, "debug runner requires -smp 1");
    assert_ne!(features.ecx & (1 << 26), 0, "XSAVE required");
    let structured = cpuid(7, 0);
    assert_ne!(structured.ebx & 1, 0, "FSGSBASE required");
    assert_ne!(structured.ebx & (1 << 7), 0, "SMEP required");
    assert_ne!(structured.ebx & (1 << 20), 0, "SMAP required");
    assert_ne!(cpuid(0xd, 1).eax & 1, 0, "XSAVEOPT required");
    arch::enable_fsgsbase();
    arch::enable_extended_states();
    // A standalone guest owns XCR0; there is no VTL0 state to inherit.
    unsafe {
        x86_64::registers::xcontrol::XCr0::write(
            x86_64::registers::xcontrol::XCr0Flags::X87
                | x86_64::registers::xcontrol::XCr0Flags::SSE,
        );
        // No device IRQ handlers yet. Mask legacy PIC; boot leaves IF clear.
        // Shared user-return code enables IF for ring 3, with no timer armed.
        core::arch::asm!("out dx, al", in("dx") 0x21u16, in("al") 0xffu8, options(nostack, nomem));
        core::arch::asm!("out dx, al", in("dx") 0xa1u16, in("al") 0xffu8, options(nostack, nomem));
    }
}

extern "C" fn kernel_main(ram_start: u64, ram_end: u64) -> ! {
    litebox_platform_lvbs::per_cpu_variables::with_per_cpu_variables(
        PerCpuVariables::allocate_xsave_areas,
    );
    arch::gdt::init();
    let mut idt = Box::new(arch::interrupts::exception_idt());
    // This debugging runner permits ring-3 INT3. The shared table defaults to
    // DPL0; retain its handler and change only this runner's software gate DPL.
    let breakpoint = idt.breakpoint.handler_addr();
    unsafe {
        idt.breakpoint
            .set_handler_addr(breakpoint)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
    }
    Box::leak(idt).load();
    Platform::enable_syscall_support();
    let text = crate::boot::text_physical_range();
    let memory = PhysFrame::range(
        PhysFrame::from_start_address(PhysAddr::new(ram_start)).unwrap(),
        PhysFrame::from_start_address(PhysAddr::new(ram_end)).unwrap(),
    );
    // SAFETY: all live code/heap/stacks lie in this validated RAM region, the
    // early mapping covers it, and relocation and allocator seeding are complete.
    let platform = unsafe {
        Platform::from_memory(
            QemuHost,
            memory,
            &[PhysAddr::new(text.start)..PhysAddr::new(text.end)],
        )
    };
    arch::enable_smep_smap();
    serial_println!(console; "QEMU-BOOT: shared kernel initialized");
    smoke(platform);
    user_smoke::run(platform);
    serial_println!(console; "QEMU-BOOT: PASS");
    exit(true)
}

fn smoke(platform: &Platform) {
    use litebox::{
        mm::exception_table::memcpy_fallible,
        platform::{
            PageManagementProvider, RawConstPointer, RawMutPointer,
            page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions},
        },
    };
    const VA: usize = 0x10000;
    let mut data = Vec::new();
    data.extend(0..128u64);
    assert_eq!(data.iter().sum::<u64>(), 8128);
    assert!(data.as_ptr() as u64 >= KERNEL_OFFSET);
    assert!(platform.page_table_manager().is_base_page_table_active());
    assert!(
        x86_64::registers::control::Cr0::read()
            .contains(x86_64::registers::control::Cr0Flags::WRITE_PROTECT)
    );
    assert!(!x86_64::registers::control::Cr4::read().intersects(
        x86_64::registers::control::Cr4Flags::PCID
            | x86_64::registers::control::Cr4Flags::PAGE_GLOBAL,
    ));
    let stack: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) stack, options(nostack, nomem, preserves_flags));
    }
    let cpu_base = litebox_platform_lvbs::per_cpu_variables::with_per_cpu_variables(|cpu| {
        core::ptr::from_ref(cpu) as u64
    });
    assert!((cpu_base..cpu_base + size_of::<PerCpuVariables>() as u64).contains(&stack));
    let task = platform.create_task_page_table().unwrap();
    unsafe {
        platform.switch_page_table(task).unwrap();
    }
    assert_eq!(platform.current_page_table_id(), task);
    let handle = platform.page_table_manager().current_page_table();
    let range = VA..VA + 4096;
    let ptr = <Platform as PageManagementProvider<4096>>::allocate_pages(
        platform,
        range.clone(),
        MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
        false,
        true,
        FixedAddressBehavior::NoReplace,
    )
    .unwrap();
    // Direct supervisor access must fault with SMAP enabled. Shared pointer
    // access below explicitly brackets the same copies with STAC/CLAC.
    let mut observed = 0u8;
    assert!(unsafe { memcpy_fallible(&raw mut observed, VA as *const u8, 1) }.is_err());
    assert!(ptr.write_at_offset(0, 0x5au8).is_some());
    assert_eq!(ptr.read_at_offset(0), Some(0x5a));
    unsafe {
        <Platform as PageManagementProvider<4096>>::update_permissions(
            platform,
            range.clone(),
            MemoryRegionPermissions::READ,
        )
        .unwrap();
    }
    assert!(ptr.write_at_offset(0, 0xff).is_none());
    assert_eq!(ptr.read_at_offset(0), Some(0x5a));
    unsafe {
        <Platform as PageManagementProvider<4096>>::deallocate_pages(platform, range).unwrap();
    }
    assert!(ptr.read_at_offset(0).is_none());
    unsafe {
        platform
            .switch_page_table(litebox_platform_lvbs::BASE_PAGE_TABLE_ID)
            .unwrap();
    }
    // A retained handle blocks teardown after the CPU switched back to base.
    assert_eq!(
        unsafe { platform.delete_task_page_table(task) },
        Err(Errno::EBUSY)
    );
    drop(handle);
    unsafe {
        platform.delete_task_page_table(task).unwrap();
    }
    let mut byte = 0u8;
    // The final kernel table dropped the identity map. This must recover #PF
    // through the shared exception table, not return successfully or triple fault.
    assert!(unsafe { memcpy_fallible(&raw mut byte, 0x1000 as *const u8, 1) }.is_err());
    serial_println!(console; "QEMU-BOOT: allocation paging protection fault-recovery OK");
}
