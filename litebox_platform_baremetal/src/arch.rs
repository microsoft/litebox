//! Architecture-specific functionality for x86_64

pub use x86_64::structures::paging::{PhysFrame, Page, PageTable, PageTableFlags};
pub use x86_64::{PhysAddr, VirtAddr};
use x86_64::registers::control::Cr3Flags;

/// Read CR2 register (page fault address)
pub fn read_cr2() -> usize {
    use x86_64::registers::control::Cr2;
    Cr2::read().map(|addr| addr.as_u64() as usize).unwrap_or(0)
}

/// Read CR3 register (page table root)
pub fn read_cr3() -> usize {
    use x86_64::registers::control::Cr3;
    let (frame, _flags) = Cr3::read();
    frame.start_address().as_u64() as usize
}

/// Write CR3 register (page table root)
///
/// # Safety
/// Changing the page table can cause memory safety issues
pub unsafe fn write_cr3(addr: usize) {
    use x86_64::registers::control::Cr3;
    use x86_64::structures::paging::PhysFrame;

    let frame = PhysFrame::containing_address(PhysAddr::new(addr as u64));
    unsafe { Cr3::write(frame, Cr3Flags::empty()) };
}

/// Halt the CPU until the next interrupt
pub fn hlt() {
    x86_64::instructions::hlt();
}

/// Disable interrupts
pub fn cli() {
    x86_64::instructions::interrupts::disable();
}

/// Enable interrupts
pub fn sti() {
    x86_64::instructions::interrupts::enable();
}

/// Read the Time Stamp Counter
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Flush a page from the TLB
pub fn invlpg(addr: usize) {
    use x86_64::instructions::tlb;
    tlb::flush(VirtAddr::new(addr as u64));
}
