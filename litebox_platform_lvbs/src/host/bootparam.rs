// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VTL1 kernel boot parameters (compatible with Linux kernel's boot_params structure and command line)

use crate::debug_serial_println;
use litebox_common_linux::errno::Errno;
use spin::Once;

static POSSIBLE_CPUS: Once<u32> = Once::new();
static VTL1_MEMORY_INFO: Once<(u64, u64)> = Once::new();

/// Funtion to get the guest physical start address and size of VTL1 memory
pub fn get_vtl1_memory_info() -> Result<(u64, u64), Errno> {
    if let Some(pair) = VTL1_MEMORY_INFO.get().copied() {
        Ok(pair)
    } else {
        Err(Errno::EINVAL)
    }
}

/// Funtion to get the number of possible cpus from the command line (Linux kernel's num_possible_cpus())
pub fn get_num_possible_cpus() -> Result<u32, Errno> {
    if let Some(cpus) = POSSIBLE_CPUS.get() {
        Ok(*cpus)
    } else {
        Err(Errno::EINVAL)
    }
}

fn save_vtl1_memory_info(start: u64, size: u64) -> Result<(), Errno> {
    if start > 0 && size > 0 {
        VTL1_MEMORY_INFO.call_once(|| (start, size));
        return Ok(());
    }
    Err(Errno::EINVAL)
}

fn save_possible_cpus(possible_cpus: u32) -> Result<(), Errno> {
     if possible_cpus > 0 {
        POSSIBLE_CPUS.call_once(|| possible_cpus as u32);
        return Ok(());
    }
    Err(Errno::EINVAL)
}
/// # Panics
///
/// Panics if possible cpus or vtl1 memory extraction fails
pub fn parse_boot_info(possible_cpus: u32, mem_pa: u64, mem_size: u64) {
    debug_serial_println!("VTL1 Boot Info possible_cpus: {}, mem_pa: {:#x}, mem_size: {:#x}", possible_cpus, mem_pa, mem_size );
    save_possible_cpus(possible_cpus).unwrap(); // Panic if CPU extraction fails
    save_vtl1_memory_info(mem_pa, mem_size).unwrap(); // Panic if memory extraction fails
}
