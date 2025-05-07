//! VTL1 kernel boot parameters (compatible with Linux kernel's boot_params structure and command line)

use crate::mshv::vtl1_mem_layout::{
    VTL1_BOOT_PARAMS_PAGE, VTL1_CMDLINE_PAGE, VtlMemoryError, get_address_of_special_page,
};
use core::ffi::{CStr, c_char};
use num_enum::TryFromPrimitive;

#[cfg(debug_assertions)]
use crate::serial_println;

// This module defines a simplified Linux boot params structure
// (based on arch/x86/include/uapi/asm/bootparam.h and
// arch/x86/include/uapi/asm/e820.h). We need this because VTL0 kernel
// passes memory information to VTL1 kernel via boot params.

const E820_MAX_ENTRIES: usize = 128;

const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;
const E820_ACPI: u32 = 3;
const E820_NVS: u32 = 4;
const E820_UNUSABLE: u32 = 5;
const E820_PMEM: u32 = 7;
const E820_PRAM: u32 = 12;
const E820_RESERVED_KERN: u32 = 128;

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
struct BootE820Entry {
    pub addr: u64,
    pub size: u64,
    pub typ: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct BootParams {
    _unused0: [u8; 720], // Elements in this area are not used.
    pub e820_table: [BootE820Entry; E820_MAX_ENTRIES],
    _unused1: [u8; 816], // Elements in this area are not used.
}

impl BootParams {
    pub fn new() -> Self {
        Self {
            _unused0: [0; 720],
            e820_table: [BootE820Entry::default(); E820_MAX_ENTRIES],
            _unused1: [0; 816],
        }
    }

    #[cfg(debug_assertions)]
    pub fn dump(&self) {
        for entry in self.e820_table {
            let typ_val = entry.typ;

            if E820Type::try_from(typ_val).unwrap_or(E820Type::Unknown) == E820Type::Unknown {
                break;
            } else {
                let addr_val = entry.addr;
                let size_val = entry.size;
                serial_println!(
                    "addr: {:#x}, size: {:#x}, type: {:?}",
                    addr_val,
                    size_val,
                    typ_val
                );
            }
        }
    }

    pub fn memory_info(&self) -> Result<(u64, u64), VtlMemoryError> {
        for entry in self.e820_table {
            let typ_val = entry.typ;

            match E820Type::try_from(typ_val).unwrap_or(E820Type::Unknown) {
                E820Type::Ram => {
                    let addr_val = entry.addr;
                    let size_val = entry.size;
                    return Ok((addr_val, size_val));
                }
                E820Type::Unknown => {
                    return Err(VtlMemoryError::InvalidBootParams);
                }
                _ => {}
            }
        }

        Err(VtlMemoryError::InvalidBootParams)
    }
}

impl Default for BootParams {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(debug_assertions)]
pub fn dump_boot_params() {
    let boot_params = get_address_of_special_page(VTL1_BOOT_PARAMS_PAGE) as *const BootParams;
    unsafe {
        (*boot_params).dump();
    }
}

#[cfg(debug_assertions)]
pub fn dump_cmdline() {
    let cmdline = get_address_of_special_page(VTL1_CMDLINE_PAGE) as *const c_char;
    if cmdline.is_null() {
        return;
    }

    if let Some(cmdline_str) = unsafe { CStr::from_ptr(cmdline).to_str().ok() } {
        serial_println!("{}", cmdline_str);
    }
}

/// Funtion to get the guest physical start address and size of VTL1 memory
pub fn get_vtl1_memory_info() -> Result<(u64, u64), VtlMemoryError> {
    let boot_params = get_address_of_special_page(VTL1_BOOT_PARAMS_PAGE) as *const BootParams;
    unsafe { (*boot_params).memory_info() }
}

/// Funtion to get the number of possible cpus from the command line (Linux kerne's num_possible_cpus())
pub fn get_num_possible_cpus() -> Result<u32, VtlMemoryError> {
    let cmdline = get_address_of_special_page(VTL1_CMDLINE_PAGE) as *const c_char;
    if cmdline.is_null() {
        return Err(VtlMemoryError::InvalidCmdLine);
    }

    if let Some(cmdline_str) = unsafe { CStr::from_ptr(cmdline).to_str().ok() } {
        for token in cmdline_str.split_whitespace() {
            if token.starts_with("possible_cpus=") {
                if let Some((_, v)) = token.split_once('=') {
                    let num = v.parse::<u32>().unwrap_or(0);
                    if num > 0 {
                        return Ok(num);
                    }
                }
            }
        }
    }

    Err(VtlMemoryError::InvalidCmdLine)
}

/// E820 entry type
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
enum E820Type {
    Ram = E820_RAM,
    Reserved = E820_RESERVED,
    Acpi = E820_ACPI,
    Nvs = E820_NVS,
    Unusable = E820_UNUSABLE,
    Pmem = E820_PMEM,
    Pram = E820_PRAM,
    ReservedKern = E820_RESERVED_KERN,
    Unknown = 0xffff_ffff,
}
