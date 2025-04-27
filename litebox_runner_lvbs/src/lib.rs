#![no_std]

use linux_boot_params::{BootE820Entry, BootParams, E820Type};
use litebox_platform_lvbs::{
    arch::{gdt, interrupts},
    mshv::{
        hvcall,
        vtl1_mem_layout::{VTL1_BOOT_PARAMS_PAGE, VtlMemoyError, get_address_of_special_page},
    },
};
use spin::Once;

/// # Panics
///
/// Panics if it failed to enable Hyper-V hypercall
pub fn per_core_init() {
    gdt::init();
    interrupts::init_idt();
    if let Err(e) = hvcall::init() {
        panic!("Err: {:?}", e);
    }
}

struct BootParamsWrapper {
    page: &'static BootParams,
}

impl BootParamsWrapper {
    #[expect(dead_code)]
    fn get_e820_table(&self) -> [BootE820Entry; 128] {
        self.page.e820_table
    }

    fn ram_addr_size(&self) -> Result<(u64, u64), VtlMemoyError> {
        for entry in self.page.e820_table {
            let typ = entry.typ;
            if typ == E820Type::Ram {
                return Ok((entry.addr, entry.size));
            }
        }

        Err(VtlMemoyError::InvalidBootParams)
    }
}

fn boot_params() -> &'static BootParamsWrapper {
    static BOOT_PARAMS_ONCE: Once<BootParamsWrapper> = Once::new();
    BOOT_PARAMS_ONCE.call_once(|| BootParamsWrapper {
        page: unsafe {
            &*(get_address_of_special_page(VTL1_BOOT_PARAMS_PAGE) as *const BootParams)
        },
    })
}

pub fn get_vtl1_base_address_size() -> Result<(u64, u64), VtlMemoyError> {
    // let boot_params_wrapper = BootParamsWrapper {
    //     page: unsafe {
    //         &*(get_address_of_special_page(VTL1_BOOT_PARAMS_PAGE) as *const BootParams)
    //     },
    // };
    // boot_params_wrapper.ram_addr_size()
    boot_params().ram_addr_size()
}
