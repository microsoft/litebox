#![no_std]

use linux_boot_params::{BootE820Entry, BootParams, E820Type};
use litebox_platform_lvbs::{
    arch::{gdt, interrupts},
    mshv::{
        hvcall,
        vtl1_mem_layout::{VTL1_BOOT_PARAMS_PAGE, get_address_of_special_page},
    },
};

pub fn per_core_init() {
    gdt::init();
    interrupts::init_idt();
    hvcall::init();
}

struct BootParamsWrapper {
    page: &'static BootParams,
}

impl BootParamsWrapper {
    #[expect(dead_code)]
    fn get_e820_table(&self) -> [BootE820Entry; 128] {
        self.page.e820_table
    }

    fn ram_addr_size(&self) -> (u64, u64) {
        for entry in self.page.e820_table {
            let typ = entry.typ;
            if typ == E820Type::Ram {
                return (entry.addr, entry.size);
            }
        }

        (0, 0)
    }
}

// the BootParams page is free from data race because it is read only at VTL1 boot
// and ignored later.
pub fn get_vtl1_base_address_size() -> (u64, u64) {
    let boot_params_wrapper = BootParamsWrapper {
        page: unsafe {
            &*(get_address_of_special_page(VTL1_BOOT_PARAMS_PAGE) as *const BootParams)
        },
    };
    boot_params_wrapper.ram_addr_size()
}
