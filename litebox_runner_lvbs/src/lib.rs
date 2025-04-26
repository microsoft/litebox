#![no_std]

use lazy_static::lazy_static;
use linux_boot_params::{BootE820Entry, BootParams, E820Type};
use litebox_platform_lvbs::{
    arch::{gdt, interrupts},
    mshv::{
        hvcall,
        vtl1_mem_layout::{VTL1_BOOT_PARAMS_PAGE, get_address_of_special_page},
    },
};
use spin::Mutex;

pub fn per_core_init() {
    gdt::init();
    interrupts::init_idt();
    hvcall::init();
}

struct BootParamsWrapper {
    page: &'static mut BootParams,
}

impl BootParamsWrapper {
    #[expect(dead_code)]
    fn get_e820_table(&self) -> [BootE820Entry; 128] {
        self.page.e820_table
    }

    fn ram_addr_size(&mut self) -> (u64, u64) {
        for entry in self.page.e820_table {
            let typ = entry.typ;
            if typ == E820Type::Ram {
                return (entry.addr, entry.size);
            }
        }

        (0, 0)
    }
}

lazy_static! {
    static ref BOOT_PARAMS_PAGE: Mutex<BootParamsWrapper> = Mutex::new(BootParamsWrapper {
        page: unsafe {
            &mut *(get_address_of_special_page(VTL1_BOOT_PARAMS_PAGE) as *mut BootParams)
        }
    });
}

pub fn ram_addr_size() -> (u64, u64) {
    BOOT_PARAMS_PAGE.lock().ram_addr_size()
}
