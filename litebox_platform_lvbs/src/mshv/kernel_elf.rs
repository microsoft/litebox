use crate::debug_serial_println;
use alloc::string::{String, ToString};
use goblin::elf::Elf;
use hashbrown::HashMap;
use x86_64::VirtAddr;

/// This function parses the `.modinfo` section of the kernel module ELF file and prints its contents.
pub fn parse_modinfo(elf_buf: &[u8]) {
    // TODO: support selective parsing of the `.modinfo` section
    let Ok(elf) = Elf::parse(elf_buf) else {
        return;
    };

    if let Some(section) = elf
        .section_headers
        .iter()
        .find(|s| s.sh_size > 0 && elf.shdr_strtab.get_at(s.sh_name) == Some(".modinfo"))
    {
        let start = usize::try_from(section.sh_offset).unwrap();
        let end = start + usize::try_from(section.sh_size).unwrap();
        let modinfo_data = &elf_buf[start..end];

        for entry in modinfo_data.split(|&b| b == 0) {
            if let Ok(s) = str::from_utf8(entry) {
                if let Some((k, v)) = s.split_once('=') {
                    if k == "name" {
                        debug_serial_println!("Modinfo: {} = {}", k, v);
                    }
                }
            }
        }
    }
}

/// This function extracts the global symbol exports from a kernel module ELF file.
pub fn get_symbol_exports(
    elf_buf: &[u8],
    load_base_addr: VirtAddr,
) -> Result<HashMap<String, VirtAddr>, KernelElfError> {
    // TODO: support selective parsing of symbols.
    let Ok(elf) = Elf::parse(elf_buf) else {
        return Err(KernelElfError::ElfParseFailed);
    };

    let mut symbol_map: HashMap<String, VirtAddr> = HashMap::new();
    for sym in &elf.syms {
        if sym.st_bind() == goblin::elf::sym::STB_GLOBAL && sym.st_value != 0 {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                match name {
                    "cleanup_module" | "init_module" => {}
                    n if n.is_empty() || n.starts_with("__") => {}
                    _ => {
                        symbol_map.insert(name.to_string(), load_base_addr + sym.st_value);
                    }
                }
            }
        }
    }

    Ok(symbol_map)
}

/// Error for Kernel ELF validation and relocation failures.
#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub enum KernelElfError {
    SectionReadFailed,
    SectionRelocationFailed,
    ElfParseFailed,
    UnsupportedSection,
    SectionNotFound,
}
