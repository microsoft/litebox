// TODO: file header comments

use crate::{
    mshv::{
        heki::ModMemType,
        instruction::{Opcode},
        vsm::{ModuleMemory, ModuleMemoryMetadata},
        vtl1_mem_layout::PAGE_SIZE,
    },
    serial_print, serial_println,
};
use aligned_vec::{AVec, ConstAlign, avec};
use alloc::{format, string::String, vec::Vec};
use core::{mem, ops::Range};
use elf::{
    ElfBytes, abi as ElfAbi,
    endian::AnyEndian,
    section::{SectionHeader, SectionHeaderTable},
    string_table::StringTable,
    symbol::{Symbol, SymbolTable},
};
use thiserror::Error as ThisError;
use x86_64::VirtAddr;

#[derive(ThisError, Debug)]
pub enum Error {
    //#[error("Error: {0}")]
    //Generic(String),
    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Elf type is not supported")]
    UnsupportedElf,

    //#[error("Unsuppoted: {0}")]
    //Unsupported(String),
    #[error("Elf section {0} missing")]
    MissingSection(String),

    #[error("Arithmetic error: {0}")]
    Arithmetic(String),

    //#[error("Bad symbol name")]
    //BadSymbolName,
    #[error("ElfParse: {0}")]
    Parser(#[from] elf::ParseError),
}

//#[derive(Default)]
//struct ModMemBuf {
//    section: Vec<(usize, Range<usize>)>,
//    len: usize, //I dont need to store this, alloc buf as end and keep size there
//    buf: Vec<u8>,
//}

#[derive(Copy, Clone)]
struct ModMemMask {
    mem_type: ModMemType,
    allow_mask: u64,
    forbid_mask: u64,
    init: bool,
}

#[derive(Clone)]
struct ModSection {
    sh_index: usize,
    shdr: SectionHeader, //TODO: do i need this, I can hget it by api
}

#[derive(Clone)]
struct ModMem {
    //mem_type: ModMemType,
    section_map: Vec<(ModSection, Range<usize>)>,
    len: usize, // Buf size grows as we process section headers.
    // Keep track of length seprately so we can call
    // expensive buf.resize() operation once at the
    // end of processing headers
    buf: AVec<u8, ConstAlign<PAGE_SIZE>>,
    vtl0_va: VirtAddr,
}

impl Default for ModMem {
    fn default() -> Self {
        ModMem {
            section_map: Vec::new(),
            len: 0,
            buf: avec![[PAGE_SIZE] | 0u8; 0],
            vtl0_va: VirtAddr::new(0),
        }
    }
}

impl ModMem {
    fn new(vtl0_va: VirtAddr) -> Self {
        ModMem {
            section_map: Vec::new(),
            len: 0,
            buf: avec![[PAGE_SIZE] | 0u8; 0],
            vtl0_va,
        }
    }

    /*fn get_section(&self, sh_index: usize) -> Option<(VirtAddr, &[u8])> {
        for (section, range) in &self.section_map {
            if sh_index == section.sh_index {
                return Some((self.vtl0_va + range.start as u64, &self.buf[range.clone()]));
            }
        }
        None
    }*/
}

fn get_section_buf(mem_map: &mut [ModMem], sh_index: usize) -> Option<(&mut [u8], VirtAddr)> {
    for mem in mem_map {
        for (section, range) in &mem.section_map {
            if sh_index == section.sh_index {
                return Some((
                    &mut mem.buf[range.clone()],
                    mem.vtl0_va + range.start as u64,
                ));
            }
        }
    }
    None
}

fn get_section_va(mem_map: &Vec<ModMem>, sh_index: usize) -> Option<VirtAddr> {
    for mem in mem_map {
        let va = mem.vtl0_va;
        for (section, range) in &mem.section_map {
            if sh_index == section.sh_index {
                return Some(va + range.start as u64);
            }
        }
    }
    None
}

fn section_is_alloc(mem_map: &Vec<ModMem>, sh_index: usize) -> bool {
    for mem in mem_map {
        for (section, _) in &mem.section_map {
            if sh_index == section.sh_index {
                return true;
            }
        }
    }
    false
}

struct ElfParams<'a> {
    elf: &'a ElfBytes<'a, AnyEndian>,
    shdrs: &'a SectionHeaderTable<'a, AnyEndian>,
    shdr_strtab: &'a StringTable<'a>,
    sym_hdr: &'a SymbolTable<'a, AnyEndian>,
    sym_strtab: &'a StringTable<'a>,
}

pub fn valid_elf(
    bytes: &[u8],
    module_in_memory: &ModuleMemory,
    mod_mem_metadata: &ModuleMemoryMetadata,
) -> Result<(), Error> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(bytes)?;

    let (Some(shdrs), Some(shdr_strtab)) = elf.section_headers_with_strtab()? else {
        return Err(Error::MissingSection(String::from("header table")));
    };

    let Some((sym_hdr, sym_strtab)) = elf.symbol_table()? else {
        return Err(Error::MissingSection(String::from("symbol table")));
    };

    let elf_params = ElfParams {
        elf: &elf,
        shdrs: &shdrs,
        shdr_strtab: &shdr_strtab,
        sym_hdr: &sym_hdr,
        sym_strtab: &sym_strtab,
    };

    // Check for Linux-specific elf attributes
    check_linux_elf(&elf_params)?;

    // Categorize section headers under module memory types
    // using linux-specific algo
    let mut mem_map = layout_elf(&elf_params, mod_mem_metadata)?;

    relocate_elf(&elf_params, &mut mem_map)?;

    let _ = finalize_elf(&elf_params, &mut mem_map);

    let elf_text = mem_map.get(usize::from(ModMemType::Text)).unwrap();
    let mut mem_text_buf = avec![[PAGE_SIZE] | 0u8; module_in_memory.text.len()];
    module_in_memory
        .text
        .read_bytes(module_in_memory.text.start().unwrap(), &mut mem_text_buf)
        .map_err(|_| Error::MissingSection(String::from("no text to compare")))?;

    serial_println!(
        "Elf text length: {} mem_tex_length:{}",
        elf_text.buf.len(),
        module_in_memory.text.len()
    );

    if elf_text.buf == mem_text_buf {
        serial_println!("Text matched!!!");
    } else {
        serial_println!("Text did NOT match");
    }

    Ok(())
}

fn check_linux_elf(elf_params: &ElfParams) -> Result<(), Error> {
    let elf = elf_params.elf;
    if elf.ehdr.class != elf::file::Class::ELF64
        || elf.ehdr.e_type != elf::abi::ET_REL
        || elf.ehdr.e_machine != elf::abi::EM_X86_64
    {
        return Err(Error::UnsupportedElf);
    }

    let Some(_shdr_modinfo) = elf.section_header_by_name(".modinfo")? else {
        return Err(Error::MissingSection(String::from(".modinfo")));
    };
    let Some(shdr_gnu) = elf.section_header_by_name(".gnu.linkonce.this_module")? else {
        return Err(Error::MissingSection(String::from(
            ".gnu.linkonce.this_module",
        )));
    };
    if shdr_gnu.sh_flags & u64::from(elf::abi::SHF_ALLOC) == 0 {
        return Err(Error::MissingSection(String::from(
            "gnu.linkonce.this_module",
        )));
    }
    // TODO: Maybe validate against struct module (why? hellps with jump labels and other optional struct)
    // TODO: It would pay to also check crc, or find some other way to veriy stuct module is as expected (correct options set)
    // For hints see early_mod_check, check_modstruct_version check_modinfo(versionmagic)
    // TODO: Get flag MODULE_INIT_IGNORE_MODVERSIONS to determine if __versions should be ignored */
    Ok(())
}

fn layout_elf(
    elf_params: &ElfParams,
    mem_metadata: &ModuleMemoryMetadata,
) -> Result<Vec<ModMem>, Error> {
    //let mut mem_map = vec![ModMem::default(); ModMemType::InitRoData as usize];

    let mut mem_map: Vec<ModMem> = (usize::from(ModMemType::Text)
        ..usize::from(ModMemType::InitRoData))
        .map(|m| {
            let mem_type = ModMemType::from(m);
            serial_println!("layout_elf: init: mod_mem_type: {:?} m:{}", mem_type, m);
            ModMem::new(
                mem_metadata
                    .get_mem_type_va(mem_type)
                    .unwrap_or(VirtAddr::zero())
            )
        })
        .collect();

    for (sh_index, shdr) in elf_params.shdrs.iter().enumerate() {
        if sh_index == 0 {
            continue;
        }

        let sh_name = elf_params.shdr_strtab.get(shdr.sh_name as usize)?;
        if MOD_SECTION_SKIP.contains(&sh_name) {
            serial_println!("kmod:layout_elf:{sh_name} skipped");
            continue;
        }

        let mut sh_flags = shdr.sh_flags;
        if MOD_SECTION_RO_AFTER_INIT.contains(&sh_name) {
            sh_flags |= u64::from(SHF_RO_AFTER_INIT);
        }

        let Some(mask) = MOD_MEM_MASK.iter().find(|&mask| {
            sh_flags & mask.allow_mask == mask.allow_mask
                && sh_flags & mask.forbid_mask == 0
                && sh_name.contains(".init") == mask.init
        }) else {
            continue;
        };

        let mem = mem_map.get_mut(usize::from(mask.mem_type)).unwrap(); //TODO: Should we just mek extended enums like elf, patch extended?

        let buf_start = mem.len.next_multiple_of(usize::try_from(shdr.sh_addralign).unwrap());
        let buf_end = buf_start
            .checked_add(usize::try_from(shdr.sh_size).unwrap())
            .ok_or(Error::Arithmetic(format!(
                "Buf size too large for section {}: start:{} size:{}",
                sh_index, buf_start, shdr.sh_size
            )))?;

        mem.section_map
            .push((ModSection { sh_index, shdr }, buf_start..buf_end));
        mem.len = buf_end;

        serial_println!(
            "kmod:layout_elf:{}: index:{} mem_type:{:?} va:{:?} size:{}/{} flag:{}",
            sh_name,
            sh_index,
            mask.mem_type,
            mem.vtl0_va + buf_start as u64,
            shdr.sh_size,
            buf_end - buf_start,
            shdr.sh_type
        );
    }

    for mem in &mut mem_map {
        mem.len = mem.len.next_multiple_of(PAGE_SIZE);
        mem.buf.resize(mem.len, 0);
        for (section, range) in &mem.section_map {
            let (data, _) = elf_params.elf.section_data(&section.shdr)?;
            if section.shdr.sh_type == ElfAbi::SHT_NOBITS {
                mem.buf[range.clone()].fill(0);
            } else {
                mem.buf[range.clone()].copy_from_slice(data);
            }
        }
    }

    Ok(mem_map)
}

fn get_symbol_value(elf_params: &ElfParams, mem_map: &Vec<ModMem>, sym: &Symbol) -> Option<u64> {
    match sym.st_shndx {
        shn_rsvd @ ElfAbi::SHN_LORESERVE..=ElfAbi::SHN_HIRESERVE => match shn_rsvd {
            ElfAbi::SHN_ABS => Some(sym.st_value),
            // SHN_LIVEPATCH | ElfAbi::SHN_COMMON implicit in default _
            _ => None,

        },
        ElfAbi::SHN_UNDEF => resolve_symbol(elf_params, sym),
        sh_index => {
            if let Some(vtl0_va) = get_section_va(mem_map, sh_index as usize) {
                if vtl0_va == VirtAddr::zero() {
                    None
                } else {
                    Some(vtl0_va.as_u64() + sym.st_value)
                }
            } else {
                None
            }
        }
    }
}

fn relocate_elf(elf_params: &ElfParams, mem_map: &mut Vec<ModMem>) -> Result<(), Error> {
    for (sh_index, shdr) in elf_params.shdrs.iter().enumerate() {
        if shdr.sh_type != ElfAbi::SHT_RELA {
            continue;
        }

        if !section_is_alloc(mem_map, shdr.sh_info as usize) {
            serial_println!(
                "Skipping {}",
                elf_params.shdr_strtab.get(shdr.sh_name as usize)?
            );
            continue;
        }

        serial_println!(
            "==Relocate from {}",
            elf_params.shdr_strtab.get(shdr.sh_name as usize)?
        );

        for rela in elf_params.elf.section_data_as_relas(&shdr)? {
            let Ok(sym) = elf_params.sym_hdr.get(rela.r_sym as usize) else {
                continue;
            };

            //serial_println!("Find sym:{:?}", sym, );
            let Some(st_value) = get_symbol_value(elf_params, &*mem_map, &sym) else {
                return Err(Error::NotFound(format!(
                    "Value for symbol sh_index:{} in rela sh_index {}",
                    sym.st_shndx, sh_index
                )));
            };

            let sym_value = (st_value.cast_signed() + rela.r_addend).cast_unsigned();
            /*serial_println!("Final sym_value: {:#x} rela_addend:{:#x}",sym_value, rela.r_addend);*/

            //add offset to dst_buf
            /*
            crate::serial_print!(
                "{}: Sym:{} type:{} offset:{:#x} addend:{:#x} ({}) st_value:{:#x} val_start:{:#x} ",
                index,
                rela.r_sym,
                rela.r_type,
                rela.r_offset,
                rela.r_addend,
                rela.r_addend,
                sym.st_value,
                sym_value
            );*/
            // Mutable dst_buf must be evaluated here to keep satisfy borrow checker
            let Some((dst_buf, vtl0_va)) = get_section_buf(mem_map, shdr.sh_info as usize) else {
                continue; //TODO: clean  up, see how to move this out ot the loop and keep nborrow checkwre happy
            };

            if vtl0_va == VirtAddr::zero() {
                continue;
            }

            let src: &[u8] = match rela.r_type {
                ElfAbi::R_X86_64_NONE => continue,
                ElfAbi::R_X86_64_64 => &sym_value.to_ne_bytes(),
                ElfAbi::R_X86_64_32 => &u32::try_from(sym_value).unwrap().to_ne_bytes(),
                ElfAbi::R_X86_64_32S => &i32::try_from(sym_value.cast_signed()).unwrap().to_ne_bytes(),
                ElfAbi::R_X86_64_PC32 | ElfAbi::R_X86_64_PLT32 => {
                    let va = vtl0_va.as_u64() + rela.r_offset;
                    let sym_value = sym_value.wrapping_sub(va);
                    &i32::try_from(sym_value.cast_signed()).unwrap().to_ne_bytes()
                }
                ElfAbi::R_X86_64_PC64 => {
                    let va = vtl0_va.as_u64() + rela.r_offset;
                    let sym_value = sym_value.wrapping_sub(va);
                    &(sym_value.cast_signed()).to_ne_bytes()
                }
                _ => panic!("Bad rela"),
            };
            /*
                        if src.len() == 4 {
                            crate::serial_println!("val:{:#x}", u32::from_ne_bytes(src.try_into().unwrap()));
                        } else {
                            crate::serial_println!("val:{:#x}", u64::from_ne_bytes(src.try_into().unwrap()));
                        }
            */

            let dst_offset = usize::try_from(rela.r_offset).unwrap();
            let dst = &mut dst_buf[dst_offset..dst_offset + src.len()];
            dst.copy_from_slice(src);
        }
    }
    Ok(())
}

#[repr(C)]
struct ParavirtPatchSite {
    instr: *mut u8,
    typ: u8,
    len: u8,
}

fn resolve_symbol(elf_params: &ElfParams, sym: &Symbol) -> Option<u64> {
    // Get symbol str name
    if sym.st_name == 0 {
        return None;
    }
    let Ok(sym_name) = elf_params.sym_strtab.get(sym.st_name as usize)  else {
            serial_println!("Symbol not found"); //TODO clean this up
            return None;
    };
    serial_println!("resolve_symbol: Look for {sym_name}");
    crate::platform_low().vtl0_kernel_info.find_symbol(sym_name)
}

fn finalize_elf(elf_params: &ElfParams, mem_map: &mut Vec<ModMem>) -> Result<(), Error> {
    //let mut alt = ElfAbi::SHF_NONE as usize;
    //let mut locks = ElfAbi::SHF_NONE as usize;
    let mut para = ElfAbi::SHF_NONE as usize;
    //let mut orc = ElfAbi::SHF_NONE as usize;
    //let mut orc_ip = ElfAbi::SHF_NONE as usize;
    //let mut retpolines = ElfAbi::SHF_NONE as usize;
    //let mut returns = ElfAbi::SHF_NONE as usize;
    //let mut calls = ElfAbi::SHF_NONE as usize;
    //let mut cfi = ElfAbi::SHF_NONE as usize;
    //let mut ibt_endbr = ElfAbi::SHF_NONE as usize;

    
    for (sh_index, shdr) in elf_params.shdrs.iter().enumerate() {
        let sh_name = elf_params.shdr_strtab.get(shdr.sh_name as usize)?;
        match sh_name {
            //".altinstructions" => alt = sh_index,
            //".smp_locks" => locks = sh_index,
            ".parainstructions" => para = sh_index,
            //".orc_unwind" => orc = sh_index,
            //".orc_unwind_ip" => orc_ip = sh_index,
            //".retpoline_sites" => retpolines = sh_index,
            //".return_sites" => returns = sh_index,
            //".call_sites" => calls = sh_index,
            //".cfi_sites" => cfi = sh_index,
            //".ibt_endbr_seal" => ibt_endbr = sh_index,
            _ => { serial_println!("{sh_name} not handled")}
        }
    }

        // Follow order of initialization and execution on Linux so we get the same results

        if para != ElfAbi::SHF_NONE as usize {
            apply_paravirt(para, mem_map);
        }

        // Disabled due to CONFIG_MITIGATION_ITS=n
        //its_init_mod()

        //if retpolines != ElfAbi::SHF_NONE as usize || cfi != ElfAbi::SHF_NONE as usize {
            //Disabled due to CONFIG_FINEIBT=N
            //apply_fineibt()
        //}

        //if retpolines != ElfAbi::SHF_NONE as usize {
            //apply_retpolines(sh_index, mem_map);
        //}
        
        // Disabled due to CONFIG_MITIGATION_ITS=n
        //its_fini_mod()

        //if returns != ElfAbi::SHF_NONE as usize {
           //apply_returns(sh_index, mem_map);
        //}

        //if alt != ElfAbi::SHF_NONE as usize as usize {
            //apply_alternatives(sh_index, mem_map);
        //}

            //let (a, b) = mem_map.split_at_mut(usize::from(ModMemType::Text));

            //let (data, _) = get_section_buf(mem_map, sh_index).unwrap();
            //let mut d = avec![[{mem::align_of::<ParavirtPatchSite>()}] | 0u8; data.len()];
            //d.copy_from_slice(data);
            //apply_paravirt(mem_map, &d);



    Ok(())
}

//#[repr(C, packed)]
//struct AltInstr {
//    instr_offset: i32,
//    repl_offset: i32,
//    ft_flags: u32,
//    instr_len: u8,
//    replacement_len: u8,
//}

/*
fn apply_returns(mem_map: &mut Vec<ModMem>, sh_index: usize) {
    let (data, _) = get_section_buf(mem_map, sh_index).unwrap();
    let mut bytes = avec![[{mem::align_of::<i32>()}] | 0u8; data.len()];
    bytes.copy_from_slice(data);

    let count = bytes.len() / mem::size_of::<u32>();
    let return_ptr = bytes.as_ptr().cast::<i32>();
    if !return_ptr.is_aligned() {
        return;
    }

    let vtl0_info = &crate::platform_low().vtl0_kernel_info;
    let Some((_, _, _, thunk_addr, _)) = vtl0_info.kinfo.get_arch_kinfo() else {
        return;
    };

    let Some(vtl0_va) = get_section_va(mem_map, sh_index) else {
        return;
    };

    let vtl0_return_ptr = vtl0_va.as_ptr::<i32>();

    for index in 0..count {
        unsafe {
            let ptr = return_ptr.offset(index as isize);
            let vtl0_ptr = vtl0_return_ptr.offset(index as isize);
            let vtl0_insn_ptr = (vtl0_ptr as *const u8).offset(*ptr as isize);
            let Some(insn) =
                get_mod_mem_byte_slice(mem_map, VirtAddr::from_ptr(vtl0_insn_ptr), MAX_INSN_SIZE)
            else {
                return;
            };

            serial_print!(
                "{index}: ptr:{ptr:p} vtl0_ptr:{vtl0_ptr:p} *s:{:x} insn:{insn:x?}",
                *ptr
            );

            let mut insn = Instruction::from(insn);
            insn.decode().unwrap();

            let dest =
                vtl0_insn_ptr as isize + insn.length() as isize + insn.imm().unwrap() as isize;

            if dest as u64 != thunk_addr {
                panic!();
            }

            // patch return. Also check dest is __x86_return_thunk_addr
            let mut pos: usize = 0;
            let mut bytes = [0u8;15];
            bytes[pos] = Opcode::RetNear.into();
            pos += 1;

            for i in pos..insn.length() {
                bytes[pos] = Opcode::Int3.into();
            }

            serial_println!(
                "  opcode:{} length:{} addr:{vtl0_insn_ptr:p} dest:{dest:x} thunk:{thunk_addr:x} bytes:{:x?}",
                insn.opcode().unwrap(),
                insn.length(), &bytes.as_slice()
            );

        }
    }
}
*/

/*
const RETPOLINE_THUNK_SIZE: isize = 32;

fn apply_retpolines(sh_index: usize, mem_map: &mut Vec<ModMem>) {
    let (data, _) = get_section_buf(mem_map, sh_index).unwrap();
    let mut bytes = avec![[{mem::align_of::<i32>()}] | 0u8; data.len()];
    bytes.copy_from_slice(data);

    let count = bytes.len() / mem::size_of::<u32>();
    let retpoline_ptr = bytes.as_ptr().cast::<i32>();
    if !retpoline_ptr.is_aligned() {
        return;
    }

    let vtl0_info = &crate::platform_low().vtl0_kernel_info;
    let Some((_, _, thunk_addr, _, _)) = vtl0_info.kinfo.get_arch_kinfo() else {
        return;
    };

    let Some(vtl0_va) = get_section_va(mem_map, sh_index) else {
        return;
    };
    serial_println!(
        "retpoline_ptr: {:p} bytes:{:x} {:x} {:x} {:x} vtl0_va:{:x}",
        retpoline_ptr,
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        vtl0_va
    );
    let vtl0_retpoline_ptr = vtl0_va.as_ptr::<i32>();

    for index in 0..count {
        unsafe {
            let ptr = retpoline_ptr.offset(index as isize);
            let vtl0_ptr = vtl0_retpoline_ptr.offset(index as isize);
            let vtl0_insn_ptr = (vtl0_ptr as *const u8).offset(*ptr as isize);
            let Some(insn) =
                get_mod_mem_byte_slice(mem_map, VirtAddr::from_ptr(vtl0_insn_ptr), MAX_INSN_SIZE)
            else {
                return;
            };

            serial_print!(
                "{index}: ptr:{ptr:p} vtl0_ptr:{vtl0_ptr:p} *s:{:x} insn:{insn:x?}",
                *ptr
            );
            //serial_println!("Instr: {:x?}", bytes);

            let mut insn = Instruction::from(insn);
            insn.decode().unwrap();

            let target =
                vtl0_insn_ptr as isize + insn.length() as isize + insn.imm().unwrap() as isize;
            let mut reg = target - thunk_addr as isize;
            if reg % RETPOLINE_THUNK_SIZE != 0 {
                return;
            }
            reg /= RETPOLINE_THUNK_SIZE;
            if reg < 0 || reg >= 15 {
                return;
            }
            //skip jcc32 check. todo later
            //skip lfence as well.
            let Some(opcode) = insn.opcode() else {
                return;
            };

            let modrm : u8= match Opcode::try_from(opcode).unwrap() {
                Opcode::CallRel32 => 0x10,
                _=> return
            };

            let mut pos: usize = 0;
            let mut bytes = [0u8;15];
            if reg >= 8 {
                bytes[pos] = 0x41;
                pos += 1;
            }
            bytes[pos] = 0xff;
            pos += 1;
            bytes[pos] = (modrm | 0xC0) + reg as u8;

            for i in pos..insn.length() {
                bytes[pos] = 0x90;
            }




            serial_println!(
                "  opcode:{} length:{} addr:{vtl0_insn_ptr:p} target:{target:x} thunk:{thunk_addr:x} reg:{reg:x} bytes:{:x?}",
                insn.opcode().unwrap(),
                insn.length(), &bytes.as_slice()
            );

            /*
            let target = addr
                .cast::<u8>()
                .offset(instr_len as isize + instr_imm as isize);

            serial_println!(
                "addr:{:p} instr_len:{} instr_imm:{:x} target:{:p}",
                addr,
                instr_len,
                instr_imm,
                target
            );

            */
            //let bytes = b"\x86\x64\x32\x16\xF0\xF2\x83\x00\x5A\x62\xC1\xFE\xCB\x6F\xD3";

            // I have *ptr. I need what ptr va corresponds to
            //mem_map.
        }
    }
}
    */

fn apply_paravirt(sh_index: usize, mem_map: &mut Vec<ModMem>) {

    let (data, _) = get_section_buf(mem_map, sh_index).unwrap();
    let mut bytes = avec![[{mem::align_of::<ParavirtPatchSite>()}] | 0u8; data.len()];
    bytes.copy_from_slice(data);

    if bytes.len() % mem::size_of::<ParavirtPatchSite>() != 0 {
        return;
    }
    let pv_count = bytes.len() / mem::size_of::<ParavirtPatchSite>();
    #[allow(clippy::cast_ptr_alignment)]
    let para: *const ParavirtPatchSite = bytes.as_ptr().cast::<ParavirtPatchSite>();
    if !para.is_aligned() {
        return;
    }

    let vtl0_info = &crate::platform_low().vtl0_kernel_info;
    let Some((pv_op_bug, pv_op_nop, _, _, _)) = vtl0_info.kinfo.get_arch_kinfo() else {
        return;
    };
    serial_println!("pv_op_bug:{:#x} pv_op_nop:{:#x}", pv_op_bug, pv_op_nop);
    for pv_index in 0..pv_count {
        let pv_addr;
        let pv_type;
        let pv_len;

        unsafe {
            let pv = para.add(pv_index);
            serial_print!(
                "    Apply paravirt: {:p}:{:#?} type:{} len:{}",
                pv,
                (*pv).instr,
                (*pv).typ,
                (*pv).len
            );
            pv_addr = (*pv).instr;
            pv_type = (*pv).typ;
            pv_len = (*pv).len;
        }
        let Some(insn) =
            get_mod_mem_byte_slice(mem_map, VirtAddr::from_ptr(pv_addr), pv_len as usize)
        else {
            continue;
        };

        //  use type to index kinfo - target
        let op_func = match vtl0_info.kinfo.get_arch_pv_op(pv_type as usize) {
            Some(pv_op) => pv_op,
            None => pv_op_bug,
        };

        serial_println!("op_func: {:#x}", op_func);

        if op_func == pv_op_nop {
            continue;
        }
        //patch_call(insn, op_func, pv_addr, pv_len)
        if insn.len() < 5
        /*CALL_INSN_SIZE*/
        {
            return;
        }

        //insn copy over to modify
        //what do i need inst for still still addr
        serial_print!(
            " insn:{:x} {:x} {:x} {:x} {:x} {:x}",
            insn[0],
            insn[1],
            insn[2],
            insn[3],
            insn[4],
            insn[5],
        );
        let _ = text_gen_insn(insn, Opcode::CallRel32, pv_addr as u64, op_func);
        serial_println!(
            " insn:{:x} {:x} {:x} {:x} {:x} {:x}",
            insn[0],
            insn[1],
            insn[2],
            insn[3],
            insn[4],
            insn[5],
        );

        //text_gen_insn(insn_buf, call_insn_opcode, target(index), addr, lem)
    }
}

//const MAX_INSN_SIZE: usize = 15;

pub fn text_gen_insn(buf: &mut [u8], opcode: Opcode, addr: u64, target: u64) -> Result<(), Error> {
    let opcode_len = match opcode {
        Opcode::CallRel32 => 5,
        _ => return Err(Error::NotFound("invalid opcode".into())),
    };
    if opcode_len > buf.len() {
        return Err(Error::NotFound("invalid length".into()));
    }
    // let code_buf = &mut buf[..opcode_len];

    let disp = target.cast_signed() - (addr + opcode_len as u64).cast_signed();
    let disp = i32::try_from(disp).unwrap();
    serial_println!("opcode_len:{} disp:{:x}", opcode_len, disp);
    buf[0] = opcode.into();
    let () = &buf[1..opcode_len].copy_from_slice(&disp.to_ne_bytes());
    let nop_len = buf.len() - opcode_len;
    if nop_len == 0 {
        return Ok(());
    }
    //let _ = &buf[opcode_len..].copy_from_slice(BYTES_NOP[nop_len - 1]);

    Ok(())
}

fn get_mod_mem_byte_slice(
    mem_map: &mut Vec<ModMem>,
    va: VirtAddr,
    len: usize,
) -> Option<&mut [u8]> {
    serial_println!("Searching mem map for {:#x}...", va);
    for mem in mem_map {
        serial_println!("Searching mem...");
        let end = VirtAddr::new(va.as_u64() + len as u64);
        let mem_end = VirtAddr::new(mem.vtl0_va.as_u64() + mem.buf.len() as u64);
        if va >= mem.vtl0_va && end <= mem_end {
            let offset = usize::try_from(va - mem.vtl0_va).unwrap();
            /*serial_println!(
                "Returning {} bytes from va:0x{:x} inside va:0x{:x} offset:0x{:x}",
                len,
                va.as_u64(),
                mem.vtl0_va.as_u64(),
                offset
            );*/
            return Some(&mut mem.buf[offset..offset + len]);
        }
    }
    None
}

const SHF_RO_AFTER_INIT: u32 = 0x00200000;
//const SHN_LIVEPATCH: u16 = 0xff20;

static MOD_MEM_MASK: [ModMemMask; 9] = [
    ModMemMask {
        mem_type: ModMemType::Text,
        allow_mask: (ElfAbi::SHF_EXECINSTR | ElfAbi::SHF_ALLOC) as u64,
        forbid_mask: 0,
        init: false,
    },
    ModMemMask {
        mem_type: ModMemType::RoData,
        allow_mask: ElfAbi::SHF_ALLOC as u64,
        forbid_mask: ElfAbi::SHF_WRITE as u64,
        init: false,
    },
    ModMemMask {
        mem_type: ModMemType::RoAfterInit,
        allow_mask: (SHF_RO_AFTER_INIT | ElfAbi::SHF_ALLOC) as u64,
        forbid_mask: 0,
        init: false,
    },
    ModMemMask {
        mem_type: ModMemType::Data,
        allow_mask: (ElfAbi::SHF_WRITE | ElfAbi::SHF_ALLOC) as u64,
        forbid_mask: 0,
        init: false,
    },
    ModMemMask {
        mem_type: ModMemType::Data,
        allow_mask: ElfAbi::SHF_ALLOC as u64,
        forbid_mask: 0,
        init: false,
    },
    ModMemMask {
        mem_type: ModMemType::InitText,
        allow_mask: (ElfAbi::SHF_EXECINSTR | ElfAbi::SHF_ALLOC) as u64,
        forbid_mask: 0,
        init: true,
    },
    ModMemMask {
        mem_type: ModMemType::InitRoData,
        allow_mask: ElfAbi::SHF_ALLOC as u64,
        forbid_mask: ElfAbi::SHF_WRITE as u64,
        init: true,
    },
    ModMemMask {
        mem_type: ModMemType::InitData,
        allow_mask: (ElfAbi::SHF_WRITE | ElfAbi::SHF_ALLOC) as u64,
        forbid_mask: 0,
        init: true,
    },
    ModMemMask {
        mem_type: ModMemType::InitData,
        allow_mask: ElfAbi::SHF_ALLOC as u64,
        forbid_mask: 0,
        init: true,
    },
];

static MOD_SECTION_SKIP: [&str; 3] = [".modinfo", "__versions", ".data..percpu"];

static MOD_SECTION_RO_AFTER_INIT: [&str; 2] = ["__jump_table", ".data..ro_after_init"];
