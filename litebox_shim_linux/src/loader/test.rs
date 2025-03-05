use alloc::{collections::btree_map::BTreeMap, ffi::CString, vec};
use elf_loader::{arch::ElfPhdr, mmap::{Mmap, MmapImpl}, object::{ElfBinary, ElfFile}, segment::PAGE_SIZE, Elf};
use litebox::platform::trivial_providers::TransparentMutPtr;
use core::arch::global_asm;

use crate::loader::stack::{AuxKey, UserStack};

extern crate std;

const TEST_EXEC_FILE: &[u8] = include_bytes!("./hello");
#[repr(align(4096))]
struct Stack([u8; 8192]);
static mut TEST_EXEC_STACK: Stack = Stack([0; 8192]);

global_asm!(
    "	
	.text
	.align	4
	.globl	trampoline
	.type	trampoline,@function
trampoline:
    xor rdx, rdx
	mov	rsp, rsi
	jmp	rdi
	/* Should not reach. */
	hlt"
);

struct LiteBoxMmap;

impl Mmap for LiteBoxMmap {
    unsafe fn mmap(
        addr: Option<usize>,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
        flags: elf_loader::mmap::MapFlags,
        offset: usize,
        fd: Option<i32>,
        need_copy: &mut bool,
    ) -> elf_loader::Result<core::ptr::NonNull<core::ffi::c_void>> {
        todo!()
    }

    unsafe fn mmap_anonymous(
        addr: usize,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
        flags: elf_loader::mmap::MapFlags,
    ) -> elf_loader::Result<core::ptr::NonNull<core::ffi::c_void>> {
        todo!()
    }

    unsafe fn munmap(addr: core::ptr::NonNull<core::ffi::c_void>, len: usize) -> elf_loader::Result<()> {
        todo!()
    }

    unsafe fn mprotect(addr: core::ptr::NonNull<core::ffi::c_void>, len: usize, prot: elf_loader::mmap::ProtFlags) -> elf_loader::Result<()> {
        todo!()
    }
}

#[test]
fn test_load_exec() {
    use elf_loader::Loader;

    let elf = {
        let mut loader = Loader::<MmapImpl>::new();
        loader.easy_load(ElfFile::from_path("./src/loader/hello").unwrap()).unwrap()
        // loader.easy_load(ElfBinary::new("hello", TEST_EXEC_FILE)).unwrap()
    };
    let interp: Option<Elf> = if let Some(interp_name) = elf.interp() {
        // /lib64/ld-linux-x86-64.so.2
        let mut loader = Loader::<MmapImpl>::new();
        loader.easy_load(ElfFile::from_path(interp_name).unwrap()).ok()
    } else {
        None
    };

    unsafe extern "C" {
        fn trampoline(entry: usize, sp: *mut usize) -> !;
    }

    #[allow(static_mut_refs)]
    let sp: *mut u8 = unsafe { TEST_EXEC_STACK.0.as_mut_ptr().add(TEST_EXEC_STACK.0.len()) };
    let argv = vec![CString::new("./hello").unwrap(), CString::new("hello").unwrap()];
    let envp = vec![CString::new("PATH=/bin").unwrap()];
    let mut aux = BTreeMap::new();
    let phdrs = elf.phdrs();
    aux.insert(AuxKey::AT_PAGESZ, PAGE_SIZE);
    aux.insert(AuxKey::AT_PHDR, if phdrs.is_empty() {
        0
    } else {
        phdrs.as_ptr() as usize
    });
    aux.insert(AuxKey::AT_PHENT, core::mem::size_of::<ElfPhdr>());
    aux.insert(AuxKey::AT_PHNUM, phdrs.len());
    aux.insert(AuxKey::AT_ENTRY, elf.entry());
    let entry = if let Some(ld) = interp {
        aux.insert(AuxKey::AT_BASE, ld.base());
        ld.entry()
    } else {
        elf.entry()
    };

    let stack: UserStack<TransparentMutPtr<u8>> = unsafe {
        #[allow(static_mut_refs)]
        UserStack::new(core::mem::transmute(sp), || {
            sp as usize
        })
    };
    let pos = stack.init(argv, envp, aux).unwrap();
    let sp = unsafe { sp.sub(pos.abs() as usize) };

    unsafe { trampoline(entry, sp as *mut usize) };
}