use alloc::{collections::btree_map::BTreeMap, ffi::CString, string::ToString, vec};
use core::arch::global_asm;
use elf_loader::{
    Elf,
    arch::ElfPhdr,
    mmap::{Mmap, MmapImpl},
    object::{ElfBinary, ElfFile},
    segment::PAGE_SIZE,
};
use litebox::platform::trivial_providers::TransparentMutPtr;

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
        let prot = prot.bits();
        let flags = flags.bits();
        let addr = addr.unwrap_or(0);
        std::println!(
            "mmap addr: {addr:#x}, len: {len:#x}, prot: {prot:?}, flags: {flags:?}, offset: {offset:#x}, fd: {fd:?}"
        );
        let ptr = unsafe {
            syscalls::syscall!(
                syscalls::Sysno::mmap,
                addr,
                len,
                prot,
                if fd.is_some() {
                    flags
                } else {
                    flags | elf_loader::mmap::MapFlags::MAP_ANONYMOUS.bits()
                },
                fd.unwrap_or(-1),
                offset
            )
            .map_err(|e| {
                std::println!("mmap syscall failed: {e:?}");
                elf_loader::Error::MmapError {
                    msg: "mmap failed".to_string(),
                }
            })?
        };
        Ok(unsafe { core::ptr::NonNull::new_unchecked(ptr as *mut core::ffi::c_void) })
    }

    unsafe fn mmap_anonymous(
        addr: usize,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
        flags: elf_loader::mmap::MapFlags,
    ) -> elf_loader::Result<core::ptr::NonNull<core::ffi::c_void>> {
        let prot = prot.bits();
        let flags = flags.bits() | elf_loader::mmap::MapFlags::MAP_ANONYMOUS.bits();
        std::println!("mmap anon addr: {addr:#x}, len: {len:#x}, prot: {prot:?}, flags: {flags:?}");
        let ptr = unsafe {
            syscalls::syscall!(syscalls::Sysno::mmap, addr, len, prot, flags, usize::MAX, 0)
                .map_err(|_| elf_loader::Error::MmapError {
                    msg: "mmap anon failed".to_string(),
                })?
        };
        Ok(unsafe { core::ptr::NonNull::new_unchecked(ptr as *mut core::ffi::c_void) })
    }

    unsafe fn munmap(
        addr: core::ptr::NonNull<core::ffi::c_void>,
        len: usize,
    ) -> elf_loader::Result<()> {
        todo!()
    }

    unsafe fn mprotect(
        addr: core::ptr::NonNull<core::ffi::c_void>,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
    ) -> elf_loader::Result<()> {
        todo!()
    }
}

#[test]
fn test_load_exec() {
    use elf_loader::Loader;

    let elf = {
        let mut loader = Loader::<LiteBoxMmap>::new();
        loader
            .easy_load(ElfFile::from_path("./src/loader/hello").unwrap())
            .unwrap()
        // loader
        //     .easy_load(ElfBinary::new("hello", TEST_EXEC_FILE))
        //     .unwrap()
    };
    let interp: Option<Elf> = if let Some(interp_name) = elf.interp() {
        // /lib64/ld-linux-x86-64.so.2
        let mut loader = Loader::<MmapImpl>::new();
        loader
            .easy_load(ElfFile::from_path(interp_name).unwrap())
            .ok()
    } else {
        None
    };

    assert!(false);

    unsafe extern "C" {
        fn trampoline(entry: usize, sp: *mut usize) -> !;
    }

    #[allow(static_mut_refs)]
    let sp: *mut u8 = unsafe { TEST_EXEC_STACK.0.as_mut_ptr().add(TEST_EXEC_STACK.0.len()) };
    let argv = vec![
        CString::new("./hello").unwrap(),
        CString::new("hello").unwrap(),
    ];
    let envp = vec![CString::new("PATH=/bin").unwrap()];
    let mut aux = BTreeMap::new();
    let phdrs = elf.phdrs();
    aux.insert(AuxKey::AT_PAGESZ, PAGE_SIZE);
    aux.insert(
        AuxKey::AT_PHDR,
        if phdrs.is_empty() {
            0
        } else {
            phdrs.as_ptr() as usize
        },
    );
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
        UserStack::new(core::mem::transmute(sp), || sp as usize)
    };
    let pos = stack.init(argv, envp, aux).unwrap();
    let sp = unsafe { sp.sub(pos.abs() as usize) };

    unsafe { trampoline(entry, sp as *mut usize) };
}
