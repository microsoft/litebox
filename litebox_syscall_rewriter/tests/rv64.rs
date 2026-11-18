// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_syscall_rewriter::{Error, hook_syscalls_in_elf};
use litebox_trampoline::{TRAMPOLINE_HEADER_SIZE, decode_trampoline_header, riscv64::GateTls};
use object::{Object as _, ObjectSection as _};
use std::{fs, mem::offset_of, path::Path, process::Command};

fn run(dir: &Path, tool: &str, args: &[&str]) {
    let status = Command::new(tool)
        .current_dir(dir)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "{tool} {args:?}: {status}");
}

#[test]
fn big_endian_riscv_rejects_only_rv64_executables() {
    let mut elf = [0u8; 64];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x02\x01");
    elf[18..20].copy_from_slice(&object::elf::EM_RISCV.to_be_bytes());
    elf[16..18].copy_from_slice(&object::elf::ET_EXEC.to_be_bytes());
    assert!(matches!(
        hook_syscalls_in_elf(&elf, None),
        Err(Error::UnsupportedExecutable(reason)) if reason.contains("big-endian RISC-V")
    ));
    elf[16..18].copy_from_slice(&object::elf::ET_REL.to_be_bytes());
    assert_eq!(hook_syscalls_in_elf(&elf, None).unwrap(), elf);
    elf[16..18].copy_from_slice(&object::elf::ET_EXEC.to_be_bytes());
    elf[4] = object::elf::ELFCLASS32;
    assert_eq!(hook_syscalls_in_elf(&elf, None).unwrap(), elf);
}

#[test]
#[ignore = "requires GNU RISC-V binutils and qemu-riscv64; run in RV64 CI"]
fn executes_rewritten_gp_tls_and_ecall() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let asm = "riscv64-linux-gnu-as";
    let link = "riscv64-linux-gnu-ld";
    fs::write(dir.join("guest.s"), include_bytes!("rv64/guest.S")).unwrap();
    run(dir, asm, &["-march=rv64gc", "guest.s", "-o", "guest.o"]);
    // Keep the text near the end of the page, within C.J reach of the gates.
    run(
        dir,
        link,
        &["-Ttext=0x20000e00", "guest.o", "-o", "guest.elf"],
    );
    let original = fs::read(dir.join("guest.elf")).unwrap();
    let hooked = hook_syscalls_in_elf(&original, None).unwrap();
    assert_eq!(hook_syscalls_in_elf(&hooked, None).unwrap(), hooked);
    let footer_start = hooked.len() - TRAMPOLINE_HEADER_SIZE;
    let footer = decode_trampoline_header(&hooked[footer_start..])
        .unwrap()
        .unwrap();
    let offset = usize::try_from(footer.file_offset.get()).unwrap();
    let size = usize::try_from(footer.trampoline_size.get()).unwrap();
    assert_ne!(size, 0);
    let end = offset.checked_add(size).unwrap();
    assert_eq!(end, footer_start);
    fs::write(dir.join("gates.bin"), &hooked[offset..end]).unwrap();
    let file = object::File::parse(&*hooked).unwrap();
    let text = file.section_by_name(".text").unwrap();
    fs::write(dir.join("text.bin"), text.data().unwrap()).unwrap();
    fs::write(dir.join("host.s"), include_bytes!("rv64/host.S")).unwrap();
    run(
        dir,
        asm,
        &[
            "-march=rv64gc",
            "--defsym",
            &format!("ENTRY={}", offset_of!(GateTls, syscall_entry)),
            "--defsym",
            &format!("GUEST_GP={}", offset_of!(GateTls, guest_gp)),
            "--defsym",
            &format!("BLOCK_SIZE={}", size_of::<GateTls>()),
            "host.s",
            "-o",
            "host.o",
        ],
    );
    run(
        dir,
        link,
        &[
            &format!("--section-start=.guest={:#x}", text.address()),
            &format!("--section-start=.gates={:#x}", footer.vaddr.get()),
            "host.o",
            "-o",
            "host",
        ],
    );
    run(
        dir,
        &std::env::var("QEMU_RISCV64").unwrap_or_else(|_| "qemu-riscv64".into()),
        &["./host"],
    );
}
