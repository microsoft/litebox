// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[path = "runner/gates.rs"]
mod gates;

use std::{
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        Self(
            tempfile::Builder::new()
                .prefix("litebox-macos-")
                .tempdir()
                .unwrap()
                .keep(),
        )
    }
    fn run(&self, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_litebox_runner_linux_on_macos_userland"))
            .args(extra)
            .arg(self.0.join("program"))
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Minimal RX ELF for register and fault regressions.
fn elf(code: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x1000];
    for instruction in code {
        bytes.extend(instruction.to_le_bytes());
    }
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    bytes[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    let size = bytes.len() as u64;
    phdr(&mut bytes[64..120], 1, 5, 0, 0, size, size, 0x10000);
    // Exclude headers and literals from the code ranges.
    let shoff = bytes.len().next_multiple_of(8);
    bytes.resize(shoff + 3 * 64, 0);
    let names = b"\0.text\0.shstrtab\0";
    let names_offset = bytes.len();
    bytes.extend_from_slice(names);
    bytes[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&3u16.to_le_bytes());
    bytes[62..64].copy_from_slice(&2u16.to_le_bytes());
    let text = &mut bytes[shoff + 64..shoff + 128];
    text[..4].copy_from_slice(&1u32.to_le_bytes()); // name
    text[4..8].copy_from_slice(&1u32.to_le_bytes()); // PROGBITS
    for (at, value) in [
        (8, 6u64),
        (16, 0x1000),
        (24, 0x1000),
        (32, (code.len() * 4) as u64),
        (48, 4),
    ] {
        text[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    let strings = &mut bytes[shoff + 128..shoff + 192];
    strings[..4].copy_from_slice(&7u32.to_le_bytes());
    strings[4..8].copy_from_slice(&3u32.to_le_bytes());
    strings[24..32].copy_from_slice(&(names_offset as u64).to_le_bytes());
    strings[32..40].copy_from_slice(&(names.len() as u64).to_le_bytes());
    bytes
}
#[allow(clippy::too_many_arguments)]
fn phdr(
    buf: &mut [u8],
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
) {
    buf[..4].copy_from_slice(&kind.to_le_bytes());
    buf[4..8].copy_from_slice(&flags.to_le_bytes());
    for (index, value) in [offset, vaddr, 0, filesz, memsz, align]
        .into_iter()
        .enumerate()
    {
        buf[8 + index * 8..16 + index * 8].copy_from_slice(&value.to_le_bytes());
    }
}
const EXIT_42: &[u32] = &[0xd2800540, 0xd2800ba8, 0xd4000001]; // x0=42; x8=exit; svc #0

#[test]
fn bad_syscall_pointer_returns_efault_without_host_crash() {
    let fixture = Fixture::new();
    let code = [
        0xd2800020, // mov x0, #1 (stdout)
        0xd2800021, // mov x1, #1 (invalid pointer)
        0xd2800022, // mov x2, #1
        0xd2800808, // mov x8, #64 (write)
        0xd4000001, // svc #0
        0xb100381f, // cmn x0, #14 (EFAULT)
        0x54000081, // b.ne failure (+16)
        0xd2800540, 0xd2800ba8, 0xd4000001, 0xd2800020, 0xd2800ba8, 0xd4000001,
    ];
    std::fs::write(fixture.0.join("program"), elf(&code)).unwrap();
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn guest_memory_fault_terminates_with_linux_status() {
    let fixture = Fixture::new();
    let code = [0xd2800000, 0xf9400000]; // mov x0, #0; ldr x0, [x0]
    std::fs::write(fixture.0.join("program"), elf(&code)).unwrap();
    let output = fixture.run(&[]);
    // Darwin SIGBUS maps to Linux SIGSEGV.
    assert_eq!(
        output.status.code(),
        Some(128 + 11),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fp_registers_survive_syscalls() {
    let fixture = Fixture::new();
    let code = [
        0xd2824689, // mov x9, #0x1234
        0x9e670120, // fmov d0, x9
        0x9e67013f, // fmov d31, x9
        0xd2801588, 0xd4000001, // getpid
        0x9e66000a, // fmov x10, d0
        0xeb0a013f, // cmp x9, x10
        0x540000e1, // b.ne failure (+28)
        0x9e6603ea, // fmov x10, d31
        0xeb0a013f, // cmp x9, x10
        0x54000081, // b.ne failure (+16)
        0xd2800540, 0xd2800ba8, 0xd4000001, 0xd2800020, 0xd2800ba8, 0xd4000001,
    ];
    std::fs::write(fixture.0.join("program"), elf(&code)).unwrap();
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_fixed_address_and_incompatible_page_layouts() {
    let fixture = Fixture::new();
    let mut binary = elf(EXIT_42);
    binary[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    std::fs::write(fixture.0.join("program"), &binary).unwrap();
    let output = fixture.run(&[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unsupported ELF type"));

    binary[16..18].copy_from_slice(&3u16.to_le_bytes());
    // 4 KiB congruent, but not 16 KiB congruent.
    binary[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
    std::fs::write(fixture.0.join("program"), &binary).unwrap();
    let output = fixture.run(&[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Bad ELF format"));

    // Disjoint LOADs sharing a native page.
    binary = elf(EXIT_42);
    binary[56..58].copy_from_slice(&2u16.to_le_bytes());
    phdr(&mut binary[120..176], 1, 6, 0x2000, 0x2000, 0, 16, 0x1000);
    std::fs::write(fixture.0.join("program"), &binary).unwrap();
    let output = fixture.run(&[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Bad ELF format"));
}

#[test]
fn auxiliary_vector_reports_native_pages() {
    let fixture = Fixture::new();
    // Check argc/argv/envp terminators, then find AT_PAGESZ and compare to 16384.
    let code = [
        0x910003e9, 0xf8408520, 0xf100041f, 0x54000201, 0xf9400520, 0xb50001c0, 0xf9400920,
        0xb5000180, 0x91006129, 0xa8c10520, 0xb4000120, 0xf100181f, 0x54ffffa1, 0xd2880002,
        0xeb02003f, 0x54000081, 0xd2800540, 0xd2800ba8, 0xd4000001, 0xd2800020, 0xd2800ba8,
        0xd4000001,
    ];
    std::fs::write(fixture.0.join("program"), elf(&code)).unwrap();
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn preserves_scratch_registers_and_accepts_nonzero_svc_immediates() {
    let fixture = Fixture::new();
    let code = [
        0xd2824690, // mov x16, #0x1234
        0xd2824691, // mov x17, #0x1234
        0xd2801588, 0xd41fffe1, // getpid via svc #0xffff
        0xd2824689, // mov x9, #0x1234
        0xeb09021f, // cmp x16, x9
        0x540000c1, // b.ne failure (+24)
        0xeb09023f, // cmp x17, x9
        0x54000081, // b.ne failure (+16)
        0xd2800540, 0xd2800ba8, 0xd4000001, 0xd2800020, 0xd2800ba8, 0xd4000001,
    ];
    std::fs::write(fixture.0.join("program"), elf(&code)).unwrap();
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_wrong_architecture_and_wx() {
    let fixture = Fixture::new();
    let mut binary = elf(EXIT_42);
    binary[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    std::fs::write(fixture.0.join("program"), binary).unwrap();
    assert!(!fixture.run(&[]).status.success());

    let mut binary = elf(EXIT_42);
    binary[68..72].copy_from_slice(&7u32.to_le_bytes()); // PF_R | PF_W | PF_X
    std::fs::write(fixture.0.join("program"), binary).unwrap();
    let output = fixture.run(&[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Bad ELF format"));
}
