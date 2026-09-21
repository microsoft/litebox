// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use litebox_common_macos::{TaskParams, VmProtection, loader::MachoParsedFile};
#[cfg(feature = "test-broker")]
use std::io::Write as _;
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn assemble(dir: &Path, source: &str) -> PathBuf {
    let asm = dir.join("guest.s");
    let obj = dir.join("guest.o");
    let binary = dir.join("guest");
    std::fs::write(&asm, source).unwrap();
    for mut command in [
        {
            let mut c = Command::new("xcrun");
            c.args(["as", "-arch", "arm64"])
                .arg(&asm)
                .arg("-o")
                .arg(&obj);
            c
        },
        {
            let mut c = Command::new("xcrun");
            c.args(["ld", "-arch", "arm64", "-static", "-e", "_start"])
                .arg(&obj)
                .arg("-o")
                .arg(&binary);
            c
        },
    ] {
        let output = command
            .output()
            .expect("Xcode command line tools are required");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    binary
}

#[cfg(feature = "test-broker")]
fn assemble_dylib(dir: &Path, source: &str) -> PathBuf {
    let asm = dir.join("mapped.s");
    let obj = dir.join("mapped.o");
    let dylib = dir.join("mapped.dylib");
    std::fs::write(&asm, source).unwrap();
    for mut command in [
        {
            let mut c = Command::new("xcrun");
            c.args(["as", "-arch", "arm64"])
                .arg(&asm)
                .arg("-o")
                .arg(&obj);
            c
        },
        {
            let mut c = Command::new("xcrun");
            c.args(["clang", "-arch", "arm64", "-dynamiclib"])
                .arg(&obj)
                .arg("-o")
                .arg(&dylib);
            c
        },
    ] {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    dylib
}

#[cfg(feature = "test-broker")]
fn symbol_address(image: &Path, symbol: &str) -> usize {
    let output = Command::new("xcrun")
        .args(["nm", "-n"])
        .arg(image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            let _kind = fields.next()?;
            (fields.next()? == symbol).then(|| usize::from_str_radix(address, 16).unwrap())
        })
        .unwrap()
}

/// Invoke the rewriter CLI and return the path of its .hooked artifact.
fn rewrite(input: &Path) -> PathBuf {
    let output_path = input.with_extension("hooked");
    let output = Command::new(env!("CARGO"))
        .args([
            "run",
            "--locked",
            "-p",
            "litebox_syscall_rewriter",
            "--",
            "--target-host",
            "macos",
            "-o",
        ])
        .arg(&output_path)
        .arg(input)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to run rewriter CLI");
    assert!(
        output.status.success(),
        "rewriter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output_path
}

fn assert_svc_gates(original: &[u8], rewritten: &[u8]) -> usize {
    const INSTRUCTION_BYTES: usize = size_of::<u32>();
    // AArch64 SVC encoding, ignoring the immediate operand.
    const SVC_MASK: u32 = 0xffe0_001f;
    const SVC_OPCODE: u32 = 0xd400_0001;
    use litebox_syscall_rewriter::{
        TargetHost,
        aarch64::{GateMetadata, decode_branch_target},
        macho::{CodeMetadata, Rewriter},
    };
    let mut plan = MachoParsedFile::parse(rewritten).unwrap();
    let trampoline = plan.parse_trampoline(rewritten).unwrap().unwrap();
    let metadata = CodeMetadata::parse(original).unwrap();
    let rewriter = Rewriter::new(TargetHost::MacOs).unwrap();
    let mut count = 0;
    for segment in &plan.segments {
        if !segment.protection.contains(VmProtection::EXECUTE) {
            continue;
        }
        for range in metadata
            .ranges_for_mapping(segment.file_range.start as u64, segment.file_range.len())
            .unwrap()
        {
            for offset in range.step_by(INSTRUCTION_BYTES) {
                let file_offset = segment.file_range.start + offset;
                let word = u32::from_le_bytes(
                    original[file_offset..file_offset + INSTRUCTION_BYTES]
                        .try_into()
                        .unwrap(),
                );
                if word & SVC_MASK != SVC_OPCODE {
                    continue;
                }
                let patched = u32::from_le_bytes(
                    rewritten[file_offset..file_offset + INSTRUCTION_BYTES]
                        .try_into()
                        .unwrap(),
                );
                let site = segment.virtual_range.start + offset;
                let target = usize::try_from(
                    decode_branch_target(patched, site as u64)
                        .expect("SVC must become a branch, not BRK"),
                )
                .unwrap();
                assert!(trampoline.virtual_range.contains(&target));
                let gate_offset =
                    trampoline.file_range.start + target - trampoline.virtual_range.start;
                let gate_len = GateMetadata::Svc.slot_size_for_host(TargetHost::MacOs);
                let gate = rewriter
                    .classify_gate_slot(
                        &rewritten[gate_offset..gate_offset + gate_len],
                        target as u64,
                        target as u64,
                    )
                    .unwrap();
                assert_eq!(gate.metadata(), GateMetadata::Svc);
                assert_eq!(gate.original_site(), site as u64);
                count += 1;
            }
        }
    }
    count
}

/// With `test-broker`, the fixture requires guest filesystem loading and stdio;
/// without it, the fixture requires stdio to be absent.
#[test]
fn static_macho_loader_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let source = format!(
        ".set TEST_STDIO, {}\n{}",
        usize::from(cfg!(feature = "test-broker")),
        include_str!("fixtures/static_macho.S"),
    );
    let binary = assemble(dir.path(), &source);
    let hooked = rewrite(&binary);
    let original = std::fs::read(&binary).unwrap();
    let rewritten = std::fs::read(&hooked).unwrap();
    let expected_sites = if cfg!(feature = "test-broker") {
        23
    } else {
        15
    };
    assert_eq!(assert_svc_gates(&original, &rewritten), expected_sites);
    let parsed = MachoParsedFile::parse(&original).unwrap();
    // Parsing is independent of the byte slice's alignment.
    let mut unaligned = vec![0];
    unaligned.extend_from_slice(&original);
    assert_eq!(
        MachoParsedFile::parse(&unaligned[1..]).unwrap().entry,
        parsed.entry
    );

    // Rewriter footer offsets are relative to the selected slice, not the container.
    let fat_raw = dir.path().join("fat-raw");
    let fat_aot = dir.path().join("fat-aot");
    for (input, output, expected) in [
        (&binary, &fat_raw, &original),
        (&hooked, &fat_aot, &rewritten),
    ] {
        let result = Command::new("xcrun")
            .args(["lipo", "-create", "-arch", "arm64"])
            .arg(input)
            .arg("-output")
            .arg(output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "lipo: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let fat = std::fs::read(output).unwrap();
        assert!(
            fat.len() > expected.len(),
            "lipo must produce a universal container"
        );
        assert_eq!(
            litebox_common_macos::loader::arm64_slice(&fat).unwrap(),
            expected
        );
    }
    for executable in [&hooked, &binary, &fat_raw, &fat_aot] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
            .arg("--env")
            .arg("KEY=VALUE")
            .arg(executable)
            .args(["one", "two"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        #[cfg(feature = "test-broker")]
        child.stdin.take().unwrap().write_all(b"hello\n").unwrap();
        // No input is needed in the default configuration.
        drop(child.stdin.take());
        let output = child.wait_with_output().unwrap();
        #[cfg(feature = "test-broker")]
        {
            println!("guest stdout: {}", String::from_utf8_lossy(&output.stdout));
            eprintln!("guest stderr: {}", String::from_utf8_lossy(&output.stderr));
        }
        assert_eq!(
            output.status.code(),
            Some(42),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: &[u8] = if cfg!(feature = "test-broker") {
            b"hello\n"
        } else {
            b""
        };
        assert_eq!(output.stdout, expected);
        assert_eq!(output.stderr, expected);
    }
}

#[cfg(feature = "test-broker")]
#[test]
fn runner_executes_mmap_mprotect_rewritten_macho_code() {
    let dir = tempfile::tempdir().unwrap();
    let dylib = assemble_dylib(
        dir.path(),
        ".section __TEXT,__text,regular,pure_instructions\n\
         .global _mapped\n\
         _mapped:\n\
         mov x16, #20\n\
         svc #0x80\n\
         ret\n",
    );
    let mapped = symbol_address(&dylib, "_mapped");
    let bootstrap = assemble(
        dir.path(),
        &format!(
            ".global _start\n\
             _start:\n\
             adr x0, 4f\n\
             mov x1, #0\n\
             mov x2, #0\n\
             mov x16, #5\n\
             svc #0x80\n\
             b.cs 2f\n\
             mov x19, x0\n\
             adr x0, 4f\n\
             mov x1, #0x01000000\n\
             mov x2, #0\n\
             mov x16, #398\n\
             svc #0x80\n\
             b.cs 2f\n\
             mov x20, x0\n\
             mov x0, x19\n\
             mov x16, #6\n\
             svc #0x80\n\
             b.cs 2f\n\
             mov x0, #0\n\
             mov x1, #1\n\
             lsl x1, x1, #14\n\
             mov x2, #1\n\
             mov x3, #2\n\
             mov x4, x20\n\
             mov x5, #0\n\
             mov x16, #197\n\
             svc #0x80\n\
             b.cs 2f\n\
             mov x19, x0\n\
             mov x0, x20\n\
             mov x16, #399\n\
             svc #0x80\n\
             b.cs 2f\n\
             mov x0, x19\n\
             mov x1, #1\n\
             mov x2, #5\n\
             mov x16, #74\n\
             svc #0x80\n\
             b.cs 2f\n\
             ldr x9, 1f\n\
             add x9, x19, x9\n\
             blr x9\n\
             cmp x0, #1\n\
             mov x0, #43\n\
             mov x10, #42\n\
             csel x0, x10, x0, eq\n\
             b 3f\n\
             .p2align 3\n\
             1: .quad {mapped:#x}\n\
             2: mov x0, #44\n\
             3: mov x16, #1\n\
             svc #0x80\n\
             4: .asciz \"/mmap-image\"\n\
             .p2align 2\n"
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg("--test-mmap-image")
        .arg(&dylib)
        .arg(&bootstrap)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(42),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dynamic_loader_enters_host_dyld_and_exposes_main_header() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("hello.c");
    let binary = dir.path().join("hello");
    std::fs::write(&source, "int main(void) { return 0; }\n").unwrap();
    let output = Command::new("xcrun")
        .args(["clang", "-arch", "arm64", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("Xcode command line tools are required to compile the dynamic fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let executable = std::fs::read(&binary).expect("reading the dynamic fixture");
    let dyld = std::fs::read("/usr/lib/dyld")
        .expect("the current boot's standalone /usr/lib/dyld is required");
    let main_image =
        MachoParsedFile::parse(litebox_common_macos::loader::arm64_slice(&executable).unwrap())
            .unwrap();
    let dyld_image =
        MachoParsedFile::parse(litebox_common_macos::loader::arm64_slice(&dyld).unwrap()).unwrap();
    assert!(dyld_image.is_dyld);
    litebox_platform_macos_userland::set_guest_abi(
        litebox_platform_macos_userland::GuestAbi::Darwin,
    );
    let shim = litebox_shim_macos::MacosShimBuilder::new(
        litebox_platform_macos_userland::MacosUserland::new(),
    )
    .build();
    let program = shim
        .load_program_with_dyld(
            TaskParams::default(),
            "/hello",
            &executable,
            &dyld,
            vec![],
            vec![],
        )
        .unwrap();
    let dyld_header = program.initial_ctx.pc - (dyld_image.entry - dyld_image.virtual_range.start);
    let main_header =
        litebox_common_macos::user_pointers::UserPtr::<usize>::from_usize(program.initial_ctx.sp)
            .read_at_offset::<litebox_platform_macos_userland::MacosUserland>(0)
            .unwrap();
    let read_u32 = |address| {
        litebox_common_macos::user_pointers::UserPtr::<u32>::from_usize(address)
            .read_at_offset::<litebox_platform_macos_userland::MacosUserland>(0)
            .unwrap()
    };
    assert_eq!(read_u32(main_header), object::macho::MH_MAGIC_64);
    assert_eq!(read_u32(dyld_header), object::macho::MH_MAGIC_64);
    assert_eq!(read_u32(dyld_header + 12), object::macho::MH_DYLINKER);
    let relocated_main_entry = main_header + (main_image.entry - main_image.virtual_range.start);
    assert_ne!(program.initial_ctx.pc, relocated_main_entry);
}

/// Verifies dyld/libSystem startup, private guest errno across a shim
/// transition, main-thread identity, and clean process exit.
#[cfg(feature = "test-broker")]
#[test]
fn dynamic_libsystem_tls_and_main_thread_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("libsystem_state.c");
    let binary = dir.path().join("libsystem_state");
    std::fs::write(
        &source,
        "#include <errno.h>\n#include <pthread.h>\n#include <unistd.h>\n\
         int main(void) { errno = E2BIG; pid_t pid = getpid(); \
         return errno == E2BIG && pid != 1 && pthread_main_np() ? 0 : 42; }\n",
    )
    .unwrap();
    let compiled = Command::new("xcrun")
        .args(["clang", "-arch", "arm64", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("Xcode command line tools are required to compile the libSystem fixture");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg(&binary)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn syscall_free_image_delivers_guest_faults() {
    let dir = tempfile::tempdir().unwrap();
    let binary = assemble(
        dir.path(),
        ".global _start\n_start:\n mov x0, #42\n mov x16, #1\n brk #0\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg(rewrite(&binary))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(139));
}

#[test]
fn invalid_images_are_rejected_and_dynamic_images_require_dyld() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid");
    std::fs::write(&path, b"not a Mach-O").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("loading Mach-O"));

    // The runner itself is a dynamically linked AArch64 Mach-O. Parsing is
    // supported, but loading without a standalone dyld input is not.
    let data = std::fs::read(env!("CARGO_BIN_EXE_litebox_runner_macos_userland")).unwrap();
    let parsed = MachoParsedFile::parse(&data).unwrap();
    assert!(parsed.uses_dyld);
    let result = litebox_shim_macos::MacosShimBuilder::new(
        litebox_platform_macos_userland::MacosUserland::new(),
    )
    .build()
    .load_program_from_bytes(TaskParams::default(), "/dynamic", &data, vec![], vec![]);
    assert!(matches!(
        result,
        Err(litebox_common_macos::loader::MachoLoaderError::Unsupported(
            "dynamic executable requires standalone dyld"
        ))
    ));
}

#[test]
fn incompatible_aot_gate_is_rejected_before_execution() {
    const INCOMPATIBLE_GATE_PROLOGUE: u32 = 0xd100_83ff; // sub sp, sp, #32 (Linux frame)
    let dir = tempfile::tempdir().unwrap();
    let binary = assemble(
        dir.path(),
        ".global _start\n_start:\n mov x0, #42\n mov x16, #1\n svc #0x80\n",
    );
    let hooked = rewrite(&binary);
    let mut data = std::fs::read(&hooked).unwrap();
    let trampoline = MachoParsedFile::parse(&data)
        .unwrap()
        .parse_trampoline(&data)
        .unwrap()
        .unwrap();
    // Mach-O SVC gates require the Darwin frame layout. Incompatible payloads
    // are rejected during finalization.
    let first_gate =
        trampoline.file_range.start + litebox_syscall_rewriter::aarch64::GATE_ALIGNMENT;
    data[first_gate..first_gate + size_of::<u32>()]
        .copy_from_slice(&INCOMPATIBLE_GATE_PROLOGUE.to_le_bytes());
    std::fs::write(&hooked, data).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg(hooked)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("incompatible Mach-O trampoline"));
}

#[test]
fn loader_teardown_and_argument_limit() {
    use litebox::platform::page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions as Perm};
    use litebox::platform::{PageManagementProvider as _, RawConstPointer as _};
    use litebox_common_macos::PAGE_SIZE;
    use litebox_platform_macos_userland::{GuestAbi, MacosUserland, set_guest_abi};
    use litebox_shim_macos::MacosShimBuilder;
    let dir = tempfile::tempdir().unwrap();
    let binary = assemble(
        dir.path(),
        ".global _start\n_start:\n mov x0, #0\n mov x16, #1\n svc #0x80\n",
    );
    let data = std::fs::read(rewrite(&binary)).unwrap();
    set_guest_abi(GuestAbi::Darwin);
    let platform = MacosUserland::new();
    let program = MacosShimBuilder::new(platform)
        .build()
        .load_program_from_bytes(TaskParams::default(), "/guest", &data, vec![], vec![])
        .unwrap();
    let mut plan = MachoParsedFile::parse(&data).unwrap();
    let trampoline = plan.parse_trampoline(&data).unwrap().unwrap();
    let base = program.initial_ctx.pc - (plan.entry - plan.virtual_range.start);
    let code_page = program.initial_ctx.pc & !(PAGE_SIZE - 1);
    let trampoline_page = base + (trampoline.virtual_range.start - plan.virtual_range.start);
    let stack_page = program.initial_ctx.sp & !(PAGE_SIZE - 1);
    drop(program);
    // Probe each kind of loader-owned mapping after teardown.
    for page in [code_page, trampoline_page, stack_page] {
        let ptr = platform
            .allocate_pages(
                page..page + PAGE_SIZE,
                Perm::READ,
                false,
                true,
                FixedAddressBehavior::NoReplace,
            )
            .unwrap();
        assert_eq!(ptr.as_usize(), page);
        // SAFETY: this test owns the idle probe mapping.
        unsafe {
            platform.deallocate_pages(page..page + PAGE_SIZE).unwrap();
        }
    }

    let huge_arg = std::ffi::CString::new(vec![b'a'; 9 * 1024 * 1024]).unwrap();
    let result = MacosShimBuilder::new(platform)
        .build()
        .load_program_from_bytes(
            TaskParams::default(),
            "/guest",
            &data,
            vec![huge_arg],
            vec![],
        );
    assert!(matches!(
        result,
        Err(litebox_common_macos::loader::MachoLoaderError::ArgumentsTooLarge)
    ));
    // Failed initialization leaves the platform able to load and run another guest.
    let program = MacosShimBuilder::new(platform)
        .build()
        .load_program_from_bytes(TaskParams::default(), "/guest", &data, vec![], vec![])
        .unwrap();
    let litebox_shim_macos::LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
    } = program;
    unsafe {
        litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx);
    }
    assert_eq!(process.exit_status(), Some(0));
}
