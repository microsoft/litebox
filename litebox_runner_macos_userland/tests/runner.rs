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
            for offset in range.step_by(4) {
                let file_offset = segment.file_range.start + offset;
                let word =
                    u32::from_le_bytes(original[file_offset..file_offset + 4].try_into().unwrap());
                if word & 0xffe0_001f != 0xd400_0001 {
                    continue;
                }
                let patched =
                    u32::from_le_bytes(rewritten[file_offset..file_offset + 4].try_into().unwrap());
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

/// Both feature configurations exercise the same AOT pipeline and gate ABI.
/// test-broker adds I/O checks; without it the fixture checks stdio is absent.
#[test]
fn static_macho_rewriter_e2e() {
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg("--env")
        .arg("KEY=VALUE")
        .arg(&hooked)
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

    // The runner requires an AOT-processed image.
    let output = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg(binary)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not rewritten"));
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
fn invalid_and_dynamic_images_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid");
    std::fs::write(&path, b"not a Mach-O").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("loading static Mach-O"));

    // The runner itself is a dynamically linked AArch64 Mach-O.
    let data = std::fs::read(env!("CARGO_BIN_EXE_litebox_runner_macos_userland")).unwrap();
    assert!(matches!(
        MachoParsedFile::parse(&data),
        Err(litebox_common_macos::loader::MachoLoaderError::Unsupported(
            _
        ))
    ));
}

#[test]
fn incompatible_aot_gate_is_rejected_before_execution() {
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
    let first_gate = trampoline.file_range.start + 16;
    data[first_gate..first_gate + 4].copy_from_slice(&0xd100_83ffu32.to_le_bytes());
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
        .load_program(TaskParams::default(), &data, vec![], vec![])
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
    let result = MacosShimBuilder::new(platform).build().load_program(
        TaskParams::default(),
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
        .load_program(TaskParams::default(), &data, vec![], vec![])
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
