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
    use litebox_syscall_rewriter::{macho::CodeMetadata, macho::Rewriter};
    use litebox_trampoline::{TargetHost, aarch64::GateMetadata, aarch64::decode_branch_target};
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
             cmp x0, #2\n\
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
    // supported, but loading without a dyld input is not.
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
            "dynamic executable requires dyld"
        ))
    ));
}

/// Without the test broker there is no guest random source, so dynamic
/// executables fail up front instead of after preparing the cache.
#[cfg(not(feature = "test-broker"))]
#[test]
fn dynamic_executables_require_the_test_broker() {
    // The runner itself is a dynamically linked AArch64 Mach-O.
    let output = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .env_remove("LITEBOX_LOG")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dynamic executables require a guest random source"),
        "{stderr}"
    );
    assert!(!stderr.contains("guest shared cache"), "{stderr}");
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
    let first_gate = trampoline.file_range.start + litebox_trampoline::aarch64::GATE_ALIGNMENT;
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
    use litebox::platform::PageManagementProvider as _;
    use litebox::platform::page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions as Perm};
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
        let reservation = unsafe {
            platform
                .reserve_and_commit_pages(
                    core::iter::empty,
                    page..page + PAGE_SIZE,
                    Perm::READ,
                    false,
                    true,
                    FixedAddressBehavior::NoReplace,
                )
                .unwrap()
        };
        let reservation: std::ops::Range<usize> = reservation.into();
        assert_eq!(reservation.start, page);
        // SAFETY: this test owns the idle probe mapping.
        unsafe {
            platform.release_pages(page..page + PAGE_SIZE).unwrap();
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

#[cfg(feature = "test-broker")]
fn compile_c(dir: &Path, source: &str) -> PathBuf {
    compile(dir, "clang", "main.c", source, &[])
}

/// Compile `source` (saved as `file`) with the host toolchain's `compiler`
/// and extra `arguments`.
#[cfg(feature = "test-broker")]
fn compile(dir: &Path, compiler: &str, file: &str, source: &str, arguments: &[&str]) -> PathBuf {
    let c = dir.join(file);
    let binary = dir.join("main");
    std::fs::write(&c, source).unwrap();
    let output = Command::new("xcrun")
        .args([compiler, "-arch", "arm64"])
        .arg(&c)
        .args(arguments)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("Xcode command line tools are required");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(feature = "test-broker")]
const HELLO_WORLD: &str =
    "#include <stdio.h>\nint main(void) { printf(\"Hello, world!\\n\"); return 0; }\n";

/// Run `binary` under the runner and return its exit code, stdout and stderr.
#[cfg(feature = "test-broker")]
fn run_guest(binary: &Path) -> (Option<i32>, Vec<u8>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg(binary)
        .env_remove("LITEBOX_LOG")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        output.status.code(),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// `_start` -> `write(1, ...)` -> `exit(0)`, raw and AOT-rewritten.
#[cfg(feature = "test-broker")]
#[test]
fn static_hello_world() {
    let dir = tempfile::tempdir().unwrap();
    let binary = assemble(
        dir.path(),
        ".global _start\n\
         _start:\n\
         mov x0, #1\n\
         adr x1, 1f\n\
         mov x2, #14\n\
         mov x16, #4\n\
         svc #0x80\n\
         mov x0, #0\n\
         mov x16, #1\n\
         svc #0x80\n\
         1: .ascii \"Hello, world!\\n\"\n\
         .p2align 2\n",
    );
    for executable in [rewrite(&binary), binary] {
        let (code, stdout, stderr) = run_guest(&executable);
        assert_eq!(
            (code, stdout.as_slice(), stderr.as_str()),
            (Some(0), &b"Hello, world!\n"[..], ""),
            "{}",
            executable.display()
        );
    }
}

/// A dynamic `printf` hello world runs on its own libSystem.
#[cfg(feature = "test-broker")]
#[test]
fn dynamic_hello_world() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_c(dir.path(), HELLO_WORLD);
    let (code, stdout, stderr) = run_guest(&binary);
    assert_eq!(
        (code, stdout.as_slice(), stderr.as_str()),
        (Some(0), &b"Hello, world!\n"[..], "")
    );
}

/// The guest's own `exit` reaches the runner's exit status.
#[cfg(feature = "test-broker")]
#[test]
fn dynamic_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_c(
        dir.path(),
        "#include <stdlib.h>\nint main(void) { exit(42); }\n",
    );
    let (code, stdout, stderr) = run_guest(&binary);
    assert_eq!(
        (code, stdout.as_slice(), stderr.as_str()),
        (Some(42), &b""[..], "")
    );
}

/// A strong `operator new` overrides libc++'s weak definition, so dyld
/// patches the cache's uses of it: it makes the cache's DATA_CONST
/// mappings writable as a whole and writes to them. Allocations made inside
/// libc++.dylib (stream buffer growth) then reach the override, which records
/// its callers.
#[cfg(feature = "test-broker")]
#[test]
fn dynamic_cpp_strong_operator_new_override() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile(
        dir.path(),
        "clang++",
        "main.cpp",
        "#include <cstdio>\n#include <cstdlib>\n#include <cstring>\n#include <dlfcn.h>\n\
         #include <new>\n#include <sstream>\n#include <string>\n\
         int new_calls;\n\
         void *callers[64];\n\
         void *operator new(std::size_t size) {\n\
           if (new_calls < 64) callers[new_calls] = __builtin_return_address(0);\n\
           ++new_calls;\n\
           void *p = std::malloc(size ? size : 1);\n\
           if (!p) std::abort();\n\
           return p;\n\
         }\n\
         void operator delete(void *p) noexcept { std::free(p); }\n\
         int main() {\n\
           int *x = new int(41);\n\
           ++*x;\n\
           int direct_calls = new_calls;\n\
           {\n\
             std::ostringstream stream;\n\
             stream << std::string(1000, 'x');\n\
             if (stream.str().size() != 1000) return 1;\n\
           }\n\
           int libcxx_calls = 0;\n\
           for (int i = 0; i < new_calls && i < 64; ++i) {\n\
             Dl_info info;\n\
             if (dladdr(callers[i], &info) && info.dli_fname &&\n\
                 std::strcmp(info.dli_fname, \"/usr/lib/libc++.1.dylib\") == 0)\n\
               ++libcxx_calls;\n\
           }\n\
           std::printf(\"operator new: %d %d %d\\n\", *x, direct_calls, libcxx_calls > 0);\n\
           delete x;\n\
           return 0;\n\
         }\n",
        &[],
    );
    let (code, stdout, stderr) = run_guest(&binary);
    assert_eq!(
        (code, stdout.as_slice(), stderr.as_str()),
        (Some(0), &b"operator new: 42 1 1\n"[..], "")
    );
}

/// The source of a guest printing zlib's version.
#[cfg(feature = "test-broker")]
const ZLIB_VERSION: &str = "#include <stdio.h>\n#include <zlib.h>\n\
     int main(void) { printf(\"zlib %s\\n\", zlibVersion()); return 0; }\n";

/// Change the path of `binary`'s dependency `from` to `to` and re-sign it.
#[cfg(feature = "test-broker")]
fn change_dependency(binary: &Path, from: &str, to: &[u8]) {
    use std::os::unix::ffi::OsStrExt as _;

    let output = Command::new("xcrun")
        .args(["install_name_tool", "-change", from])
        .arg(std::ffi::OsStr::from_bytes(to))
        .arg(binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("codesign")
        .args(["-s", "-", "-f"])
        .arg(binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "test-broker")]
fn assert_prints_zlib_version(binary: &Path) {
    let (code, stdout, stderr) = run_guest(binary);
    let stdout = String::from_utf8(stdout).unwrap();
    assert_eq!((code, stderr.as_str()), (Some(0), ""), "{stdout}");
    let version = stdout
        .strip_prefix("zlib ")
        .and_then(|rest| rest.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("{stdout:?}"));
    assert!(
        !version.is_empty() && version.split('.').all(|part| part.parse::<u32>().is_ok()),
        "{stdout:?}"
    );
}

/// A cache library the executable links beyond libSystem runs: its code is
/// rewritten and executable, and no gate island is placed inside it.
#[cfg(feature = "test-broker")]
#[test]
fn dynamic_guest_calls_a_linked_cache_library() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile(dir.path(), "clang", "main.c", ZLIB_VERSION, &["-lz"]);
    assert_prints_zlib_version(&binary);
}

/// A cache library linked through `@rpath` and the executable's `LC_RPATH`
/// is resolved like dyld does and runs.
#[cfg(feature = "test-broker")]
#[test]
fn dynamic_guest_calls_a_cache_library_linked_through_rpath() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile(
        dir.path(),
        "clang",
        "main.c",
        ZLIB_VERSION,
        &["-lz", "-Wl,-rpath,/usr/lib"],
    );
    change_dependency(&binary, "/usr/lib/libz.1.dylib", b"@rpath/libz.1.dylib");
    assert_prints_zlib_version(&binary);
}

/// dyld accepts a weakly linked dylib whose name is not UTF-8 (and does not
/// exist); such an executable still runs under its dyld.
#[cfg(feature = "test-broker")]
#[test]
fn dynamic_guest_with_a_non_utf8_weak_dependency_runs() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile(
        dir.path(),
        "clang",
        "main.c",
        HELLO_WORLD,
        &["-Wl,-weak-lz"],
    );
    change_dependency(
        &binary,
        "/usr/lib/libz.1.dylib",
        b"/usr/lib/lib\xff.1.dylib",
    );
    let (code, stdout, stderr) = run_guest(&binary);
    assert_eq!(
        (code, stdout.as_slice(), stderr.as_str()),
        (Some(0), &b"Hello, world!\n"[..], "")
    );
}

/// Host state the guest must never touch.
#[cfg(feature = "test-broker")]
mod host_state {
    unsafe extern "C" {
        fn _dyld_get_shared_cache_range(length: *mut usize) -> *const u8;
        fn dladdr(address: *const core::ffi::c_void, info: *mut DlInfo) -> i32;
        fn getpid() -> i32;
    }

    #[repr(C)]
    struct DlInfo {
        fname: *const core::ffi::c_char,
        fbase: *const u8,
        sname: *const core::ffi::c_char,
        saddr: *const core::ffi::c_void,
    }

    pub fn shared_cache_base() -> usize {
        let mut length = 0;
        // SAFETY: `length` is writable; the call only reports the live range.
        unsafe { _dyld_get_shared_cache_range(&raw mut length) as usize }
    }

    /// The host's `libsystem_kernel` `__TEXT` bytes (it implements `getpid`).
    pub fn libsystem_kernel_text() -> Vec<u8> {
        let mut info = DlInfo {
            fname: core::ptr::null(),
            fbase: core::ptr::null(),
            sname: core::ptr::null(),
            saddr: core::ptr::null(),
        };
        // SAFETY: `info` is writable; getpid is a live host symbol.
        assert_ne!(unsafe { dladdr(getpid as *const _, &raw mut info) }, 0);
        // SAFETY: dladdr reported a loaded image's Mach header.
        let header = unsafe { core::slice::from_raw_parts(info.fbase, 32) };
        let commands = u32::from_le_bytes(header[16..20].try_into().unwrap());
        let mut offset = 32;
        for _ in 0..commands {
            // SAFETY: load commands follow the mapped header.
            let command = unsafe { core::slice::from_raw_parts(info.fbase.add(offset), 72) };
            let size = u32::from_le_bytes(command[4..8].try_into().unwrap()) as usize;
            if u32::from_le_bytes(command[..4].try_into().unwrap()) == 0x19
                && command[8..14] == *b"__TEXT"
            {
                let length = u64::from_le_bytes(command[32..40].try_into().unwrap());
                // SAFETY: the image's __TEXT is mapped from its header onward.
                return unsafe {
                    core::slice::from_raw_parts(info.fbase, usize::try_from(length).unwrap())
                }
                .to_vec();
            }
            offset += size;
        }
        panic!("libsystem_kernel has no __TEXT");
    }

    pub fn thread_pointer() -> usize {
        let value: usize;
        // SAFETY: reading this thread's TPIDRRO_EL0 has no side effects.
        unsafe { core::arch::asm!("mrs {}, tpidrro_el0", out(reg) value) };
        value
    }

    /// This thread's TSD slot 0 (`_PTHREAD_TSD_SLOT_PTHREAD_SELF`).
    pub fn pthread_self_slot() -> usize {
        // TPIDRRO_EL0 holds the TSD base; its low bits may carry a CPU number.
        let tsd = (thread_pointer() & !7) as *const usize;
        // SAFETY: the TSD of the running thread is live and readable.
        unsafe { tsd.read() }
    }
}

/// The guest's own dyld reports its private cache instance, above the host's
/// shared region and at another base.
#[cfg(feature = "test-broker")]
#[test]
fn dynamic_guest_cache_base_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_c(
        dir.path(),
        "#include <stdio.h>\n#include <stddef.h>\n\
         extern const void *_dyld_get_shared_cache_range(size_t *length);\n\
         int main(void) {\n\
           size_t length = 0;\n\
           const void *base = _dyld_get_shared_cache_range(&length);\n\
           printf(\"%p %zx\\n\", base, length);\n\
           return 0;\n\
         }\n",
    );
    let (code, stdout, stderr) = run_guest(&binary);
    assert_eq!((code, stderr.as_str()), (Some(0), ""));
    let stdout = String::from_utf8(stdout).unwrap();
    let mut fields = stdout.split_whitespace();
    let guest_base =
        usize::from_str_radix(fields.next().unwrap().trim_start_matches("0x"), 16).unwrap();
    let guest_length = usize::from_str_radix(fields.next().unwrap(), 16).unwrap();
    assert!(
        guest_base >= litebox_shim_macos::shared_cache::SHARED_CACHE_MIN_ADDRESS,
        "{stdout}"
    );
    assert_ne!(guest_base, host_state::shared_cache_base());
    assert_ne!(guest_length, 0);
}

/// An in-process dynamic guest runs on its own private cache instance and
/// leaves the host's libSystem, cache and TSD untouched.
#[cfg(feature = "test-broker")]
#[test]
fn dynamic_guest_leaves_host_runtime_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_c(dir.path(), HELLO_WORLD);
    let host_cache = host_state::shared_cache_base();
    assert!(
        host_cache != 0 && host_cache < litebox_shim_macos::shared_cache::SHARED_CACHE_MIN_ADDRESS,
        "the host's shared region lies below every guest instance"
    );
    let text = host_state::libsystem_kernel_text();
    let thread_pointer = host_state::thread_pointer();
    let pthread_self = host_state::pthread_self_slot();
    // SAFETY: pthread_self has no preconditions.
    assert_eq!(pthread_self, unsafe { libc::pthread_self() } as usize);
    // The guest runs on this thread, in this process.
    let status = litebox_runner_macos_userland::run(litebox_runner_macos_userland::CliArgs {
        program_and_arguments: vec![binary.to_str().unwrap().to_owned()],
        environment_variables: Vec::new(),
        test_mmap_image: None,
    })
    .unwrap();
    assert_eq!(status, 0);
    assert_eq!(host_state::shared_cache_base(), host_cache);
    assert_eq!(host_state::thread_pointer(), thread_pointer);
    assert_eq!(host_state::pthread_self_slot(), pthread_self);
    assert!(
        host_state::libsystem_kernel_text() == text,
        "host libsystem_kernel __TEXT changed"
    );
}

/// Run `binary` with `arguments` under the runner, failing if it has not
/// exited within `timeout`; returns its exit code, stdout and stderr.
#[cfg(feature = "test-broker")]
fn run_guest_with_timeout(
    binary: &Path,
    arguments: &[&str],
    timeout: std::time::Duration,
) -> (Option<i32>, Vec<u8>, String) {
    use std::io::Read as _;
    let mut child = Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
        .arg(binary)
        .args(arguments)
        .env_remove("LITEBOX_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("guest {arguments:?} did not exit within {timeout:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status.code(), stdout, stderr)
}

/// The guest-thread scenarios of `fixtures/threads.c`, compiled once per test.
#[cfg(feature = "test-broker")]
fn run_thread_scenario(scenario: &str) -> (Option<i32>, Vec<u8>, String) {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile(
        dir.path(),
        "clang",
        "threads.c",
        include_str!("fixtures/threads.c"),
        &["-O1"],
    );
    run_guest_with_timeout(&binary, &[scenario], std::time::Duration::from_secs(60))
}

/// Threads created and joined with return values, detached threads, TSD
/// destructors, `_Thread_local`, per-thread errno, unique thread IDs and
/// ports, and `mach_thread_self() == pthread_mach_thread_np(pthread_self())`.
#[cfg(feature = "test-broker")]
#[test]
fn threads_create_join_and_keep_per_thread_state() {
    let (code, stdout, stderr) = run_thread_scenario("join");
    assert_eq!(
        (
            code,
            String::from_utf8_lossy(&stdout).as_ref(),
            stderr.as_str()
        ),
        (
            Some(0),
            "results 0 distinct 1 consistent 16 destructors 20 tls -1 main 1\n",
            ""
        )
    );
}

/// `os_unfair_lock` under contention: 8 threads x 100k increments.
#[cfg(feature = "test-broker")]
#[test]
fn threads_contend_on_an_unfair_lock() {
    let (code, stdout, stderr) = run_thread_scenario("unfair");
    assert_eq!(
        (code, stdout.as_slice(), stderr.as_str()),
        (Some(0), &b"counter 800000\n"[..], "")
    );
}

/// `pthread_exit` from main while workers run: the status is 0 once the
/// last thread exits.
#[cfg(feature = "test-broker")]
#[test]
fn threads_outlive_a_main_thread_that_exits() {
    let (code, stdout, stderr) = run_thread_scenario("main_exit");
    assert_eq!(
        (code, stdout.as_slice(), stderr.as_str()),
        (Some(0), &b"finished 4\n"[..], "")
    );
}

/// `exit(42)` from a worker ends threads that run guest code, sleep, and
/// wait in `pthread_join` and on unfair locks, promptly and with its status.
/// The exiting thread first checks that every join and unfair-lock waiter is
/// blocked in the kernel (status 43 otherwise).
#[cfg(feature = "test-broker")]
#[test]
fn threads_end_with_the_status_of_an_exit_from_any_thread() {
    let (code, stdout, stderr) = run_thread_scenario("exit_blocked");
    assert_eq!(
        (code, stdout.as_slice(), stderr.as_str()),
        (Some(42), &b""[..], "")
    );
}

/// `pthread_setschedparam` (`thread_policy`) on a worker and on main, and
/// its rejection of an invalid priority or policy.
#[cfg(feature = "test-broker")]
#[test]
fn threads_set_scheduling_parameters() {
    let (code, stdout, stderr) = run_thread_scenario("schedparam");
    assert_eq!(
        (
            code,
            String::from_utf8_lossy(&stdout).as_ref(),
            stderr.as_str()
        ),
        (
            Some(0),
            "fifo 0 kept 1 rr 0 bad_priority 1 bad_policy 1 self 0\n",
            ""
        )
    );
}

/// The number of threads of process `pid` (`proc_pidinfo`'s
/// `PROC_PIDTASKINFO`), 0 if it cannot be read.
#[cfg(feature = "test-broker")]
fn host_thread_count(pid: i32) -> i32 {
    // SAFETY: proc_taskinfo is plain integers, zero-valid.
    let mut info = unsafe { std::mem::zeroed::<libc::proc_taskinfo>() };
    let size = i32::try_from(size_of::<libc::proc_taskinfo>()).unwrap();
    // SAFETY: info is writable storage of `size` bytes.
    let read =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTASKINFO, 0, (&raw mut info).cast(), size) };
    if read == size { info.pti_threadnum } else { 0 }
}

/// The runner's thread keeps the forwarded signals (SIGINT, SIGALRM) blocked
/// outside guest execution, so while it waits for the guest's other threads
/// after the main thread's `pthread_exit`, XNU delivers Ctrl-C to one of them.
#[cfg(feature = "test-broker")]
#[test]
fn the_runner_thread_leaves_forwarded_signals_to_guest_threads() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_c(dir.path(), HELLO_WORLD);
    let status = litebox_runner_macos_userland::run(litebox_runner_macos_userland::CliArgs {
        program_and_arguments: vec![binary.to_str().unwrap().to_owned()],
        environment_variables: Vec::new(),
        test_mmap_image: None,
    })
    .unwrap();
    assert_eq!(status, 0);
    // SAFETY: zero is valid for this integer bitmask.
    let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: a null new mask only reads this thread's mask into live storage.
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &raw mut mask) },
        0
    );
    for signal in [libc::SIGINT, libc::SIGALRM] {
        // SAFETY: mask is an initialized sigset_t.
        assert_eq!(unsafe { libc::sigismember(&raw const mask, signal) }, 1);
    }
}

/// Kills and reaps the runner child unless it was already reaped, so a failed
/// test does not leave it running.
#[cfg(feature = "test-broker")]
struct KillOnDrop(std::process::Child);

#[cfg(feature = "test-broker")]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Ctrl-C after the main thread's `pthread_exit` ends the guest through its
/// remaining threads with status 130; the runner thread waiting for them
/// does not take the signal. The signal is sent once a worker's
/// `pthread_join` of the main thread returned, which the worker shows by
/// creating a third guest thread. (XNU picks the receiving thread, so this
/// alone does not always catch a runner thread that takes it; the test above
/// does.)
#[cfg(feature = "test-broker")]
#[test]
fn threads_take_ctrl_c_after_the_main_thread_exits() {
    use std::io::Read as _;

    let dir = tempfile::tempdir().unwrap();
    let binary = compile(
        dir.path(),
        "clang",
        "threads.c",
        include_str!("fixtures/threads.c"),
        &["-O1"],
    );
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
            .arg(&binary)
            .arg("interrupt_after_main_exit")
            .env_remove("LITEBOX_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    // The runner thread, the two workers main created, and the thread the
    // reporting worker creates after its join of main returned.
    let pid = i32::try_from(child.0.id()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while host_thread_count(pid) < 4 {
        assert!(
            std::time::Instant::now() < deadline,
            "the guest never reported the main thread's exit"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // SAFETY: kill has no memory preconditions; the child has not been reaped.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the guest did not end after Ctrl-C"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let mut stdout = String::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert_eq!(
        (status.code(), stdout.as_str()),
        (Some(130), "main exited\n"),
        "{status:?}"
    );
}

/// When every thread terminates without `exit`, the process exits with
/// status 0 without running exit handlers.
#[cfg(feature = "test-broker")]
#[test]
fn threads_that_all_terminate_end_the_process() {
    let (code, stdout, stderr) = run_thread_scenario("last_terminate");
    assert_eq!(
        (code, stdout.as_slice(), stderr.as_str()),
        (Some(0), &b""[..], "")
    );
}

/// The scenarios of `fixtures/psynch.c` with the guest environment `env`.
#[cfg(feature = "test-broker")]
fn run_psynch_scenario(scenario: &str, env: &[&str]) -> (Option<i32>, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile(
        dir.path(),
        "clang",
        "psynch.c",
        include_str!("fixtures/psynch.c"),
        &["-O1"],
    );
    let mut arguments = Vec::new();
    for entry in env {
        arguments.extend(["--env", entry]);
    }
    arguments.extend(["--", binary.to_str().unwrap(), scenario]);
    let (code, stdout, stderr) = run_runner_with_timeout(&arguments);
    (code, String::from_utf8(stdout).unwrap(), stderr)
}

/// Run the runner with `arguments`, failing if it has not exited within a
/// minute.
#[cfg(feature = "test-broker")]
fn run_runner_with_timeout(arguments: &[&str]) -> (Option<i32>, Vec<u8>, String) {
    use std::io::Read as _;
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_litebox_runner_macos_userland"))
            .args(arguments)
            .env_remove("LITEBOX_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdout = Vec::new();
    let mut out = child.0.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        out.read_to_end(&mut stdout).unwrap();
        stdout
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "guest {arguments:?} did not exit within a minute"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status.code(), reader.join().unwrap(), stderr)
}

/// A contended `pthread_mutex` (psynch): 8 threads x 100k increments with
/// the default first-fit policy and with fair share.
#[cfg(feature = "test-broker")]
#[test]
fn threads_contend_on_a_pthread_mutex() {
    assert_eq!(
        run_psynch_scenario("mutex", &[]),
        (
            Some(0),
            "firstfit 800000 fairshare 800000 ulock 0\n".to_owned(),
            String::new()
        )
    );
}

/// Producers and consumers on psynch condition variables, and
/// `pthread_cond_timedwait` (absolute, relative, and ended by a signal).
#[cfg(feature = "test-broker")]
#[test]
fn threads_share_pthread_condition_variables() {
    assert_eq!(
        run_psynch_scenario("condvar", &[]),
        (
            Some(0),
            "consumed 80000 sum 1 absolute 1 waited 1 relative 1 signaled 1 ulock 0\n".to_owned(),
            String::new()
        )
    );
}

/// The same mutex and condition variable programs on the ulock path
/// (`PTHREAD_MUTEX_USE_ULOCK=1` in the guest's environment).
#[cfg(feature = "test-broker")]
#[test]
fn threads_use_ulock_pthread_mutexes_and_condition_variables() {
    let ulock = ["PTHREAD_MUTEX_USE_ULOCK=1"];
    assert_eq!(
        run_psynch_scenario("mutex", &ulock),
        (
            Some(0),
            "firstfit 800000 fairshare 800000 ulock 1\n".to_owned(),
            String::new()
        )
    );
    assert_eq!(
        run_psynch_scenario("condvar", &ulock),
        (
            Some(0),
            "consumed 80000 sum 1 absolute 1 waited 1 relative 1 signaled 1 ulock 1\n".to_owned(),
            String::new()
        )
    );
}

/// Readers and writers on a `pthread_rwlock`: readers never see a write
/// half done.
#[cfg(feature = "test-broker")]
#[test]
fn threads_share_a_pthread_rwlock() {
    assert_eq!(
        run_psynch_scenario("rwlock", &[]),
        (
            Some(0),
            "writes 4000 reads 12000 torn 0\n".to_owned(),
            String::new()
        )
    );
}

/// `pthread_once` from 16 threads at once runs the initializer once, and
/// every caller returns after it finished.
#[cfg(feature = "test-broker")]
#[test]
fn threads_call_pthread_once_together() {
    assert_eq!(
        run_psynch_scenario("once", &[]),
        (Some(0), "initialized 1 saw 16\n".to_owned(), String::new())
    );
}

/// `printf` from 8 threads at once: stdout's FILE lock (a pthread mutex)
/// keeps each of the 1600 lines whole.
#[cfg(feature = "test-broker")]
#[test]
fn threads_printf_concurrently() {
    let (code, stdout, stderr) = run_psynch_scenario("printf", &[]);
    assert_eq!((code, stderr.as_str()), (Some(0), ""));
    let mut lines: Vec<&str> = stdout.lines().collect();
    lines.sort_unstable();
    let expected: Vec<String> = (0..8)
        .flat_map(|thread| (0..200).map(move |line| format!("thread {thread:02} line {line:03}")))
        .collect();
    assert_eq!(lines, expected);
}

/// C++ `std::thread`, `std::mutex` and `std::condition_variable`
/// (including `wait_for` timing out) on the guest's libc++ and libpthread.
#[cfg(feature = "test-broker")]
#[test]
fn threads_use_cpp_std_mutex_and_condition_variable() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile(
        dir.path(),
        "clang++",
        "psynch.cpp",
        include_str!("fixtures/psynch_cxx.h"),
        &["-std=c++17", "-O1"],
    );
    let (code, stdout, stderr) = run_runner_with_timeout(&[binary.to_str().unwrap()]);
    assert_eq!(
        (code, String::from_utf8(stdout).unwrap(), stderr),
        (
            Some(0),
            "counter 800000 sum 199990000 timeout 1 waited 1\n".to_owned(),
            String::new()
        )
    );
}

/// The scenarios of `fixtures/sync.c`.
#[cfg(feature = "test-broker")]
fn run_sync_scenario(scenario: &str) -> (Option<i32>, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile(
        dir.path(),
        "clang",
        "sync.c",
        include_str!("fixtures/sync.c"),
        &["-O1"],
    );
    let (code, stdout, stderr) = run_runner_with_timeout(&[binary.to_str().unwrap(), scenario]);
    (code, String::from_utf8(stdout).unwrap(), stderr)
}

/// `pthread_join` of threads on stacks the program allocated: the joiner
/// waits on the semaphore `bsdthread_terminate` signals before it frees the
/// stack.
#[cfg(feature = "test-broker")]
#[test]
fn threads_join_threads_with_custom_stacks() {
    assert_eq!(
        run_sync_scenario("custom_stack"),
        (Some(0), "joined 64\n".to_owned(), String::new())
    );
}

/// `dispatch_semaphore` ping-pong between two pthreads (Mach semaphores, no
/// dispatch queues), and a timed wait that times out.
#[cfg(feature = "test-broker")]
#[test]
fn threads_ping_pong_on_dispatch_semaphores() {
    assert_eq!(
        run_sync_scenario("dispatch"),
        (
            Some(0),
            "rounds 20000 timeout 1\n".to_owned(),
            String::new()
        )
    );
}

/// `pthread_cancel` of threads blocked in `pthread_cond_wait` (the cleanup
/// handler runs with the mutex reacquired) and `sleep()`, and of a thread
/// calling `write()` in a loop.
#[cfg(feature = "test-broker")]
#[test]
fn threads_cancel_threads_at_cancellation_points() {
    assert_eq!(
        run_sync_scenario("cancel"),
        (
            Some(0),
            "cond 1 cleanup 1 relocked 1 sleep 1 write 1 fast 1\n".to_owned(),
            String::new()
        )
    );
}

/// `usleep`, `nanosleep` and `sleep` in threads sleep for their time.
#[cfg(feature = "test-broker")]
#[test]
fn threads_sleep_with_nanosleep_usleep_and_sleep() {
    assert_eq!(
        run_sync_scenario("sleep"),
        (Some(0), "slept 4\n".to_owned(), String::new())
    );
}

/// Mach message ping-pong between two threads: receives block until the
/// other thread's message arrives.
#[cfg(feature = "test-broker")]
#[test]
fn threads_ping_pong_mach_messages() {
    assert_eq!(
        run_sync_scenario("mach"),
        (Some(0), "main 10000 peer 9999\n".to_owned(), String::new())
    );
}

/// C++ `std::async(std::launch::async)`, `std::promise` and
/// `std::this_thread::sleep_for`.
#[cfg(feature = "test-broker")]
#[test]
fn threads_run_cpp_std_async() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile(
        dir.path(),
        "clang++",
        "sync.cpp",
        include_str!("fixtures/sync_cxx.h"),
        &["-std=c++17", "-O1"],
    );
    let (code, stdout, stderr) = run_runner_with_timeout(&[binary.to_str().unwrap()]);
    assert_eq!(
        (code, String::from_utf8(stdout).unwrap(), stderr),
        (
            Some(0),
            "total 31996000 promised 42 waited 1\n".to_owned(),
            String::new()
        )
    );
}
