// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! No AOT rewriting of either the guest or its ld.so/libc dependencies.
#![cfg(target_arch = "aarch64")]
#[allow(dead_code)]
mod cache;
#[allow(dead_code)]
mod common;
use common::runner::Runner;

#[test]
fn runtime_island_signals() {
    let path = common::compile("./tests/gate_signals.c", "island_signals", false, false);
    Runner::new_unpatched(&path, "island_signals").run();
}

#[test]
fn runtime_island_stack_spill_sigsegv_on_altstack() {
    let path = common::compile("./tests/sigreturn.c", "island_spill_fault", false, false);
    Runner::new_unpatched(&path, "island_spill_fault").run();
}

#[test]
fn runtime_island_signal_simd() {
    let path = common::compile("./tests/sigreturn_simd.c", "island_simd", false, false);
    Runner::new_unpatched(&path, "island_simd").run();
}

#[test]
fn runtime_island_arbitrary_far_chunk_and_frame_reconstruction() {
    let path = common::compile("./tests/island_far.c", "island_far", true, false);
    Runner::new_unpatched(&path, "island_far").run();
}

#[test]
fn runtime_mapping_lifecycle_and_growth() {
    let path = common::compile("./tests/island_mappings.c", "island_mappings", false, false);
    let mut runner = Runner::new_unpatched(&path, "island_mappings");
    let library = runner.tar_dir().join("lib/island_growth.so");
    let output = std::process::Command::new("gcc")
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-T,tests/island_growth.ld",
            "-Wl,-z,max-page-size=4096",
            "tests/island_growth.S",
            "-o",
        ])
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    runner.run();
}

#[test]
fn runtime_island_partial_mprotect_failure_rescans_modified_code() {
    let path = common::compile("./tests/island_mprotect.c", "island_mprotect", false, false);
    let mut runner = Runner::new_unpatched(&path, "island_mprotect");
    std::fs::write(
        runner.tar_dir().join("island-mprotect-readonly"),
        [0x5a; 4096],
    )
    .unwrap();
    let output = std::process::Command::new("gcc")
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-T,tests/island_growth.ld",
            "-Wl,-z,max-page-size=4096",
            "tests/island_growth.S",
            "-o",
        ])
        .arg(runner.tar_dir().join("lib/island_growth.so"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    runner.run();
}

#[test]
fn runtime_island_failed_and_committed_nonleader_exec() {
    let path = common::compile("./tests/execve.c", "island_exec", false, false);
    let mut runner = Runner::new_unpatched(&path, "island_exec");
    std::fs::create_dir_all(runner.tar_dir().join("tmp")).unwrap();
    runner.run();
}

#[test]
#[cfg(feature = "aarch64_virtualize_x18")]
fn runtime_island_x18_operations() {
    let path = common::compile(
        "./tests/x18_virtualization.S",
        "island_x18_operations",
        true,
        true,
    );
    Runner::new_unpatched(&path, "island_x18_operations").run();
}

#[test]
fn sparse_large_dso_with_only_above_image_island_space() {
    let path = common::compile("./tests/island_sparse.c", "island_sparse", false, false);
    let mut runner = Runner::new_unpatched(&path, "island_sparse");
    let library = runner.tar_dir().join("lib/island_sparse.so");
    let output = std::process::Command::new("gcc")
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-T,tests/island_sparse.ld",
            "-Wl,-z,max-page-size=4096",
            "tests/island_growth.S",
            "-o",
        ])
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    runner.run();
}

fn retired_callback(mode: &str) {
    let name = format!("island_retirement_{mode}");
    let path = common::compile("./tests/island_retirement.c", &name, false, false);
    let mut runner = Runner::new_unpatched(&path, &name);
    let output = std::process::Command::new("gcc")
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-T,tests/island_retirement.ld",
            "-Wl,-z,max-page-size=4096",
            "tests/island_retirement.S",
            "-o",
        ])
        .arg(runner.tar_dir().join("lib/island_retirement.so"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    runner.arg(mode).run();
}

#[test]
fn runtime_island_current_callback_unmaps_sole_site() {
    retired_callback("self");
}

#[test]
fn runtime_island_blocked_callback_outlives_sole_site() {
    retired_callback("thread");
}

fn gapless_dlopen(tiny: bool, aot: bool, align: usize, relro: &str) {
    let name = format!("island_gapless_{tiny}_{aot}_{align}_{relro}");
    let path = common::compile("./tests/island_gapless.c", &name, false, false);
    let mut runner = Runner::new_unpatched(&path, &name);
    let library = path.with_file_name(format!("{name}.so"));
    let mut command = std::process::Command::new("gcc");
    command
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-z,noseparate-code",
            "tests/island_gapless.S",
            "-o",
        ])
        .arg(&library)
        .arg(format!("-Wl,-z,max-page-size={align}"))
        .arg(format!("-Wl,-z,{relro}"));
    if !tiny {
        command.arg("-DLARGE");
    }
    if align > 4096 {
        command.arg("-DMANY_SITES");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    if relro == "norelro" {
        assert!(std::fs::metadata(&library).unwrap().len() < 4096);
    }
    let target = runner.tar_dir().join("lib/island_gapless.so");
    if aot {
        assert!(common::rewrite_with_cache(&library, &target, &[]));
    } else {
        std::fs::copy(&library, target).unwrap();
    }
    runner.run();
}

#[test]
fn gapless_dso_runtime() {
    gapless_dlopen(false, false, 4096, "relro");
}
#[test]
fn gapless_dso_aot() {
    gapless_dlopen(false, true, 4096, "relro");
}
#[test]
fn tiny_gapless_dso_runtime() {
    gapless_dlopen(true, false, 4096, "relro");
}
#[test]
fn tiny_gapless_dso_aot() {
    gapless_dlopen(true, true, 4096, "relro");
}

#[test]
fn overaligned_gapless_dso_aot() {
    gapless_dlopen(true, true, 65536, "relro");
}

#[test]
fn unrewritten_elf_with_incidental_litebox_tail() {
    let path = common::compile("./tests/hello.c", "incidental_litebox_source", false, false);
    let mut elf = std::fs::read(&path).unwrap();
    elf.extend_from_slice(b"arbitrary trailing LITEBOX text!!");
    let path = path.with_file_name("incidental_litebox_tail");
    std::fs::write(&path, elf).unwrap();
    Runner::new_unpatched(&path, "incidental_litebox_runtime").run();
    Runner::new(&path, "incidental_litebox_aot").run();
}

#[test]
fn subpage_gapless_dso_runtime() {
    gapless_dlopen(true, false, 4096, "norelro");
}
#[test]
fn subpage_gapless_dso_aot() {
    gapless_dlopen(true, true, 4096, "norelro");
}

// Three page-distinct LOADs alias file page zero. This stripped PIE has exactly
// three instructions (MOV x0,#0; MOV x8,#94; SVC #0), and no libc or relocations.
fn shared_page_pie() -> Vec<u8> {
    let code = 0x200;
    let data = 0x220;
    let mut bytes = vec![0; data + 8];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, value) in [(16, 3u16), (18, 183), (52, 64), (54, 56), (56, 3)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x1200u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    for (i, (flags, offset, address, size)) in [
        (4u32, 0, 0, 0x200),
        (5, code, 0x1200, 12),
        (6, data, 0x2220, 8),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + i * 56;
        bytes[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        for (field, value) in [
            (8, offset),
            (16, address),
            (32, size),
            (40, size),
            (48, 4096),
        ] {
            bytes[at + field..at + field + 8].copy_from_slice(&(value as u64).to_le_bytes());
        }
    }
    for (i, word) in [0xd280_0000u32, 0xd280_0bc8, 0xd400_0001]
        .into_iter()
        .enumerate()
    {
        bytes[code + i * 4..code + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn run_shared_page_pie(aot: bool, interpreter: bool) {
    use std::os::unix::fs::PermissionsExt as _;
    let name = format!("shared_page_pie_{aot}_{interpreter}");
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(&name);
    let interp = path.with_file_name(format!("{name}.ld"));
    let mut bytes = shared_page_pie();
    if interpreter {
        std::fs::write(&interp, shared_page_pie()).unwrap();
        std::fs::set_permissions(&interp, std::fs::Permissions::from_mode(0o755)).unwrap();
        let name = format!("{}\0", interp.display());
        // Room for PT_INTERP and its path before the executable file bytes.
        bytes[56..58].copy_from_slice(&4u16.to_le_bytes());
        let at = 64 + 3 * 56;
        bytes[at..at + 4].copy_from_slice(&3u32.to_le_bytes());
        for (field, value) in [(8, 0x120), (32, name.len()), (40, name.len()), (48, 1)] {
            bytes[at + field..at + field + 8].copy_from_slice(&(value as u64).to_le_bytes());
        }
        // The program headers end at 0x120; keep the path clear of them.
        assert!(name.len() <= 0xe0);
        bytes[0x120..0x120 + name.len()].copy_from_slice(name.as_bytes());
    }
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        std::process::Command::new(&path)
            .status()
            .unwrap()
            .success()
    );
    let mut runner = if aot {
        Runner::new(&path, &name)
    } else {
        Runner::new_unpatched(&path, &name)
    };
    if interpreter {
        let dest = runner.tar_dir().join(interp.strip_prefix("/").unwrap());
        if aot {
            assert!(common::rewrite_with_cache(&interp, &dest, &[]));
        } else {
            std::fs::copy(&interp, dest).unwrap();
        }
    }
    runner.run();
}

#[test]
fn shared_file_page_pie_runtime() {
    run_shared_page_pie(false, false);
}
#[test]
fn shared_file_page_pie_aot() {
    run_shared_page_pie(true, false);
}
#[test]
fn shared_file_page_pie_interpreter_runtime() {
    run_shared_page_pie(false, true);
}
#[test]
fn shared_file_page_pie_interpreter_aot() {
    run_shared_page_pie(true, true);
}
