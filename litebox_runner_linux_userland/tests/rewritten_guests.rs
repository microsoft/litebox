// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tests for guests whose syscall sites the rewriter redirected.
//!
//! Guests are rewritten before being loaded into the broker-owned file system.

#[allow(dead_code, reason = "shared with the other test binaries")]
mod cache;
#[allow(dead_code, reason = "shared with the other test binaries")]
mod common;

use common::runner::Runner;

fn run_rewritten_fixture(source: &str, unique_name: &str) -> Vec<u8> {
    let target = common::compile(source, unique_name, true, false);
    Runner::new(&target, unique_name).output()
}

#[test]
fn test_rewritten_program() {
    let output = run_rewritten_fixture("./tests/hello.c", "rewritten_program");
    let stdout = String::from_utf8_lossy(&output);
    println!("{stdout}");
    assert!(stdout.contains("argv[0] = "), "unexpected stdout: {stdout}");
}

/// Linux AArch64 SVC preserves x16/x17 despite their AAPCS veneer role.
/// On non-AArch64 the fixture is a no-op.
#[test]
fn test_svc_scratch_registers_survive_rewritten_syscall() {
    run_rewritten_fixture("./tests/svc_scratch_regs.c", "svc_scratch_regs_rewriter");
}

/// The synthetic AArch64 restorer must invoke rt_sigreturn, which restores
/// caller-saved registers and sp after the handler returns. Other architectures
/// cover handler entry and return without register checks.
#[test]
fn test_signal_handler_returns_through_sigreturn() {
    let output = run_rewritten_fixture("./tests/sigreturn.c", "sigreturn_rewriter");
    assert!(
        String::from_utf8_lossy(&output).contains("sigreturn ok"),
        "guest did not reach the post-sigreturn write: {}",
        String::from_utf8_lossy(&output),
    );
}

/// An asynchronous resume has no outbound stub, so x16 must survive the direct
/// resume into the handler and the rt_sigreturn resume to the caller.
/// Other architectures cover signal delivery to a busy guest without x16
/// checks.
#[test]
fn test_guest_x16_survives_asynchronous_resume() {
    let output = run_rewritten_fixture("./tests/async_x16.c", "async_x16_rewriter");
    assert!(
        String::from_utf8_lossy(&output).contains("async x16 ok"),
        "guest did not resume after the interruption: {}",
        String::from_utf8_lossy(&output),
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_guest_simd_survives_signal_delivery() {
    run_rewritten_fixture("./tests/sigreturn_simd.c", "sigreturn_simd_rewriter");
}

/// Semantic stress only: sampling cannot prove a signal PC landed inside a
/// short gate; synthetic tests cover each gate instruction boundary.
#[test]
#[cfg(target_arch = "aarch64")]
fn test_signals_while_exercising_each_aarch64_gate_kind() {
    let output = run_rewritten_fixture("./tests/gate_signals.c", "gate_signals_rewriter");
    assert!(
        String::from_utf8_lossy(&output).contains("gate signals ok"),
        "guest did not finish all gate loops: {}",
        String::from_utf8_lossy(&output),
    );
}

#[test]
#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
fn test_x18_virtualization() {
    let target = common::compile(
        "./tests/x18_virtualization.S",
        "x18_virtualization_nolibc",
        true,
        true,
    );
    Runner::new(&target, "x18_virtualization_rewriter").run();
}

#[test]
#[cfg(target_arch = "aarch64")]
fn aot_island_chain_uses_arbitrary_far_chunks() {
    let target = common::compile("./tests/island_far.c", "phase4_far", true, false);
    Runner::new(&target, "phase4_far").run();
}

#[test]
#[cfg(target_arch = "aarch64")]
fn aot_dso_mapping_lifecycle() {
    let target = common::compile(
        "./tests/aot_island_mappings.c",
        "phase4_mappings",
        false,
        false,
    );
    let mut runner = Runner::new(&target, "phase4_mappings");
    let library = target.with_file_name("phase4_aot_growth.so");
    let output = std::process::Command::new("gcc")
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-T,tests/aot_island_growth.ld",
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
    assert!(common::rewrite_with_cache(
        &library,
        &runner.tar_dir().join("lib/aot_growth.so"),
        &[]
    ));
    runner.run();
}

#[cfg(target_arch = "aarch64")]
fn serialized_islands(
    path: &std::path::Path,
) -> Option<litebox_syscall_rewriter::aarch64::elf_islands::ElfIslands> {
    use litebox_syscall_rewriter::{
        RewriteOptions, TargetHost,
        aarch64::{ElfCodeMetadata, elf_islands::ElfIslands},
    };
    let bytes = std::fs::read(path).unwrap();
    let payload = ElfIslands::parse(&bytes).unwrap()?;
    let options = RewriteOptions::new(TargetHost::Linux, cfg!(feature = "aarch64_virtualize_x18"));
    payload.check_compatibility(options, 4096).unwrap();
    if payload.pairs.is_empty() {
        // Size-zero is legitimate only when the admitted code has no sites.
        let mut words: Vec<u64> = bytes
            .chunks(8)
            .map(|c| {
                let mut word = [0; 8];
                word[..c.len()].copy_from_slice(c);
                u64::from_ne_bytes(word)
            })
            .collect();
        let metadata = ElfCodeMetadata::parse_aligned_in_place(&mut words, bytes.len()).unwrap();
        assert_eq!(
            metadata.island_slot_upper_bound(&bytes, options).unwrap(),
            0
        );
    } else {
        assert_eq!(payload.options, options);
    }
    Some(payload)
}

#[test]
#[cfg(target_arch = "aarch64")]
fn aot_packager_dynamic_main_and_dependencies() {
    let target = common::compile("./tests/hello.c", "phase4_packaged", false, false);
    let mut runner = Runner::new_empty(&target, "phase4_packaged");
    let tar = target.with_file_name("phase4-packaged.tar");
    let main = runner.tar_dir().join(target.strip_prefix("/").unwrap());
    for unrewritten in [true, false] {
        // Only this test's named rootfs is removed, never a host library tree.
        if runner.tar_dir().exists() {
            std::fs::remove_dir_all(runner.tar_dir()).unwrap();
        }
        std::fs::create_dir_all(runner.tar_dir()).unwrap();
        let mut command = std::process::Command::new(env!("CARGO"));
        command.args(["run", "-p", "litebox_packager", "--"]);
        #[cfg(feature = "aarch64_virtualize_x18")]
        command.arg("--virtualize-x18");
        if unrewritten {
            command.arg("--no-rewrite").arg(&target);
        }
        let output = command.arg(&target).arg("-o").arg(&tar).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = std::process::Command::new("tar")
            .arg("-xf")
            .arg(&tar)
            .arg("-C")
            .arg(runner.tar_dir())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if unrewritten {
            assert!(
                serialized_islands(&main).is_none(),
                "negative control must reject an unrewritten main"
            );
            continue;
        }
        // The runner helper also adds optional pthread-cancel libgcc_s; hello
        // does not depend on it, and the packager correctly need not include it.
        let dependencies = common::find_dependencies(target.to_str().unwrap());
        for path in std::iter::once(target.clone()).chain(
            dependencies
                .into_iter()
                .filter(|path| !path.ends_with("/libgcc_s.so.1"))
                .map(std::path::PathBuf::from),
        ) {
            let archived = runner.tar_dir().join(path.strip_prefix("/").unwrap());
            assert!(
                serialized_islands(&archived).is_some(),
                "missing serialized islands: {}",
                archived.display()
            );
        }
    }
    runner.run();
}

#[cfg(target_arch = "aarch64")]
fn aot_retired_callback(mode: &str) {
    let name = format!("phase4_retirement_{mode}");
    let target = common::compile("./tests/aot_island_retirement.c", &name, false, false);
    let mut runner = Runner::new(&target, &name);
    let library = target.with_file_name(format!("{name}.so"));
    let output = std::process::Command::new("gcc")
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-T,tests/island_retirement.ld",
            "-Wl,-z,max-page-size=4096",
            "tests/island_retirement.S",
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
    assert!(common::rewrite_with_cache(
        &library,
        &runner.tar_dir().join("lib/island_retirement.so"),
        &[]
    ));
    let payload = serialized_islands(&runner.tar_dir().join("lib/island_retirement.so")).unwrap();
    let [(pair, slot)] = payload
        .pairs
        .iter()
        .flat_map(|pair| {
            (0..pair.slots_used()).filter_map(move |index| {
                let slot = litebox_syscall_rewriter::aarch64::island::decode_island_slot(
                    pair.island(),
                    pair.island_vaddr(),
                    index,
                )
                .unwrap();
                (!slot.auxiliary && slot.site == 8192 - 4).then_some((pair, slot))
            })
        })
        .collect::<Vec<_>>()[..]
    else {
        panic!("missing sole-site serialized chain");
    };
    assert_eq!(slot.resume, 8192);
    runner.arg(mode).arg(pair.island_vaddr().to_string()).run();
}

#[test]
fn compile_cache_tracks_included_retirement_implementation() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("retirement_cache_inputs");
    std::fs::create_dir_all(&dir).unwrap();
    let wrapper = dir.join("aot_island_retirement.c");
    let included = dir.join("island_retirement.c");
    std::fs::write(&wrapper, "#include \"island_retirement.c\"\n").unwrap();
    let mut previous = Vec::new();
    for value in [1, 2] {
        std::fs::write(&included, format!("int main(void) {{return {value};}}\n")).unwrap();
        let binary = common::compile(
            wrapper.to_str().unwrap(),
            "retirement_cache_binary",
            true,
            false,
        );
        let bytes = std::fs::read(binary).unwrap();
        assert!(
            bytes != previous,
            "included C change must invalidate compilation cache"
        );
        previous = bytes;
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[cfg(target_arch = "aarch64")]
fn aot_current_callback_unmaps_sole_site() {
    aot_retired_callback("self");
}

#[test]
#[cfg(target_arch = "aarch64")]
fn aot_blocked_callback_outlives_sole_site() {
    aot_retired_callback("thread");
}

#[test]
#[cfg(target_arch = "aarch64")]
fn aot_dynamic_island_chain_uses_arbitrary_far_chunks() {
    let target = common::compile("./tests/island_far.c", "phase4_dynamic_far", false, false);
    Runner::new(&target, "phase4_dynamic_far").run();
}
