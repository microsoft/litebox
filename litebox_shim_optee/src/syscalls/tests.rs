// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::keystack::KeyStackCommandId;
use crate::syscalls::pta::{
    PseudoTa, TA_DERIVED_EXTRA_DATA_MAX_SIZE, TA_DERIVED_KEY_MAX_SIZE, TA_DERIVED_KEY_MIN_SIZE,
};
extern crate std;

use alloc::{vec, vec::Vec};
use litebox_common_optee::TeeUuid;
use litebox_common_optee::{TeeParamType, TeeResult, UteeParams};
use litebox_platform_multiplex::{Platform, set_platform};

// Ensure we only init the platform once
static INIT_FUNC: spin::Once = spin::Once::new();

fn ensure_platform() {
    INIT_FUNC.call_once(|| {
        #[cfg(target_os = "linux")]
        let platform = Platform::new(None);

        #[cfg(not(target_os = "linux"))]
        let platform = Platform::new();

        #[cfg(target_os = "linux")]
        platform.initialize_boot_specific_kdf_support();

        set_platform(platform);
    });
}

#[must_use]
pub(crate) fn init_platform() -> crate::Task {
    ensure_platform();

    let shim_builder = crate::OpteeShimBuilder::new();
    let _litebox = shim_builder.litebox();
    shim_builder.build().0.new_test_task()
}

#[test]
fn test_sys_log() {
    let task = init_platform();
    let result = task.sys_log(b"Hello! This is litebox_shim_optee.");
    assert!(result.is_ok());
}

#[test]
fn test_cryp_random_number_generate() {
    let task = init_platform();
    let mut buf = [0u8; 16];
    let result = task.sys_cryp_random_number_generate(&mut buf);
    assert!(result.is_ok() && buf != [0u8; 16]);
}

#[test]
fn test_sys_get_time_system_is_monotonic() {
    use litebox::platform::RawConstPointer as _;
    use litebox_common_optee::{TeeTime, TeeTimeCategory};

    let task = init_platform();

    let mut first = TeeTime::default();
    let first_ptr = crate::UserMutPtr::<TeeTime>::from_usize(&raw mut first as usize);
    task.sys_get_time(TeeTimeCategory::System, first_ptr)
        .expect("system time should be supported");

    let mut second = TeeTime::default();
    let second_ptr = crate::UserMutPtr::<TeeTime>::from_usize(&raw mut second as usize);
    task.sys_get_time(TeeTimeCategory::System, second_ptr)
        .expect("system time should be supported");

    // `millis` is the sub-second remainder, so always in `0..1000`.
    assert!(first.millis < 1000 && second.millis < 1000);

    let first_ms = u64::from(first.seconds) * 1000 + u64::from(first.millis);
    let second_ms = u64::from(second.seconds) * 1000 + u64::from(second.millis);
    assert!(second_ms >= first_ms, "system time went backwards");
}

#[test]
fn test_sys_map_zi_uses_bottom_up_placement() {
    use litebox::mm::linux::PAGE_SIZE;
    use litebox_common_optee::LdelfMapFlags;

    let task = init_platform();
    let (header, header_cleanup) = task
        .sys_map_zi(0, PAGE_SIZE, 0, 0, LdelfMapFlags::empty())
        .expect("header mapping should succeed");
    let (image, image_cleanup) = task
        .sys_map_zi(
            0,
            PAGE_SIZE,
            PAGE_SIZE,
            2 * PAGE_SIZE,
            LdelfMapFlags::empty(),
        )
        .expect("padded image mapping should succeed");

    assert!(header < image, "OP-TEE-chosen mappings must grow upward");
    image_cleanup.run(&task);
    header_cleanup.run(&task);
}

// ---------------------------------------------------------------------------
// Key stack PTA: differential test against the C original
// ---------------------------------------------------------------------------

const KEY_STACK_CMD: u32 = KeyStackCommandId::DeriveTaSvnKeyStack as u32;

struct Case {
    key_size: u32,
    stack_size: u32,
    ta_svn: u32,
    uuid: [u8; 16],
    extra_data: Vec<u8>,
}

fn compile_c_reference(dir: &std::path::Path) -> std::path::PathBuf {
    let src = alloc::format!("{}/tests/keystack_ref.c", env!("CARGO_MANIFEST_DIR"));
    let out = dir.join("keystack_ref");
    let output = std::process::Command::new("gcc")
        .args(["-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&out)
        .arg(&src)
        .arg("-lcrypto")
        .output()
        .unwrap_or_else(|e| panic!("failed to run gcc (is a C toolchain installed?): {e}"));
    assert!(
        output.status.success(),
        "failed to compile {src} (needs gcc and libssl-dev):\n{}",
        std::string::String::from_utf8_lossy(&output.stderr)
    );
    out
}

fn run_c_reference(cases: &[Case]) -> Vec<alloc::string::String> {
    use alloc::string::{String, ToString};
    use core::fmt::Write as _;

    let dir = tempfile::tempdir().expect("create temp dir");
    let bin = compile_c_reference(dir.path());

    let mut input = String::new();
    for c in cases {
        let mut uuid = String::new();
        for b in &c.uuid {
            write!(uuid, "{b:02x}").unwrap();
        }
        let mut extra = String::new();
        for b in &c.extra_data {
            write!(extra, "{b:02x}").unwrap();
        }
        writeln!(
            input,
            "{} {} {} {} {}",
            c.key_size,
            c.stack_size,
            c.ta_svn,
            uuid,
            if extra.is_empty() { "-" } else { &extra }
        )
        .unwrap();
    }

    let cases_path = dir.path().join("cases");
    std::fs::write(&cases_path, input).expect("write cases file");

    let output = std::process::Command::new(&bin)
        .arg(&cases_path)
        .output()
        .expect("run C reference");
    assert!(
        output.status.success(),
        "C reference failed:\n{}",
        std::string::String::from_utf8_lossy(&output.stderr)
    );

    std::string::String::from_utf8(output.stdout)
        .expect("C output is utf-8")
        .lines()
        .map(ToString::to_string)
        .collect()
}

fn run_rust_implementation(case: &Case) -> alloc::string::String {
    use alloc::string::String;
    use core::fmt::Write as _;

    let shim_builder = crate::OpteeShimBuilder::new();
    let _litebox = shim_builder.litebox();
    let task = shim_builder.build().0.new_test_task_with_uuid_and_svn(
        TeeUuid {
            time_low: u32::from_le_bytes(case.uuid[0..4].try_into().unwrap()),
            time_mid: u16::from_le_bytes(case.uuid[4..6].try_into().unwrap()),
            time_hi_and_version: u16::from_le_bytes(case.uuid[6..8].try_into().unwrap()),
            clock_seq_and_node: case.uuid[8..16].try_into().unwrap(),
        },
        case.ta_svn,
    );

    let buf_len = case.key_size as usize * (case.ta_svn as usize + 1);
    let mut key_buf = vec![0u8; buf_len];
    let mut params = key_stack_params(
        u64::from(case.key_size),
        u64::from(case.stack_size),
        &case.extra_data,
        &mut key_buf,
    );

    let mut out = String::new();
    match invoke_key_stack(&task, KEY_STACK_CMD, &mut params) {
        Ok(()) => {
            out.push_str("00000000 ");
            for b in &key_buf {
                write!(out, "{b:02x}").unwrap();
            }
        }
        Err(e) => write!(out, "{:08x} -", u32::from(e)).unwrap(),
    }
    out
}

fn invoke_key_stack(
    task: &crate::Task,
    cmd_id: u32,
    params: &mut UteeParams,
) -> Result<(), TeeResult> {
    PseudoTa::KeyStack
        .invoke_command(task, cmd_id, params)
        .map(|_| ())
}

fn key_stack_params(
    key_size: u64,
    stack_size: u64,
    extra_data: &[u8],
    key_buf: &mut [u8],
) -> UteeParams {
    let mut params = UteeParams::new();
    params.set_type(0, TeeParamType::ValueInput).unwrap();
    params.set_values(0, key_size, stack_size).unwrap();
    params.set_type(1, TeeParamType::MemrefInput).unwrap();
    params
        .set_values(1, extra_data.as_ptr() as u64, extra_data.len() as u64)
        .unwrap();
    params.set_type(2, TeeParamType::MemrefOutput).unwrap();
    params
        .set_values(2, key_buf.as_mut_ptr() as u64, key_buf.len() as u64)
        .unwrap();
    params.set_type(3, TeeParamType::None).unwrap();
    params
}

fn differential_cases() -> Vec<Case> {
    let min_key_size = u32::try_from(TA_DERIVED_KEY_MIN_SIZE).unwrap();
    let max_key_size = u32::try_from(TA_DERIVED_KEY_MAX_SIZE).unwrap();

    let uuid = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    // (key_size, stack_size, ta_svn, extra_len)
    let boundaries: &[(u32, u32, u32, usize)] = &[
        // Every interesting key size, including non-multiples of the digest
        // length, which catch bad HMAC truncation.
        (16, 8, 0, 16),
        (17, 8, 0, 16),
        (24, 8, 0, 16),
        (31, 8, 0, 16),
        (32, 8, 0, 16),
        // Extra data boundaries.
        (32, 8, 0, 0),
        (32, 8, 0, 1),
        (32, 8, 0, TA_DERIVED_EXTRA_DATA_MAX_SIZE),
        // ta_svn > 0 exercises the `i * key_size` output offsets.
        (32, 8, 1, 8),
        (32, 8, 3, 8),
        (32, 8, 7, 8),
        (16, 8, 7, 8),
        (32, 16, 5, 8),
        // ta_svn >= chain depth: only a suffix of the buffer is written.
        (32, 2, 3, 8),
        (32, 1, 5, 8),
        (32, 4, 10, 8),
        // Chain depth boundaries, including the 4096 maximum.
        (32, 1, 0, 8),
        (32, 4096, 2, 8),
        (32, 4095, 0, 8),
        // Inputs both implementations must reject.
        (min_key_size - 1, 8, 0, 8),                    // key too small
        (max_key_size + 1, 8, 0, 8),                    // key too large
        (32, 8, 0, TA_DERIVED_EXTRA_DATA_MAX_SIZE + 1), // extra data too long
        (32, 0, 0, 8),                                  // empty chain
        (32, 4097, 0, 8),                               // chain longer than the 4096 maximum
    ];

    let mut cases: Vec<Case> = boundaries
        .iter()
        .map(|&(key_size, stack_size, ta_svn, extra_len)| Case {
            key_size,
            stack_size,
            ta_svn,
            uuid,
            extra_data: (0..extra_len)
                .map(|i| u8::try_from(i % 256).unwrap())
                .collect(),
        })
        .collect();

    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = |n: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % n
    };
    for _ in 0..200 {
        let key_size = 16 + u32::try_from(next(17)).unwrap();
        let stack_size = 1 + u32::try_from(next(64)).unwrap();
        let ta_svn = u32::try_from(next(16)).unwrap();
        let extra_len = usize::try_from(next(64)).unwrap();
        let mut uuid = [0u8; 16];
        for b in &mut uuid {
            *b = u8::try_from(next(256)).unwrap();
        }
        cases.push(Case {
            key_size,
            stack_size,
            ta_svn,
            uuid,
            extra_data: (0..extra_len)
                .map(|_| u8::try_from(next(256)).unwrap())
                .collect(),
        });
    }
    cases
}

/// Differential test.
///
/// Both Rust and C sides derive from the same seed/base key.
#[test]
fn key_stack_matches_c_reference() {
    ensure_platform();

    let cases = differential_cases();
    let c_output = run_c_reference(&cases);
    assert_eq!(
        c_output.len(),
        cases.len(),
        "C reference produced {} lines for {} cases",
        c_output.len(),
        cases.len()
    );

    let mut derived = 0;
    let mut rejected = 0;
    for (index, (case, expected)) in cases.iter().zip(c_output.iter()).enumerate() {
        let actual = run_rust_implementation(case);
        assert_eq!(
            &actual,
            expected,
            "case {index} diverged from the C original: key_size={} stack_size={} \
             ta_svn={} extra_data_len={}",
            case.key_size,
            case.stack_size,
            case.ta_svn,
            case.extra_data.len()
        );
        if expected.starts_with("00000000 ") {
            derived += 1;
        } else {
            rejected += 1;
        }
    }

    assert!(
        derived > 0 && rejected >= 5,
        "derived={derived} rejected={rejected}"
    );
}
