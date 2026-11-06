// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of the SVN key stack pseudo TA.

use crate::syscalls::Cleanup;
use crate::syscalls::pta::{
    HmacSha256, PTA_DEFAULT_FLAGS, TA_DERIVED_EXTRA_DATA_MAX_SIZE, TA_DERIVED_KEY_MAX_SIZE,
    TA_DERIVED_KEY_MIN_SIZE, huk_subkey_derive, open_pta_session_no_params,
};
use crate::{Task, UserConstPtr, UserMutPtr};
use alloc::{vec, vec::Vec};
use hmac::Mac;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt;
use litebox_common_optee::{HukSubkeyUsage, TaFlags, TeeParamType, TeeResult, TeeUuid, UteeParams};
use num_enum::TryFromPrimitive;
use zeroize::Zeroizing;

/// Maximum number of keys in SVN key stack.
const SVN_KEY_STACK_MAX_SIZE: u32 = 4096;

/// Domain-separation label for the key stack's first-stage KDF.
///
/// It must precede the TA UUID; otherwise `PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY`
/// with `extra_data = label || ...` would yield the same root key.
const KEY_STACK_KDF_LABEL: &[u8] = b"LiteBox OP-TEE SVN key stack v1";

pub(crate) struct KeyStackPta;

/// Command IDs accepted by [`KeyStackPta`].
#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
enum KeyStackCommandId {
    DeriveTaSvnKeyStack = 0,
}

impl KeyStackPta {
    pub(crate) const FLAGS: TaFlags = PTA_DEFAULT_FLAGS.union(TaFlags::CONCURRENT);

    // TODO: Replace this placeholder with the UUID agreed upon with the
    // consuming TA before this PTA is treated as a stable interface.
    pub(crate) const UUID: TeeUuid = TeeUuid {
        time_low: 0x978a_f7a7,
        time_mid: 0x074f,
        time_hi_and_version: 0x4f59,
        clock_seq_and_node: [0xb3, 0xae, 0x33, 0xa5, 0x93, 0xc1, 0xd4, 0x88],
    };

    pub(crate) fn open_session(params: &UteeParams) -> Result<u32, TeeResult> {
        open_pta_session_no_params(params)
    }

    pub(crate) fn close_session<Platform: crate::OpteeShimPlatform>(
        _task: &Task<Platform>,
        _session_id: u32,
    ) {
        // The key stack PTA has no per-session state.
    }

    pub(crate) fn invoke_command<Platform: crate::OpteeShimPlatform>(
        task: &Task<Platform>,
        cmd_id: u32,
        params: &mut UteeParams,
    ) -> Result<Cleanup, TeeResult> {
        match KeyStackCommandId::try_from(cmd_id).map_err(|_| TeeResult::BadParameters)? {
            KeyStackCommandId::DeriveTaSvnKeyStack => {
                Self::derive_ta_svn_key_stack(task, params).map(|()| Cleanup::None)
            }
        }
    }

    /// Derives a stack of unique keys for a TA, one for each possible
    /// Secure Version Number (SVN) value up to a maximum.
    ///
    /// The key derivation follows a two-stage process:
    /// 1. First stage: KDF(huk, label || uuid || extra_data) -> base key,
    ///    where `label` is [`KEY_STACK_KDF_LABEL`]
    /// 2. Second stage: Iterate from max SVN down to 0, chaining keys:
    ///    - Key\[max\] = HMAC(base_key, max)
    ///    - Key\[n\] = HMAC(Key\[n+1\], n)
    ///
    /// Only keys for SVN values <= current TA version are copied to output.
    fn derive_ta_svn_key_stack<Platform: crate::OpteeShimPlatform>(
        task: &Task<Platform>,
        params: &mut UteeParams,
    ) -> Result<(), TeeResult> {
        use TeeParamType::{MemrefInput, MemrefOutput, None, ValueInput};
        // Validate parameter types:
        // [in]  params[0].value.a         Size of each key
        // [in]  params[0].value.b         Number of keys to derive
        // [in]  params[1].memref.buffer   Extra data for key derivation
        // [in]  params[1].memref.size     Extra data size
        // [out] params[2].memref.buffer   Output buffer for key stack
        // [out] params[2].memref.size     Buffer size
        if !params.has_types([ValueInput, MemrefInput, MemrefOutput, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (key_size_u64, svn_key_stack_size_u64) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let key_size: usize = key_size_u64.trunc();
        let svn_key_stack_size =
            u32::try_from(svn_key_stack_size_u64).map_err(|_| TeeResult::BadParameters)?;

        let (extra_data_addr, extra_data_size_u64) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let extra_data_size: usize = extra_data_size_u64.trunc();

        let (key_stack_addr, key_stack_buffer_size_u64) = params
            .get_values(2)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;

        if !(TA_DERIVED_KEY_MIN_SIZE..=TA_DERIVED_KEY_MAX_SIZE).contains(&key_size)
            || extra_data_size > TA_DERIVED_EXTRA_DATA_MAX_SIZE
            || svn_key_stack_size > SVN_KEY_STACK_MAX_SIZE
            || svn_key_stack_size == 0
            || (extra_data_size > 0 && extra_data_addr == 0)
            || key_stack_addr == 0
        {
            return Err(TeeResult::BadParameters);
        }

        // Only keys for SVN <= ta_svn are emitted, and the chain is only
        // `svn_key_stack_size` deep, so the buffer need cover just that many.
        let ta_svn = task.ta_svn;
        let emitted_key_count = ta_svn.saturating_add(1).min(svn_key_stack_size);
        let required_stack_buffer_size = key_size
            .checked_mul(emitted_key_count as usize)
            .ok_or(TeeResult::BadParameters)?;
        let required_stack_buffer_size_u64 =
            u64::try_from(required_stack_buffer_size).map_err(|_| TeeResult::BadParameters)?;
        if key_stack_buffer_size_u64 < required_stack_buffer_size_u64 {
            params
                .set_values(2, key_stack_addr, required_stack_buffer_size_u64)
                .map_err(|_| TeeResult::BadParameters)?;
            return Err(TeeResult::ShortBuffer);
        }

        let extra_data = if extra_data_size == 0 {
            Vec::new().into_boxed_slice()
        } else {
            let extra_data_ptr = UserConstPtr::<Platform, u8>::from_usize(extra_data_addr.trunc());
            extra_data_ptr
                .to_owned_slice(extra_data_size)
                .ok_or(TeeResult::BadParameters)?
        };

        // Unlike OP-TEE OS, `UserMutPtr`/`UserConstPtr` ensure this pointer can never
        // be used to access normal-world memory.
        let key_stack_ptr = UserMutPtr::<Platform, u8>::from_usize(key_stack_addr.trunc());

        // First stage: derive base key = KDF(huk, usage || label || ta_uuid || extra data)
        let uuid_bytes = task.ta_app_id.to_le_bytes();
        let mut stage_key = Zeroizing::new(vec![0u8; key_size]);
        huk_subkey_derive(
            task,
            HukSubkeyUsage::UniqueTa,
            &[KEY_STACK_KDF_LABEL, &uuid_bytes, &extra_data],
            &mut stage_key,
        )?;

        // Derive keys from max SVN down to 0
        for svn_idx in (0..svn_key_stack_size).rev() {
            // Second stage KDF: HMAC(current_key, SVN_index)
            // Key_v2047 = KDF(KDF(HUK, label || UUID), 2047)
            // Key_v2046 = KDF(Key_v2047, 2046)
            // ...
            // Key_v001 = KDF(Key_v002, 001)
            // Key_v000 = KDF(Key_v001, 000)
            let mut hmac =
                HmacSha256::new_from_slice(&stage_key).map_err(|_| TeeResult::BadParameters)?;
            hmac.update(&svn_idx.to_le_bytes());

            let hmac_bytes = Zeroizing::new(hmac.finalize().into_bytes());
            let derived_key = &hmac_bytes[..key_size];

            // Only copy keys for SVN values <= current TA version to userspace
            if svn_idx <= ta_svn {
                let offset = svn_idx as usize * key_size;
                key_stack_ptr
                    .copy_from_slice(offset, derived_key)
                    .ok_or(TeeResult::AccessDenied)?;
            }
            stage_key.copy_from_slice(derived_key);
        }

        // Report how many bytes were actually written.
        params
            .set_values(2, key_stack_addr, required_stack_buffer_size_u64)
            .map_err(|_| TeeResult::BadParameters)
    }
}

/// Differential test against the C original in `tests/keystack_ref.c`.
///
/// Ignored by default because it compiles the C reference, which needs `gcc`
/// and OpenSSL headers (`libssl-dev`). CI runs it explicitly. To run locally:
///
/// ```text
/// cargo nextest run -p litebox_shim_optee --run-ignored only -E 'test(key_stack_matches_c_reference)'
/// ```
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::syscalls::tests::shim_builder;
    use core::fmt::Write as _;
    use litebox_platform_linux_userland::LinuxUserland as Platform;
    use std::{
        path::{Path, PathBuf},
        process::Command,
        string::{String, ToString},
    };

    const KEY_STACK_CMD: u32 = KeyStackCommandId::DeriveTaSvnKeyStack as u32;

    struct Case {
        key_size: u32,
        stack_size: u32,
        ta_svn: u32,
        uuid: [u8; 16],
        extra_data: Vec<u8>,
    }

    fn compile_c_reference(dir: &Path) -> PathBuf {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/keystack_ref.c");
        let out = dir.join("keystack_ref");
        let output = Command::new("gcc")
            .args(["-O2", "-Wall", "-Wextra", "-o"])
            .arg(&out)
            .arg(&src)
            .arg("-lcrypto")
            .output()
            .unwrap_or_else(|e| panic!("failed to run gcc (is a C toolchain installed?): {e}"));
        assert!(
            output.status.success(),
            "failed to compile {} (needs gcc and libssl-dev):\n{}",
            src.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        out
    }

    fn run_c_reference(cases: &[Case]) -> Vec<String> {
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

        let output = Command::new(&bin)
            .arg(&cases_path)
            .output()
            .expect("run C reference");
        assert!(
            output.status.success(),
            "C reference failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        String::from_utf8(output.stdout)
            .expect("C output is utf-8")
            .lines()
            .map(ToString::to_string)
            .collect()
    }

    fn run_rust_implementation(case: &Case) -> String {
        let shim_builder = shim_builder();
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
        task: &Task<Platform>,
        cmd_id: u32,
        params: &mut UteeParams,
    ) -> Result<(), TeeResult> {
        KeyStackPta::invoke_command(task, cmd_id, params).map(|_| ())
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
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
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
            (min_key_size - 1, 8, 0, 8), // key too small
            (max_key_size + 1, 8, 0, 8), // key too large
            (32, 8, 0, TA_DERIVED_EXTRA_DATA_MAX_SIZE + 1), // extra data too long
            (32, 0, 0, 8),               // empty chain
            (32, 4097, 0, 8),            // chain longer than the 4096 maximum
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

    /// Both sides derive from the same HUK: the C reference reads
    /// `/proc/sys/kernel/random/boot_id`, which is what `LinuxUserland` uses.
    #[test]
    #[ignore = "needs gcc + libssl-dev; CI runs it with --run-ignored"]
    fn key_stack_matches_c_reference() {
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
                 ta_svn={} extra_data_len={} (differing keys can also mean \
                 `LinuxUserland` no longer uses the boot ID as the HUK)",
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
}
