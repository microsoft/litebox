// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs a TA from the first boot module, a tar with `ldelf.elf`, `ta.elf` and,
//! optionally, `cmds.json` (the format of
//! `litebox_runner_optee_on_linux_userland/tests/*-cmds.json`). Without
//! `cmds.json`, only a session is opened.

use alloc::boxed::Box;
use litebox_bootloader::handoff::BootInfo;
use litebox_common_linux::PtRegs;
use litebox_common_optee::{UteeEntryFunc, UteeParamOwned};
use litebox_platform_vm_kernel::{KERNEL_OFFSET, VmKernel};
use litebox_shim_optee::session::SessionManager;

struct Payload {
    ldelf: &'static [u8],
    ta: &'static [u8],
    command_sequence: Option<&'static str>,
}

fn payload(info: &BootInfo) -> Result<Payload, &'static str> {
    let module = info
        .modules
        .first()
        .ok_or("no payload module (pass -initrd)")?;
    let len = usize::try_from(module.end - module.start).unwrap();
    // Safety: boot modules are excluded from the heap and stay mapped at
    // `PA + KERNEL_OFFSET` for the kernel's lifetime.
    let data: &'static [u8] =
        unsafe { core::slice::from_raw_parts((module.start + KERNEL_OFFSET) as *const u8, len) };
    let archive = tar_no_std::TarArchiveRef::new(data).map_err(|_| "payload is not a tar")?;

    let mut ldelf = None;
    let mut ta = None;
    let mut command_sequence = None;
    for entry in archive.entries() {
        let filename = entry.filename();
        let Ok(name) = filename.as_str() else {
            continue;
        };
        let bytes: &'static [u8] = entry.data();
        match name.trim_start_matches("./") {
            "ldelf.elf" => ldelf = Some(bytes),
            "ta.elf" => ta = Some(bytes),
            "cmds.json" => {
                command_sequence =
                    Some(core::str::from_utf8(bytes).map_err(|_| "cmds.json is not UTF-8")?);
            }
            _ => {}
        }
    }
    Ok(Payload {
        ldelf: ldelf.ok_or("payload has no ldelf.elf")?,
        ta: ta.ok_or("payload has no ta.elf")?,
        command_sequence,
    })
}

/// # Panics
///
/// Panics on any failure, including a TA error.
pub fn run(platform: &'static VmKernel, info: &BootInfo) {
    let payload = payload(info).unwrap_or_else(|e| panic!("payload: {e}"));

    let session_manager: &'static SessionManager<VmKernel> =
        Box::leak(Box::new(SessionManager::new()));
    let shim_builder = litebox_shim_optee::OpteeShimBuilder::new_with_litebox(
        platform,
        session_manager,
        crate::broker::litebox(platform),
    );
    let shim = shim_builder.build();

    // The address space lives until VM exit; no teardown is performed.
    let address_space = platform.create_address_space();
    // Safety: nothing references user memory yet; the task table shares the
    // kernel mappings the kernel is running on.
    unsafe { platform.switch_address_space(address_space) }
        .expect("failed to switch address space");

    match payload.command_sequence {
        None => run_ta_with_default_commands(&shim, payload.ldelf, payload.ta),
        Some(json) => {
            crate::tests::run_ta_with_test_commands(&shim, payload.ldelf, payload.ta, json);
        }
    }
}

fn run_ta_with_default_commands(
    shim: &litebox_shim_optee::OpteeShim<VmKernel>,
    ldelf_bin: &[u8],
    ta_bin: &[u8],
) {
    let ta_uuid = litebox_common_optee::parse_ta_head(ta_bin)
        .expect("Failed to parse TA header from ta_bin")
        .uuid;
    assert!(shim.store_ta_bin(&ta_uuid, ta_bin));
    let params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];

    let session_token = shim
        .session_manager()
        .try_acquire_open_session_token()
        .unwrap();
    let session_id = session_token.session_id().unwrap();
    let loaded_program = shim
        .load_ldelf(ldelf_bin, ta_uuid)
        .unwrap_or_else(|e| panic!("Failed to load ldelf: {e:?}"));
    let entrypoints = loaded_program.entrypoints.as_ref().unwrap();
    let mut ctx = PtRegs::default();
    // Safety: the platform is set up, and threads run one at a time.
    unsafe {
        litebox_platform_vm_kernel::run_thread_ref(entrypoints, &mut ctx);
    }
    assert!(
        ctx.rax == 0,
        "ldelf exits with error: return_code={:#x}",
        ctx.rax
    );

    entrypoints
        .load_ta_context(
            params.as_slice(),
            session_id,
            UteeEntryFunc::OpenSession as u32,
            None,
        )
        .unwrap_or_else(|e| panic!("Failed to load TA context: {e:?}"));
    let mut ctx = PtRegs::default();
    // Safety: the platform is set up, and threads run one at a time.
    unsafe {
        litebox_platform_vm_kernel::reenter_thread_ref(entrypoints, &mut ctx);
    }
    assert!(
        ctx.rax == 0,
        "OpenSession fails: return_code={:#x}",
        ctx.rax
    );
}
