//! VTL switch related functions

use crate::{
    host::{
        hv_hypercall_page_address,
        per_cpu_variables::{
            PerCpuVariablesAsmOffset, with_per_cpu_variables, with_per_cpu_variables_asm_mut,
            with_per_cpu_variables_mut,
        },
    },
    mshv::{
        HV_REGISTER_VSM_CODEPAGE_OFFSETS, HV_VTL_NORMAL, HvRegisterVsmCodePageOffsets,
        NUM_VTLCALL_PARAMS, VTL_ENTRY_REASON_INTERRUPT, VTL_ENTRY_REASON_LOWER_VTL_CALL,
        VsmFunction, hvcall_vp::hvcall_get_vp_registers, vsm::vsm_dispatch,
        vsm_intercept::vsm_handle_intercept, vsm_optee_smc,
    },
};
use core::arch::{asm, naked_asm};
use litebox_common_linux::errno::Errno;
use num_enum::TryFromPrimitive;

/// Assembly macro to return to VTL0 using the Hyper-V hypercall stub.
/// Although Hyper-V lets each core use the same VTL return address, this implementation
/// uses per-CPU return address to avoid using a mutable global variable.
/// `ret_off` is the offset of the PerCpuVariablesAsm which holds the VTL return address.
macro_rules! VTL_RETURN_ASM {
    ($ret_off:tt) => {
        concat!(
            "xor ecx, ecx\n",
            "mov rax, gs:[",
            stringify!($ret_off),
            "]\n",
            "call rax\n",
        )
    };
}

// The following registers are shared between different VTLs.
// If VTL entry is due to VTL call, we don't need to worry about VTL0 registers because
// the caller saves them. However, if VTL entry is due to interrupt or intercept,
// we should save/restore VTL0 registers. For now, we conservatively save/restore all
// VTL0/VTL1 registers (results in performance degradation) but we can optimize it later.
/// Struct to save VTL state (general-purpose registers)
#[allow(clippy::pub_underscore_fields)]
#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct VtlState {
    pub rbp: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // To ease the stack alignment, ensure this struct size is multiple of 16 bytes.
    // (15 + 1) * 8 = 128. 128 % 16 == 0
    pub _pad: u64,
    // CR2
    // DR[0-6]
    // We use a separeate buffer to save/register extended states
    // X87, XMM, AVX, XCR
}

impl VtlState {
    pub fn new() -> Self {
        VtlState {
            ..VtlState::default()
        }
    }

    pub fn get_rax_rcx(&self) -> (u64, u64) {
        (self.rax, self.rcx)
    }

    pub fn get_vtlcall_params(&self) -> [u64; NUM_VTLCALL_PARAMS] {
        [self.rdi, self.rsi, self.rdx, self.r8]
    }
}

pub fn vtl_switch_loop_entry(platform: Option<&'static crate::Platform>) -> ! {
    if let Some(platform) = platform {
        crate::set_platform_low(platform);
    }
    unsafe {
        asm!(
            "jmp {vtl_switch_loop_asm}",
            vtl_switch_loop_asm = sym vtl_switch_loop_asm,
            options(noreturn, nostack, preserves_flags),
        );
    }
}

/// Assembly macro to save VTL state using the stack as temporary storage.
/// `fn_save_state` is the function to save VTL state stored in the stack.
/// `scratch_off` is the offset of the PerCpuVariablesAsm which holds the
/// scratch space to save/restore the current stack pointer.
macro_rules! SAVE_VTL_STATE_ASM {
    ($fn_save_state:tt, $scratch_off:tt) => {
        concat!(
            "mov gs:[",
            stringify!($scratch_off),
            "], rsp\n",
            "push r15\n", // alignment
            "push r15\n",
            "push r14\n",
            "push r13\n",
            "push r12\n",
            "push r11\n",
            "push r10\n",
            "push r9\n",
            "push r8\n",
            "push rdi\n",
            "push rsi\n",
            "push rdx\n",
            "push rcx\n",
            "push rbx\n",
            "push rax\n",
            "push rbp\n",
            "lea rdi, [rsp]\n",
            "call ",
            stringify!($fn_save_state),
            "\n",
            "mov rsp, gs:[",
            stringify!($scratch_off),
            "]\n",
        )
    };
}

/// Assembly macro to load VTL state. It uses the stack as temporary storage.
/// `fn_load_state` is the function to load VTL state to the stack.
/// `state_size` is the size of `VtlState` structure.
/// `scratch_off` is the offset of the PerCpuVariablesAsm which holds the scratch space to
/// save/restore the current stack pointer.
macro_rules! LOAD_VTL_STATE_ASM {
    ($fn_load_state:tt, $state_size:tt, $scratch_off:tt) => {
        concat!(
            "mov gs:[",
            stringify!($scratch_off),
            "], rsp\n",
            "sub rsp, ",
            stringify!($state_size),
            "\n",
            "lea rdi, [rsp]\n",
            "call ",
            stringify!($fn_load_state),
            "\n",
            "mov rsp, gs:[",
            stringify!($scratch_off),
            "]\n", // anchor
            "sub rsp, ",
            stringify!($state_size),
            "\n",
            "pop rbp\n",
            "pop rax\n",
            "pop rbx\n",
            "pop rcx\n",
            "pop rdx\n",
            "pop rsi\n",
            "pop rdi\n",
            "pop r8\n",
            "pop r9\n",
            "pop r10\n",
            "pop r11\n",
            "pop r12\n",
            "pop r13\n",
            "pop r14\n",
            "pop r15\n",
            "mov rsp, gs:[",
            stringify!($scratch_off),
            "]\n",
        )
    };
}

/// Saves VTL0 state to per-CPU storage.
///
/// # Safety
/// - `vtl_state` must be a valid pointer to a readable `VtlState` structure
/// - Must be called from VTL1 context with valid per-CPU variables initialized
unsafe extern "C" fn save_vtl0_state(vtl_state: *const VtlState) {
    with_per_cpu_variables_mut(|pcv| {
        let dst = &raw mut pcv.vtl0_state;
        // SAFETY: vtl_state points to valid VtlState.
        // dst points to per-CPU storage initialized during boot.
        unsafe {
            if vtl_state.is_aligned() {
                core::ptr::copy_nonoverlapping(vtl_state, dst, 1);
            } else {
                core::ptr::write(dst, core::ptr::read_unaligned(vtl_state));
            }
        }
    });
}

/// Loads VTL0 state from per-CPU storage.
///
/// # Safety
/// - `vtl_state` must be a valid pointer to a writable `VtlState` structure
/// - Must be called from VTL1 context with valid per-CPU variables initialized
unsafe extern "C" fn load_vtl0_state(vtl_state: *mut VtlState) {
    with_per_cpu_variables(|pcv| {
        let src = &raw const pcv.vtl0_state;
        // SAFETY: src points to per-CPU storage with valid VtlState.
        // vtl_state points to valid VtlState space.
        unsafe {
            if vtl_state.is_aligned() {
                core::ptr::copy_nonoverlapping(src, vtl_state, 1);
            } else {
                core::ptr::write_unaligned(vtl_state, core::ptr::read(src));
            }
        }
    });
}

#[unsafe(naked)]
unsafe extern "C" fn vtl_switch_loop_asm() -> ! {
    naked_asm!(
        "1:",
        "mov rsp, gs:[{kernel_sp_off}]", // reset kernel stack pointer. Hyper-V saves/restores rsp and rip.
        VTL_RETURN_ASM!({vtl_ret_addr_off}),
        // *** VTL1 resumes here regardless of the entry reason (VTL switch or intercept) ***
        SAVE_VTL_STATE_ASM!({save_vtl0_state}, {scratch_off}),
        "mov rbp, rsp", // rbp contains VTL0's stack frame, so update it.
        "call {loop_body}",
        LOAD_VTL_STATE_ASM!({load_vtl0_state}, {vtl_state_size}, {scratch_off}),
        "jmp 1b",
        kernel_sp_off = const { PerCpuVariablesAsmOffset::KernelStackPtr as usize },
        vtl_ret_addr_off = const { PerCpuVariablesAsmOffset::VtlReturnAddr as usize },
        scratch_off = const { PerCpuVariablesAsmOffset::Scratch as usize },
        save_vtl0_state = sym save_vtl0_state,
        load_vtl0_state = sym load_vtl0_state,
        vtl_state_size = const core::mem::size_of::<VtlState>(),
        loop_body = sym vtl_switch_loop_body,
    )
}

unsafe extern "C" fn vtl_switch_loop_body() {
    // TODO: We must save/restore VTL1's state when there is RPC from VTL1 to VTL0 (e.g., dynamically
    // loading OP-TEE TAs). This should use global data structures since the core which makes the RPC
    // can be different from the core where the VTL1 is running.
    // TODO: Even if we don't have RPC from VTL1 to VTL0, we may still need to save VTL1's state for
    // debugging purposes.

    // Since we do not know whether the VTL0 kernel saves its extended states (e.g., if a VTL switch
    // is due to memory or register access violation, the VTL0 kernel might not have saved
    // its states), we conservatively save and restore its extended states on every VTL switch.
    with_per_cpu_variables_mut(|per_cpu_variables| {
        per_cpu_variables.save_extended_states(HV_VTL_NORMAL);
    });

    let reason = with_per_cpu_variables(|per_cpu_variables| unsafe {
        (*per_cpu_variables.hv_vp_assist_page_as_ptr()).vtl_entry_reason
    });
    match VtlEntryReason::try_from(reason).unwrap_or(VtlEntryReason::Unknown) {
        #[allow(clippy::cast_sign_loss)]
        VtlEntryReason::VtlCall => {
            let params = with_per_cpu_variables(|per_cpu_variables| {
                per_cpu_variables.vtl0_state.get_vtlcall_params()
            });
            if VsmFunction::try_from(u32::try_from(params[0]).unwrap_or(u32::MAX))
                .unwrap_or(VsmFunction::Unknown)
                == VsmFunction::Unknown
            {
                todo!("unknown function ID = {:#x}", params[0]);
            } else {
                let result = vtlcall_dispatch(&params);
                with_per_cpu_variables_mut(|per_cpu_variables| {
                    per_cpu_variables.set_vtl_return_value(result as u64);
                });
            }
        }
        VtlEntryReason::Interrupt => {
            vsm_handle_intercept();
        }
        VtlEntryReason::Unknown => {}
    }

    with_per_cpu_variables(|per_cpu_variables| {
        per_cpu_variables.restore_extended_states(HV_VTL_NORMAL);
    });
}

fn vtlcall_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> i64 {
    let func_id = VsmFunction::try_from(u32::try_from(params[0]).unwrap_or(u32::MAX))
        .unwrap_or(VsmFunction::Unknown);
    match func_id {
        VsmFunction::Unknown => Errno::EINVAL.as_neg().into(),
        VsmFunction::OpteeMessage => vsm_optee_smc::optee_smc_dispatch(params[1]),
        _ => vsm_dispatch(func_id, &params[1..]),
    }
}

pub(crate) fn mshv_vsm_get_code_page_offsets() -> Result<(), Errno> {
    let value =
        hvcall_get_vp_registers(HV_REGISTER_VSM_CODEPAGE_OFFSETS).map_err(|_| Errno::EIO)?;
    let code_page_offsets = HvRegisterVsmCodePageOffsets::from_u64(value);
    let hvcall_page = usize::try_from(hv_hypercall_page_address()).unwrap();
    let vtl_return_address = hvcall_page
        .checked_add(usize::from(code_page_offsets.vtl_return_offset()))
        .ok_or(Errno::EOVERFLOW)?;
    with_per_cpu_variables_asm_mut(|pcv_asm| {
        pcv_asm.set_vtl_return_addr(vtl_return_address);
    });
    Ok(())
}

/// VTL Entry Reason
#[derive(Debug, TryFromPrimitive)]
#[repr(u32)]
pub enum VtlEntryReason {
    VtlCall = VTL_ENTRY_REASON_LOWER_VTL_CALL,
    Interrupt = VTL_ENTRY_REASON_INTERRUPT,
    Unknown = 0xffff_ffff,
}
