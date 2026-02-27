// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    debug_serial_println,
    host::per_cpu_variables::with_per_cpu_variables,
    mshv::{
        DEFAULT_REG_PIN_MASK, HV_REGISTER_PENDING_EVENT0, HV_X64_REGISTER_APIC_BASE,
        HV_X64_REGISTER_CR0, HV_X64_REGISTER_CR4, HV_X64_REGISTER_CSTAR, HV_X64_REGISTER_EFER,
        HV_X64_REGISTER_GDTR, HV_X64_REGISTER_IDTR, HV_X64_REGISTER_LDTR, HV_X64_REGISTER_LSTAR,
        HV_X64_REGISTER_RIP, HV_X64_REGISTER_SFMASK, HV_X64_REGISTER_STAR,
        HV_X64_REGISTER_SYSENTER_CS, HV_X64_REGISTER_SYSENTER_EIP, HV_X64_REGISTER_SYSENTER_ESP,
        HV_X64_REGISTER_TR, HvInterceptMessage, HvInterceptMessageHeader, HvMemInterceptMessage,
        HvMessageType, HvMsrInterceptMessage, HvPendingExceptionEvent, MSR_CSTAR, MSR_EFER,
        MSR_IA32_APICBASE, MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_EIP, MSR_IA32_SYSENTER_ESP,
        MSR_LSTAR, MSR_STAR, MSR_SYSCALL_MASK, X86Cr0Flags, X86Cr4Flags, hvcall::HypervCallError,
        hvcall_vp::hvcall_set_vp_vtl0_registers,
    },
};
use num_enum::TryFromPrimitive;

/// A list of MSR indexes that VSM prevents VTL0 from writing to.
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum InterceptedMsrIndex {
    MsrEfer = MSR_EFER,
    MsrStar = MSR_STAR,
    MsrLstar = MSR_LSTAR,
    MsrCstar = MSR_CSTAR,
    MsrSyscallMask = MSR_SYSCALL_MASK,
    MsrApicBase = MSR_IA32_APICBASE,
    MsrSysenterCs = MSR_IA32_SYSENTER_CS,
    MsrSysenterEsp = MSR_IA32_SYSENTER_ESP,
    MsrSysenterEip = MSR_IA32_SYSENTER_EIP,
    Unknown = 0xffff_ffff,
}

/// A list of control registers that VSM prevents VTL0 from writing to.
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum InterceptedRegisterName {
    HvX64RegisterCr0 = HV_X64_REGISTER_CR0,
    HvX64RegisterCr4 = HV_X64_REGISTER_CR4,
    HvX64RegisterGdtr = HV_X64_REGISTER_GDTR,
    HvX64RegisterIdtr = HV_X64_REGISTER_IDTR,
    HvX64RegisterLdtr = HV_X64_REGISTER_LDTR,
    HvX64RegisterTr = HV_X64_REGISTER_TR,
    Unknown = 0xffff_ffff,
}

/// # Panics
///
/// Panics if:
/// - Failed to get intercept message type
/// - Failed to raise VTL0 GP fault
/// - Intercepted write to unknown MSR/register
pub fn vsm_handle_intercept() {
    // Extract the intercept message from the SIMP page and clear it,
    // all within the `with_per_cpu_variables` scope.
    let msg = with_per_cpu_variables(|pcv| pcv.take_sint_message(0));

    match HvMessageType::try_from(msg.header.message_type).unwrap() {
        HvMessageType::GpaIntercept => {
            let int_msg = unsafe {
                let ptr = core::ptr::addr_of!(msg.payload).cast::<HvMemInterceptMessage>();
                &*ptr
            };

            let gpa = int_msg.gpa;
            debug_serial_println!("VSM: GPA intercept on {gpa:#x}");
            raise_vtl0_gp_fault().expect("Failed to raise VTL0 GP fault on GPA intercept");
        }
        HvMessageType::MsrIntercept => {
            let int_msg = unsafe {
                let ptr = core::ptr::addr_of!(msg.payload).cast::<HvMsrInterceptMessage>();
                &*ptr
            };

            let msr_index = int_msg.msr;
            let value = (int_msg.rdx << 32) | (int_msg.rax & 0xffff_ffff);

            // `msr_index` contains an intercepted architectural MSR index. Translate it to the corresponding Hyper-V register name.
            let reg_name = match InterceptedMsrIndex::try_from(msr_index)
                .unwrap_or(InterceptedMsrIndex::Unknown)
            {
                InterceptedMsrIndex::MsrEfer => HV_X64_REGISTER_EFER,
                InterceptedMsrIndex::MsrStar => HV_X64_REGISTER_STAR,
                InterceptedMsrIndex::MsrLstar => HV_X64_REGISTER_LSTAR,
                InterceptedMsrIndex::MsrCstar => HV_X64_REGISTER_CSTAR,
                InterceptedMsrIndex::MsrSyscallMask => HV_X64_REGISTER_SFMASK,
                InterceptedMsrIndex::MsrApicBase => HV_X64_REGISTER_APIC_BASE,
                InterceptedMsrIndex::MsrSysenterCs => HV_X64_REGISTER_SYSENTER_CS,
                InterceptedMsrIndex::MsrSysenterEsp => HV_X64_REGISTER_SYSENTER_ESP,
                InterceptedMsrIndex::MsrSysenterEip => HV_X64_REGISTER_SYSENTER_EIP,
                InterceptedMsrIndex::Unknown => {
                    panic!("Intercepted write to unexpected MSR {msr_index:#x}");
                }
            };

            validate_and_continue_vtl0_register_write(
                reg_name,
                value,
                DEFAULT_REG_PIN_MASK,
                &int_msg.hdr,
            );
        }
        HvMessageType::RegisterIntercept => {
            let int_msg = unsafe {
                let ptr = core::ptr::addr_of!(msg.payload).cast::<HvInterceptMessage>();
                &*ptr
            };

            let reg_name = int_msg.reg_name;
            let value = unsafe { int_msg.info.reg_value_low };

            match InterceptedRegisterName::try_from(reg_name)
                .unwrap_or(InterceptedRegisterName::Unknown)
            {
                InterceptedRegisterName::HvX64RegisterCr0 => {
                    let mask = u64::from(X86Cr0Flags::CR0_PIN_MASK.bits());
                    validate_and_continue_vtl0_register_write(reg_name, value, mask, &int_msg.hdr);
                }
                InterceptedRegisterName::HvX64RegisterCr4 => {
                    let mask = u64::from(X86Cr4Flags::CR4_PIN_MASK.bits());
                    validate_and_continue_vtl0_register_write(reg_name, value, mask, &int_msg.hdr);
                }
                InterceptedRegisterName::HvX64RegisterGdtr
                | InterceptedRegisterName::HvX64RegisterIdtr
                | InterceptedRegisterName::HvX64RegisterLdtr
                | InterceptedRegisterName::HvX64RegisterTr => {
                    // any write attempts to these registers are disallowed
                    raise_vtl0_gp_fault().expect("Failed to raise VTL0 GP fault");
                }
                InterceptedRegisterName::Unknown => {
                    panic!("Intercepted write to unexpected register {reg_name:#x}");
                }
            }
        }
        _ => {
            let msg_type = msg.header.message_type;
            debug_serial_println!(
                "VSM: Ignore unknown synthetic interrupt message type {msg_type:#x}"
            );
        }
    }
}

#[inline]
fn advance_vtl0_rip(int_msg_hdr: &HvInterceptMessageHeader) -> Result<u64, HypervCallError> {
    let new_vtl0_rip = int_msg_hdr.rip + u64::from(int_msg_hdr.instruction_length);
    hvcall_set_vp_vtl0_registers(HV_X64_REGISTER_RIP, new_vtl0_rip)
}

#[inline]
pub fn raise_vtl0_gp_fault() -> Result<u64, HypervCallError> {
    let mut exception = HvPendingExceptionEvent::new();
    exception.set_event_pending(true);
    exception.set_event_type(0_u8);
    exception.set_deliver_error_code(true);
    exception.set_vector(u16::from(
        x86_64::structures::idt::ExceptionVector::GeneralProtection as u8,
    ));
    exception.set_error_code(0_u32);

    hvcall_set_vp_vtl0_registers(HV_REGISTER_PENDING_EVENT0, exception.as_u64())
}

#[inline]
fn validate_and_continue_vtl0_register_write(
    reg_name: u32,
    value: u64,
    mask: u64,
    int_msg_hdr: &HvInterceptMessageHeader,
) {
    let allowed_value = with_per_cpu_variables(|per_cpu_variables| {
        per_cpu_variables.vtl0_locked_regs.get().get(reg_name)
    });
    if let Some(allowed_value) = allowed_value {
        if value & mask == allowed_value {
            hvcall_set_vp_vtl0_registers(reg_name, value).expect("Failed to write VTL0 register");
            advance_vtl0_rip(int_msg_hdr).expect("Failed to advance VTL0 RIP");
        } else {
            debug_serial_println!("VSM: Writing {value:#x} to reg {reg_name:#x} is disallowed");
            raise_vtl0_gp_fault().expect("Failed to raise VTL0 GP fault");
        }
    } else {
        panic!("vtl0_locked_regs does not contain register {reg_name:#x}");
    }
}
