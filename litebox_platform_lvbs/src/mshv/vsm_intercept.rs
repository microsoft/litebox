use crate::{
    kernel_context::get_per_core_kernel_context,
    mshv::{
        DEFAULT_REG_PIN_MASK, HV_REGISTER_PENDING_EVENT0, HV_X64_REGISTER_APIC_BASE,
        HV_X64_REGISTER_CR0, HV_X64_REGISTER_CR4, HV_X64_REGISTER_CSTAR, HV_X64_REGISTER_EFER,
        HV_X64_REGISTER_GDTR, HV_X64_REGISTER_IDTR, HV_X64_REGISTER_LDTR, HV_X64_REGISTER_LSTAR,
        HV_X64_REGISTER_RIP, HV_X64_REGISTER_SFMASK, HV_X64_REGISTER_STAR,
        HV_X64_REGISTER_SYSENTER_CS, HV_X64_REGISTER_SYSENTER_EIP, HV_X64_REGISTER_SYSENTER_ESP,
        HV_X64_REGISTER_TR, HvInterceptMessage, HvInterceptMessageHeader, HvMemInterceptMessage,
        HvMessageType, HvMsrInterceptMessage, HvPendingExceptionEvent, MSR_CSTAR, MSR_EFER,
        MSR_IA32_APICBASE, MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_EIP, MSR_IA32_SYSENTER_ESP,
        MSR_LSTAR, MSR_STAR, MSR_SYSCALL_MASK, X86Cr0Flags, X86Cr4Flags,
        hvcall_vp::hvcall_set_vp_vtl0_registers,
    },
    serial_println,
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

#[allow(clippy::too_many_lines)]
pub fn vsm_handle_intercept() -> i64 {
    let kernel_context = get_per_core_kernel_context();
    let simp_page = kernel_context.hv_simp_page_as_mut_ptr();

    let msg_type = unsafe { (*simp_page).sint_message[0].header.message_type };
    unsafe {
        (*simp_page).sint_message[0].header.message_type = HvMessageType::None.into();
    }
    let payload = unsafe { (*simp_page).sint_message[0].payload };

    match HvMessageType::try_from(msg_type).unwrap() {
        HvMessageType::GpaIntercept => {
            let int_msg = unsafe {
                let ptr = payload.as_ptr().cast::<HvMemInterceptMessage>();
                &(*ptr) as &HvMemInterceptMessage
            };

            let gpa = int_msg.gpa;
            serial_println!("VSM: GPA intercept on {:#x}", gpa);
            return raise_vtl0_gp_fault();
        }
        HvMessageType::MsrIntercept => {
            let int_msg = unsafe {
                let ptr = payload.as_ptr().cast::<HvMsrInterceptMessage>();
                &(*ptr) as &HvMsrInterceptMessage
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
                    panic!(
                        "Intercepted write to MSR {:#x} that we do not expect",
                        msr_index,
                    );
                }
            };

            if !check_and_write_vtl0_register(reg_name, value, DEFAULT_REG_PIN_MASK) {
                serial_println!(
                    "VSM: Writing a value ({:#x}) to MSR {:#x} is disallowed",
                    value,
                    msr_index,
                );
                return raise_vtl0_gp_fault();
            }

            let int_msg_hdr = int_msg.hdr;
            advance_vtl0_rip(&int_msg_hdr)
        }
        HvMessageType::RegisterIntercept => {
            let int_msg = unsafe {
                let ptr = payload.as_ptr().cast::<HvInterceptMessage>();
                &(*ptr) as &HvInterceptMessage
            };

            let reg_name = int_msg.reg_name;
            let value = unsafe { int_msg.info.reg_value_low };

            let mask = match InterceptedRegisterName::try_from(reg_name)
                .unwrap_or(InterceptedRegisterName::Unknown)
            {
                InterceptedRegisterName::HvX64RegisterCr0 => {
                    u64::from(X86Cr0Flags::CR0_PIN_MASK.bits())
                }
                InterceptedRegisterName::HvX64RegisterCr4 => {
                    u64::from(X86Cr4Flags::CR4_PIN_MASK.bits())
                }
                InterceptedRegisterName::HvX64RegisterGdtr
                | InterceptedRegisterName::HvX64RegisterIdtr
                | InterceptedRegisterName::HvX64RegisterLdtr
                | InterceptedRegisterName::HvX64RegisterTr => {
                    // any write attempts to these registers are disallowed
                    return raise_vtl0_gp_fault();
                }
                InterceptedRegisterName::Unknown => {
                    panic!(
                        "Intercepted write to register {:#x} that we do not expect",
                        reg_name
                    );
                }
            };

            if !check_and_write_vtl0_register(reg_name, value, mask) {
                serial_println!(
                    "VSM: Writing a value ({:#x}) to reg {:#x} is disallowed",
                    value,
                    reg_name
                );
                return raise_vtl0_gp_fault();
            }

            let int_msg_hdr = int_msg.hdr;
            advance_vtl0_rip(&int_msg_hdr)
        }
        _ => {
            serial_println!(
                "VSM: Ignore unhandled/unknown synthetic interrupt message type {:#x}",
                msg_type
            );
            return 0;
        }
    };

    0
}

#[inline]
fn advance_vtl0_rip(int_msg_hdr: &HvInterceptMessageHeader) -> i64 {
    let new_vtl0_rip = int_msg_hdr.rip + u64::from(int_msg_hdr.instruction_length);

    if let Err(result) = write_vtl0_register(HV_X64_REGISTER_RIP, new_vtl0_rip) {
        return result;
    }
    0
}

#[inline]
fn raise_vtl0_gp_fault() -> i64 {
    let mut exception = HvPendingExceptionEvent::new();
    exception.set_event_pending();
    exception.set_event_type(0);
    exception.set_deliver_error_code();
    exception.set_vector(u64::from(
        x86_64::structures::idt::ExceptionVector::GeneralProtection as u8,
    ));
    exception.set_error_code(0);

    if let Err(result) = write_vtl0_register(HV_REGISTER_PENDING_EVENT0, exception.as_u64()) {
        return result;
    }
    0
}

#[inline]
fn write_vtl0_register(reg_name: u32, value: u64) -> Result<(), i64> {
    if let Err(result) = hvcall_set_vp_vtl0_registers(reg_name, value) {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return Err(err.into());
    }

    Ok(())
}

#[inline]
fn check_and_write_vtl0_register(reg_name: u32, value: u64, mask: u64) -> bool {
    let kernel_context = get_per_core_kernel_context();
    if let Some(allowed_value) = kernel_context.vtl0_locked_regs.get(reg_name) {
        if value & mask == allowed_value && write_vtl0_register(reg_name, value).is_ok() {
            return true;
        }
    } else {
        panic!("vtl0_locked_regs does not contain register {:#x}", reg_name);
    }

    false
}
