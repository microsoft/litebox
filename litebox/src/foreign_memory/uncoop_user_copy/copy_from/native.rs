// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use true_tales::amd64::Amd64Thread;
#[cfg(verus_only)]
use true_tales::amd64::{Reg, cpu_ready, df_clear, df_unchanged};
use true_tales::fmem::ptr::ForeignPtr;
#[cfg(verus_only)]
use true_tales::machine::cpu::Cpu;
use true_tales::rmem::rmem_stack::RmemStack;
use vstd::prelude::*;

use super::super::CopyError;
#[cfg(verus_only)]
use crate::foreign_memory::domains::uncoop_user_fault::UNCOOP_FAULT_REGION;

verus! {

// This function axiomatizes the behavior of `memcpy_fallible`. Callers use the
// shared dispatcher so its contract stays aligned with the True Tales model.
#[verifier::external_body]
pub(super) fn copy_from_uncoop_user_native<RM: RmemStack>(
    dst: &mut [u8],
    src: ForeignPtr,
    hw: &mut Amd64Thread<RM>,
) -> (res: Result<(), CopyError>)
    requires
        old(dst)@.len() > 0,
        old(hw).wf(),
        cpu_ready(old(hw).cpu_spec()),
        df_clear(old(hw).cpu_spec()),
        src.region() == UNCOOP_FAULT_REGION,
        src.cursor().addr() + old(dst)@.len() <= usize::MAX,
    ensures
        final(hw).wf(),
        cpu_ready(final(hw).cpu_spec()),
        df_unchanged(old(hw).cpu_spec(), final(hw).cpu_spec()),
        !old(hw).cpu_spec().get_reg_spec(Reg::Rax).is_slice_ptr()
            ==> final(hw).cpu_spec().get_reg_spec(Reg::Rax) == old(hw).cpu_spec().get_reg_spec(
            Reg::Rax,
        ),
        !old(hw).cpu_spec().get_reg_spec(Reg::Rdx).is_slice_ptr()
            ==> final(hw).cpu_spec().get_reg_spec(Reg::Rdx) == old(hw).cpu_spec().get_reg_spec(
            Reg::Rdx,
        ),
        final(hw).rmem_spec() == old(hw).rmem_spec(),
        final(dst)@.len() == old(dst)@.len(),
{
    let _ = hw;
    // SAFETY: `dst` is a real Rust output slice. `src.cursor()` is the retained
    // userspace pointer; the exception-table copy reports source faults.
    if unsafe {
        crate::mm::exception_table::memcpy_fallible(
            dst.as_mut_ptr(),
            src.cursor().cast_const(),
            dst.len(),
        )
    }.is_ok() {
        Ok(())
    } else {
        Err(CopyError::Fault)
    }
}

} // verus!
