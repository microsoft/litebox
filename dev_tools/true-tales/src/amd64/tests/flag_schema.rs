// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::*;
use crate::rmem::rmem_stack::RmemNil;

#[cfg(verus_only)]
use vstd::prelude::*;

verus! {

fn drive_flag_schema() {
    let mut hw = Amd64Thread::<RmemNil>::new();
    let ghost f0 = hw.cpu_spec().flags_spec();

    assert(df_clear(hw.cpu_spec()));
    assert(hw.cpu_spec().flags_spec().df_spec() == false);
    assert(hw.cpu_spec().flags_spec().zf_spec() is Undef);
    assert(cpu_ready(hw.cpu_spec()));

    hw.cld();
    assert(hw.cpu_spec().flags_spec() == f0.clear_df());
    assert(df_clear(hw.cpu_spec()));
    assert(hw.cpu_spec().flags_spec().zf_spec() == f0.zf_spec());

    hw.reg_int_load_imm64(Reg::Rcx, 2);
    assert(hw.cpu_spec().flags_spec().zf_spec() is Undef);

    hw.reg_int_dec(Reg::Rcx);
    assert(hw.cpu_spec().flags_spec().zf_spec() == FlagVal::Defined(false));
    let nonzero = hw.flag_read_zf();
    assert(!nonzero);

    let _ = nonzero;

    hw.reg_int_dec(Reg::Rcx);
    assert(hw.cpu_spec().flags_spec().zf_spec() == FlagVal::Defined(true));
    let zero = hw.flag_read_zf();
    assert(zero);
    let _ = zero;

    assert(df_clear(hw.cpu_spec()));

    let ghost f_dec = hw.cpu_spec().flags_spec();
    hw.reg_int_add_imm64(Reg::Rcx, 7);
    assert(hw.cpu_spec().flags_spec() == f_dec.arith_write_all());
    assert(hw.cpu_spec().flags_spec().zf_spec() is Undef);
    assert(df_clear(hw.cpu_spec()));
    assert(hw.cpu_spec().flags_spec().df_spec() == false);

    assert(cpu_ready(hw.cpu_spec()));
    let faulted = hw.fault_taken();
    assert(!faulted);
    let _ = faulted;
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_schema_drives() {
        drive_flag_schema();
    }
}
