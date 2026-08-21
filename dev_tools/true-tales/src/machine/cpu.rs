// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::ids::ForeignDomainId;
use crate::machine::reg_val::*;
use vstd::prelude::*;

verus! {

pub trait Cpu: Sized + Copy {
    type Reg: Copy;

    spec fn wf(&self) -> bool;

    spec fn ready(&self) -> bool;

    spec fn get_reg_spec(self, reg: Self::Reg) -> RegVal;

    spec fn set_reg_spec(self, reg: Self::Reg, val: RegVal) -> Self;

    fn bind_reg(&mut self, reg: Self::Reg, val: RegVal)
        requires
            old(self).wf(),
            old(self).ready(),
        ensures
            final(self).wf(),
            *final(self) == old(self).set_reg_spec(reg, val),
            final(self).get_reg_spec(reg) == val,
            forall|r: Self::Reg|
                r != reg ==> final(self).get_reg_spec(r) == old(self).get_reg_spec(r),
    ;

    spec fn clear_rust_slice_addr_spec(self, addr: usize) -> Self;

    fn clear_rust_slice_addr(&mut self, addr: usize)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            *final(self) == old(self).clear_rust_slice_addr_spec(addr),
            forall|r: Self::Reg|
                #![auto]
                old(self).get_reg_spec(r).is_slice_ptr() && old(self).get_reg_spec(r).slice_addr()
                    == addr ==> final(self).get_reg_spec(r) == RegVal::Unknown,
            forall|r: Self::Reg|
                #![auto]
                !(old(self).get_reg_spec(r).is_slice_ptr() && old(self).get_reg_spec(r).slice_addr()
                    == addr) ==> final(self).get_reg_spec(r) == old(self).get_reg_spec(r),
    ;

    fn clear_foreign_domain(&mut self, domain: ForeignDomainId)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            forall|r: Self::Reg|
                #![auto]
                old(self).get_reg_spec(r).is_foreign() && old(self).get_reg_spec(
                    r,
                ).foreign_domain().addr() == domain.addr() ==> final(self).get_reg_spec(r)
                    == RegVal::Unknown,
            forall|r: Self::Reg|
                #![auto]
                !(old(self).get_reg_spec(r).is_foreign() && old(self).get_reg_spec(
                    r,
                ).foreign_domain().addr() == domain.addr()) ==> final(self).get_reg_spec(r) == old(
                    self,
                ).get_reg_spec(r),
    ;
}

} // verus!
