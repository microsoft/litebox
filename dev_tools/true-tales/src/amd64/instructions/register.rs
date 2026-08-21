// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::*;
#[cfg(verus_only)]
use crate::machine::{cpu::*, hardware_thread::*, reg_val::*};
#[cfg(verus_only)]
use crate::rmem::rmem_stack::*;
#[cfg(verus_only)]
use vstd::prelude::*;

verus! {

impl<S: RmemStack> HardwareThread<Amd64Cpu, S> {
    /// Load an immediate value into a register.
    pub fn reg_int_load_imm64(&mut self, reg: Reg, imm: u64)
        requires
            cpu_ready(old(self).cpu_spec()),
        ensures
            final(self).cpu_spec().get_reg_spec(reg) == RegVal::Int(imm),
            regs_unchanged_except1(old(self).cpu_spec(), final(self).cpu_spec(), reg),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            fault_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
    {
        self.cpu.regs.set(reg, RegVal::int(imm));
    }

    /// Add an immediate value to a register value with no Rust-slice capability.
    pub fn reg_int_add_imm64(&mut self, reg: Reg, imm: u64)
        requires
            cpu_ready(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(reg) is Int,
            (old(self).cpu_spec().get_reg_spec(reg).as_int() as nat) + (imm as nat)
                <= u64::MAX as nat,
        ensures
            final(self).cpu_spec().get_reg_spec(reg) == RegVal::Int(
                (old(self).cpu_spec().get_reg_spec(reg).as_int() + imm) as u64,
            ),
            regs_unchanged_except1(old(self).cpu_spec(), final(self).cpu_spec(), reg),
            final(self).cpu_spec().flags_spec() == old(
                self,
            ).cpu_spec().flags_spec().arith_write_all(),
            fault_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
    {
        let old_val = self.cpu.regs.get(reg).unwrap_int();
        self.cpu.regs.set(reg, RegVal::int(old_val + imm));
        self.cpu.flags = self.cpu.flags.compute_arith_write_all();
    }

    /// Decrements a plain integer register by one and sets the zero flag to
    /// reflect whether the result is zero (this is what the following `jnz`
    /// reads). The `bits >= 1` precondition keeps the result in range; the
    /// byte-copy loop only decrements while the counter is non-zero, so it is
    /// always met.
    pub fn reg_int_dec(&mut self, reg: Reg)
        requires
            cpu_ready(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(reg) is Int,
            old(self).cpu_spec().get_reg_spec(reg).as_int() >= 1,
        ensures
            final(self).cpu_spec().get_reg_spec(reg) == RegVal::Int(
                (old(self).cpu_spec().get_reg_spec(reg).as_int() - 1) as u64,
            ),
            final(self).cpu_spec().flags_spec() == old(self).cpu_spec().flags_spec().arith_write(
                FlagVal::Defined(final(self).cpu_spec().get_reg_spec(reg).as_int() == 0),
            ),
            regs_unchanged_except1(old(self).cpu_spec(), final(self).cpu_spec(), reg),
            fault_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
    {
        let old_val = self.cpu.regs.get(reg).unwrap_int();
        let new_bits = old_val - 1;
        self.cpu.regs.set(reg, RegVal::int(new_bits));
        self.cpu.flags = self.cpu.flags.compute_arith_write(FlagVal::Defined(new_bits == 0));
    }

    /// Capability-preserving cursor increment by one byte, distinct from the
    /// plain-integer `add_imm64`. For a `RustMutSlicePtr` or
    /// `RustSharedSlicePtr`, only the offset advances; the slice capability
    /// stays fixed. For a `ForeignMemPtr`, the domain and region stay fixed
    /// while the offset is bumped.
    pub fn reg_ptr_inc(&mut self, reg: Reg)
        requires
            cpu_ready(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(reg) is RustMutSlicePtr || old(
                self,
            ).cpu_spec().get_reg_spec(reg) is RustSharedSlicePtr || old(
                self,
            ).cpu_spec().get_reg_spec(reg) is ForeignMemPtr,
            old(self).cpu_spec().get_reg_spec(reg).is_slice_ptr() ==> old(
                self,
            ).cpu_spec().get_reg_spec(reg).slice_offset() < usize::MAX,
            old(self).cpu_spec().get_reg_spec(reg) is ForeignMemPtr ==> old(
                self,
            ).cpu_spec().get_reg_spec(reg).foreign_offset() < usize::MAX,
        ensures
            old(self).cpu_spec().get_reg_spec(reg) is RustMutSlicePtr ==> {
                &&& final(self).cpu_spec().get_reg_spec(reg) is RustMutSlicePtr
                &&& final(self).cpu_spec().get_reg_spec(reg).slice_pptr() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).slice_pptr()
                &&& final(self).cpu_spec().get_reg_spec(reg).slice_addr() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).slice_addr()
                &&& final(self).cpu_spec().get_reg_spec(reg).slice_offset() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).slice_offset() + 1
            },
            old(self).cpu_spec().get_reg_spec(reg) is RustSharedSlicePtr ==> {
                &&& final(self).cpu_spec().get_reg_spec(reg) is RustSharedSlicePtr
                &&& final(self).cpu_spec().get_reg_spec(reg).slice_pptr() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).slice_pptr()
                &&& final(self).cpu_spec().get_reg_spec(reg).slice_addr() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).slice_addr()
                &&& final(self).cpu_spec().get_reg_spec(reg).slice_offset() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).slice_offset() + 1
            },
            old(self).cpu_spec().get_reg_spec(reg) is ForeignMemPtr ==> {
                &&& final(self).cpu_spec().get_reg_spec(reg) is ForeignMemPtr
                &&& final(self).cpu_spec().get_reg_spec(reg).foreign_domain() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).foreign_domain()
                &&& final(self).cpu_spec().get_reg_spec(reg).foreign_region() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).foreign_region()
                &&& final(self).cpu_spec().get_reg_spec(reg).foreign_ptr() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).foreign_ptr().advance(1)
                &&& old(self).cpu_spec().get_reg_spec(reg).foreign_offset() < usize::MAX
                    ==> final(self).cpu_spec().get_reg_spec(reg).foreign_offset() == old(
                    self,
                ).cpu_spec().get_reg_spec(reg).foreign_offset() + 1
            },
            regs_unchanged_except1(old(self).cpu_spec(), final(self).cpu_spec(), reg),
            final(self).cpu_spec().flags_spec() == old(self).cpu_spec().flags_spec().arith_write(
                FlagVal::Undef,
            ),
            fault_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
    {
        let old_val = self.cpu.regs.get(reg);
        match old_val {
            RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr, offset }) => {
                self.cpu.regs.set(reg, RegVal::rust_mut_slice_ptr(slice_pptr, offset + 1));
            },
            RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr, offset }) => {
                self.cpu.regs.set(reg, RegVal::rust_shared_slice_ptr(slice_pptr, offset + 1));
            },
            RegVal::ForeignMemPtr(ptr) => {
                self.cpu.regs.set(reg, RegVal::foreign_mem_ptr(ptr.advance(1)));
            },
            _ => {},
        }
        self.cpu.flags = self.cpu.flags.compute_arith_write(FlagVal::Undef);
    }

    /// Clear the direction flag.
    pub fn cld(&mut self)
        requires
            cpu_ready(old(self).cpu_spec()),
        ensures
            regs_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            final(self).cpu_spec().flags_spec() == old(self).cpu_spec().flags_spec().clear_df(),
            fault_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
    {
        self.cpu.flags = self.cpu.flags.compute_clear_df();
    }
}

} // verus!
