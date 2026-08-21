// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::*;
#[cfg(verus_only)]
use crate::machine::{cpu::*, hardware_thread::*, reg_val::*};
#[cfg(verus_only)]
use crate::rmem::rmem_stack::*;
use vstd::pervasive::unreached;
#[cfg(verus_only)]
use vstd::prelude::*;

verus! {

/// AMD64 Rust-memory pseudo-instructions routed by the `ErasedPPtr` carried in
/// the register.
impl<S: RmemStack> HardwareThread<Amd64Cpu, S> {
    /// Store the least-significant byte of register `src` into the injected
    /// Rust slice cursor held in register `addr`.
    pub fn rmem_int_store_byte(&mut self, addr: Reg, src: Reg)
        requires
            cpu_ready(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(addr) is RustMutSlicePtr,
            old(self).cpu_spec().get_reg_spec(src) is Int,
            ({
                let ptr = old(self).cpu_spec().get_reg_spec(addr);
                let cell = ptr.slice_pptr();
                let offset = ptr.slice_offset();
                &&& old(self).rmem_spec().wf()
                &&& old(self).rmem_spec()->Some_0.has_mut_any(cell)
                &&& old(self).rmem_spec()->Some_0.matches_pptr_any(cell)
                &&& offset < old(self).rmem_spec()->Some_0.view_any(cell).len()
            }),
        ensures
            regs_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            fault_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            ({
                let ptr = old(self).cpu_spec().get_reg_spec(addr);
                let cell = ptr.slice_pptr();
                let offset = ptr.slice_offset();
                &&& final(self).rmem_spec() is Some
                &&& final(self).rmem_spec()->Some_0.wf()
                &&& final(self).rmem_spec()->Some_0.has_mut_any(cell)
                &&& final(self).rmem_spec()->Some_0.matches_pptr_any(cell)
                &&& final(self).rmem_spec()->Some_0.is_mut_any(cell) == old(
                    self,
                ).rmem_spec()->Some_0.is_mut_any(cell)
                &&& final(self).rmem_spec()->Some_0.view_any(cell) == old(
                    self,
                ).rmem_spec()->Some_0.view_any(cell).update(
                    offset as int,
                    low8(old(self).cpu_spec().get_reg_spec(src).as_int()),
                )
                &&& S::mut_preserved_any(
                    final(self).rmem_spec()->Some_0,
                    old(self).rmem_spec()->Some_0,
                    cell,
                )
                &&& S::unchanged_except_any(
                    final(self).rmem_spec()->Some_0,
                    old(self).rmem_spec()->Some_0,
                    cell,
                )
            }),
    {
        let (cell, offset) = self.cpu.regs.get(addr).unwrap_rust_slice_ptr();
        let val: u8 = compute_low8(self.cpu.regs.get(src).unwrap_int());
        let src_buf = [val];
        match self.rmem {
            Option::Some(ref mut rmem) => {
                rmem.copy_from_slice(cell, offset, &src_buf);
            },
            Option::None => unreached(),
        };
    }

    /// Load one byte from the Rust slice cursor in `addr` into `dst`.
    pub fn rmem_int_load_byte(&mut self, dst: Reg, addr: Reg)
        requires
            cpu_ready(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(addr).is_slice_ptr(),
            ({
                let v = old(self).cpu_spec().get_reg_spec(addr);
                let cell = v.slice_pptr();
                let offset = v.slice_offset();
                &&& old(self).rmem_spec().wf()
                &&& old(self).rmem_spec()->Some_0.has_read_any(cell)
                &&& old(self).rmem_spec()->Some_0.matches_pptr_any(cell)
                &&& offset < old(self).rmem_spec()->Some_0.view_any(cell).len()
                &&& old(self).rmem_spec()->Some_0.is_mut_any(cell) == (v is RustMutSlicePtr)
            }),
        ensures
            ({
                let v = old(self).cpu_spec().get_reg_spec(addr);
                let cell = v.slice_pptr();
                let offset = v.slice_offset();
                final(self).cpu_spec().get_reg_spec(dst) == RegVal::Int(
                    old(self).rmem_spec()->Some_0.view_any(cell)[offset as int] as u64,
                )
            }),
            regs_unchanged_except1(old(self).cpu_spec(), final(self).cpu_spec(), dst),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            fault_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
    {
        let (cell, offset, is_mut) = match self.cpu.regs.get(addr) {
            RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr, offset }) => (
                slice_pptr,
                offset,
                true,
            ),
            RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr, offset }) => (
                slice_pptr,
                offset,
                false,
            ),
            _ => { unreached() },
        };
        let mut dst_buf = [0u8];
        match self.rmem {
            Option::Some(ref rmem) => {
                rmem.copy_to_slice(cell, offset, is_mut, &mut dst_buf);
            },
            Option::None => unreached(),
        };
        let value = dst_buf[0];
        self.cpu.regs.set(dst, RegVal::int(value as u64));
    }
}

} // verus!
