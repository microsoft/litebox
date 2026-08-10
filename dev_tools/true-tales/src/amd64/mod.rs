// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AMD64 (x86-64) specialization of the generic machine model.
use crate::fmem::ids::ForeignDomainId;
use crate::machine::{cpu::*, hardware_thread::*, reg_val::*};
use crate::rmem::rmem_stack::*;
use vstd::prelude::*;

mod instructions;

#[cfg(test)]
mod tests;

verus! {

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Reg {
    Rcx,
    Rsi,
    Rdi,
    Rax,
    Rdx,
}

/// The least-significant byte of a 64-bit register value (the `al` of `rax`),
/// expressed with modulo so it is friendly to Verus arithmetic reasoning (`x %
/// 256` is exactly the low 8 bits).
pub open spec fn low8(x: u64) -> u8 {
    (x % 0x100) as u8
}

/// Executable computation of [`low8`].
fn compute_low8(x: u64) -> (r: u8)
    ensures
        r == low8(x),
{
    (x % 0x100) as u8
}

/// One register's value after a slice purge for capability address `addr`.
pub open spec fn clear_slice_reg_spec(v: RegVal, addr: usize) -> RegVal {
    if v.is_slice_ptr() && v.slice_addr() == addr {
        RegVal::Unknown
    } else {
        v
    }
}

/// All registers outside `regs` are unchanged.
pub open spec fn regs_unchanged_except(pre: Amd64Cpu, post: Amd64Cpu, regs: Set<Reg>) -> bool {
    forall|r: Reg| #![auto] !regs.contains(r) ==> post.get_reg_spec(r) == pre.get_reg_spec(r)
}

/// All registers except `reg` are unchanged.
pub open spec fn regs_unchanged_except1(pre: Amd64Cpu, post: Amd64Cpu, reg: Reg) -> bool {
    forall|r: Reg| r != reg ==> post.get_reg_spec(r) == pre.get_reg_spec(r)
}

/// No registers changed.
pub open spec fn regs_unchanged(pre: Amd64Cpu, post: Amd64Cpu) -> bool {
    post.regs_spec() == pre.regs_spec()
}

/// No flags changed.
pub open spec fn flags_unchanged(pre: Amd64Cpu, post: Amd64Cpu) -> bool {
    post.flags_spec() == pre.flags_spec()
}

/// The recoverable fault latch did not change.
pub open spec fn fault_unchanged(pre: Amd64Cpu, post: Amd64Cpu) -> bool {
    post.ready() == pre.ready()
}

/// Normal instruction execution is allowed only when no recoverable fault is
/// pending.
pub open spec fn cpu_ready(cpu: Amd64Cpu) -> bool {
    cpu.ready()
}

/// Control-flow marker returned by an instruction that latched a recoverable fault.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Fault;

/// The instruction result exactly reflects the recoverable-fault latch.
pub open spec fn fault_result_matches(cpu: Amd64Cpu, out: Result<(), Fault>) -> bool {
    out is Ok <==> cpu_ready(cpu)
}

/// The direction flag did not change. Rust requires DF to be clear on asm block
/// entry and exit, so instructions that write other flags still carry this
/// unchanged condition.
pub open spec fn df_unchanged(pre: Amd64Cpu, post: Amd64Cpu) -> bool {
    post.flags_spec().df_spec() == pre.flags_spec().df_spec()
}

/// The direction flag is clear, i.e. string operations run **forward**.
///
/// Rust guarantees DF clear on entry to an `asm!` block and requires it clear
/// on exit, so this is the state every modelled block starts and ends in; see
/// [`HardwareThread::cld`] for why there is no way to reach the opposite one.
pub open spec fn df_clear(cpu: Amd64Cpu) -> bool {
    !cpu.flags_spec().df_spec()
}

/// The Rust-memory subsystem did not change.
pub open spec fn rmem_unchanged<S: RmemStack>(
    pre: HardwareThread<Amd64Cpu, S>,
    post: HardwareThread<Amd64Cpu, S>,
) -> bool {
    post.rmem_spec() == pre.rmem_spec()
}

/// The value of a status flag.
///
/// On entry to an `asm!` block, x86 makes **no** guarantee about the arithmetic
/// status flags (CF, PF, AF, ZF, SF, OF): each holds an architecturally
/// "undefined value". Only the direction flag (DF) is guaranteed clear on entry
/// (see the Rust Reference, "Rules for inline assembly").
///
/// A status flag is `Undef` until an instruction writes it.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum FlagVal {
    /// Architecturally undefined: its value may not be interpreted.
    Undef,
    /// A defined boolean value.
    Defined(bool),
}

/// The x86 status flags this model carries.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Flags {
    cf: FlagVal,
    pf: FlagVal,
    af: FlagVal,
    df: bool,
    zf: FlagVal,
    sf: FlagVal,
    of: FlagVal,
}

impl Flags {
    /// The direction flag.
    pub closed spec fn df_spec(&self) -> bool {
        self.df
    }

    /// The zero flag.
    pub closed spec fn zf_spec(&self) -> FlagVal {
        self.zf
    }

    /// The flag effect of an arithmetic instruction that does not write CF.
    pub closed spec fn arith_write(self, zf: FlagVal) -> Self {
        Flags {
            cf: self.cf,
            pf: FlagVal::Undef,
            af: FlagVal::Undef,
            df: self.df,
            zf,
            sf: FlagVal::Undef,
            of: FlagVal::Undef,
        }
    }

    /// The flag effect of an arithmetic instruction that writes all six status
    /// flags.
    pub closed spec fn arith_write_all(self) -> Self {
        Flags { cf: FlagVal::Undef, ..self.arith_write(FlagVal::Undef) }
    }

    pub closed spec fn clear_df(self) -> Self {
        Flags { df: false, ..self }
    }

    /// Executable [`Self::arith_write`].
    fn compute_arith_write(self, zf: FlagVal) -> (f: Self)
        ensures
            f == self.arith_write(zf),
    {
        Flags {
            cf: self.cf,
            pf: FlagVal::Undef,
            af: FlagVal::Undef,
            df: self.df,
            zf,
            sf: FlagVal::Undef,
            of: FlagVal::Undef,
        }
    }

    /// Executable [`Self::arith_write_all`].
    fn compute_arith_write_all(self) -> (f: Self)
        ensures
            f == self.arith_write_all(),
    {
        let f = self.compute_arith_write(FlagVal::Undef);
        Flags { cf: FlagVal::Undef, ..f }
    }

    /// Executable [`Self::clear_df`].
    fn compute_clear_df(self) -> (f: Self)
        ensures
            f == self.clear_df(),
    {
        Flags { df: false, ..self }
    }
}

/// The projections of [`Flags::arith_write`] a caller outside this module needs
/// once the constructor's body stops being visible.
pub broadcast proof fn lemma_arith_write_frame(f: Flags, zf: FlagVal)
    ensures
        (#[trigger] f.arith_write(zf)).df_spec() == f.df_spec(),
        f.arith_write(zf).zf_spec() == zf,
{
}

/// The projections of [`Flags::arith_write_all`]; see
/// [`lemma_arith_write_frame`].
pub broadcast proof fn lemma_arith_write_all_frame(f: Flags)
    ensures
        (#[trigger] f.arith_write_all()).df_spec() == f.df_spec(),
        f.arith_write_all().zf_spec() == FlagVal::Undef,
{
}

/// The projections of [`Flags::clear_df`]; see [`lemma_arith_write_frame`].
pub broadcast proof fn lemma_clear_df_frame(f: Flags)
    ensures
        !(#[trigger] f.clear_df()).df_spec(),
        f.clear_df().zf_spec() == f.zf_spec(),
{
}

/// The five architectural registers this model carries.
///
/// TODO: extend to full register set.
#[derive(Copy, Clone)]
pub struct RegisterFile {
    rcx: RegVal,
    rsi: RegVal,
    rdi: RegVal,
    rax: RegVal,
    rdx: RegVal,
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterFile {
    pub fn new() -> (regs: Self)
        ensures
            regs.get_spec(Reg::Rcx) == RegVal::Unknown,
            regs.get_spec(Reg::Rsi) == RegVal::Unknown,
            regs.get_spec(Reg::Rdi) == RegVal::Unknown,
            regs.get_spec(Reg::Rax) == RegVal::Unknown,
            regs.get_spec(Reg::Rdx) == RegVal::Unknown,
    {
        RegisterFile {
            rcx: RegVal::unknown(),
            rsi: RegVal::unknown(),
            rdi: RegVal::unknown(),
            rax: RegVal::unknown(),
            rdx: RegVal::unknown(),
        }
    }

    /// Read register `reg`.
    pub closed spec fn get_spec(&self, reg: Reg) -> RegVal {
        match reg {
            Reg::Rcx => self.rcx,
            Reg::Rsi => self.rsi,
            Reg::Rdi => self.rdi,
            Reg::Rax => self.rax,
            Reg::Rdx => self.rdx,
        }
    }

    /// Functional single-register update; backs [`Amd64Cpu::set_reg_spec`].
    pub closed spec fn set_spec(self, reg: Reg, val: RegVal) -> Self {
        match reg {
            Reg::Rcx => RegisterFile { rcx: val, ..self },
            Reg::Rsi => RegisterFile { rsi: val, ..self },
            Reg::Rdi => RegisterFile { rdi: val, ..self },
            Reg::Rax => RegisterFile { rax: val, ..self },
            Reg::Rdx => RegisterFile { rdx: val, ..self },
        }
    }

    #[verifier::when_used_as_spec(get_spec)]
    pub fn get(&self, reg: Reg) -> (value: RegVal)
        ensures
            value == self.get_spec(reg),
    {
        match reg {
            Reg::Rcx => self.rcx,
            Reg::Rsi => self.rsi,
            Reg::Rdi => self.rdi,
            Reg::Rax => self.rax,
            Reg::Rdx => self.rdx,
        }
    }

    pub(crate) fn set(&mut self, reg: Reg, value: RegVal)
        ensures
            *final(self) == old(self).set_spec(reg, value),
            final(self).get_spec(reg) == value,
            forall|r: Reg| r != reg ==> final(self).get_spec(r) == old(self).get_spec(r),
    {
        match reg {
            Reg::Rcx => {
                self.rcx = value;
            },
            Reg::Rsi => {
                self.rsi = value;
            },
            Reg::Rdi => {
                self.rdi = value;
            },
            Reg::Rax => {
                self.rax = value;
            },
            Reg::Rdx => {
                self.rdx = value;
            },
        }
    }

    fn clear_rust_slice_addr_reg(reg_val: &mut RegVal, addr: usize)
        ensures
            *final(reg_val) == clear_slice_reg_spec(*old(reg_val), addr),
            old(reg_val).is_slice_ptr() && old(reg_val).slice_addr() == addr ==> *final(reg_val)
                == RegVal::Unknown,
            !(old(reg_val).is_slice_ptr() && old(reg_val).slice_addr() == addr) ==> *final(reg_val)
                == *old(reg_val),
    {
        // Explicit match required by Verus.
        #[allow(clippy::collapsible_match)]
        match *reg_val {
            RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr, .. }) => {
                if slice_pptr.addr() == addr {
                    *reg_val = RegVal::unknown();
                }
            },
            RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr, .. }) => {
                if slice_pptr.addr() == addr {
                    *reg_val = RegVal::unknown();
                }
            },
            _ => {},
        }
    }

    fn clear_foreign_domain_reg(reg_val: &mut RegVal, domain: ForeignDomainId)
        ensures
            old(reg_val).is_foreign() && old(reg_val).foreign_domain().addr() == domain.addr()
                ==> *final(reg_val) == RegVal::Unknown,
            !(old(reg_val).is_foreign() && old(reg_val).foreign_domain().addr() == domain.addr())
                ==> *final(reg_val) == *old(reg_val),
    {
        if let RegVal::ForeignMemPtr(ptr) = *reg_val {
            if ptr.domain().addr() == domain.addr() {
                *reg_val = RegVal::unknown();
            }
        }
    }

    pub closed spec fn clear_rust_slice_addr_spec(self, addr: usize) -> Self {
        RegisterFile {
            rcx: clear_slice_reg_spec(self.rcx, addr),
            rsi: clear_slice_reg_spec(self.rsi, addr),
            rdi: clear_slice_reg_spec(self.rdi, addr),
            rax: clear_slice_reg_spec(self.rax, addr),
            rdx: clear_slice_reg_spec(self.rdx, addr),
        }
    }

    pub fn clear_rust_slice_addr(&mut self, addr: usize)
        ensures
            *final(self) == old(self).clear_rust_slice_addr_spec(addr),
            forall|r: Reg|
                #![auto]
                old(self).get_spec(r).is_slice_ptr() && old(self).get_spec(r).slice_addr() == addr
                    ==> final(self).get_spec(r) == RegVal::Unknown,
            forall|r: Reg|
                #![auto]
                !(old(self).get_spec(r).is_slice_ptr() && old(self).get_spec(r).slice_addr()
                    == addr) ==> final(self).get_spec(r) == old(self).get_spec(r),
    {
        Self::clear_rust_slice_addr_reg(&mut self.rcx, addr);
        Self::clear_rust_slice_addr_reg(&mut self.rsi, addr);
        Self::clear_rust_slice_addr_reg(&mut self.rdi, addr);
        Self::clear_rust_slice_addr_reg(&mut self.rax, addr);
        Self::clear_rust_slice_addr_reg(&mut self.rdx, addr);
    }

    pub fn clear_foreign_domain(&mut self, domain: ForeignDomainId)
        ensures
            forall|r: Reg|
                #![auto]
                old(self).get_spec(r).is_foreign() && old(self).get_spec(r).foreign_domain().addr()
                    == domain.addr() ==> final(self).get_spec(r) == RegVal::Unknown,
            forall|r: Reg|
                #![auto]
                !(old(self).get_spec(r).is_foreign() && old(self).get_spec(
                    r,
                ).foreign_domain().addr() == domain.addr()) ==> final(self).get_spec(r) == old(
                    self,
                ).get_spec(r),
    {
        Self::clear_foreign_domain_reg(&mut self.rcx, domain);
        Self::clear_foreign_domain_reg(&mut self.rsi, domain);
        Self::clear_foreign_domain_reg(&mut self.rdi, domain);
        Self::clear_foreign_domain_reg(&mut self.rax, domain);
        Self::clear_foreign_domain_reg(&mut self.rdx, domain);
    }
}

/// AMD64 CPU state: register file, status flags, and fault latch.
#[derive(Copy, Clone)]
pub struct Amd64Cpu {
    regs: RegisterFile,
    flags: Flags,
    fault: bool,
}

impl Amd64Cpu {
    /// The register file.
    pub closed spec fn regs_spec(self) -> RegisterFile {
        self.regs
    }

    /// The status flags.
    pub closed spec fn flags_spec(self) -> Flags {
        self.flags
    }

    /// Clear the fault latch (to be used when entering into the fault handler).
    pub closed spec fn clear_fault_spec(self) -> Self {
        Amd64Cpu { fault: false, ..self }
    }
}

pub broadcast proof fn lemma_clear_fault_spec_frame(c: Amd64Cpu)
    ensures
        cpu_ready(#[trigger] c.clear_fault_spec()),
        c.clear_fault_spec().regs_spec() == c.regs_spec(),
        c.clear_fault_spec().flags_spec() == c.flags_spec(),
{
}

pub broadcast proof fn lemma_clear_fault_spec_ready(c: Amd64Cpu)
    requires
        cpu_ready(c),
    ensures
        #[trigger] c.clear_fault_spec() == c,
{
}

impl<S: RmemStack> HardwareThread<Amd64Cpu, S> {
    pub closed spec fn clear_fault_spec(self) -> Self {
        HardwareThread { cpu: self.cpu.clear_fault_spec(), ..self }
    }
}

pub broadcast proof fn lemma_thread_clear_fault_spec_frame<S: RmemStack>(
    t: HardwareThread<Amd64Cpu, S>,
)
    ensures
        (#[trigger] t.clear_fault_spec()).cpu_spec() == t.cpu_spec().clear_fault_spec(),
        t.clear_fault_spec().rmem_spec() == t.rmem_spec(),
{
}

pub broadcast proof fn lemma_thread_clear_fault_spec_ready<S: RmemStack>(
    t: HardwareThread<Amd64Cpu, S>,
)
    requires
        cpu_ready(t.cpu_spec()),
    ensures
        #[trigger] t.clear_fault_spec() == t,
{
}

pub broadcast proof fn lemma_set_reg_spec_frame(c: Amd64Cpu, r: Reg, v: RegVal)
    ensures
        cpu_ready(#[trigger] c.set_reg_spec(r, v)) == cpu_ready(c),
        c.set_reg_spec(r, v).flags_spec() == c.flags_spec(),
        c.set_reg_spec(r, v).regs_spec() == c.regs_spec().set_spec(r, v),
{
}

pub broadcast proof fn lemma_clear_rust_slice_addr_spec_frame(c: Amd64Cpu, addr: usize)
    ensures
        cpu_ready(#[trigger] c.clear_rust_slice_addr_spec(addr)) == cpu_ready(c),
        c.clear_rust_slice_addr_spec(addr).flags_spec() == c.flags_spec(),
        c.clear_rust_slice_addr_spec(addr).regs_spec() == c.regs_spec().clear_rust_slice_addr_spec(
            addr,
        ),
{
}

pub broadcast proof fn lemma_reg_set_spec_frame(f: RegisterFile, r: Reg, v: RegVal, r2: Reg)
    ensures
        (#[trigger] f.set_spec(r, v).get_spec(r2)) == if r2 == r {
            v
        } else {
            f.get_spec(r2)
        },
{
}

pub broadcast proof fn lemma_reg_clear_rust_slice_addr_spec_frame(
    f: RegisterFile,
    addr: usize,
    r: Reg,
)
    ensures
        (#[trigger] f.clear_rust_slice_addr_spec(addr).get_spec(r)) == clear_slice_reg_spec(
            f.get_spec(r),
            addr,
        ),
{
}

pub broadcast group group_amd64_frames {
    lemma_arith_write_frame,
    lemma_arith_write_all_frame,
    lemma_clear_df_frame,
    lemma_clear_fault_spec_frame,
    lemma_clear_fault_spec_ready,
    lemma_set_reg_spec_frame,
    lemma_clear_rust_slice_addr_spec_frame,
    lemma_reg_set_spec_frame,
    lemma_reg_clear_rust_slice_addr_spec_frame,
    lemma_thread_clear_fault_spec_frame,
    lemma_thread_clear_fault_spec_ready,
}

impl Cpu for Amd64Cpu {
    type Reg = Reg;

    open spec fn wf(&self) -> bool {
        true
    }

    closed spec fn ready(&self) -> bool {
        !self.fault
    }

    open spec fn get_reg_spec(self, reg: Reg) -> RegVal {
        self.regs_spec().get_spec(reg)
    }

    closed spec fn set_reg_spec(self, reg: Reg, val: RegVal) -> Self {
        Amd64Cpu { regs: self.regs.set_spec(reg, val), ..self }
    }

    fn bind_reg(&mut self, reg: Reg, val: RegVal)
        ensures
            *final(self) == old(self).set_reg_spec(reg, val),
            final(self).get_reg_spec(reg) == val,
            forall|r: Reg| r != reg ==> final(self).get_reg_spec(r) == old(self).get_reg_spec(r),
    {
        self.regs.set(reg, val);
    }

    closed spec fn clear_rust_slice_addr_spec(self, addr: usize) -> Self {
        Amd64Cpu { regs: self.regs.clear_rust_slice_addr_spec(addr), ..self }
    }

    fn clear_rust_slice_addr(&mut self, addr: usize)
        ensures
            *final(self) == old(self).clear_rust_slice_addr_spec(addr),
            forall|r: Reg|
                #![auto]
                old(self).get_reg_spec(r).is_slice_ptr() && old(self).get_reg_spec(r).slice_addr()
                    == addr ==> final(self).get_reg_spec(r) == RegVal::Unknown,
            forall|r: Reg|
                #![auto]
                !(old(self).get_reg_spec(r).is_slice_ptr() && old(self).get_reg_spec(r).slice_addr()
                    == addr) ==> final(self).get_reg_spec(r) == old(self).get_reg_spec(r),
    {
        self.regs.clear_rust_slice_addr(addr);
    }

    fn clear_foreign_domain(&mut self, domain: ForeignDomainId)
        ensures
            forall|r: Reg|
                #![auto]
                old(self).get_reg_spec(r).is_foreign() && old(self).get_reg_spec(
                    r,
                ).foreign_domain().addr() == domain.addr() ==> final(self).get_reg_spec(r)
                    == RegVal::Unknown,
            forall|r: Reg|
                #![auto]
                !(old(self).get_reg_spec(r).is_foreign() && old(self).get_reg_spec(
                    r,
                ).foreign_domain().addr() == domain.addr()) ==> final(self).get_reg_spec(r) == old(
                    self,
                ).get_reg_spec(r),
    {
        self.regs.clear_foreign_domain(domain);
    }
}

/// The AMD64 hardware thread: a [`HardwareThread`] whose CPU is [`Amd64Cpu`].
pub type Amd64Thread<S> = HardwareThread<Amd64Cpu, S>;

/// Top-level constructor: a fresh, unscoped hardware thread holding no
/// Rust-slice permissions.
impl HardwareThread<Amd64Cpu, RmemNil> {
    pub fn new() -> (hw: Self)
        ensures
            df_clear(hw.cpu_spec()),
            hw.cpu_spec().flags_spec().zf_spec() == FlagVal::Undef,
            cpu_ready(hw.cpu_spec()),
            hw.cpu_spec().get_reg_spec(Reg::Rcx) == RegVal::Unknown,
            hw.cpu_spec().get_reg_spec(Reg::Rsi) == RegVal::Unknown,
            hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::Unknown,
            hw.cpu_spec().get_reg_spec(Reg::Rax) == RegVal::Unknown,
            hw.cpu_spec().get_reg_spec(Reg::Rdx) == RegVal::Unknown,
            hw.rmem_spec() == Option::Some(RmemNil),
            hw.wf(),
    {
        HardwareThread {
            cpu: Amd64Cpu {
                regs: RegisterFile::new(),
                // Every arithmetic flag starts `Undef`: on entry to an `asm!`
                // block x86 guarantees nothing about CF/PF/AF/ZF/SF/OF. Only DF
                // is guaranteed clear (corresponding to Rust's inline asm
                // rules).
                flags: Flags {
                    cf: FlagVal::Undef,
                    pf: FlagVal::Undef,
                    af: FlagVal::Undef,
                    df: false,
                    zf: FlagVal::Undef,
                    sf: FlagVal::Undef,
                    of: FlagVal::Undef,
                },
                fault: false,
            },
            rmem: Option::Some(RmemNil::new()),
        }
    }
}

impl Default for HardwareThread<Amd64Cpu, RmemNil> {
    fn default() -> (hw: Self) {
        HardwareThread::<Amd64Cpu, RmemNil>::new()
    }
}

impl<S: RmemStack> HardwareThread<Amd64Cpu, S> {
    pub fn reg_int_read(&self, reg: Reg) -> (value: u64)
        requires
            self.cpu_spec().get_reg_spec(reg) is Int,
        ensures
            value == self.cpu_spec().get_reg_spec(reg).as_int(),
    {
        self.cpu.regs.get(reg).unwrap_int()
    }

    pub fn begin_fault_handler(&mut self)
        requires
            !cpu_ready(old(self).cpu_spec()),
        ensures
            *final(self) == old(self).clear_fault_spec(),
    {
        self.cpu.fault = false;
    }

    pub fn fault_taken(&self) -> (b: bool)
        ensures
            b == !cpu_ready(self.cpu_spec()),
    {
        self.cpu.fault
    }

    fn fault_result(&self) -> (out: Result<(), Fault>)
        ensures
            fault_result_matches(self.cpu_spec(), out),
    {
        if self.fault_taken() {
            Err(Fault)
        } else {
            Ok(())
        }
    }

    pub fn flag_read_zf(&self) -> (set: bool)
        requires
            cpu_ready(self.cpu_spec()),
            self.cpu_spec().flags_spec().zf_spec() is Defined,
        ensures
            self.cpu_spec().flags_spec().zf_spec() == FlagVal::Defined(set),
    {
        match self.cpu.flags.zf {
            FlagVal::Defined(set) => set,
            FlagVal::Undef => { false },
        }
    }
}

} // verus!
