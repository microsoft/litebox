// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::*;
use crate::fmem::capability::BoundSession;
use crate::fmem::session::DomainSession;
#[cfg(verus_only)]
use crate::machine::{cpu::*, hardware_thread::*, reg_val::*};
#[cfg(verus_only)]
use crate::rmem::rmem_stack::*;
use vstd::pervasive::unreached;
#[cfg(verus_only)]
use vstd::prelude::*;

verus! {

impl<S: RmemStack> HardwareThread<Amd64Cpu, S> {
    fn rep_movsb_foreign_to_rust<T: DomainSession>(&mut self, sess: &mut BoundSession<T>) -> (out:
        Result<(), Fault>)
        requires
            cpu_ready(old(self).cpu_spec()),
            df_clear(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr,
            old(self).cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr,
            old(self).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
            old(sess).cap() == old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr().cap(),
            T::wf(old(sess).st()),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                let cell = dst.slice_pptr();
                &&& n <= usize::MAX as nat
                &&& src.cursor().addr() as nat + n <= usize::MAX as nat
                &&& dst.slice_offset() as nat + n <= usize::MAX as nat
                &&& old(self).rmem_spec().wf()
                &&& old(self).rmem_spec()->Some_0.has_mut_any(cell)
                &&& old(self).rmem_spec()->Some_0.matches_pptr_any(cell)
                &&& dst.slice_offset() as nat + n <= old(self).rmem_spec()->Some_0.view_any(
                    cell,
                ).len()
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                forall|env: T::State, off: usize|
                    #![trigger T::load_disposition(env, src.region(), off, 1)]
                    T::interfere(old(sess).st(), env) && src.cursor().addr() <= off
                        < src.cursor().addr() + n ==> (T::load_disposition(
                        env,
                        src.region(),
                        off,
                        1,
                    ).permits_success() || T::load_disposition(
                        env,
                        src.region(),
                        off,
                        1,
                    ).permits_fault())
            }),
            ({
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                forall|env: T::State, post: T::State, off: usize, obs: Seq<u8>|
                    #![trigger T::load_post(env, post, src.region(), off, 1, obs)]
                    T::interfere(old(sess).st(), env) && T::load_post(
                        env,
                        post,
                        src.region(),
                        off,
                        1,
                        obs,
                    ) ==> T::interfere(old(sess).st(), post)
            }),
        ensures
            fault_result_matches(final(self).cpu_spec(), out),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            regs_unchanged_except(
                old(self).cpu_spec(),
                final(self).cpu_spec(),
                set![Reg::Rcx, Reg::Rsi, Reg::Rdi],
            ),
            T::wf(final(sess).st()),
            final(sess).cap() == old(sess).cap(),
            T::interfere(old(sess).st(), final(sess).st()),
            final(self).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                &&& m <= n
                &&& !cpu_ready(final(self).cpu_spec()) ==> m > 0
                &&& cpu_ready(final(self).cpu_spec()) ==> m == 0
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as usize;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(k)
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi).slice_pptr() == dst.slice_pptr()
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi).slice_offset()
                    == dst.slice_offset() + k
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as usize;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                !cpu_ready(final(self).cpu_spec()) ==> T::load_disposition(
                    final(sess).st(),
                    src.region(),
                    (src.cursor().addr() + k) as usize,
                    1,
                ).permits_fault()
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as int;
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                let cell = dst.slice_pptr();
                let doff = dst.slice_offset() as int;
                &&& final(self).rmem_spec() is Some
                &&& final(self).rmem_spec()->Some_0.wf()
                &&& final(self).rmem_spec()->Some_0.has_mut_any(cell)
                &&& final(self).rmem_spec()->Some_0.matches_pptr_any(cell)
                &&& final(self).rmem_spec()->Some_0.is_mut_any(cell) == old(
                    self,
                ).rmem_spec()->Some_0.is_mut_any(cell)
                &&& final(self).rmem_spec()->Some_0.view_any(cell).len() == old(
                    self,
                ).rmem_spec()->Some_0.view_any(cell).len()
                &&& forall|i: int|
                    #![trigger final(self).rmem_spec()->Some_0.view_any(cell)[i]]
                    0 <= i < final(self).rmem_spec()->Some_0.view_any(cell).len() && !(doff <= i
                        < doff + k) ==> final(self).rmem_spec()->Some_0.view_any(cell)[i] == old(
                        self,
                    ).rmem_spec()->Some_0.view_any(cell)[i]
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
        let ghost s0 = sess.st();
        let ghost cap0 = sess.cap();
        let src = match self.cpu.regs.get(Reg::Rsi) {
            RegVal::ForeignMemPtr(p) => p,
            _ => { unreached() },
        };
        let (cell, doff) = self.cpu.regs.get(Reg::Rdi).unwrap_rust_slice_ptr();
        let n: usize = self.cpu.regs.get(Reg::Rcx).unwrap_int() as usize;
        let region = src.region();
        let saddr = src.cursor().addr();

        let mut buf: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        let mut faulted: bool = false;
        proof {
            T::lemma_interfere_refl(s0);
        }
        while i < n && !faulted
            invariant
                i <= n,
                buf@.len() == i,
                faulted ==> i < n,
                faulted ==> T::load_disposition(
                    sess.st(),
                    region,
                    (saddr + i) as usize,
                    1,
                ).permits_fault(),
                saddr + n <= usize::MAX,
                T::wf(sess.st()),
                sess.cap() == cap0,
                T::interfere(s0, sess.st()),
                forall|env: T::State, off: usize|
                    #![trigger T::load_disposition(env, region, off, 1)]
                    T::interfere(s0, env) && saddr <= off < saddr + n ==> (T::load_disposition(
                        env,
                        region,
                        off,
                        1,
                    ).permits_success() || T::load_disposition(
                        env,
                        region,
                        off,
                        1,
                    ).permits_fault()),
                forall|env: T::State, post: T::State, off: usize, obs: Seq<u8>|
                    #![trigger T::load_post(env, post, region, off, 1, obs)]
                    T::interfere(s0, env) && T::load_post(env, post, region, off, 1, obs)
                        ==> T::interfere(s0, post),
            decreases
                    n - i,
                    if faulted {
                        0int
                    } else {
                        1int
                    },
        {
            let ghost sk = sess.st();
            assert forall|env: T::State| #[trigger] T::interfere(sk, env) implies (
            T::load_disposition(env, region, (saddr + i) as usize, 1).permits_success()
                || T::load_disposition(env, region, (saddr + i) as usize, 1).permits_fault()) by {
                T::lemma_interfere_trans(s0, sk, env);
            }
            let (f, bytes) = sess.try_load_atomic(region, saddr + i, 1);
            proof {
                if f {
                    T::lemma_interfere_trans(s0, sk, sess.st());
                } else {
                    let env = choose|env: T::State|
                        #![trigger T::interfere(sk, env)]
                        T::interfere(sk, env) && T::load_post(
                            env,
                            sess.st(),
                            region,
                            (saddr + i) as usize,
                            1,
                            bytes@,
                        );
                    T::lemma_interfere_trans(s0, sk, env);
                }
            }
            if f {
                faulted = true;
            } else {
                buf.push(bytes[0]);
                i += 1;
            }
        }

        match self.rmem {
            Option::Some(ref mut rmem) => {
                rmem.copy_from_slice(cell, doff, buf.as_slice());
            },
            Option::None => unreached(),
        };
        self.cpu.regs.set(Reg::Rcx, RegVal::int((n - i) as u64));
        self.cpu.regs.set(Reg::Rsi, RegVal::foreign_mem_ptr(src.advance(i)));
        self.cpu.regs.set(Reg::Rdi, RegVal::rust_mut_slice_ptr(cell, doff + i));
        if faulted {
            self.cpu.fault = true;
        }
        self.fault_result()
    }

    fn rep_movsb_rust_to_rust(&mut self) -> (out: Result<(), Fault>)
        requires
            cpu_ready(old(self).cpu_spec()),
            df_clear(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(Reg::Rsi).is_slice_ptr(),
            old(self).cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr,
            old(self).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi);
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                &&& n <= usize::MAX as nat
                &&& src.slice_pptr() != dst.slice_pptr()
                &&& src.slice_offset() as nat + n <= usize::MAX as nat
                &&& dst.slice_offset() as nat + n <= usize::MAX as nat
                &&& old(self).rmem_spec().wf()
                &&& old(self).rmem_spec()->Some_0.has_read_any(src.slice_pptr())
                &&& old(self).rmem_spec()->Some_0.matches_pptr_any(src.slice_pptr())
                &&& old(self).rmem_spec()->Some_0.is_mut_any(src.slice_pptr()) == (
                src is RustMutSlicePtr)
                &&& src.slice_offset() as nat + n <= old(self).rmem_spec()->Some_0.view_any(
                    src.slice_pptr(),
                ).len()
                &&& old(self).rmem_spec()->Some_0.has_mut_any(dst.slice_pptr())
                &&& old(self).rmem_spec()->Some_0.matches_pptr_any(dst.slice_pptr())
                &&& dst.slice_offset() as nat + n <= old(self).rmem_spec()->Some_0.view_any(
                    dst.slice_pptr(),
                ).len()
            }),
        ensures
            out is Ok,
            cpu_ready(final(self).cpu_spec()),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            regs_unchanged_except(
                old(self).cpu_spec(),
                final(self).cpu_spec(),
                set![Reg::Rcx, Reg::Rsi, Reg::Rdi],
            ),
            final(self).cpu_spec().get_reg_spec(Reg::Rcx) == RegVal::Int(0),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as usize;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi);
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi).is_slice_ptr()
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi).slice_pptr() == src.slice_pptr()
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi).slice_offset()
                    == src.slice_offset() + n
                &&& (final(self).cpu_spec().get_reg_spec(Reg::Rsi) is RustMutSlicePtr) == (
                src is RustMutSlicePtr)
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi).slice_pptr() == dst.slice_pptr()
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi).slice_offset()
                    == dst.slice_offset() + n
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as int;
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                let cell = dst.slice_pptr();
                let doff = dst.slice_offset() as int;
                &&& final(self).rmem_spec() is Some
                &&& final(self).rmem_spec()->Some_0.wf()
                &&& final(self).rmem_spec()->Some_0.has_mut_any(cell)
                &&& final(self).rmem_spec()->Some_0.matches_pptr_any(cell)
                &&& final(self).rmem_spec()->Some_0.is_mut_any(cell) == old(
                    self,
                ).rmem_spec()->Some_0.is_mut_any(cell)
                &&& final(self).rmem_spec()->Some_0.view_any(cell).len() == old(
                    self,
                ).rmem_spec()->Some_0.view_any(cell).len()
                &&& forall|i: int|
                    #![trigger final(self).rmem_spec()->Some_0.view_any(cell)[i]]
                    0 <= i < final(self).rmem_spec()->Some_0.view_any(cell).len() && !(doff <= i
                        < doff + n) ==> final(self).rmem_spec()->Some_0.view_any(cell)[i] == old(
                        self,
                    ).rmem_spec()->Some_0.view_any(cell)[i]
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
        let src = self.cpu.regs.get(Reg::Rsi);
        let dst = self.cpu.regs.get(Reg::Rdi);
        let (src_cell, src_offset, src_is_mut) = match src {
            RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr, offset }) => {
                (slice_pptr, offset, false)
            },
            RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr, offset }) => {
                (slice_pptr, offset, true)
            },
            _ => unreached(),
        };
        let (dst_cell, dst_offset) = dst.unwrap_rust_slice_ptr();
        let n = self.cpu.regs.get(Reg::Rcx).unwrap_int() as usize;
        let mut buf: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < n
            invariant
                i <= n,
                buf@.len() == i,
            decreases n - i,
        {
            buf.push(0);
            i += 1;
        }
        match self.rmem {
            Option::Some(ref mut rmem) => {
                rmem.copy_to_slice(src_cell, src_offset, src_is_mut, buf.as_mut_slice());
                rmem.copy_from_slice(dst_cell, dst_offset, buf.as_slice());
            },
            Option::None => unreached(),
        }
        self.cpu.regs.set(Reg::Rcx, RegVal::int(0));
        match src {
            RegVal::RustSharedSlicePtr(_) => {
                self.cpu.regs.set(
                    Reg::Rsi,
                    RegVal::rust_shared_slice_ptr(src_cell, src_offset + n),
                );
            },
            RegVal::RustMutSlicePtr(_) => {
                self.cpu.regs.set(Reg::Rsi, RegVal::rust_mut_slice_ptr(src_cell, src_offset + n));
            },
            _ => unreached(),
        }
        self.cpu.regs.set(Reg::Rdi, RegVal::rust_mut_slice_ptr(dst_cell, dst_offset + n));
        self.fault_result()
    }

    fn rep_movsb_rust_to_foreign<T: DomainSession>(&mut self, sess: &mut BoundSession<T>) -> (out:
        Result<(), Fault>)
        requires
            cpu_ready(old(self).cpu_spec()),
            df_clear(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(Reg::Rsi).is_slice_ptr(),
            old(self).cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr,
            old(self).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
            old(sess).cap() == old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr().cap(),
            T::wf(old(sess).st()),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi);
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                &&& n <= usize::MAX as nat
                &&& src.slice_offset() as nat + n <= usize::MAX as nat
                &&& dst.cursor().addr() as nat + n <= usize::MAX as nat
                &&& old(self).rmem_spec().wf()
                &&& old(self).rmem_spec()->Some_0.has_read_any(src.slice_pptr())
                &&& old(self).rmem_spec()->Some_0.matches_pptr_any(src.slice_pptr())
                &&& old(self).rmem_spec()->Some_0.is_mut_any(src.slice_pptr()) == (
                src is RustMutSlicePtr)
                &&& src.slice_offset() as nat + n <= old(self).rmem_spec()->Some_0.view_any(
                    src.slice_pptr(),
                ).len()
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                forall|env: T::State, off: usize|
                    #![trigger T::store_disposition(env, dst.region(), off, 1)]
                    T::interfere(old(sess).st(), env) && dst.cursor().addr() <= off
                        < dst.cursor().addr() + n ==> (T::store_disposition(
                        env,
                        dst.region(),
                        off,
                        1,
                    ).permits_success() || T::store_disposition(
                        env,
                        dst.region(),
                        off,
                        1,
                    ).permits_fault())
            }),
            ({
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                forall|env: T::State, post: T::State, off: usize, data: Seq<u8>|
                    #![trigger T::store_post(env, post, dst.region(), off, 1, data)]
                    T::interfere(old(sess).st(), env) && T::store_post(
                        env,
                        post,
                        dst.region(),
                        off,
                        1,
                        data,
                    ) ==> T::interfere(old(sess).st(), post)
            }),
        ensures
            fault_result_matches(final(self).cpu_spec(), out),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            regs_unchanged_except(
                old(self).cpu_spec(),
                final(self).cpu_spec(),
                set![Reg::Rcx, Reg::Rsi, Reg::Rdi],
            ),
            rmem_unchanged(*old(self), *final(self)),
            T::wf(final(sess).st()),
            final(sess).cap() == old(sess).cap(),
            T::interfere(old(sess).st(), final(sess).st()),
            final(self).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                &&& m <= n
                &&& !cpu_ready(final(self).cpu_spec()) ==> m > 0
                &&& cpu_ready(final(self).cpu_spec()) ==> m == 0
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as usize;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi);
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi).is_slice_ptr()
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi).slice_pptr() == src.slice_pptr()
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi).slice_offset()
                    == src.slice_offset() + k
                &&& (final(self).cpu_spec().get_reg_spec(Reg::Rsi) is RustMutSlicePtr) == (
                src is RustMutSlicePtr)
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr() == dst.advance(k)
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as usize;
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                !cpu_ready(final(self).cpu_spec()) ==> T::store_disposition(
                    final(sess).st(),
                    dst.region(),
                    (dst.cursor().addr() + k) as usize,
                    1,
                ).permits_fault()
            }),
    {
        let ghost s0 = sess.st();
        let ghost cap0 = sess.cap();
        let src = self.cpu.regs.get(Reg::Rsi);
        let dst = match self.cpu.regs.get(Reg::Rdi) {
            RegVal::ForeignMemPtr(p) => p,
            _ => unreached(),
        };
        let (src_cell, src_offset, src_is_mut) = match src {
            RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr, offset }) => {
                (slice_pptr, offset, false)
            },
            RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr, offset }) => {
                (slice_pptr, offset, true)
            },
            _ => unreached(),
        };
        let n = self.cpu.regs.get(Reg::Rcx).unwrap_int() as usize;
        let daddr = dst.cursor().addr();
        let region = dst.region();
        let ghost rmem0 = self.rmem_spec();
        let mut i: usize = 0;
        let mut faulted = false;
        proof {
            T::lemma_interfere_refl(s0);
        }
        while i < n && !faulted
            invariant
                i <= n,
                faulted ==> i < n,
                faulted ==> T::store_disposition(
                    sess.st(),
                    region,
                    (daddr + i) as usize,
                    1,
                ).permits_fault(),
                daddr + n <= usize::MAX,
                src_offset + n <= usize::MAX,
                self.rmem_spec() == rmem0,
                self.rmem_spec().wf(),
                self.rmem_spec()->Some_0.has_read_any(src_cell),
                self.rmem_spec()->Some_0.matches_pptr_any(src_cell),
                self.rmem_spec()->Some_0.is_mut_any(src_cell) == src_is_mut,
                src_offset + n <= self.rmem_spec()->Some_0.view_any(src_cell).len(),
                T::wf(sess.st()),
                sess.cap() == cap0,
                T::interfere(s0, sess.st()),
                forall|env: T::State, off: usize|
                    #![trigger T::store_disposition(env, region, off, 1)]
                    T::interfere(s0, env) && daddr <= off < daddr + n ==> (T::store_disposition(
                        env,
                        region,
                        off,
                        1,
                    ).permits_success() || T::store_disposition(
                        env,
                        region,
                        off,
                        1,
                    ).permits_fault()),
                forall|env: T::State, post: T::State, off: usize, data: Seq<u8>|
                    #![trigger T::store_post(env, post, region, off, 1, data)]
                    T::interfere(s0, env) && T::store_post(env, post, region, off, 1, data)
                        ==> T::interfere(s0, post),
            decreases
                    n - i,
                    if faulted {
                        0int
                    } else {
                        1int
                    },
        {
            let mut byte = [0u8];
            match self.rmem {
                Option::Some(ref rmem) => {
                    rmem.copy_to_slice(src_cell, src_offset + i, src_is_mut, &mut byte);
                },
                Option::None => unreached(),
            }
            let ghost sk = sess.st();
            assert forall|env: T::State| #[trigger] T::interfere(sk, env) implies (
            T::store_disposition(env, region, (daddr + i) as usize, 1).permits_success()
                || T::store_disposition(env, region, (daddr + i) as usize, 1).permits_fault()) by {
                T::lemma_interfere_trans(s0, sk, env);
            }
            let f = sess.try_store_atomic(region, daddr + i, 1, &byte);
            proof {
                if f {
                    T::lemma_interfere_trans(s0, sk, sess.st());
                } else {
                    let env = choose|env: T::State|
                        #![trigger T::interfere(sk, env)]
                        T::interfere(sk, env) && T::store_post(
                            env,
                            sess.st(),
                            region,
                            (daddr + i) as usize,
                            1,
                            byte@,
                        );
                    T::lemma_interfere_trans(s0, sk, env);
                }
            }
            if f {
                faulted = true;
            } else {
                i += 1;
            }
        }
        self.cpu.regs.set(Reg::Rcx, RegVal::int((n - i) as u64));
        match src {
            RegVal::RustSharedSlicePtr(_) => {
                self.cpu.regs.set(
                    Reg::Rsi,
                    RegVal::rust_shared_slice_ptr(src_cell, src_offset + i),
                );
            },
            RegVal::RustMutSlicePtr(_) => {
                self.cpu.regs.set(Reg::Rsi, RegVal::rust_mut_slice_ptr(src_cell, src_offset + i));
            },
            _ => unreached(),
        }
        self.cpu.regs.set(Reg::Rdi, RegVal::foreign_mem_ptr(dst.advance(i)));
        if faulted {
            self.cpu.fault = true;
        }
        self.fault_result()
    }

    fn rep_movsb_foreign_to_foreign<Src: DomainSession, Dst: DomainSession>(
        &mut self,
        src_sess: &mut BoundSession<Src>,
        dst_sess: &mut BoundSession<Dst>,
    ) -> (out: Result<(), Fault>)
        requires
            cpu_ready(old(self).cpu_spec()),
            df_clear(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr,
            old(self).cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr,
            old(self).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
            old(src_sess).cap() == old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr().cap(),
            old(dst_sess).cap() == old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr().cap(),
            Src::wf(old(src_sess).st()),
            Dst::wf(old(dst_sess).st()),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                &&& n <= usize::MAX as nat
                &&& src.cursor().addr() as nat + n <= usize::MAX as nat
                &&& dst.cursor().addr() as nat + n <= usize::MAX as nat
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                forall|env: Src::State, off: usize|
                    #![trigger Src::load_disposition(env, src.region(), off, 1)]
                    Src::interfere(old(src_sess).st(), env) && src.cursor().addr() <= off
                        < src.cursor().addr() + n ==> (Src::load_disposition(
                        env,
                        src.region(),
                        off,
                        1,
                    ).permits_success() || Src::load_disposition(
                        env,
                        src.region(),
                        off,
                        1,
                    ).permits_fault())
            }),
            ({
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                forall|env: Src::State, post: Src::State, off: usize, obs: Seq<u8>|
                    #![trigger Src::load_post(env, post, src.region(), off, 1, obs)]
                    Src::interfere(old(src_sess).st(), env) && Src::load_post(
                        env,
                        post,
                        src.region(),
                        off,
                        1,
                        obs,
                    ) ==> Src::interfere(old(src_sess).st(), post)
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                forall|env: Dst::State, off: usize|
                    #![trigger Dst::store_disposition(env, dst.region(), off, 1)]
                    Dst::interfere(old(dst_sess).st(), env) && dst.cursor().addr() <= off
                        < dst.cursor().addr() + n ==> (Dst::store_disposition(
                        env,
                        dst.region(),
                        off,
                        1,
                    ).permits_success() || Dst::store_disposition(
                        env,
                        dst.region(),
                        off,
                        1,
                    ).permits_fault())
            }),
            ({
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                forall|env: Dst::State, post: Dst::State, off: usize, data: Seq<u8>|
                    #![trigger Dst::store_post(env, post, dst.region(), off, 1, data)]
                    Dst::interfere(old(dst_sess).st(), env) && Dst::store_post(
                        env,
                        post,
                        dst.region(),
                        off,
                        1,
                        data,
                    ) ==> Dst::interfere(old(dst_sess).st(), post)
            }),
        ensures
            fault_result_matches(final(self).cpu_spec(), out),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            regs_unchanged_except(
                old(self).cpu_spec(),
                final(self).cpu_spec(),
                set![Reg::Rcx, Reg::Rsi, Reg::Rdi],
            ),
            rmem_unchanged(*old(self), *final(self)),
            Src::wf(final(src_sess).st()),
            final(src_sess).cap() == old(src_sess).cap(),
            Src::interfere(old(src_sess).st(), final(src_sess).st()),
            Dst::wf(final(dst_sess).st()),
            final(dst_sess).cap() == old(dst_sess).cap(),
            Dst::interfere(old(dst_sess).st(), final(dst_sess).st()),
            final(self).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                &&& m <= n
                &&& !cpu_ready(final(self).cpu_spec()) ==> m > 0
                &&& cpu_ready(final(self).cpu_spec()) ==> m == 0
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as usize;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(k)
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr
                &&& final(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr() == dst.advance(k)
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as usize;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                !cpu_ready(final(self).cpu_spec()) ==> (Src::load_disposition(
                    final(src_sess).st(),
                    src.region(),
                    (src.cursor().addr() + k) as usize,
                    1,
                ).permits_fault() || Dst::store_disposition(
                    final(dst_sess).st(),
                    dst.region(),
                    (dst.cursor().addr() + k) as usize,
                    1,
                ).permits_fault())
            }),
    {
        let ghost src_s0 = src_sess.st();
        let ghost dst_s0 = dst_sess.st();
        let ghost src_cap0 = src_sess.cap();
        let ghost dst_cap0 = dst_sess.cap();
        let src = match self.cpu.regs.get(Reg::Rsi) {
            RegVal::ForeignMemPtr(p) => p,
            _ => unreached(),
        };
        let dst = match self.cpu.regs.get(Reg::Rdi) {
            RegVal::ForeignMemPtr(p) => p,
            _ => unreached(),
        };
        let n = self.cpu.regs.get(Reg::Rcx).unwrap_int() as usize;
        let saddr = src.cursor().addr();
        let daddr = dst.cursor().addr();
        let sregion = src.region();
        let dregion = dst.region();
        let mut i: usize = 0;
        let mut source_fault = false;
        let mut destination_fault = false;
        proof {
            Src::lemma_interfere_refl(src_s0);
            Dst::lemma_interfere_refl(dst_s0);
        }
        while i < n && !source_fault && !destination_fault
            invariant
                i <= n,
                source_fault ==> i < n,
                destination_fault ==> i < n,
                source_fault ==> Src::load_disposition(
                    src_sess.st(),
                    sregion,
                    (saddr + i) as usize,
                    1,
                ).permits_fault(),
                destination_fault ==> Dst::store_disposition(
                    dst_sess.st(),
                    dregion,
                    (daddr + i) as usize,
                    1,
                ).permits_fault(),
                saddr + n <= usize::MAX,
                daddr + n <= usize::MAX,
                Src::wf(src_sess.st()),
                Dst::wf(dst_sess.st()),
                src_sess.cap() == src_cap0,
                dst_sess.cap() == dst_cap0,
                Src::interfere(src_s0, src_sess.st()),
                Dst::interfere(dst_s0, dst_sess.st()),
                forall|env: Src::State, off: usize|
                    #![trigger Src::load_disposition(env, sregion, off, 1)]
                    Src::interfere(src_s0, env) && saddr <= off < saddr + n ==> (
                    Src::load_disposition(env, sregion, off, 1).permits_success()
                        || Src::load_disposition(env, sregion, off, 1).permits_fault()),
                forall|env: Src::State, post: Src::State, off: usize, obs: Seq<u8>|
                    #![trigger Src::load_post(env, post, sregion, off, 1, obs)]
                    Src::interfere(src_s0, env) && Src::load_post(env, post, sregion, off, 1, obs)
                        ==> Src::interfere(src_s0, post),
                forall|env: Dst::State, off: usize|
                    #![trigger Dst::store_disposition(env, dregion, off, 1)]
                    Dst::interfere(dst_s0, env) && daddr <= off < daddr + n ==> (
                    Dst::store_disposition(env, dregion, off, 1).permits_success()
                        || Dst::store_disposition(env, dregion, off, 1).permits_fault()),
                forall|env: Dst::State, post: Dst::State, off: usize, data: Seq<u8>|
                    #![trigger Dst::store_post(env, post, dregion, off, 1, data)]
                    Dst::interfere(dst_s0, env) && Dst::store_post(env, post, dregion, off, 1, data)
                        ==> Dst::interfere(dst_s0, post),
            decreases
                    n - i,
                    if source_fault || destination_fault {
                        0int
                    } else {
                        1int
                    },
        {
            let ghost src_sk = src_sess.st();
            assert forall|env: Src::State| #[trigger] Src::interfere(src_sk, env) implies (
            Src::load_disposition(env, sregion, (saddr + i) as usize, 1).permits_success()
                || Src::load_disposition(
                env,
                sregion,
                (saddr + i) as usize,
                1,
            ).permits_fault()) by {
                Src::lemma_interfere_trans(src_s0, src_sk, env);
            }
            let (sf, bytes) = src_sess.try_load_atomic(sregion, saddr + i, 1);
            proof {
                if sf {
                    Src::lemma_interfere_trans(src_s0, src_sk, src_sess.st());
                } else {
                    let env = choose|env: Src::State|
                        #![trigger Src::interfere(src_sk, env)]
                        Src::interfere(src_sk, env) && Src::load_post(
                            env,
                            src_sess.st(),
                            sregion,
                            (saddr + i) as usize,
                            1,
                            bytes@,
                        );
                    Src::lemma_interfere_trans(src_s0, src_sk, env);
                }
            }
            if sf {
                source_fault = true;
            } else {
                let ghost dst_sk = dst_sess.st();
                assert forall|env: Dst::State| #[trigger] Dst::interfere(dst_sk, env) implies (
                Dst::store_disposition(env, dregion, (daddr + i) as usize, 1).permits_success()
                    || Dst::store_disposition(
                    env,
                    dregion,
                    (daddr + i) as usize,
                    1,
                ).permits_fault()) by {
                    Dst::lemma_interfere_trans(dst_s0, dst_sk, env);
                }
                let df = dst_sess.try_store_atomic(dregion, daddr + i, 1, bytes.as_slice());
                proof {
                    if df {
                        Dst::lemma_interfere_trans(dst_s0, dst_sk, dst_sess.st());
                    } else {
                        let env = choose|env: Dst::State|
                            #![trigger Dst::interfere(dst_sk, env)]
                            Dst::interfere(dst_sk, env) && Dst::store_post(
                                env,
                                dst_sess.st(),
                                dregion,
                                (daddr + i) as usize,
                                1,
                                bytes@,
                            );
                        Dst::lemma_interfere_trans(dst_s0, dst_sk, env);
                    }
                }
                if df {
                    destination_fault = true;
                } else {
                    i += 1;
                }
            }
        }
        self.cpu.regs.set(Reg::Rcx, RegVal::int((n - i) as u64));
        self.cpu.regs.set(Reg::Rsi, RegVal::foreign_mem_ptr(src.advance(i)));
        self.cpu.regs.set(Reg::Rdi, RegVal::foreign_mem_ptr(dst.advance(i)));
        if source_fault || destination_fault {
            self.cpu.fault = true;
        }
        self.fault_result()
    }

    pub fn rep_movsb<Src: DomainSession, Dst: DomainSession>(
        &mut self,
        src_sess: Option<&mut BoundSession<Src>>,
        dst_sess: Option<&mut BoundSession<Dst>>,
    ) -> (out: Result<(), Fault>)
        requires
            cpu_ready(old(self).cpu_spec()),
            df_clear(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
            old(self).cpu_spec().get_reg_spec(Reg::Rsi).is_slice_ptr() || old(
                self,
            ).cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr,
            old(self).cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr || old(
                self,
            ).cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr,
            (src_sess is Some) == (old(self).cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr),
            (dst_sess is Some) == (old(self).cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr),
            src_sess is Some ==> old(src_sess->Some_0).cap() == old(self).cpu_spec().get_reg_spec(
                Reg::Rsi,
            ).foreign_ptr().cap(),
            dst_sess is Some ==> old(dst_sess->Some_0).cap() == old(self).cpu_spec().get_reg_spec(
                Reg::Rdi,
            ).foreign_ptr().cap(),
            src_sess is Some ==> Src::wf(old(src_sess->Some_0).st()),
            dst_sess is Some ==> Dst::wf(old(dst_sess->Some_0).st()),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi);
                if src is ForeignMemPtr {
                    src.foreign_ptr().cursor().addr() as nat + n <= usize::MAX as nat
                } else {
                    &&& src.slice_offset() as nat + n <= usize::MAX as nat
                    &&& old(self).rmem_spec().wf()
                    &&& old(self).rmem_spec()->Some_0.has_read_any(src.slice_pptr())
                    &&& old(self).rmem_spec()->Some_0.matches_pptr_any(src.slice_pptr())
                    &&& old(self).rmem_spec()->Some_0.is_mut_any(src.slice_pptr()) == (
                    src is RustMutSlicePtr)
                    &&& src.slice_offset() as nat + n <= old(self).rmem_spec()->Some_0.view_any(
                        src.slice_pptr(),
                    ).len()
                }
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi);
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                if dst is ForeignMemPtr {
                    dst.foreign_ptr().cursor().addr() as nat + n <= usize::MAX as nat
                } else {
                    &&& dst.slice_offset() as nat + n <= usize::MAX as nat
                    &&& old(self).rmem_spec().wf()
                    &&& old(self).rmem_spec()->Some_0.has_mut_any(dst.slice_pptr())
                    &&& old(self).rmem_spec()->Some_0.matches_pptr_any(dst.slice_pptr())
                    &&& dst.slice_offset() as nat + n <= old(self).rmem_spec()->Some_0.view_any(
                        dst.slice_pptr(),
                    ).len()
                    &&& src.is_slice_ptr() ==> src.slice_pptr() != dst.slice_pptr()
                }
            }),
            src_sess is Some ==> ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                forall|env: Src::State, off: usize|
                    #![trigger Src::load_disposition(env, src.region(), off, 1)]
                    Src::interfere(old(src_sess->Some_0).st(), env) && src.cursor().addr() <= off
                        < src.cursor().addr() + n ==> (Src::load_disposition(
                        env,
                        src.region(),
                        off,
                        1,
                    ).permits_success() || Src::load_disposition(
                        env,
                        src.region(),
                        off,
                        1,
                    ).permits_fault())
            }),
            src_sess is Some ==> ({
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
                forall|env: Src::State, post: Src::State, off: usize, obs: Seq<u8>|
                    #![trigger Src::load_post(env, post, src.region(), off, 1, obs)]
                    Src::interfere(old(src_sess->Some_0).st(), env) && Src::load_post(
                        env,
                        post,
                        src.region(),
                        off,
                        1,
                        obs,
                    ) ==> Src::interfere(old(src_sess->Some_0).st(), post)
            }),
            dst_sess is Some ==> ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                forall|env: Dst::State, off: usize|
                    #![trigger Dst::store_disposition(env, dst.region(), off, 1)]
                    Dst::interfere(old(dst_sess->Some_0).st(), env) && dst.cursor().addr() <= off
                        < dst.cursor().addr() + n ==> (Dst::store_disposition(
                        env,
                        dst.region(),
                        off,
                        1,
                    ).permits_success() || Dst::store_disposition(
                        env,
                        dst.region(),
                        off,
                        1,
                    ).permits_fault())
            }),
            dst_sess is Some ==> ({
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
                forall|env: Dst::State, post: Dst::State, off: usize, data: Seq<u8>|
                    #![trigger Dst::store_post(env, post, dst.region(), off, 1, data)]
                    Dst::interfere(old(dst_sess->Some_0).st(), env) && Dst::store_post(
                        env,
                        post,
                        dst.region(),
                        off,
                        1,
                        data,
                    ) ==> Dst::interfere(old(dst_sess->Some_0).st(), post)
            }),
        ensures
            fault_result_matches(final(self).cpu_spec(), out),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            regs_unchanged_except(
                old(self).cpu_spec(),
                final(self).cpu_spec(),
                set![Reg::Rcx, Reg::Rsi, Reg::Rdi],
            ),
            final(self).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                &&& m <= n
                &&& !cpu_ready(final(self).cpu_spec()) ==> m > 0
                &&& cpu_ready(final(self).cpu_spec()) ==> m == 0
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as usize;
                let src0 = old(self).cpu_spec().get_reg_spec(Reg::Rsi);
                let src1 = final(self).cpu_spec().get_reg_spec(Reg::Rsi);
                if src0 is ForeignMemPtr {
                    &&& src1 is ForeignMemPtr
                    &&& src1.foreign_ptr() == src0.foreign_ptr().advance(k)
                } else {
                    &&& src1.is_slice_ptr()
                    &&& src1.slice_pptr() == src0.slice_pptr()
                    &&& src1.slice_offset() == src0.slice_offset() + k
                    &&& (src1 is RustMutSlicePtr) == (src0 is RustMutSlicePtr)
                }
            }),
            ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as usize;
                let dst0 = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                let dst1 = final(self).cpu_spec().get_reg_spec(Reg::Rdi);
                if dst0 is ForeignMemPtr {
                    &&& dst1 is ForeignMemPtr
                    &&& dst1.foreign_ptr() == dst0.foreign_ptr().advance(k)
                } else {
                    &&& dst1 is RustMutSlicePtr
                    &&& dst1.slice_pptr() == dst0.slice_pptr()
                    &&& dst1.slice_offset() == dst0.slice_offset() + k
                }
            }),
            src_sess is Some ==> {
                &&& Src::wf(final(src_sess->Some_0).st())
                &&& final(src_sess->Some_0).cap() == old(src_sess->Some_0).cap()
                &&& Src::interfere(old(src_sess->Some_0).st(), final(src_sess->Some_0).st())
            },
            dst_sess is Some ==> {
                &&& Dst::wf(final(dst_sess->Some_0).st())
                &&& final(dst_sess->Some_0).cap() == old(dst_sess->Some_0).cap()
                &&& Dst::interfere(old(dst_sess->Some_0).st(), final(dst_sess->Some_0).st())
            },
            old(self).cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr ==> rmem_unchanged(
                *old(self),
                *final(self),
            ),
            old(self).cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr ==> ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as int;
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                let cell = dst.slice_pptr();
                let doff = dst.slice_offset() as int;
                &&& final(self).rmem_spec() is Some
                &&& final(self).rmem_spec()->Some_0.wf()
                &&& final(self).rmem_spec()->Some_0.has_mut_any(cell)
                &&& final(self).rmem_spec()->Some_0.matches_pptr_any(cell)
                &&& final(self).rmem_spec()->Some_0.is_mut_any(cell) == old(
                    self,
                ).rmem_spec()->Some_0.is_mut_any(cell)
                &&& final(self).rmem_spec()->Some_0.view_any(cell).len() == old(
                    self,
                ).rmem_spec()->Some_0.view_any(cell).len()
                &&& forall|i: int|
                    #![trigger final(self).rmem_spec()->Some_0.view_any(cell)[i]]
                    0 <= i < final(self).rmem_spec()->Some_0.view_any(cell).len() && !(doff <= i
                        < doff + k) ==> final(self).rmem_spec()->Some_0.view_any(cell)[i] == old(
                        self,
                    ).rmem_spec()->Some_0.view_any(cell)[i]
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
            !cpu_ready(final(self).cpu_spec()) ==> ({
                let n = old(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let m = final(self).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                let k = (n - m) as usize;
                let src = old(self).cpu_spec().get_reg_spec(Reg::Rsi);
                let dst = old(self).cpu_spec().get_reg_spec(Reg::Rdi);
                ||| src_sess is Some && Src::load_disposition(
                    final(src_sess->Some_0).st(),
                    src.foreign_ptr().region(),
                    (src.foreign_ptr().cursor().addr() + k) as usize,
                    1,
                ).permits_fault()
                ||| dst_sess is Some && Dst::store_disposition(
                    final(dst_sess->Some_0).st(),
                    dst.foreign_ptr().region(),
                    (dst.foreign_ptr().cursor().addr() + k) as usize,
                    1,
                ).permits_fault()
            }),
    {
        match (self.cpu.regs.get(Reg::Rsi), self.cpu.regs.get(Reg::Rdi)) {
            (RegVal::ForeignMemPtr(_), RegVal::RustMutSlicePtr(_)) => {
                match src_sess {
                    Option::Some(sess) => self.rep_movsb_foreign_to_rust(sess),
                    Option::None => unreached(),
                }
            },
            (
                RegVal::RustSharedSlicePtr(_)
                | RegVal::RustMutSlicePtr(_),
                RegVal::ForeignMemPtr(_),
            ) => {
                match dst_sess {
                    Option::Some(sess) => self.rep_movsb_rust_to_foreign(sess),
                    Option::None => unreached(),
                }
            },
            (
                RegVal::RustSharedSlicePtr(_)
                | RegVal::RustMutSlicePtr(_),
                RegVal::RustMutSlicePtr(_),
            ) => self.rep_movsb_rust_to_rust(),
            (RegVal::ForeignMemPtr(_), RegVal::ForeignMemPtr(_)) => {
                match (src_sess, dst_sess) {
                    (Option::Some(src), Option::Some(dst)) => {
                        self.rep_movsb_foreign_to_foreign(src, dst)
                    },
                    _ => unreached(),
                }
            },
            _ => unreached(),
        }
    }
}

} // verus!
