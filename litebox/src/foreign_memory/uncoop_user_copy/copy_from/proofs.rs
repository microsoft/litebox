// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![allow(clippy::elidable_lifetime_names, clippy::wildcard_imports)]

use vstd::prelude::*;

use true_tales::amd64::*;
use true_tales::fmem::capability::BoundSession;
#[cfg(verus_only)]
use true_tales::fmem::ptr::ForeignPtr;
use true_tales::fmem::session::DomainSession;
#[cfg(verus_only)]
use true_tales::machine::cpu::Cpu;
use true_tales::machine::hardware_thread::*;
#[cfg(verus_only)]
use true_tales::machine::reg_val::RegVal;
use true_tales::rmem::rmem_stack::*;

use super::super::CopyError;
use crate::foreign_memory::domains::uncoop_user_fault::UncoopFaultSession;
#[cfg(verus_only)]
use crate::foreign_memory::domains::uncoop_user_fault::UncoopFaultSessionView;
use crate::foreign_memory::fault_range::FaultRangePost;
#[cfg(verus_only)]
use crate::foreign_memory::fault_range::fault_cleared;

verus! {

#[cfg(verus_only)]
use true_tales::helpers::erased_pptr::ErasedPPtr;

broadcast use true_tales::amd64::group_amd64_frames;

pub(super) struct FallibleErrPost;

impl<'a, RM: RmemStack> RSliceMutPost<
    (),
    Amd64Cpu,
    RM,
    BoundSession<UncoopFaultSession<'a>>,
    Result<(), CopyError>,
> for FallibleErrPost {
    #[verifier::prophetic]
    open spec fn scoped<'scope>(
        _ctx: (),
        pre: Amd64Thread<RM>,
        _init_scope: Amd64Thread<RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        initial_slice: Seq<u8>,
        _orig_payload: BoundSession<UncoopFaultSession<'a>>,
        out: (Amd64Thread<RmemCons<'scope, RM>>, Result<(), CopyError>),
        final_payload: BoundSession<UncoopFaultSession<'a>>,
    ) -> bool {
        &&& copy_scope_post(out, slice_pptr, pre, initial_slice)
        &&& UncoopFaultSession::wf(final_payload.st())
    }

    #[verifier::prophetic]
    open spec fn outer(
        _ctx: (),
        pre: Amd64Thread<RM>,
        post: Amd64Thread<RM>,
        initial_slice: Seq<u8>,
        final_slice: Seq<u8>,
        _orig_payload: BoundSession<UncoopFaultSession<'a>>,
        final_payload: BoundSession<UncoopFaultSession<'a>>,
        _result: Result<(), CopyError>,
    ) -> bool {
        &&& post.wf()
        &&& post.rmem_spec() == pre.rmem_spec()
        &&& !pre.cpu_spec().get_reg_spec(Reg::Rax).is_slice_ptr() ==> post.cpu_spec().get_reg_spec(
            Reg::Rax,
        ) == pre.cpu_spec().get_reg_spec(Reg::Rax)
        &&& !pre.cpu_spec().get_reg_spec(Reg::Rdx).is_slice_ptr() ==> post.cpu_spec().get_reg_spec(
            Reg::Rdx,
        ) == pre.cpu_spec().get_reg_spec(Reg::Rdx)
        &&& df_unchanged(pre.cpu_spec(), post.cpu_spec())
        &&& cpu_ready(post.cpu_spec())
        &&& final_slice.len() == initial_slice.len()
        &&& UncoopFaultSession::wf(final_payload.st())
    }

    proof fn lift<'scope>(
        _ctx: (),
        _pre: Amd64Thread<RM>,
        _init_scope: Amd64Thread<RmemCons<'scope, RM>>,
        _slice_pptr: ErasedPPtr,
        _initial_slice: Seq<u8>,
        _orig_payload: BoundSession<UncoopFaultSession<'a>>,
        _out: (Amd64Thread<RmemCons<'scope, RM>>, Result<(), CopyError>),
        _final_payload: BoundSession<UncoopFaultSession<'a>>,
        _post: Amd64Thread<RM>,
        _final_slice: Seq<u8>,
    ) {
    }
}

#[verifier::prophetic]
pub open spec fn copy_scope_post<'a, RM: RmemStack>(
    out: (Amd64Thread<RmemCons<'a, RM>>, Result<(), CopyError>),
    pptr: ErasedPPtr,
    pre: Amd64Thread<RM>,
    dst_orig: Seq<u8>,
) -> bool {
    &&& out.0.wf()
    &&& Amd64Thread::rslice_mut_scope_reclaimable(out.0, pptr, pre)
    &&& out.0.cpu_spec().get_reg_spec(Reg::Rax) == pre.cpu_spec().get_reg_spec(Reg::Rax)
    &&& out.0.cpu_spec().get_reg_spec(Reg::Rdx) == pre.cpu_spec().get_reg_spec(Reg::Rdx)
    &&& df_unchanged(pre.cpu_spec(), out.0.cpu_spec())
    &&& cpu_ready(out.0.cpu_spec())
    &&& out.0.rmem_spec()->Some_0.view_any(pptr).len() == dst_orig.len()
}

pub(super) open spec fn session_load_ready(
    s0: UncoopFaultSessionView,
    src: ForeignPtr,
    len: usize,
) -> bool {
    &&& UncoopFaultSession::interfere(s0, s0)
    &&& UncoopFaultSession::load_disposition(s0, src.region(), src.cursor().addr(), len).permits_fault()
    &&& forall|env: UncoopFaultSessionView, off: usize|
        #![trigger UncoopFaultSession::load_disposition(env, src.region(), off, 1)]
        UncoopFaultSession::interfere(s0, env) && src.cursor().addr() <= off
            < src.cursor().addr() + len ==> (UncoopFaultSession::load_disposition(
        env,
        src.region(),
        off,
        1,
    ).permits_success() || UncoopFaultSession::load_disposition(env, src.region(), off, 1).permits_fault())
    &&& forall|env: UncoopFaultSessionView, p: UncoopFaultSessionView, off: usize, obs: Seq<u8>|
        #![trigger UncoopFaultSession::load_post(env, p, src.region(), off, 1, obs)]
        UncoopFaultSession::interfere(s0, env) && UncoopFaultSession::load_post(
            env,
            p,
            src.region(),
            off,
            1,
            obs,
        ) ==> UncoopFaultSession::interfere(s0, p)
}

pub(super) proof fn prepare_session_load(
    s0: UncoopFaultSessionView,
    src: ForeignPtr,
    len: usize,
)
    requires
        UncoopFaultSession::wf(s0),
        s0.region == src.region(),
    ensures
        session_load_ready(s0, src, len),
{
    UncoopFaultSession::lemma_interfere_refl(s0);
}

pub(super) open spec fn copy_scope_pre<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    session: BoundSession<UncoopFaultSession>,
    pre: Amd64Thread<RM>,
    dst_orig: Seq<u8>,
    s0: UncoopFaultSessionView,
    src: ForeignPtr,
    len: usize,
) -> bool {
    &&& Amd64Thread::rslice_mut_scope_ready(hw, pptr, Reg::Rdi, pre, dst_orig)
    &&& len > 0
    &&& dst_orig.len() == len
    &&& cpu_ready(pre.cpu_spec())
    &&& df_clear(pre.cpu_spec())
    &&& session.st() == s0
    &&& session.cap() == src.cap()
    &&& UncoopFaultSession::wf(s0)
    &&& s0.region == src.region()
    &&& src.cursor().addr() + len <= usize::MAX
    &&& session_load_ready(s0, src, len)
}

#[verifier::prophetic]
pub(super) open spec fn copy_scope_ensures<'a, RM: RmemStack>(
    initial: Amd64Thread<RmemCons<'a, RM>>,
    final_session: BoundSession<UncoopFaultSession>,
    out: (Amd64Thread<RmemCons<'a, RM>>, Result<(), CopyError>),
    pptr: ErasedPPtr,
    pre: Amd64Thread<RM>,
    dst_orig: Seq<u8>,
) -> bool {
    &&& Amd64Thread::rslice_mut_scope_finishable(out.0, pptr, pre, initial)
    &&& copy_scope_post(out, pptr, pre, dst_orig)
    &&& UncoopFaultSession::wf(final_session.st())
}

pub(super) open spec fn copy_range_pre<S: RmemStack, T: DomainSession>(
    h: Amd64Thread<S>,
    s: BoundSession<T>,
) -> bool {
    &&& df_clear(h.cpu_spec())
    &&& h.cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr
    &&& h.cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr
    &&& h.cpu_spec().get_reg_spec(Reg::Rcx) is Int
    &&& s.cap() == h.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr().cap()
    &&& T::wf(s.st())
    &&& ({
        let n = h.cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
        let src = h.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
        let dst = h.cpu_spec().get_reg_spec(Reg::Rdi);
        let cell = dst.slice_pptr();
        &&& n <= usize::MAX as nat
        &&& src.cursor().addr() as nat + n <= usize::MAX as nat
        &&& dst.slice_offset() as nat + n <= usize::MAX as nat
        &&& h.rmem_spec().wf()
        &&& h.rmem_spec()->Some_0.has_mut_any(cell)
        &&& h.rmem_spec()->Some_0.matches_pptr_any(cell)
        &&& dst.slice_offset() as nat + n <= h.rmem_spec()->Some_0.view_any(cell).len()
    })
    &&& ({
        let n = h.cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
        let src = h.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
        forall|env: T::State, off: usize|
            #![trigger T::load_disposition(env, src.region(), off, 1)]
            T::interfere(s.st(), env) && src.cursor().addr() <= off < src.cursor().addr() + n ==> (
            T::load_disposition(env, src.region(), off, 1).permits_success()
                || T::load_disposition(env, src.region(), off, 1).permits_fault())
    })
    &&& ({
        let src = h.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
        forall|env: T::State, p: T::State, off: usize, obs: Seq<u8>|
            #![trigger T::load_post(env, p, src.region(), off, 1, obs)]
            T::interfere(s.st(), env) && T::load_post(env, p, src.region(), off, 1, obs)
                ==> T::interfere(s.st(), p)
    })
}

pub(super) open spec fn copy_range_pre_fn<S: RmemStack, T: DomainSession>(
) -> spec_fn(Amd64Thread<S>, BoundSession<T>) -> bool {
    |h: Amd64Thread<S>, s: BoundSession<T>| copy_range_pre(h, s)
}

pub(super) proof fn establish_copy_range_pre<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    session: BoundSession<UncoopFaultSession>,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    pre: Amd64Thread<RM>,
    dst_orig: Seq<u8>,
    s0: UncoopFaultSessionView,
    src: ForeignPtr,
    len: usize,
)
    requires
        Amd64Thread::rslice_mut_scope_ready(init_hw, pptr, Reg::Rdi, pre, dst_orig),
        df_clear(pre.cpu_spec()),
        hw.wf(),
        hw.cpu_spec().get_reg_spec(Reg::Rsi) == RegVal::ForeignMemPtr(src),
        hw.cpu_spec().get_reg_spec(Reg::Rcx) == RegVal::Int(len as u64),
        hw.cpu_spec().get_reg_spec(Reg::Rdi) == init_hw.cpu_spec().get_reg_spec(Reg::Rdi),
        flags_unchanged(init_hw.cpu_spec(), hw.cpu_spec()),
        hw.rmem_spec() == init_hw.rmem_spec(),
        session.st() == s0,
        session.cap() == src.cap(),
        UncoopFaultSession::wf(s0),
        src.cursor().addr() + len <= usize::MAX,
        dst_orig.len() == len,
        session_load_ready(s0, src, len),
    ensures
        copy_range_pre(hw, session),
{
    assert(copy_range_pre(hw, session));
}

pub(super) struct CopyRangePost;

impl<S: RmemStack, T: DomainSession> FaultRangePost<S, T, ()> for CopyRangePost {
    #[verifier::prophetic]
    open spec fn post(
        _ctx: (),
        h0: Amd64Thread<S>,
        s0: BoundSession<T>,
        h1: Amd64Thread<S>,
        s1: BoundSession<T>,
        out: Result<(), Fault>,
    ) -> bool {
        &&& flags_unchanged(h0.cpu_spec(), h1.cpu_spec())
        &&& regs_unchanged_except(
            h0.cpu_spec(),
            h1.cpu_spec(),
            set![Reg::Rcx, Reg::Rsi, Reg::Rdi],
        )
        &&& T::wf(s1.st())
        &&& s1.cap() == s0.cap()
        &&& T::interfere(s0.st(), s1.st())
        &&& h1.cpu_spec().get_reg_spec(Reg::Rcx) is Int
        &&& ({
            let n = h0.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let m = h1.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            &&& m <= n
            &&& out is Err ==> m > 0
            &&& out is Ok ==> m == 0
        })
        &&& ({
            let n = h0.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let m = h1.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let k = (n - m) as usize;
            let src = h0.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
            let dst = h0.cpu_spec().get_reg_spec(Reg::Rdi);
            &&& h1.cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr
            &&& h1.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(k)
            &&& h1.cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr
            &&& h1.cpu_spec().get_reg_spec(Reg::Rdi).slice_pptr() == dst.slice_pptr()
            &&& h1.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() == dst.slice_offset() + k
        })
        &&& ({
            let n = h0.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let m = h1.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let k = (n - m) as usize;
            let src = h0.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
            out is Err ==> T::load_disposition(
                s1.st(),
                src.region(),
                (src.cursor().addr() + k) as usize,
                1,
            ).permits_fault()
        })
        &&& ({
            let n = h0.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let m = h1.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let k = (n - m) as int;
            let dst = h0.cpu_spec().get_reg_spec(Reg::Rdi);
            let cell = dst.slice_pptr();
            let doff = dst.slice_offset() as int;
            &&& h1.rmem_spec() is Some
            &&& h1.rmem_spec()->Some_0.wf()
            &&& h1.rmem_spec()->Some_0.has_mut_any(cell)
            &&& h1.rmem_spec()->Some_0.matches_pptr_any(cell)
            &&& h1.rmem_spec()->Some_0.is_mut_any(cell) == h0.rmem_spec()->Some_0.is_mut_any(cell)
            &&& h1.rmem_spec()->Some_0.view_any(cell).len() == h0.rmem_spec()->Some_0.view_any(
                cell,
            ).len()
            &&& forall|i: int|
                #![trigger h1.rmem_spec()->Some_0.view_any(cell)[i]]
                0 <= i < h1.rmem_spec()->Some_0.view_any(cell).len() && !(doff <= i < doff + k)
                    ==> h1.rmem_spec()->Some_0.view_any(cell)[i] == h0.rmem_spec()->Some_0.view_any(
                    cell,
                )[i]
            &&& S::mut_preserved_any(h1.rmem_spec()->Some_0, h0.rmem_spec()->Some_0, cell)
            &&& S::unchanged_except_any(h1.rmem_spec()->Some_0, h0.rmem_spec()->Some_0, cell)
        })
    }
}

pub(super) open spec fn copy_range_body_pre<S: RmemStack, T: DomainSession>(
    h: Amd64Thread<S>,
    s: BoundSession<T>,
) -> bool {
    cpu_ready(h.cpu_spec()) && copy_range_pre(h, s)
}

#[verifier::prophetic]
pub(super) open spec fn copy_range_body_post<S: RmemStack, T: DomainSession>(
    h0: Amd64Thread<S>,
    s0: BoundSession<T>,
    h1: Amd64Thread<S>,
    s1: BoundSession<T>,
    out: Result<(), Fault>,
) -> bool {
    &&& fault_result_matches(h1.cpu_spec(), out)
    &&& CopyRangePost::post((), h0, s0, fault_cleared(h1), s1, out)
}

proof fn copy_scope_finishable<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    pre: Amd64Thread<RM>,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
)
    requires
        pre.wf(),
        hw.wf(),
        init_hw.wf(),
        pre.rmem_spec() is Some,
        hw.rmem_spec()->Some_0.tail == pre.rmem_spec()->Some_0,
        hw.rmem_spec()->Some_0.addr == pptr.addr(),
        hw.rmem_spec().has_mut_any(pptr),
        hw.rmem_spec().matches_pptr_any(pptr),
        hw.rmem_spec().is_mut_any(pptr),
        RmemCons::mut_preserved_any(hw.rmem_spec()->Some_0, init_hw.rmem_spec()->Some_0, pptr),
    ensures
        Amd64Thread::rslice_mut_scope_finishable(hw, pptr, pre, init_hw),
{
    hw.rmem_spec()->Some_0.tail.lemma_matches_contains_any(pptr);
    hw.rmem_spec()->Some_0.tail.lemma_has_mut_matches_any(pptr);
}

pub(super) proof fn finish_copy_scope<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    session: BoundSession<UncoopFaultSession>,
    range_pre_hw: Amd64Thread<RmemCons<'a, RM>>,
    range_pre_session: BoundSession<UncoopFaultSession>,
    range_result: Result<(), Fault>,
    pptr: ErasedPPtr,
    pre: Amd64Thread<RM>,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
    dst_orig: Seq<u8>,
)
    requires
        copy_range_pre(range_pre_hw, range_pre_session),
        CopyRangePost::post(
            (),
            range_pre_hw,
            range_pre_session,
            hw,
            session,
            range_result,
        ),
        Amd64Thread::rslice_mut_scope_ready(init_hw, pptr, Reg::Rdi, pre, dst_orig),
        range_pre_hw.cpu_spec().get_reg_spec(Reg::Rax)
            == pre.cpu_spec().get_reg_spec(Reg::Rax),
        range_pre_hw.cpu_spec().get_reg_spec(Reg::Rdx)
            == pre.cpu_spec().get_reg_spec(Reg::Rdx),
        df_clear(range_pre_hw.cpu_spec()),
        flags_unchanged(pre.cpu_spec(), range_pre_hw.cpu_spec()),
        cpu_ready(hw.cpu_spec()),
        range_pre_hw.rmem_spec() == init_hw.rmem_spec(),
        range_pre_hw.cpu_spec().get_reg_spec(Reg::Rdi)
            == init_hw.cpu_spec().get_reg_spec(Reg::Rdi),
    ensures
        Amd64Thread::rslice_mut_scope_finishable(hw, pptr, pre, init_hw),
        copy_scope_post(
            (
                hw,
                if range_result is Ok {
                    Result::Ok(())
                } else {
                    Result::Err(CopyError::Fault)
                },
            ),
            pptr,
            pre,
            dst_orig,
        ),
        UncoopFaultSession::wf(session.st()),
{
    let copied = dst_orig.len() - hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
    assert(CopyRangePost::post(
        (),
        range_pre_hw,
        range_pre_session,
        hw,
        session,
        range_result,
    ));
    assert(hw.cpu_spec().get_reg_spec(Reg::Rax) == pre.cpu_spec().get_reg_spec(Reg::Rax)) by {
        assert(!set![Reg::Rcx, Reg::Rsi, Reg::Rdi].contains(Reg::Rax));
    }
    assert(hw.cpu_spec().get_reg_spec(Reg::Rdx) == pre.cpu_spec().get_reg_spec(Reg::Rdx)) by {
        assert(!set![Reg::Rcx, Reg::Rsi, Reg::Rdi].contains(Reg::Rdx));
    }
    assert(df_clear(hw.cpu_spec()));
    assert(hw.rmem_spec()->Some_0.view_any(pptr).len()
        == range_pre_hw.rmem_spec()->Some_0.view_any(pptr).len());
    assert(range_pre_hw.rmem_spec()->Some_0.view_any(pptr).len()
        == init_hw.rmem_spec()->Some_0.view_any(pptr).len());
    assert(init_hw.rmem_spec()->Some_0.view_any(pptr).len() == dst_orig.len());
    assert(hw.rmem_spec().view_any(pptr).len() == dst_orig.len());
    assert forall|i: int|
        copied <= i < dst_orig.len() implies #[trigger] hw.rmem_spec().view_any(pptr)[i]
        == dst_orig[i] by {}
    assert(pre.wf());
    assert(hw.wf());
    assert(init_hw.wf());
    assert(pre.rmem_spec() is Some);
    assert(hw.rmem_spec()->Some_0.tail == pre.rmem_spec()->Some_0);
    assert(hw.rmem_spec()->Some_0.addr == pptr.addr());
    assert(hw.rmem_spec().has_mut_any(pptr));
    assert(hw.rmem_spec().matches_pptr_any(pptr));
    assert(hw.rmem_spec().is_mut_any(pptr));
    assert(RmemCons::mut_preserved_any(
        hw.rmem_spec()->Some_0,
        init_hw.rmem_spec()->Some_0,
        pptr,
    ));
    copy_scope_finishable(hw, pptr, pre, init_hw);
    assert(Amd64Thread::rslice_mut_scope_reclaimable(hw, pptr, pre));
    assert(df_unchanged(pre.cpu_spec(), hw.cpu_spec()));
    assert(cpu_ready(hw.cpu_spec()));
    assert(copy_scope_post(
        (
            hw,
            if range_result is Ok {
                Result::Ok(())
            } else {
                Result::Err(CopyError::Fault)
            },
        ),
        pptr,
        pre,
        dst_orig,
    ));
}

} // verus!
