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
use true_tales::helpers::erased_pptr::ErasedPPtr;
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

broadcast use true_tales::amd64::group_amd64_frames;

pub(super) struct CopyToPost;

impl<'a, RM: RmemStack> RSlicePost<
    (),
    Amd64Cpu,
    RM,
    BoundSession<UncoopFaultSession<'a>>,
    Result<(), CopyError>,
> for CopyToPost {
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
        &&& out.0.wf()
        &&& Amd64Thread::rslice_scope_finishable(out.0, slice_pptr, pre)
        &&& out.0.rmem_spec()->Some_0.view_any(slice_pptr) == initial_slice
        &&& out.0.cpu_spec().get_reg_spec(Reg::Rax) == pre.cpu_spec().get_reg_spec(Reg::Rax)
        &&& out.0.cpu_spec().get_reg_spec(Reg::Rdx) == pre.cpu_spec().get_reg_spec(Reg::Rdx)
        &&& df_unchanged(pre.cpu_spec(), out.0.cpu_spec())
        &&& cpu_ready(out.0.cpu_spec())
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
        &&& !pre.cpu_spec().get_reg_spec(Reg::Rax).is_slice_ptr()
            ==> post.cpu_spec().get_reg_spec(Reg::Rax)
                == pre.cpu_spec().get_reg_spec(Reg::Rax)
        &&& !pre.cpu_spec().get_reg_spec(Reg::Rdx).is_slice_ptr()
            ==> post.cpu_spec().get_reg_spec(Reg::Rdx)
                == pre.cpu_spec().get_reg_spec(Reg::Rdx)
        &&& df_unchanged(pre.cpu_spec(), post.cpu_spec())
        &&& cpu_ready(post.cpu_spec())
        &&& final_slice == initial_slice
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

pub(super) open spec fn session_store_ready(
    s0: UncoopFaultSessionView,
    dst: ForeignPtr,
    len: usize,
) -> bool {
    &&& UncoopFaultSession::interfere(s0, s0)
    &&& forall|env: UncoopFaultSessionView, off: usize|
        #![trigger UncoopFaultSession::store_disposition(env, dst.region(), off, 1)]
        UncoopFaultSession::interfere(s0, env) && dst.cursor().addr() <= off
            < dst.cursor().addr() + len ==> (UncoopFaultSession::store_disposition(
        env,
        dst.region(),
        off,
        1,
    ).permits_success() || UncoopFaultSession::store_disposition(env, dst.region(), off, 1).permits_fault())
    &&& forall|env: UncoopFaultSessionView, p: UncoopFaultSessionView, off: usize, data: Seq<u8>|
        #![trigger UncoopFaultSession::store_post(env, p, dst.region(), off, 1, data)]
        UncoopFaultSession::interfere(s0, env) && UncoopFaultSession::store_post(
            env,
            p,
            dst.region(),
            off,
            1,
            data,
        ) ==> UncoopFaultSession::interfere(s0, p)
}

pub(super) proof fn prepare_session_store(
    s0: UncoopFaultSessionView,
    dst: ForeignPtr,
    len: usize,
)
    requires
        UncoopFaultSession::wf(s0),
        s0.region == dst.region(),
    ensures
        session_store_ready(s0, dst, len),
{
    UncoopFaultSession::lemma_interfere_refl(s0);
}

pub(super) open spec fn copy_scope_pre<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    session: BoundSession<UncoopFaultSession>,
    pre: Amd64Thread<RM>,
    src_orig: Seq<u8>,
    s0: UncoopFaultSessionView,
    dst: ForeignPtr,
    len: usize,
) -> bool {
    &&& Amd64Thread::rslice_scope_ready(hw, pptr, Reg::Rsi, pre, src_orig)
    &&& len > 0
    &&& src_orig.len() == len
    &&& cpu_ready(pre.cpu_spec())
    &&& df_clear(pre.cpu_spec())
    &&& session.st() == s0
    &&& session.cap() == dst.cap()
    &&& UncoopFaultSession::wf(s0)
    &&& s0.region == dst.region()
    &&& dst.cursor().addr() + len <= usize::MAX
    &&& session_store_ready(s0, dst, len)
}

#[verifier::prophetic]
pub(super) open spec fn copy_scope_ensures<'a, RM: RmemStack>(
    initial: Amd64Thread<RmemCons<'a, RM>>,
    initial_session: BoundSession<UncoopFaultSession>,
    final_session: BoundSession<UncoopFaultSession>,
    out: (Amd64Thread<RmemCons<'a, RM>>, Result<(), CopyError>),
    pptr: ErasedPPtr,
    pre: Amd64Thread<RM>,
    src_orig: Seq<u8>,
) -> bool {
    &&& Amd64Thread::rslice_scope_finishable(out.0, pptr, pre)
    &&& CopyToPost::scoped(
        (),
        pre,
        initial,
        pptr,
        src_orig,
        initial_session,
        out,
        final_session,
    )
}

pub(super) open spec fn copy_range_pre<S: RmemStack, T: DomainSession>(
    h: Amd64Thread<S>,
    s: BoundSession<T>,
) -> bool {
    &&& df_clear(h.cpu_spec())
    &&& h.cpu_spec().get_reg_spec(Reg::Rsi) is RustSharedSlicePtr
    &&& h.cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr
    &&& h.cpu_spec().get_reg_spec(Reg::Rcx) is Int
    &&& s.cap() == h.cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr().cap()
    &&& T::wf(s.st())
    &&& ({
        let n = h.cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
        let src = h.cpu_spec().get_reg_spec(Reg::Rsi);
        let dst = h.cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
        let cell = src.slice_pptr();
        &&& n <= usize::MAX as nat
        &&& src.slice_offset() as nat + n <= usize::MAX as nat
        &&& dst.cursor().addr() as nat + n <= usize::MAX as nat
        &&& h.rmem_spec().wf()
        &&& h.rmem_spec()->Some_0.has_read_any(cell)
        &&& h.rmem_spec()->Some_0.matches_pptr_any(cell)
        &&& !h.rmem_spec()->Some_0.is_mut_any(cell)
        &&& src.slice_offset() as nat + n <= h.rmem_spec()->Some_0.view_any(cell).len()
    })
    &&& ({
        let n = h.cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
        let dst = h.cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
        forall|env: T::State, off: usize|
            #![trigger T::store_disposition(env, dst.region(), off, 1)]
            T::interfere(s.st(), env) && dst.cursor().addr() <= off < dst.cursor().addr() + n ==> (
            T::store_disposition(env, dst.region(), off, 1).permits_success()
                || T::store_disposition(env, dst.region(), off, 1).permits_fault())
    })
    &&& ({
        let dst = h.cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
        forall|env: T::State, p: T::State, off: usize, data: Seq<u8>|
            #![trigger T::store_post(env, p, dst.region(), off, 1, data)]
            T::interfere(s.st(), env) && T::store_post(env, p, dst.region(), off, 1, data)
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
    src_orig: Seq<u8>,
    s0: UncoopFaultSessionView,
    dst: ForeignPtr,
    len: usize,
)
    requires
        Amd64Thread::rslice_scope_ready(init_hw, pptr, Reg::Rsi, pre, src_orig),
        df_clear(pre.cpu_spec()),
        hw.wf(),
        hw.cpu_spec().get_reg_spec(Reg::Rsi) == init_hw.cpu_spec().get_reg_spec(Reg::Rsi),
        hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::ForeignMemPtr(dst),
        hw.cpu_spec().get_reg_spec(Reg::Rcx) == RegVal::Int(len as u64),
        flags_unchanged(init_hw.cpu_spec(), hw.cpu_spec()),
        hw.rmem_spec() == init_hw.rmem_spec(),
        session.st() == s0,
        session.cap() == dst.cap(),
        UncoopFaultSession::wf(s0),
        dst.cursor().addr() + len <= usize::MAX,
        src_orig.len() == len,
        session_store_ready(s0, dst, len),
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
        &&& h1.rmem_spec() == h0.rmem_spec()
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
            let src = h0.cpu_spec().get_reg_spec(Reg::Rsi);
            let dst = h0.cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
            &&& h1.cpu_spec().get_reg_spec(Reg::Rsi) is RustSharedSlicePtr
            &&& h1.cpu_spec().get_reg_spec(Reg::Rsi).slice_pptr() == src.slice_pptr()
            &&& h1.cpu_spec().get_reg_spec(Reg::Rsi).slice_offset() == src.slice_offset() + k
            &&& h1.cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr
            &&& h1.cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr() == dst.advance(k)
        })
        &&& ({
            let n = h0.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let m = h1.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let k = (n - m) as usize;
            let dst = h0.cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
            out is Err ==> T::store_disposition(
                s1.st(),
                dst.region(),
                (dst.cursor().addr() + k) as usize,
                1,
            ).permits_fault()
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

pub(super) proof fn finish_copy_scope<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    session: BoundSession<UncoopFaultSession>,
    range_pre_hw: Amd64Thread<RmemCons<'a, RM>>,
    range_pre_session: BoundSession<UncoopFaultSession>,
    range_result: Result<(), Fault>,
    pptr: ErasedPPtr,
    pre: Amd64Thread<RM>,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
    src_orig: Seq<u8>,
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
        Amd64Thread::rslice_scope_ready(init_hw, pptr, Reg::Rsi, pre, src_orig),
        range_pre_hw.cpu_spec().get_reg_spec(Reg::Rax)
            == pre.cpu_spec().get_reg_spec(Reg::Rax),
        range_pre_hw.cpu_spec().get_reg_spec(Reg::Rdx)
            == pre.cpu_spec().get_reg_spec(Reg::Rdx),
        df_clear(range_pre_hw.cpu_spec()),
        flags_unchanged(pre.cpu_spec(), range_pre_hw.cpu_spec()),
        cpu_ready(hw.cpu_spec()),
        range_pre_hw.rmem_spec() == init_hw.rmem_spec(),
    ensures
        Amd64Thread::rslice_scope_finishable(hw, pptr, pre),
        hw.rmem_spec()->Some_0.view_any(pptr) == src_orig,
        hw.cpu_spec().get_reg_spec(Reg::Rax) == pre.cpu_spec().get_reg_spec(Reg::Rax),
        hw.cpu_spec().get_reg_spec(Reg::Rdx) == pre.cpu_spec().get_reg_spec(Reg::Rdx),
        df_unchanged(pre.cpu_spec(), hw.cpu_spec()),
        cpu_ready(hw.cpu_spec()),
        UncoopFaultSession::wf(session.st()),
{
    assert(hw.cpu_spec().get_reg_spec(Reg::Rax) == pre.cpu_spec().get_reg_spec(Reg::Rax)) by {
        assert(!set![Reg::Rcx, Reg::Rsi, Reg::Rdi].contains(Reg::Rax));
    }
    assert(hw.cpu_spec().get_reg_spec(Reg::Rdx) == pre.cpu_spec().get_reg_spec(Reg::Rdx)) by {
        assert(!set![Reg::Rcx, Reg::Rsi, Reg::Rdi].contains(Reg::Rdx));
    }
    assert(df_clear(hw.cpu_spec()));
    assert(hw.rmem_spec() == init_hw.rmem_spec());
    assert(hw.rmem_spec()->Some_0.view_any(pptr) == src_orig);
    assert(Amd64Thread::rslice_scope_finishable(hw, pptr, pre));
}

} // verus!
