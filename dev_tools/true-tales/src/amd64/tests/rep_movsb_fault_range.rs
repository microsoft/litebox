// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::*;
use crate::fmem::capability::{BoundSession, open_bound};
#[cfg(verus_only)]
use crate::fmem::erasure::DynState;
use crate::fmem::erasure::ErasedArc;
use crate::fmem::ids::ForeignRegionId;
use crate::fmem::map::DomainMap;
use crate::fmem::ptr::ForeignPtr;
#[cfg(verus_only)]
use crate::fmem::session::AccessDisposition;
use crate::fmem::session::DomainSession;
#[cfg(verus_only)]
use crate::fmem::test_domains::uncoop_fault::UncoopFaultSession;
#[cfg(verus_only)]
use crate::fmem::test_domains::uncoop_fault::UncoopFaultSessionView;
use crate::fmem::test_domains::uncoop_fault::{UncoopFaultDomain, UncoopFaultDomainState};
#[cfg(verus_only)]
use crate::helpers::erased_pptr::ErasedPPtr;
#[cfg(verus_only)]
use crate::machine::hardware_thread::*;

#[cfg(verus_only)]
use crate::machine::reg_val::RegVal;
#[cfg(verus_only)]
use crate::rmem::rmem_stack::RmemCons;
use crate::rmem::rmem_stack::{RmemNil, RmemStack};
#[cfg(verus_only)]
use vstd::prelude::*;

verus! {

pub open spec fn fault_cleared<S: RmemStack>(t: Amd64Thread<S>) -> Amd64Thread<S> {
    t.clear_fault_spec()
}

pub type FaultRangePre<S, T> = Ghost<spec_fn(Amd64Thread<S>, BoundSession<T>) -> bool>;

pub trait FaultRangePost<S: RmemStack, T: DomainSession, Ctx> {
    #[verifier::prophetic]
    spec fn post(
        ctx: Ctx,
        h0: Amd64Thread<S>,
        s0: BoundSession<T>,
        h1: Amd64Thread<S>,
        s1: BoundSession<T>,
        out: Result<(), Fault>,
    ) -> bool;
}

#[allow(unused_variables)]
pub fn fault_range<S: RmemStack, T: DomainSession, Ctx, Post, Body>(
    hw: &mut Amd64Thread<S>,
    sess: &mut BoundSession<T>,
    ctx: Ghost<Ctx>,
    pre: FaultRangePre<S, T>,
    body: Body,
) -> (r: Result<(), Fault>) where
    Post: FaultRangePost<S, T, Ctx>,
    Body: FnOnce(&mut Amd64Thread<S>, &mut BoundSession<T>) -> Result<(), Fault>,

    requires
        cpu_ready(old(hw).cpu_spec()),
        pre@(*old(hw), *old(sess)),
        forall|h: &mut Amd64Thread<S>, s: &mut BoundSession<T>|
            #![trigger body.requires((h, s))]
            (cpu_ready(h.cpu_spec()) && pre@(*h, *s)) ==> body.requires((h, s)),
        forall|h: &mut Amd64Thread<S>, s: &mut BoundSession<T>, out: Result<(), Fault>|
            #![trigger body.ensures((h, s), out)]
            (cpu_ready(h.cpu_spec()) && pre@(*h, *s) && body.ensures((h, s), out)) ==> {
                &&& fault_result_matches(final(h).cpu_spec(), out)
                &&& Post::post(ctx@, *h, *s, fault_cleared(*final(h)), *final(s), out)
            },
    ensures
        cpu_ready(final(hw).cpu_spec()),
        Post::post(ctx@, *old(hw), *old(sess), *final(hw), *final(sess), r),
{
    let r = body(hw, sess);
    if r.is_err() {
        let ghost mid = *hw;
        hw.begin_fault_handler();
        assert(*hw == fault_cleared(mid));
    }
    assert(*hw == fault_cleared(*hw));
    r
}

pub proof fn rep_movsb_scope_finishable<'a, RM: RmemStack>(
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

pub struct RepMovsbPost;

impl<RM: RmemStack, Pld> RSliceMutPost<(), Amd64Cpu, RM, Pld, usize> for RepMovsbPost {
    #[verifier::prophetic]
    open spec fn scoped<'scope>(
        _ctx: (),
        pre: Amd64Thread<RM>,
        _init_scope: Amd64Thread<RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        initial_slice: Seq<u8>,
        _orig_payload: Pld,
        out: (Amd64Thread<RmemCons<'scope, RM>>, usize),
        _final_payload: Pld,
    ) -> bool {
        &&& out.1 <= initial_slice.len()
        &&& cpu_ready(out.0.cpu_spec())
        &&& flags_unchanged(pre.cpu_spec(), out.0.cpu_spec())
        &&& out.0.rmem_spec()->Some_0.view_any(slice_pptr).len() == initial_slice.len()
        &&& forall|i: int|
            out.1 <= i < initial_slice.len() ==> #[trigger] out.0.rmem_spec()->Some_0.view_any(
                slice_pptr,
            )[i] == initial_slice[i]
    }

    #[verifier::prophetic]
    open spec fn outer(
        _ctx: (),
        pre: Amd64Thread<RM>,
        post: Amd64Thread<RM>,
        initial_slice: Seq<u8>,
        final_slice: Seq<u8>,
        _orig_payload: Pld,
        _final_payload: Pld,
        result: usize,
    ) -> bool {
        &&& result <= initial_slice.len()
        &&& cpu_ready(post.cpu_spec())
        &&& flags_unchanged(pre.cpu_spec(), post.cpu_spec())
        &&& final_slice.len() == initial_slice.len()
        &&& forall|i: int|
            result <= i < initial_slice.len() ==> #[trigger] final_slice[i] == initial_slice[i]
    }

    proof fn lift<'scope>(
        _ctx: (),
        _pre: Amd64Thread<RM>,
        _init_scope: Amd64Thread<RmemCons<'scope, RM>>,
        _slice_pptr: ErasedPPtr,
        _initial_slice: Seq<u8>,
        _orig_payload: Pld,
        _out: (Amd64Thread<RmemCons<'scope, RM>>, usize),
        _final_payload: Pld,
        _post: Amd64Thread<RM>,
        _final_slice: Seq<u8>,
    ) {
    }
}

pub open spec fn rep_movsb_load_range_pre<S: RmemStack, T: DomainSession>(
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
            T::load_disposition(env, src.region(), off, 1).permits_success() || T::load_disposition(
                env,
                src.region(),
                off,
                1,
            ).permits_fault())
    })
    &&& ({
        let src = h.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
        forall|env: T::State, p: T::State, off: usize, obs: Seq<u8>|
            #![trigger T::load_post(env, p, src.region(), off, 1, obs)]
            T::interfere(s.st(), env) && T::load_post(env, p, src.region(), off, 1, obs)
                ==> T::interfere(s.st(), p)
    })
}

pub struct RepMovsbLoadRangePost;

impl<S: RmemStack, T: DomainSession> FaultRangePost<S, T, ()> for RepMovsbLoadRangePost {
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
        &&& regs_unchanged_except(h0.cpu_spec(), h1.cpu_spec(), set![Reg::Rcx, Reg::Rsi, Reg::Rdi])
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

#[allow(unused_variables)]
pub fn rep_movsb_load_range<S: RmemStack, T: DomainSession>(
    hw: &mut Amd64Thread<S>,
    sess: &mut BoundSession<T>,
) -> (r: Result<(), Fault>)
    requires
        cpu_ready(old(hw).cpu_spec()),
        rep_movsb_load_range_pre(*old(hw), *old(sess)),
    ensures
        cpu_ready(final(hw).cpu_spec()),
        RepMovsbLoadRangePost::post((), *old(hw), *old(sess), *final(hw), *final(sess), r),
{
    let ghost pre: spec_fn(Amd64Thread<S>, BoundSession<T>) -> bool = |
        h: Amd64Thread<S>,
        s: BoundSession<T>,
    |
        rep_movsb_load_range_pre::<S, T>(h, s);

    fault_range::<S, T, (), RepMovsbLoadRangePost, _>(
        hw,
        sess,
        Ghost(()),
        Ghost(pre),
        |h: &mut Amd64Thread<S>, s: &mut BoundSession<T>| -> (out: Result<(), Fault>)
            requires
                cpu_ready(old(h).cpu_spec()),
                pre(*old(h), *old(s)),
            ensures
                fault_result_matches(final(h).cpu_spec(), out),
                RepMovsbLoadRangePost::post(
                    (),
                    *old(h),
                    *old(s),
                    fault_cleared(*final(h)),
                    *final(s),
                    out,
                ),
            { h.rep_movsb::<T, T>(Option::Some(s), Option::None) },
    )
}

pub fn copy_from_uncoop_user_rep_movsb<RM: RmemStack>(
    dst: &mut [u8],
    src: ForeignPtr,
    h: &ErasedArc,
    hw: &mut Amd64Thread<RM>,
) -> (copied: usize)
    requires
        old(hw).wf(),
        cpu_ready(old(hw).cpu_spec()),
        df_clear(old(hw).cpu_spec()),
        old(dst)@.len() > 0,
        h.wf(),
        *h == src.cap(),
        src.cursor().addr() + old(dst)@.len() <= usize::MAX,
    ensures
        final(hw).wf(),
        final(hw).rmem_spec() == old(hw).rmem_spec(),
        cpu_ready(final(hw).cpu_spec()),
        flags_unchanged(old(hw).cpu_spec(), final(hw).cpu_spec()),
        copied <= old(dst)@.len(),
        final(dst)@.len() == old(dst)@.len(),
        forall|i: int| copied <= i < old(dst)@.len() ==> #[trigger] final(dst)@[i] == old(dst)@[i],
{
    let len: usize = dst.len();

    let sess = match open_bound::<UncoopFaultDomain>(h) {
        Option::Some(x) => x,
        Option::None => return 0,
    };
    assert(dst@ =~= old(dst)@);
    assert(sess.cap() == src.cap());

    let a = src.cursor().addr();
    let _disposition = sess.check_load_disposition(src.region(), a, 1);
    if _disposition.is_invalid() {
        sess.close();
        return 0;
    }
    let ghost dst_orig = dst@;
    let ghost hw_pre = *hw;
    let ghost s0 = sess.st();
    proof {
        UncoopFaultSession::lemma_interfere_refl(s0);
        match _disposition {
            AccessDisposition::Infallible => {
                assert(BoundSession::<UncoopFaultSession>::load_disposition(
                    s0,
                    src.region(),
                    a,
                    1,
                ).is_infallible());
            },
            AccessDisposition::AlwaysFaults => {
                assert(BoundSession::<UncoopFaultSession>::load_disposition(
                    s0,
                    src.region(),
                    a,
                    1,
                ).is_always_faulting());
            },
            AccessDisposition::MayFault => {
                assert(BoundSession::<UncoopFaultSession>::load_disposition(
                    s0,
                    src.region(),
                    a,
                    1,
                ).is_invalid() == false);
            },
            AccessDisposition::Invalid => {},
        }
        assert(BoundSession::<UncoopFaultSession>::load_disposition(
            s0,
            src.region(),
            a,
            1,
        ).is_invalid() == false);
        assert(UncoopFaultSession::load_disposition(s0, src.region(), a, 1).is_invalid() == false);
        assert(s0.region == src.region());
    }

    let (_dst_final, copied) = hw.with_rslice_mut::<(), RepMovsbPost, (), usize, _>(
        Reg::Rdi,
        dst,
        Ghost(()),
        &mut (),
        Ghost(()),
        move |mut hw_dst, dst_pptr, _payload| -> (out: (Amd64Thread<_>, usize))
            requires
                Amd64Thread::rslice_mut_scope_ready(hw_dst, dst_pptr, Reg::Rdi, hw_pre, dst_orig),
                len > 0,
                dst_orig.len() == len,
                cpu_ready(hw_pre.cpu_spec()),
                df_clear(hw_pre.cpu_spec()),
                sess.st() == s0,
                sess.cap() == src.cap(),
                UncoopFaultSession::wf(s0),
                s0.region == src.region(),
                src.cursor().addr() + len <= usize::MAX,
            ensures
                Amd64Thread::rslice_mut_scope_finishable(out.0, dst_pptr, hw_pre, hw_dst),
                RepMovsbPost::scoped((), hw_pre, hw_dst, dst_pptr, dst_orig, (), out, ()),
            {
                let ghost init_hw = hw_dst;
                let mut open_sess = sess;

                let _ = dst_pptr;

                hw_dst.bind_foreign_ptr(Reg::Rsi, src, h);
                hw_dst.reg_int_load_imm64(Reg::Rcx, len as u64);

                hw_dst.reg_int_load_imm64(Reg::Rax, 0xa5);
                let ghost pre_movsb = hw_dst;

                assert forall|env: UncoopFaultSessionView, off: usize|
                    #![trigger UncoopFaultSession::load_disposition(env, src.region(), off, 1)]
                    UncoopFaultSession::interfere(s0, env) && src.cursor().addr() <= off
                        < src.cursor().addr() + len implies (UncoopFaultSession::load_disposition(
                    env,
                    src.region(),
                    off,
                    1,
                ).permits_success() || UncoopFaultSession::load_disposition(
                    env,
                    src.region(),
                    off,
                    1,
                ).permits_fault()) by {}

                assert forall|
                    env: UncoopFaultSessionView,
                    p: UncoopFaultSessionView,
                    off: usize,
                    obs: Seq<u8>,
                |
                    #![trigger UncoopFaultSession::load_post(env, p, src.region(), off, 1, obs)]
                    UncoopFaultSession::interfere(s0, env) && UncoopFaultSession::load_post(
                        env,
                        p,
                        src.region(),
                        off,
                        1,
                        obs,
                    ) implies UncoopFaultSession::interfere(s0, p) by {}

                assert(rep_movsb_load_range_pre(hw_dst, open_sess));

                let r = rep_movsb_load_range(&mut hw_dst, &mut open_sess);
                let _ = r;

                let copied: usize = len - hw_dst.reg_int_read(Reg::Rcx) as usize;

                assert(cpu_ready(hw_dst.cpu_spec()));
                assert(copied <= len);
                assert(r is Err ==> copied < len);
                assert(r is Ok ==> copied == len);

                assert(hw_dst.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(
                    copied,
                ));
                assert(hw_dst.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() == copied);
                assert(r is Err ==> UncoopFaultSession::load_disposition(
                    open_sess.st(),
                    src.region(),
                    (src.cursor().addr() + copied) as usize,
                    1,
                ).permits_fault());

                assert(hw_dst.cpu_spec().get_reg_spec(Reg::Rax) == RegVal::Int(0xa5)) by {
                    assert(!set![Reg::Rcx, Reg::Rsi, Reg::Rdi].contains(Reg::Rax));
                }
                assert(hw_dst.cpu_spec().get_reg_spec(Reg::Rdx)
                    == pre_movsb.cpu_spec().get_reg_spec(Reg::Rdx)) by {
                    assert(!set![Reg::Rcx, Reg::Rsi, Reg::Rdi].contains(Reg::Rdx));
                }

                assert(hw_dst.rmem_spec().view_any(dst_pptr).len() == len);
                assert forall|i: int|
                    copied <= i < len implies #[trigger] hw_dst.rmem_spec().view_any(dst_pptr)[i]
                    == dst_orig[i] by {}

                assert(df_clear(hw_dst.cpu_spec()));

                proof {
                    rep_movsb_scope_finishable(hw_dst, dst_pptr, hw_pre, init_hw);
                }
                open_sess.close();
                (hw_dst, copied)
            },
    );

    copied
}

pub fn drive_copy_from_uncoop_user_rep_movsb(obj: UncoopFaultDomainState, dst: &mut [u8])
    requires
        obj.wf(),
        old(dst)@.len() > 0,
        obj.backing().spec_base() as int + old(dst)@.len() <= usize::MAX,
{
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut fmem = DomainMap::new();
    let region = obj.region();

    let (_id, src, h) = fmem.inject_domain_ptr::<UncoopFaultDomain>(region, obj);

    assert(src.cursor().addr() == 0);
    let _copied = copy_from_uncoop_user_rep_movsb(dst, src, &h, &mut hw);
}

} // verus!

#[test]
fn copy_from_uncoop_user_rep_movsb_drives() {
    use crate::fmem::ids::DomainCookie;
    let region = ForeignRegionId { raw: 3 };
    let cookie = DomainCookie { raw: 5 };
    let obj = UncoopFaultDomainState::zeroed(region, 0, 4, cookie);
    let mut dst: [u8; 4] = [0xffu8; 4];

    drive_copy_from_uncoop_user_rep_movsb(obj, &mut dst);
}
