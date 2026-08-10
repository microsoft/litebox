use crate::amd64::*;
use crate::fmem::capability::{BoundSession, open_bound};
#[cfg(verus_only)]
use crate::fmem::erasure::DynState;
use crate::fmem::map::DomainMap;
use crate::fmem::ptr::ForeignPtr;
use crate::fmem::session::{AccessDisposition, DomainSession};
#[cfg(verus_only)]
use crate::fmem::test_domains::stable::StableUserSessionView;
use crate::fmem::test_domains::stable::{
    StableUserDomain, StableUserDomainState, StableUserSession,
};
#[cfg(verus_only)]
use crate::machine::hardware_thread::*;
use crate::machine::reg_val::RegVal;
#[cfg(verus_only)]
use crate::rmem::rmem_stack::RmemCons;
use crate::rmem::rmem_stack::{RmemNil, RmemStack};
#[cfg(verus_only)]
use vstd::assert_seqs_equal;
use vstd::pervasive::unreached;
#[cfg(verus_only)]
use vstd::prelude::*;

verus! {

#[cfg(verus_only)]
use crate::helpers::erased_pptr::ErasedPPtr;

pub open spec fn stable_session_src_inv(
    st_now: StableUserSessionView,
    s0: StableUserSessionView,
    src: ForeignPtr,
    src_bytes: Seq<u8>,
    len: usize,
) -> bool {
    &&& st_now == s0
    &&& StableUserSession::wf(s0)
    &&& s0.base <= src.cursor().addr()
    &&& src.cursor().addr() + len <= usize::MAX
    &&& src.cursor().addr() - s0.base + len <= s0.bytes().len()
    &&& src_bytes == s0.bytes().subrange(
        src.cursor().addr() - s0.base,
        src.cursor().addr() - s0.base + len,
    )
    &&& src_bytes.len() == len
    &&& forall|k: usize|
        k < len ==> #[trigger] StableUserSession::load_disposition(
            s0,
            src.region(),
            (src.cursor().addr() + k) as usize,
            1,
        ).permits_success()
}

pub open spec fn byte_copy_stable_session_loop_running<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
) -> bool {
    hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int() >= 1
}

#[verifier::prophetic]
pub open spec fn byte_copy_stable_session_loop_inv<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    src: ForeignPtr,
    src_bytes: Seq<u8>,
    len: usize,
    pre_dst_rmem: Option<RM>,
    old_df: bool,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
) -> bool {
    &&& hw.cpu_spec().get_reg_spec(Reg::Rcx) is Int
    &&& hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int() >= 1
    &&& hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int() <= len
    &&& hw.cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr
    &&& hw.cpu_spec().get_reg_spec(Reg::Rdi).slice_addr() == pptr.addr()
    &&& hw.cpu_spec().get_reg_spec(Reg::Rdi).slice_pptr() == pptr
    &&& hw.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() == len - hw.cpu_spec().get_reg_spec(
        Reg::Rcx,
    ).as_int()
    &&& hw.cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr
    &&& src.cursor().addr() + len <= usize::MAX
    &&& src_bytes.len() == len
    &&& hw.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(
        (len - hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int()) as usize,
    )
    &&& hw.rmem_spec().wf()
    &&& hw.rmem_spec()->Some_0.addr == pptr.addr()
    &&& hw.rmem_spec().has_mut_any(pptr)
    &&& hw.rmem_spec().matches_pptr_any(pptr)
    &&& hw.rmem_spec().is_mut_any(pptr)
    &&& hw.rmem_spec().view_any(pptr).len() == len
    &&& hw.rmem_spec().view_any(pptr).subrange(
        0,
        (len - hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int()) as int,
    ) == src_bytes.subrange(0, (len - hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int()) as int)
    &&& pre_dst_rmem is Some
    &&& hw.rmem_spec()->Some_0.tail == pre_dst_rmem->Some_0
    &&& hw.cpu_spec().flags_spec().df_spec() == old_df
    &&& cpu_ready(hw.cpu_spec())
    &&& RmemCons::mut_preserved_any(hw.rmem_spec()->Some_0, init_hw.rmem_spec()->Some_0, pptr)
}

#[verifier::prophetic]
pub open spec fn byte_copy_stable_session_loop_exit<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    src: ForeignPtr,
    src_bytes: Seq<u8>,
    len: usize,
    pre_dst_rmem: Option<RM>,
    old_df: bool,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
) -> bool {
    &&& hw.cpu_spec().get_reg_spec(Reg::Rcx) is Int
    &&& hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int() == 0
    &&& hw.cpu_spec().flags_spec().zf_spec() == FlagVal::Defined(true)
    &&& hw.cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr
    &&& src.cursor().addr() + len <= usize::MAX
    &&& src_bytes.len() == len
    &&& hw.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(len)
    &&& hw.rmem_spec().wf()
    &&& hw.rmem_spec()->Some_0.addr == pptr.addr()
    &&& hw.rmem_spec().has_mut_any(pptr)
    &&& hw.rmem_spec().matches_pptr_any(pptr)
    &&& hw.rmem_spec().is_mut_any(pptr)
    &&& hw.rmem_spec().view_any(pptr).len() == len
    &&& hw.rmem_spec().view_any(pptr).subrange(0, len as int) == src_bytes.subrange(0, len as int)
    &&& pre_dst_rmem is Some
    &&& hw.rmem_spec()->Some_0.tail == pre_dst_rmem->Some_0
    &&& byte_copy_stable_session_dst_rmem_finishable(hw, pptr, pre_dst_rmem)
    &&& hw.cpu_spec().flags_spec().df_spec() == old_df
    &&& cpu_ready(hw.cpu_spec())
    &&& RmemCons::mut_preserved_any(hw.rmem_spec()->Some_0, init_hw.rmem_spec()->Some_0, pptr)
}

pub open spec fn byte_copy_stable_session_dst_rmem_finishable<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    pre_rmem: Option<RM>,
) -> bool {
    &&& pre_rmem is Some
    &&& hw.rmem_spec().wf()
    &&& hw.rmem_spec()->Some_0.tail == pre_rmem->Some_0
    &&& hw.rmem_spec()->Some_0.addr == pptr.addr()
    &&& hw.rmem_spec().has_mut_any(pptr)
    &&& hw.rmem_spec().matches_pptr_any(pptr)
    &&& hw.rmem_spec().is_mut_any(pptr)
}

pub open spec fn byte_copy_stable_session_loop_decreases<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
) -> u64 {
    hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int()
}

pub proof fn byte_copy_stable_session_after_rmem_store<'a, RM: RmemStack>(
    pre: Amd64Thread<RmemCons<'a, RM>>,
    post: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    src_bytes: Seq<u8>,
    len: usize,
    pre_dst_rmem: Option<RM>,
)
    requires
        pre_dst_rmem is Some,
        pre.rmem_spec() is Some,
        pre.rmem_spec()->Some_0.wf(),
        pre.rmem_spec()->Some_0.has_mut_any(pptr),
        pre.rmem_spec()->Some_0.matches_pptr_any(pptr),
        pre.rmem_spec()->Some_0.is_mut_any(pptr),
        pre.rmem_spec()->Some_0.addr == pptr.addr(),
        pre.rmem_spec()->Some_0.tail == pre_dst_rmem->Some_0,
        pre.rmem_spec()->Some_0.view_any(pptr).len() == len,
        regs_unchanged(pre.cpu_spec(), post.cpu_spec()),
        flags_unchanged(pre.cpu_spec(), post.cpu_spec()),
        post.rmem_spec() is Some,
        post.rmem_spec()->Some_0.wf(),
        post.rmem_spec()->Some_0.has_mut_any(pptr),
        post.rmem_spec()->Some_0.matches_pptr_any(pptr),
        post.rmem_spec()->Some_0.is_mut_any(pptr) == pre.rmem_spec()->Some_0.is_mut_any(pptr),
        pre.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() < pre.rmem_spec()->Some_0.view_any(
            pptr,
        ).len(),
        src_bytes.len() == len,
        pre.rmem_spec()->Some_0.view_any(pptr).subrange(
            0,
            pre.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() as int,
        ) == src_bytes.subrange(0, pre.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() as int),
        low8(pre.cpu_spec().get_reg_spec(Reg::Rax).as_int())
            == src_bytes[pre.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() as int],
        post.rmem_spec()->Some_0.view_any(pptr) == pre.rmem_spec()->Some_0.view_any(pptr).update(
            pre.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() as int,
            low8(pre.cpu_spec().get_reg_spec(Reg::Rax).as_int()),
        ),
        RmemCons::unchanged_except_any(post.rmem_spec()->Some_0, pre.rmem_spec()->Some_0, pptr),
    ensures
        byte_copy_stable_session_dst_rmem_finishable(post, pptr, pre_dst_rmem),
        post.rmem_spec()->Some_0.view_any(pptr).len() == len,
        post.rmem_spec()->Some_0.view_any(pptr).subrange(
            0,
            pre.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() as int + 1,
        ) == src_bytes.subrange(0, pre.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() as int + 1),
{
    let off = pre.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() as int;
    let val = low8(pre.cpu_spec().get_reg_spec(Reg::Rax).as_int());
    let preview = pre.rmem_spec()->Some_0.view_any(pptr);
    let postview = post.rmem_spec()->Some_0.view_any(pptr);
    pre.rmem_spec()->Some_0.tail.lemma_matches_contains_any(pptr);
    pre.rmem_spec()->Some_0.tail.lemma_has_mut_matches_any(pptr);
    assert_seqs_equal!(postview.subrange(0, off + 1) == src_bytes.subrange(0, off + 1));
}

pub proof fn byte_copy_stable_session_after_setup<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    src: ForeignPtr,
    src_bytes: Seq<u8>,
    len: usize,
    pre_dst_rmem: Option<RM>,
    old_df: bool,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
)
    requires
        len > 0,
        byte_copy_stable_session_dst_rmem_finishable(hw, pptr, pre_dst_rmem),
        hw.cpu_spec().get_reg_spec(Reg::Rcx) == RegVal::Int(len as u64),
        hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::RustMutSlicePtr(
            RustSliceCursor { slice_pptr: pptr, offset: 0 },
        ),
        hw.cpu_spec().get_reg_spec(Reg::Rsi) == RegVal::ForeignMemPtr(src),
        src.cursor().addr() + len <= usize::MAX,
        src_bytes.len() == len,
        hw.rmem_spec()->Some_0.view_any(pptr).len() == len,
        hw.cpu_spec().flags_spec().df_spec() == old_df,
        cpu_ready(hw.cpu_spec()),
        RmemCons::mut_preserved_any(hw.rmem_spec()->Some_0, init_hw.rmem_spec()->Some_0, pptr),
    ensures
        byte_copy_stable_session_loop_inv(
            hw,
            pptr,
            src,
            src_bytes,
            len,
            pre_dst_rmem,
            old_df,
            init_hw,
        ),
{
    src.lemma_advance_zero();
    assert(src_bytes.subrange(0, len as int) =~= src_bytes);
    assert(hw.rmem_spec()->Some_0.view_any(pptr).subrange(0, 0) =~= src_bytes.subrange(0, 0));
}

pub proof fn byte_copy_stable_session_after_load(
    s0: StableUserSessionView,
    s1: StableUserSessionView,
    src: ForeignPtr,
    src_bytes: Seq<u8>,
    len: usize,
    copied: usize,
    observed: u8,
)
    requires
        stable_session_src_inv(s0, s0, src, src_bytes, len),
        copied < len,
        exists|env: StableUserSessionView| #[trigger]
            StableUserSession::interfere(s0, env) && StableUserSession::load_post(
                env,
                s1,
                src.region(),
                (src.cursor().addr() + copied) as usize,
                1,
                seq![observed],
            ),
    ensures
        s1 == s0,
        observed == src_bytes[copied as int],
{
    let a = src.cursor().addr();

    let env = choose|e: StableUserSessionView|
        #![trigger StableUserSession::interfere(s0, e)]
        StableUserSession::interfere(s0, e) && StableUserSession::load_post(
            e,
            s1,
            src.region(),
            (a + copied) as usize,
            1,
            seq![observed],
        );
    assert(env == s0);
    assert(s1 == s0);

    assert(seq![observed] == s0.bytes().subrange(a + copied - s0.base, a + copied - s0.base + 1));
    assert(s0.bytes().subrange(a + copied - s0.base, a + copied - s0.base + 1)[0] == s0.bytes()[a
        + copied - s0.base]);
    assert(src_bytes[copied as int] == s0.bytes()[a - s0.base + copied]);
}

pub proof fn byte_copy_stable_session_after_rsi_inc<'a, RM: RmemStack>(
    pre: Amd64Thread<RmemCons<'a, RM>>,
    post: Amd64Thread<RmemCons<'a, RM>>,
    src: ForeignPtr,
    copied: usize,
    next_copied: usize,
)
    requires
        next_copied == copied + 1,
        src.cursor().addr() + next_copied <= usize::MAX,
        pre.cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr,
        pre.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(copied),
        post.cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr,
        post.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == pre.cpu_spec().get_reg_spec(
            Reg::Rsi,
        ).foreign_ptr().advance(1),
        post.cpu_spec().get_reg_spec(Reg::Rsi).foreign_domain() == pre.cpu_spec().get_reg_spec(
            Reg::Rsi,
        ).foreign_domain(),
        post.cpu_spec().get_reg_spec(Reg::Rsi).foreign_region() == pre.cpu_spec().get_reg_spec(
            Reg::Rsi,
        ).foreign_region(),
        pre.cpu_spec().get_reg_spec(Reg::Rsi).foreign_offset() < usize::MAX
            ==> post.cpu_spec().get_reg_spec(Reg::Rsi).foreign_offset()
            == pre.cpu_spec().get_reg_spec(Reg::Rsi).foreign_offset() + 1,
    ensures
        post.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(next_copied),
{
    src.lemma_advance_fields(copied);
    src.lemma_advance_add(copied, 1);
}

pub proof fn byte_copy_stable_session_scope_finishable<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    pre: Amd64Thread<RM>,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
)
    requires
        pre.wf(),
        hw.wf(),
        init_hw.wf(),
        byte_copy_stable_session_dst_rmem_finishable(hw, pptr, pre.rmem_spec()),
        RmemCons::mut_preserved_any(hw.rmem_spec()->Some_0, init_hw.rmem_spec()->Some_0, pptr),
    ensures
        Amd64Thread::rslice_mut_scope_finishable(hw, pptr, pre, init_hw),
{
    hw.rmem_spec()->Some_0.tail.lemma_matches_contains_any(pptr);
    hw.rmem_spec()->Some_0.tail.lemma_has_mut_matches_any(pptr);
}

#[allow(unused_variables)]
fn byte_copy_stable_session_loop_mechanical<'s, RM: RmemStack>(
    dst: &mut [u8],
    src: ForeignPtr,
    sess: BoundSession<StableUserSession<'s>>,
    hw: &mut Amd64Thread<RM>,
)
    requires
        old(dst)@.len() > 0,
        old(hw).wf(),
        cpu_ready(old(hw).cpu_spec()),
        sess.cap() == src.cap(),
        StableUserSession::wf(sess.st()),
        StableUserSession::load_disposition(
            sess.st(),
            src.region(),
            src.cursor().addr(),
            old(dst)@.len() as usize,
        ).permits_success(),
    ensures
        final(hw).wf(),
        final(hw).rmem_spec() == old(hw).rmem_spec(),
        final(dst)@ == sess.st().bytes().subrange(
            src.cursor().addr() - sess.st().base,
            src.cursor().addr() - sess.st().base + old(dst)@.len(),
        ),
{
    let len: usize = dst.len();

    let ghost dst_orig = dst@;
    let ghost hw_pre_dst = *hw;
    let ghost s0 = sess.st();
    let ghost a = src.cursor().addr();
    let ghost src_bytes = s0.bytes().subrange(a - s0.base, a - s0.base + len);

    proof {
        assert(s0.bytes().len() == s0.len);
        assert(a + len <= usize::MAX);
        assert(src_bytes.len() == len);
        assert forall|k: usize| k < len implies #[trigger] StableUserSession::load_disposition(
            s0,
            src.region(),
            (a + k) as usize,
            1,
        ).permits_success() by {}
        assert(stable_session_src_inv(s0, s0, src, src_bytes, len));
    }

    let (_dst_final, ()) = hw.with_rslice_mut::<Seq<u8>, FinalSliceEq, (), (), _>(
        Reg::Rdi,
        dst,
        Ghost(src_bytes),
        &mut (),
        Ghost(()),
        move |mut hw_dst, dst_pptr, _payload| -> (out: (Amd64Thread<_>, ()))
            requires
                Amd64Thread::rslice_mut_scope_ready(
                    hw_dst,
                    dst_pptr,
                    Reg::Rdi,
                    hw_pre_dst,
                    dst_orig,
                ),
                *_payload == (),
                len > 0,
                dst_orig.len() == len,
                sess.st() == s0,
                sess.cap() == src.cap(),
                stable_session_src_inv(s0, s0, src, src_bytes, len),
            ensures
                Amd64Thread::rslice_mut_scope_finishable(out.0, dst_pptr, hw_pre_dst, hw_dst),
                out.0.rmem_spec()->Some_0.view_any(dst_pptr) =~= src_bytes,
            {
                let ghost init_hw = hw_dst;
                let mut open_sess = sess;

                let _ = dst_pptr;

                hw_dst.cpu.regs.set(Reg::Rsi, RegVal::ForeignMemPtr(src));
                hw_dst.reg_int_load_imm64(Reg::Rcx, len as u64);
                proof {
                    byte_copy_stable_session_after_setup(
                        hw_dst,
                        dst_pptr,
                        src,
                        src_bytes,
                        len,
                        hw_pre_dst.rmem_spec(),
                        hw_pre_dst.cpu_spec().flags_spec().df_spec(),
                        init_hw,
                    );
                }

                'label2: loop
                    invariant_except_break
                        byte_copy_stable_session_loop_running(hw_dst),
                        byte_copy_stable_session_loop_inv(
                            hw_dst,
                            dst_pptr,
                            src,
                            src_bytes,
                            len,
                            hw_pre_dst.rmem_spec(),
                            hw_pre_dst.cpu_spec().flags_spec().df_spec(),
                            init_hw,
                        ),
                        stable_session_src_inv(open_sess.st(), s0, src, src_bytes, len),
                        open_sess.cap() == src.cap(),
                    ensures
                        byte_copy_stable_session_loop_exit(
                            hw_dst,
                            dst_pptr,
                            src,
                            src_bytes,
                            len,
                            hw_pre_dst.rmem_spec(),
                            hw_pre_dst.cpu_spec().flags_spec().df_spec(),
                            init_hw,
                        ),
                        stable_session_src_inv(open_sess.st(), s0, src, src_bytes, len),
                    decreases byte_copy_stable_session_loop_decreases(hw_dst),
                {
                    let ghost pre_load = hw_dst;
                    let ghost rcx = pre_load.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                    let ghost copied = (len - rcx) as usize;
                    let ghost next_copied = (copied + 1) as usize;

                    proof {
                        src.lemma_advance_fields(copied);
                    }
                    assert forall|env: StableUserSessionView| #[trigger]
                        StableUserSession::interfere(
                            open_sess.st(),
                            env,
                        ) implies StableUserSession::load_disposition(
                        env,
                        hw_dst.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr().region(),
                        hw_dst.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr().cursor().addr(),
                        1,
                    ).permits_success() by {
                        assert(StableUserSession::load_disposition(
                            s0,
                            src.region(),
                            (src.cursor().addr() + copied) as usize,
                            1,
                        ).permits_success());
                    }

                    let _obs = hw_dst.fmem_int_load_byte(Reg::Rax, Reg::Rsi, &mut open_sess);
                    proof {
                        byte_copy_stable_session_after_load(
                            s0,
                            open_sess.st(),
                            src,
                            src_bytes,
                            len,
                            copied,
                            _obs@,
                        );
                    }

                    let ghost pre_store = hw_dst;
                    hw_dst.rmem_int_store_byte(Reg::Rdi, Reg::Rax);
                    proof {
                        byte_copy_stable_session_after_rmem_store(
                            pre_store,
                            hw_dst,
                            dst_pptr,
                            src_bytes,
                            len,
                            hw_pre_dst.rmem_spec(),
                        );
                    }

                    hw_dst.reg_ptr_inc(Reg::Rdi);

                    let ghost pre_rsi_inc = hw_dst;
                    hw_dst.reg_ptr_inc(Reg::Rsi);
                    proof {
                        byte_copy_stable_session_after_rsi_inc(
                            pre_rsi_inc,
                            hw_dst,
                            src,
                            copied,
                            next_copied,
                        );
                    }

                    hw_dst.reg_int_dec(Reg::Rcx);

                    if !hw_dst.flag_read_zf() {
                        continue 'label2 ;
                    }
                    break 'label2 ;
                }

                proof {
                    byte_copy_stable_session_scope_finishable(
                        hw_dst,
                        dst_pptr,
                        hw_pre_dst,
                        init_hw,
                    );

                    let v = hw_dst.rmem_spec()->Some_0.view_any(dst_pptr);
                    assert(v =~= v.subrange(0, len as int));
                }

                open_sess.close();
                (hw_dst, ())
            },
    );

}

pub fn drive_byte_copy_stable_session(obj: StableUserDomainState, dst: &mut [u8])
    requires
        obj.wf(),
        old(dst)@.len() > 0,
{
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut fmem = DomainMap::new();

    let region = obj.region();
    let len = dst.len();

    let (_id, src, h) = fmem.inject_domain_ptr::<StableUserDomain>(region, obj);
    hw.cpu.bind_reg(Reg::Rsi, RegVal::ForeignMemPtr(src));

    let sess = match open_bound::<StableUserDomain>(&h) {
        Option::Some(x) => x,
        Option::None => unreached(),
    };

    assert(h == src.cap());
    assert(sess.cap() == src.cap());

    let a = src.cursor().addr();
    let AccessDisposition::Infallible = sess.check_load_disposition(region, a, len) else {
        return;
    };
    proof {
        StableUserSession::lemma_interfere_refl(sess.st());
        assert(StableUserSession::load_disposition(sess.st(), region, a, len).is_infallible());
    }

    byte_copy_stable_session_loop_mechanical(dst, src, sess, &mut hw);
}

} // verus!
#[test]
fn byte_copy_stable_session_loop_runs() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let mut dst: [u8; 4] = [0xff; 4];
    let region = ForeignRegionId { raw: 0 };
    let cookie = DomainCookie { raw: 1 };
    let obj = StableUserDomainState::from_backing(region, 0, vec![0x11, 0x22, 0x33, 0x44], cookie);

    drive_byte_copy_stable_session(obj, &mut dst);
    assert_eq!(dst, [0x11, 0x22, 0x33, 0x44]);
}
