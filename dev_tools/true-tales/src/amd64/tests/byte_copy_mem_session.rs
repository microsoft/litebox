// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::*;
use crate::fmem::capability::{handle_obj, open_bound};
use crate::fmem::erasure::ErasedArc;
#[cfg(verus_only)]
use crate::fmem::erasure::{DynState, UnsizeShim};
use crate::fmem::ids::{ForeignDomainId, ForeignRegionId};
use crate::fmem::map::DomainMap;
use crate::fmem::ptr::ForeignPtr;
use crate::fmem::session::{AccessDisposition, DomainSession};
#[cfg(verus_only)]
use crate::fmem::test_domains::uncoop::UncoopUserSession;
#[cfg(verus_only)]
use crate::fmem::test_domains::uncoop::UncoopUserSessionView;
use crate::fmem::test_domains::uncoop::{UncoopUserDomain, UncoopUserDomainState};
#[cfg(verus_only)]
use crate::helpers::rust_any::type_tag;
#[cfg(verus_only)]
use crate::machine::hardware_thread::*;
use crate::machine::reg_val::RegVal;
#[cfg(verus_only)]
use crate::rmem::rmem_stack::RmemCons;
use crate::rmem::rmem_stack::{RmemNil, RmemStack};
use std::sync::Arc;
#[cfg(verus_only)]
use vstd::prelude::*;
use vstd::rwlock::{RwLock, RwLockPredicate};

verus! {

#[cfg(verus_only)]
use crate::helpers::erased_pptr::ErasedPPtr;

pub open spec fn uncoop_session_src_inv(
    st_now: UncoopUserSessionView,
    s0: UncoopUserSessionView,
    src: ForeignPtr,
    len: usize,
) -> bool {
    &&& st_now == s0
    &&& src.cursor().addr() + len <= usize::MAX
    &&& forall|k: usize|
        k < len ==> #[trigger] UncoopUserSession::load_disposition(
            s0,
            src.region(),
            (src.cursor().addr() + k) as usize,
            1,
        ).permits_success()
}

pub open spec fn byte_copy_mem_session_loop_running<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
) -> bool {
    hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int() >= 1
}

#[verifier::prophetic]
pub open spec fn byte_copy_mem_session_loop_inv<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    src: ForeignPtr,
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
    &&& hw.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(
        (len - hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int()) as usize,
    )
    &&& hw.rmem_spec().wf()
    &&& hw.rmem_spec()->Some_0.addr == pptr.addr()
    &&& hw.rmem_spec().has_mut_any(pptr)
    &&& hw.rmem_spec().matches_pptr_any(pptr)
    &&& hw.rmem_spec().is_mut_any(pptr)
    &&& hw.rmem_spec().view_any(pptr).len() == len
    &&& pre_dst_rmem is Some
    &&& hw.rmem_spec()->Some_0.tail == pre_dst_rmem->Some_0
    &&& hw.cpu_spec().flags_spec().df_spec() == old_df
    &&& cpu_ready(hw.cpu_spec())
    &&& RmemCons::mut_preserved_any(hw.rmem_spec()->Some_0, init_hw.rmem_spec()->Some_0, pptr)
}

#[verifier::prophetic]
pub open spec fn byte_copy_mem_session_loop_exit<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    src: ForeignPtr,
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
    &&& hw.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(len)
    &&& hw.rmem_spec().wf()
    &&& hw.rmem_spec()->Some_0.addr == pptr.addr()
    &&& hw.rmem_spec().has_mut_any(pptr)
    &&& hw.rmem_spec().matches_pptr_any(pptr)
    &&& hw.rmem_spec().is_mut_any(pptr)
    &&& hw.rmem_spec().view_any(pptr).len() == len
    &&& pre_dst_rmem is Some
    &&& hw.rmem_spec()->Some_0.tail == pre_dst_rmem->Some_0
    &&& byte_copy_mem_session_dst_rmem_finishable(hw, pptr, pre_dst_rmem)
    &&& hw.cpu_spec().flags_spec().df_spec() == old_df
    &&& cpu_ready(hw.cpu_spec())
    &&& RmemCons::mut_preserved_any(hw.rmem_spec()->Some_0, init_hw.rmem_spec()->Some_0, pptr)
}

pub open spec fn byte_copy_mem_session_dst_rmem_finishable<'a, RM: RmemStack>(
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

pub open spec fn byte_copy_mem_session_loop_decreases<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
) -> u64 {
    hw.cpu_spec().get_reg_spec(Reg::Rcx).as_int()
}

pub proof fn byte_copy_mem_session_after_rmem_store<'a, RM: RmemStack>(
    pre: Amd64Thread<RmemCons<'a, RM>>,
    post: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
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
        post.rmem_spec()->Some_0.view_any(pptr) == pre.rmem_spec()->Some_0.view_any(pptr).update(
            pre.cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() as int,
            low8(pre.cpu_spec().get_reg_spec(Reg::Rax).as_int()),
        ),
        RmemCons::unchanged_except_any(post.rmem_spec()->Some_0, pre.rmem_spec()->Some_0, pptr),
    ensures
        byte_copy_mem_session_dst_rmem_finishable(post, pptr, pre_dst_rmem),
        post.rmem_spec()->Some_0.view_any(pptr).len() == len,
{
    pre.rmem_spec()->Some_0.tail.lemma_matches_contains_any(pptr);
    pre.rmem_spec()->Some_0.tail.lemma_has_mut_matches_any(pptr);
}

pub proof fn byte_copy_mem_session_after_setup<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    src: ForeignPtr,
    len: usize,
    pre_dst_rmem: Option<RM>,
    old_df: bool,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
)
    requires
        len > 0,
        byte_copy_mem_session_dst_rmem_finishable(hw, pptr, pre_dst_rmem),
        hw.cpu_spec().get_reg_spec(Reg::Rcx) == RegVal::Int(len as u64),
        hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::RustMutSlicePtr(
            RustSliceCursor { slice_pptr: pptr, offset: 0 },
        ),
        hw.cpu_spec().get_reg_spec(Reg::Rsi) == RegVal::ForeignMemPtr(src),
        src.cursor().addr() + len <= usize::MAX,
        hw.rmem_spec()->Some_0.view_any(pptr).len() == len,
        hw.cpu_spec().flags_spec().df_spec() == old_df,
        cpu_ready(hw.cpu_spec()),
        RmemCons::mut_preserved_any(hw.rmem_spec()->Some_0, init_hw.rmem_spec()->Some_0, pptr),
    ensures
        byte_copy_mem_session_loop_inv(hw, pptr, src, len, pre_dst_rmem, old_df, init_hw),
{
    src.lemma_advance_zero();
}

pub proof fn byte_copy_mem_session_after_rsi_inc<'a, RM: RmemStack>(
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

pub proof fn byte_copy_mem_session_scope_finishable<'a, RM: RmemStack>(
    hw: Amd64Thread<RmemCons<'a, RM>>,
    pptr: ErasedPPtr,
    pre: Amd64Thread<RM>,
    init_hw: Amd64Thread<RmemCons<'a, RM>>,
)
    requires
        pre.wf(),
        hw.wf(),
        init_hw.wf(),
        byte_copy_mem_session_dst_rmem_finishable(hw, pptr, pre.rmem_spec()),
        RmemCons::mut_preserved_any(hw.rmem_spec()->Some_0, init_hw.rmem_spec()->Some_0, pptr),
    ensures
        Amd64Thread::rslice_mut_scope_finishable(hw, pptr, pre, init_hw),
{
    hw.rmem_spec()->Some_0.tail.lemma_matches_contains_any(pptr);
    hw.rmem_spec()->Some_0.tail.lemma_has_mut_matches_any(pptr);
}

#[allow(unused_variables)]
fn byte_copy_mem_session_loop_mechanical<RM: RmemStack>(
    dst: &mut [u8],
    src: ForeignPtr,
    h: &ErasedArc,
    hw: &mut Amd64Thread<RM>,
) -> Result<(), ()>
    requires
        old(dst)@.len() > 0,
        old(hw).wf(),
        cpu_ready(old(hw).cpu_spec()),
        h.wf(),
        h.spec_tag() == type_tag::<UnsizeShim<UncoopUserDomainState>>(),
        *h == src.cap(),
    ensures
        final(hw).wf(),
        final(hw).rmem_spec() == old(hw).rmem_spec(),
{
    let len: usize = dst.len();

    let sess = match open_bound::<UncoopUserDomain>(h) {
        Option::Some(x) => x,
        Option::None => return Err(()),
    };

    assert(*h == src.cap());
    assert(sess.cap() == src.cap());

    let a = src.cursor().addr();
    let AccessDisposition::Infallible = sess.check_load_disposition(src.region(), a, len) else {
        return Err(());
    };
    proof {
        UncoopUserSession::lemma_interfere_refl(sess.st());
        assert(UncoopUserSession::load_disposition(
            sess.st(),
            src.region(),
            a,
            len,
        ).is_infallible());
    }

    let ghost dst_orig = dst@;
    let ghost hw_pre_dst = *hw;
    let ghost s0 = sess.st();
    let ghost a = src.cursor().addr();

    proof {
        assert(a + len <= usize::MAX);
        assert forall|k: usize| k < len implies #[trigger] UncoopUserSession::load_disposition(
            s0,
            src.region(),
            (a + k) as usize,
            1,
        ).permits_success() by {}
        assert(uncoop_session_src_inv(s0, s0, src, len));
    }

    let (_dst_final, ()) = hw.with_rslice_mut::<(), NoopRSliceMutPost, (), (), _>(
        Reg::Rdi,
        dst,
        Ghost(()),
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
                uncoop_session_src_inv(s0, s0, src, len),
                *h == src.cap(),
            ensures
                Amd64Thread::rslice_mut_scope_finishable(out.0, dst_pptr, hw_pre_dst, hw_dst),
            {
                let ghost init_hw = hw_dst;
                let mut open_sess = sess;

                let _ = dst_pptr;

                hw_dst.bind_foreign_ptr(Reg::Rsi, src, h);
                hw_dst.reg_int_load_imm64(Reg::Rcx, len as u64);
                proof {
                    byte_copy_mem_session_after_setup(
                        hw_dst,
                        dst_pptr,
                        src,
                        len,
                        hw_pre_dst.rmem_spec(),
                        hw_pre_dst.cpu_spec().flags_spec().df_spec(),
                        init_hw,
                    );
                }

                'label2: loop
                    invariant_except_break
                        byte_copy_mem_session_loop_running(hw_dst),
                        byte_copy_mem_session_loop_inv(
                            hw_dst,
                            dst_pptr,
                            src,
                            len,
                            hw_pre_dst.rmem_spec(),
                            hw_pre_dst.cpu_spec().flags_spec().df_spec(),
                            init_hw,
                        ),
                        uncoop_session_src_inv(open_sess.st(), s0, src, len),
                        open_sess.cap() == src.cap(),
                    ensures
                        byte_copy_mem_session_loop_exit(
                            hw_dst,
                            dst_pptr,
                            src,
                            len,
                            hw_pre_dst.rmem_spec(),
                            hw_pre_dst.cpu_spec().flags_spec().df_spec(),
                            init_hw,
                        ),
                    decreases byte_copy_mem_session_loop_decreases(hw_dst),
                {
                    let ghost pre_load = hw_dst;
                    let ghost rcx = pre_load.cpu_spec().get_reg_spec(Reg::Rcx).as_int();
                    let ghost copied = (len - rcx) as usize;
                    let ghost next_copied = (copied + 1) as usize;

                    proof {
                        src.lemma_advance_fields(copied);
                    }
                    assert forall|env: UncoopUserSessionView| #[trigger]
                        UncoopUserSession::interfere(
                            open_sess.st(),
                            env,
                        ) implies UncoopUserSession::load_disposition(
                        env,
                        hw_dst.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr().region(),
                        hw_dst.cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr().cursor().addr(),
                        1,
                    ).permits_success() by {
                        assert(UncoopUserSession::load_disposition(
                            s0,
                            src.region(),
                            (src.cursor().addr() + copied) as usize,
                            1,
                        ).permits_success());
                    }

                    let _obs = hw_dst.fmem_int_load_byte(Reg::Rax, Reg::Rsi, &mut open_sess);

                    let ghost pre_store = hw_dst;
                    hw_dst.rmem_int_store_byte(Reg::Rdi, Reg::Rax);
                    proof {
                        byte_copy_mem_session_after_rmem_store(
                            pre_store,
                            hw_dst,
                            dst_pptr,
                            len,
                            hw_pre_dst.rmem_spec(),
                        );
                    }

                    hw_dst.reg_ptr_inc(Reg::Rdi);

                    let ghost pre_rsi_inc = hw_dst;
                    hw_dst.reg_ptr_inc(Reg::Rsi);
                    proof {
                        byte_copy_mem_session_after_rsi_inc(
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
                    byte_copy_mem_session_scope_finishable(hw_dst, dst_pptr, hw_pre_dst, init_hw);
                }
                open_sess.close();
                (hw_dst, ())
            },
    );

    Ok(())
}

pub fn drive_byte_copy_mem_session(obj: UncoopUserDomainState, dst: &mut [u8])
    requires
        obj.wf(),
        old(dst)@.len() > 0,
{
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut fmem = DomainMap::new();
    let region = obj.region();
    let _len = dst.len();

    let (_id, src, h) = fmem.inject_domain_ptr::<UncoopUserDomain>(region, obj);
    hw.cpu.bind_reg(Reg::Rsi, RegVal::ForeignMemPtr(src));

    let _ = byte_copy_mem_session_loop_mechanical(dst, src, &h, &mut hw);
}

pub struct DomainMapInv;

impl RwLockPredicate<DomainMap> for DomainMapInv {
    open spec fn inv(self, v: DomainMap) -> bool {
        v.wf()
    }
}

pub type SharedFmem = Arc<RwLock<DomainMap, DomainMapInv>>;

pub fn syscall_byte_copy_mem_session<RM: RmemStack>(
    fmem: &SharedFmem,
    id: ForeignDomainId,
    region: ForeignRegionId,
    cursor: *mut u8,
    dst: &mut [u8],
    hw: &mut Amd64Thread<RM>,
) -> Result<(), ()>
    requires
        old(dst)@.len() > 0,
        old(hw).wf(),
        cpu_ready(old(hw).cpu_spec()),
        (**fmem).pred() == DomainMapInv,
    ensures
        final(hw).wf(),
        final(hw).rmem_spec() == old(hw).rmem_spec(),
{
    let rh = (**fmem).acquire_read();
    let taken = rh.borrow().take_handle(id);
    rh.release_read();

    let h = match taken {
        Option::Some(h) => h,
        Option::None => return Err(()),
    };

    let _obj_ref = match handle_obj::<UncoopUserDomain>(&h) {
        Option::Some(o) => o,
        Option::None => return Err(()),
    };

    let src = ForeignPtr::from_handle(id, region, cursor, &h);
    assert(src.cap() == h);

    hw.cpu.bind_reg(Reg::Rsi, RegVal::ForeignMemPtr(src));

    byte_copy_mem_session_loop_mechanical(dst, src, &h, hw)
}

pub fn drive_shared_byte_copy_mem_session(
    obj_a: UncoopUserDomainState,
    obj_b: UncoopUserDomainState,
    dst_a: &mut [u8],
    dst_b: &mut [u8],
)
    requires
        obj_a.wf(),
        obj_b.wf(),
        old(dst_a)@.len() > 0,
        old(dst_b)@.len() > 0,
{
    let mut m = DomainMap::new();
    let region_a = obj_a.region();
    let region_b = obj_b.region();
    let (id_a, _ptr_a, _h_a) = m.inject_domain_ptr::<UncoopUserDomain>(region_a, obj_a);
    let (id_b, _ptr_b, _h_b) = m.inject_domain_ptr::<UncoopUserDomain>(region_b, obj_b);

    let fmem: SharedFmem = Arc::new(RwLock::new(m, Ghost(DomainMapInv)));

    let mut hw_a = Amd64Thread::<RmemNil>::new();
    let mut hw_b = Amd64Thread::<RmemNil>::new();

    let _ = syscall_byte_copy_mem_session(
        &fmem,
        id_a,
        region_a,
        core::ptr::null_mut(),
        dst_a,
        &mut hw_a,
    );
    let _ = syscall_byte_copy_mem_session(
        &fmem,
        id_b,
        region_b,
        core::ptr::null_mut(),
        dst_b,
        &mut hw_b,
    );
}

pub fn drive_shared_byte_copy_unrouted(
    obj: UncoopUserDomainState,
    other: UncoopUserDomainState,
    dst: &mut [u8],
)
    requires
        obj.wf(),
        other.wf(),
        old(dst)@.len() > 0,
{
    let mut m = DomainMap::new();
    let region = obj.region();
    let (_id, _ptr, _h) = m.inject_domain_ptr::<UncoopUserDomain>(region, obj);

    let mut other_map = DomainMap::new();
    let (foreign_id, _ptr2, _h2) = other_map.inject_domain_ptr::<UncoopUserDomain>(
        other.region(),
        other,
    );

    let fmem: SharedFmem = Arc::new(RwLock::new(m, Ghost(DomainMapInv)));

    let mut hw = Amd64Thread::<RmemNil>::new();
    let _ = syscall_byte_copy_mem_session(
        &fmem,
        foreign_id,
        region,
        core::ptr::null_mut(),
        dst,
        &mut hw,
    );
}

} // verus!

#[test]
fn byte_copy_mem_session_loop_runs() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let mut dst: [u8; 4] = [0xff; 4];
    let len = dst.len();
    let region = ForeignRegionId { raw: 0 };
    let cookie = DomainCookie { raw: 1 };
    let obj = UncoopUserDomainState::new(region, len, cookie);
    drive_byte_copy_mem_session(obj, &mut dst);
    assert_eq!(dst, [0u8; 4]);
}

#[test]
fn byte_copy_mem_session_shared_map_runs() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let mut dst_a: [u8; 4] = [0xff; 4];
    let mut dst_b: [u8; 3] = [0xee; 3];
    let obj_a = UncoopUserDomainState::new(
        ForeignRegionId { raw: 0 },
        dst_a.len(),
        DomainCookie { raw: 1 },
    );
    let obj_b = UncoopUserDomainState::new(
        ForeignRegionId { raw: 1 },
        dst_b.len(),
        DomainCookie { raw: 2 },
    );
    drive_shared_byte_copy_mem_session(obj_a, obj_b, &mut dst_a, &mut dst_b);
    assert_eq!(dst_a, [0u8; 4]);
    assert_eq!(dst_b, [0u8; 3]);
}

#[test]
fn byte_copy_mem_session_unrouted_id_is_rejected() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let mut dst: [u8; 4] = [0xff; 4];
    let obj = UncoopUserDomainState::new(
        ForeignRegionId { raw: 0 },
        dst.len(),
        DomainCookie { raw: 1 },
    );
    let other = UncoopUserDomainState::new(
        ForeignRegionId { raw: 9 },
        dst.len(),
        DomainCookie { raw: 2 },
    );
    drive_shared_byte_copy_unrouted(obj, other, &mut dst);
    assert_eq!(dst, [0xffu8; 4]);
}
