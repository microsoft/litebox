// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::{Amd64Thread, Fault, Reg};
#[cfg(verus_only)]
use crate::amd64::{cpu_ready, df_clear, flags_unchanged, regs_unchanged_except};
use crate::fmem::capability::BoundSession;
use crate::fmem::capability::open_bound;
use crate::fmem::ids::{DomainCookie, ForeignRegionId};
use crate::fmem::map::DomainMap;
use crate::fmem::session::DomainSession;
use crate::fmem::test_domains::stable::{
    StableUserDomain, StableUserDomainState, StableUserSession,
};
use crate::fmem::test_domains::uncoop_fault::{UncoopFaultDomain, UncoopFaultDomainState};
#[cfg(verus_only)]
use crate::machine::cpu::Cpu;
#[cfg(verus_only)]
use crate::machine::reg_val::RegVal;
use crate::rmem::rmem_stack::{RmemNil, RmemStack};
use vstd::prelude::*;

verus! {

pub fn drive_rep_movsb_rust_to_rust<S: RmemStack, Src: DomainSession, Dst: DomainSession>(
    hw: &mut Amd64Thread<S>,
) -> (out: Result<(), Fault>)
    requires
        cpu_ready(old(hw).cpu_spec()),
        df_clear(old(hw).cpu_spec()),
        old(hw).cpu_spec().get_reg_spec(Reg::Rsi).is_slice_ptr(),
        old(hw).cpu_spec().get_reg_spec(Reg::Rdi) is RustMutSlicePtr,
        old(hw).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
        ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
            let src = old(hw).cpu_spec().get_reg_spec(Reg::Rsi);
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi);
            &&& n <= usize::MAX as nat
            &&& src.slice_pptr() != dst.slice_pptr()
            &&& src.slice_offset() as nat + n <= usize::MAX as nat
            &&& dst.slice_offset() as nat + n <= usize::MAX as nat
            &&& old(hw).rmem_spec().wf()
            &&& old(hw).rmem_spec()->Some_0.has_read_any(src.slice_pptr())
            &&& old(hw).rmem_spec()->Some_0.matches_pptr_any(src.slice_pptr())
            &&& old(hw).rmem_spec()->Some_0.is_mut_any(src.slice_pptr()) == (src is RustMutSlicePtr)
            &&& src.slice_offset() as nat + n <= old(hw).rmem_spec()->Some_0.view_any(
                src.slice_pptr(),
            ).len()
            &&& old(hw).rmem_spec()->Some_0.has_mut_any(dst.slice_pptr())
            &&& old(hw).rmem_spec()->Some_0.matches_pptr_any(dst.slice_pptr())
            &&& dst.slice_offset() as nat + n <= old(hw).rmem_spec()->Some_0.view_any(
                dst.slice_pptr(),
            ).len()
        }),
    ensures
        out is Ok,
        cpu_ready(final(hw).cpu_spec()),
        df_clear(final(hw).cpu_spec()),
        final(hw).cpu_spec().get_reg_spec(Reg::Rcx) == RegVal::Int(0),
        flags_unchanged(old(hw).cpu_spec(), final(hw).cpu_spec()),
        regs_unchanged_except(
            old(hw).cpu_spec(),
            final(hw).cpu_spec(),
            set![Reg::Rcx, Reg::Rsi, Reg::Rdi],
        ),
        ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as usize;
            let src = old(hw).cpu_spec().get_reg_spec(Reg::Rsi);
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi);
            &&& final(hw).cpu_spec().get_reg_spec(Reg::Rsi).slice_pptr() == src.slice_pptr()
            &&& final(hw).cpu_spec().get_reg_spec(Reg::Rsi).slice_offset() == src.slice_offset() + n
            &&& final(hw).cpu_spec().get_reg_spec(Reg::Rdi).slice_pptr() == dst.slice_pptr()
            &&& final(hw).cpu_spec().get_reg_spec(Reg::Rdi).slice_offset() == dst.slice_offset() + n
        }),
{
    let out = hw.rep_movsb::<Src, Dst>(Option::None, Option::None);
    assert(out is Ok);
    assert(df_clear(hw.cpu_spec()));
    out
}

pub fn drive_rep_movsb_rust_to_foreign<S: RmemStack, Src: DomainSession, Dst: DomainSession>(
    hw: &mut Amd64Thread<S>,
    dst_sess: &mut BoundSession<Dst>,
) -> (out: Result<(), Fault>)
    requires
        cpu_ready(old(hw).cpu_spec()),
        df_clear(old(hw).cpu_spec()),
        old(hw).cpu_spec().get_reg_spec(Reg::Rsi).is_slice_ptr(),
        old(hw).cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr,
        old(hw).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
        old(dst_sess).cap() == old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr().cap(),
        Dst::wf(old(dst_sess).st()),
        ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
            let src = old(hw).cpu_spec().get_reg_spec(Reg::Rsi);
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
            &&& n <= usize::MAX as nat
            &&& src.slice_offset() as nat + n <= usize::MAX as nat
            &&& dst.cursor().addr() as nat + n <= usize::MAX as nat
            &&& old(hw).rmem_spec().wf()
            &&& old(hw).rmem_spec()->Some_0.has_read_any(src.slice_pptr())
            &&& old(hw).rmem_spec()->Some_0.matches_pptr_any(src.slice_pptr())
            &&& old(hw).rmem_spec()->Some_0.is_mut_any(src.slice_pptr()) == (src is RustMutSlicePtr)
            &&& src.slice_offset() as nat + n <= old(hw).rmem_spec()->Some_0.view_any(
                src.slice_pptr(),
            ).len()
        }),
        ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
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
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
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
        out is Ok ==> final(hw).cpu_spec().get_reg_spec(Reg::Rcx) == RegVal::Int(0),
        out is Err ==> final(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int() > 0,
        out is Err ==> ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let m = final(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let k = (n - m) as usize;
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
            Dst::store_disposition(
                final(dst_sess).st(),
                dst.region(),
                (dst.cursor().addr() + k) as usize,
                1,
            ).permits_fault()
        }),
        df_clear(final(hw).cpu_spec()),
        flags_unchanged(old(hw).cpu_spec(), final(hw).cpu_spec()),
        regs_unchanged_except(
            old(hw).cpu_spec(),
            final(hw).cpu_spec(),
            set![Reg::Rcx, Reg::Rsi, Reg::Rdi],
        ),
        ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let m = final(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let k = (n - m) as usize;
            let src = old(hw).cpu_spec().get_reg_spec(Reg::Rsi);
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
            &&& final(hw).cpu_spec().get_reg_spec(Reg::Rsi).slice_offset() == src.slice_offset() + k
            &&& final(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr() == dst.advance(k)
        }),
{
    let out = hw.rep_movsb::<Src, Dst>(Option::None, Option::Some(dst_sess));
    assert(df_clear(hw.cpu_spec()));
    out
}

pub fn drive_rep_movsb_foreign_to_foreign<S: RmemStack, Src: DomainSession, Dst: DomainSession>(
    hw: &mut Amd64Thread<S>,
    src_sess: &mut BoundSession<Src>,
    dst_sess: &mut BoundSession<Dst>,
) -> (out: Result<(), Fault>)
    requires
        cpu_ready(old(hw).cpu_spec()),
        df_clear(old(hw).cpu_spec()),
        old(hw).cpu_spec().get_reg_spec(Reg::Rsi) is ForeignMemPtr,
        old(hw).cpu_spec().get_reg_spec(Reg::Rdi) is ForeignMemPtr,
        old(hw).cpu_spec().get_reg_spec(Reg::Rcx) is Int,
        old(src_sess).cap() == old(hw).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr().cap(),
        old(dst_sess).cap() == old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr().cap(),
        Src::wf(old(src_sess).st()),
        Dst::wf(old(dst_sess).st()),
        ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
            let src = old(hw).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
            &&& n <= usize::MAX as nat
            &&& src.cursor().addr() as nat + n <= usize::MAX as nat
            &&& dst.cursor().addr() as nat + n <= usize::MAX as nat
        }),
        ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
            let src = old(hw).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
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
            let src = old(hw).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
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
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int() as nat;
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
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
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
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
        out is Ok ==> final(hw).cpu_spec().get_reg_spec(Reg::Rcx) == RegVal::Int(0),
        out is Err ==> final(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int() > 0,
        out is Err ==> ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let m = final(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let k = (n - m) as usize;
            let src = old(hw).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
            ||| Src::load_disposition(
                final(src_sess).st(),
                src.region(),
                (src.cursor().addr() + k) as usize,
                1,
            ).permits_fault()
            ||| Dst::store_disposition(
                final(dst_sess).st(),
                dst.region(),
                (dst.cursor().addr() + k) as usize,
                1,
            ).permits_fault()
        }),
        df_clear(final(hw).cpu_spec()),
        flags_unchanged(old(hw).cpu_spec(), final(hw).cpu_spec()),
        regs_unchanged_except(
            old(hw).cpu_spec(),
            final(hw).cpu_spec(),
            set![Reg::Rcx, Reg::Rsi, Reg::Rdi],
        ),
        ({
            let n = old(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let m = final(hw).cpu_spec().get_reg_spec(Reg::Rcx).as_int();
            let k = (n - m) as usize;
            let src = old(hw).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr();
            let dst = old(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr();
            &&& final(hw).cpu_spec().get_reg_spec(Reg::Rsi).foreign_ptr() == src.advance(k)
            &&& final(hw).cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr() == dst.advance(k)
        }),
{
    let out = hw.rep_movsb(Option::Some(src_sess), Option::Some(dst_sess));
    assert(df_clear(hw.cpu_spec()));
    out
}

} // verus!

#[test]
fn rust_to_rust_shared_source() {
    let hw = Amd64Thread::<RmemNil>::new();
    let src = [1u8, 2, 3];
    let mut dst = [0u8; 3];
    let (hw, src_pptr) = hw.inject_rslice(Reg::Rsi, &src);
    let (mut hw, dst_pptr) = hw.inject_rslice_mut(Reg::Rdi, &mut dst);
    hw.reg_int_load_imm64(Reg::Rcx, 3);
    hw.reg_int_load_imm64(Reg::Rax, 0xa5);
    let out =
        drive_rep_movsb_rust_to_rust::<_, StableUserSession<'_>, StableUserSession<'_>>(&mut hw);
    assert!(out.is_ok());
    assert_eq!(hw.reg_int_read(Reg::Rcx), 0);
    assert_eq!(hw.reg_int_read(Reg::Rax), 0xa5);
    let (hw, _) = hw.reclaim_rslice_mut(dst_pptr);
    let (_, _) = hw.reclaim_rslice(src_pptr);
    assert_eq!(dst, src);
}

#[test]
fn rust_to_rust_mutable_source() {
    let hw = Amd64Thread::<RmemNil>::new();
    let mut src = [1u8, 2, 3];
    let mut dst = [0u8; 3];
    let (hw, src_pptr) = hw.inject_rslice_mut(Reg::Rsi, &mut src);
    let (mut hw, dst_pptr) = hw.inject_rslice_mut(Reg::Rdi, &mut dst);
    hw.reg_int_load_imm64(Reg::Rcx, 3);
    let out =
        drive_rep_movsb_rust_to_rust::<_, StableUserSession<'_>, StableUserSession<'_>>(&mut hw);
    assert!(out.is_ok());
    let (hw, _) = hw.reclaim_rslice_mut(dst_pptr);
    let (_, _) = hw.reclaim_rslice_mut(src_pptr);
    assert_eq!(dst, src);
}

#[test]
fn rust_to_foreign_success() {
    let hw = Amd64Thread::<RmemNil>::new();
    let src = [1u8, 2, 3];
    let (mut hw, src_pptr) = hw.inject_rslice(Reg::Rsi, &src);
    let mut map = DomainMap::new();
    let region = ForeignRegionId { raw: 1 };
    let obj = StableUserDomainState::from_backing(region, 0, vec![0u8; 3], DomainCookie { raw: 1 });
    let (_, dst, handle) = map.inject_domain_ptr::<StableUserDomain>(region, obj);
    hw.bind_foreign_ptr(Reg::Rdi, dst, &handle);
    hw.reg_int_load_imm64(Reg::Rcx, 3);
    hw.reg_int_load_imm64(Reg::Rax, 0xa5);
    let mut sess = open_bound::<StableUserDomain>(&handle).unwrap();
    let out = drive_rep_movsb_rust_to_foreign::<_, StableUserSession<'_>, _>(&mut hw, &mut sess);
    assert!(out.is_ok());
    assert_eq!(hw.reg_int_read(Reg::Rcx), 0);
    assert_eq!(hw.reg_int_read(Reg::Rax), 0xa5);
    sess.close();
    let (_, _) = hw.reclaim_rslice(src_pptr);
}

#[test]
fn foreign_to_foreign_success() {
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut map = DomainMap::new();
    let src_region = ForeignRegionId { raw: 1 };
    let dst_region = ForeignRegionId { raw: 2 };
    let src_obj = StableUserDomainState::from_backing(
        src_region,
        0,
        vec![1u8, 2, 3],
        DomainCookie { raw: 1 },
    );
    let dst_obj =
        StableUserDomainState::from_backing(dst_region, 0, vec![0u8; 3], DomainCookie { raw: 2 });
    let (_, src, src_handle) = map.inject_domain_ptr::<StableUserDomain>(src_region, src_obj);
    let (_, dst, dst_handle) = map.inject_domain_ptr::<StableUserDomain>(dst_region, dst_obj);
    hw.bind_foreign_ptr(Reg::Rsi, src, &src_handle);
    hw.bind_foreign_ptr(Reg::Rdi, dst, &dst_handle);
    hw.reg_int_load_imm64(Reg::Rcx, 3);
    hw.reg_int_load_imm64(Reg::Rax, 0xa5);
    let mut src_sess = open_bound::<StableUserDomain>(&src_handle).unwrap();
    let mut dst_sess = open_bound::<StableUserDomain>(&dst_handle).unwrap();
    let out = drive_rep_movsb_foreign_to_foreign(&mut hw, &mut src_sess, &mut dst_sess);
    assert!(out.is_ok());
    assert_eq!(hw.reg_int_read(Reg::Rcx), 0);
    assert_eq!(hw.reg_int_read(Reg::Rax), 0xa5);
    src_sess.close();
    dst_sess.close();
}

#[test]
fn foreign_source_fault() {
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut map = DomainMap::new();
    let src_region = ForeignRegionId { raw: 1 };
    let dst_region = ForeignRegionId { raw: 2 };
    let src_obj = UncoopFaultDomainState::zeroed(src_region, 0, 0, DomainCookie { raw: 1 });
    let dst_obj =
        StableUserDomainState::from_backing(dst_region, 0, vec![0u8], DomainCookie { raw: 2 });
    let (_, src, src_handle) = map.inject_domain_ptr::<UncoopFaultDomain>(src_region, src_obj);
    let (_, dst, dst_handle) = map.inject_domain_ptr::<StableUserDomain>(dst_region, dst_obj);
    hw.bind_foreign_ptr(Reg::Rsi, src, &src_handle);
    hw.bind_foreign_ptr(Reg::Rdi, dst, &dst_handle);
    hw.reg_int_load_imm64(Reg::Rcx, 1);
    let mut src_sess = open_bound::<UncoopFaultDomain>(&src_handle).unwrap();
    let mut dst_sess = open_bound::<StableUserDomain>(&dst_handle).unwrap();
    let out = drive_rep_movsb_foreign_to_foreign(&mut hw, &mut src_sess, &mut dst_sess);
    assert!(out.is_err());
    assert_eq!(hw.reg_int_read(Reg::Rcx), 1);
    src_sess.close();
    dst_sess.close();
}

#[test]
fn foreign_destination_fault() {
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut map = DomainMap::new();
    let src_region = ForeignRegionId { raw: 1 };
    let dst_region = ForeignRegionId { raw: 2 };
    let src_obj =
        StableUserDomainState::from_backing(src_region, 0, vec![1u8], DomainCookie { raw: 1 });
    let dst_obj = UncoopFaultDomainState::zeroed(dst_region, 0, 0, DomainCookie { raw: 2 });
    let (_, src, src_handle) = map.inject_domain_ptr::<StableUserDomain>(src_region, src_obj);
    let (_, dst, dst_handle) = map.inject_domain_ptr::<UncoopFaultDomain>(dst_region, dst_obj);
    hw.bind_foreign_ptr(Reg::Rsi, src, &src_handle);
    hw.bind_foreign_ptr(Reg::Rdi, dst, &dst_handle);
    hw.reg_int_load_imm64(Reg::Rcx, 1);
    let mut src_sess = open_bound::<StableUserDomain>(&src_handle).unwrap();
    let mut dst_sess = open_bound::<UncoopFaultDomain>(&dst_handle).unwrap();
    let out = drive_rep_movsb_foreign_to_foreign(&mut hw, &mut src_sess, &mut dst_sess);
    assert!(out.is_err());
    assert_eq!(hw.reg_int_read(Reg::Rcx), 1);
    src_sess.close();
    dst_sess.close();
}
