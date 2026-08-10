// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{cpu::*, reg_val::*};
use crate::fmem::capability::BoundSession;
use crate::fmem::erasure::ErasedArc;
use crate::fmem::ptr::ForeignPtr;
use crate::fmem::session::DomainSession;
use crate::helpers::erased_pptr::*;
use crate::rmem::rmem_stack::*;
use vstd::pervasive::unreached;
use vstd::prelude::*;

verus! {

pub struct HardwareThread<C: Cpu, RM: RmemStack> {
    pub(crate) cpu: C,
    pub rmem: Option<RM>,
}

pub trait RSlicePost<Ctx, C: Cpu, RM: RmemStack, Pld, R> {
    #[verifier::prophetic]
    spec fn scoped<'scope>(
        ctx: Ctx,
        pre: HardwareThread<C, RM>,
        init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        initial_slice: Seq<u8>,
        orig_payload: Pld,
        out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        final_payload: Pld,
    ) -> bool;

    #[verifier::prophetic]
    spec fn outer(
        ctx: Ctx,
        pre: HardwareThread<C, RM>,
        post: HardwareThread<C, RM>,
        initial_slice: Seq<u8>,
        final_slice: Seq<u8>,
        orig_payload: Pld,
        final_payload: Pld,
        result: R,
    ) -> bool;

    proof fn lift<'scope>(
        ctx: Ctx,
        pre: HardwareThread<C, RM>,
        init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        initial_slice: Seq<u8>,
        orig_payload: Pld,
        out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        final_payload: Pld,
        post: HardwareThread<C, RM>,
        final_slice: Seq<u8>,
    )
        requires
            Self::scoped(
                ctx,
                pre,
                init_scope,
                slice_pptr,
                initial_slice,
                orig_payload,
                out,
                final_payload,
            ),
            HardwareThread::<C, RM>::rslice_scope_finishable(out.0, slice_pptr, pre),
            final_slice =~= out.0.rmem_spec()->Some_0.view_any(slice_pptr),
            post.rmem_spec() == pre.rmem_spec(),
            post.cpu_spec() == out.0.cpu_spec().clear_rust_slice_addr_spec(slice_pptr.addr()),
        ensures
            Self::outer(
                ctx,
                pre,
                post,
                initial_slice,
                final_slice,
                orig_payload,
                final_payload,
                out.1,
            ),
    ;
}

pub trait RSliceMutPost<Ctx, C: Cpu, RM: RmemStack, Pld, R> {
    #[verifier::prophetic]
    spec fn scoped<'scope>(
        ctx: Ctx,
        pre: HardwareThread<C, RM>,
        init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        initial_slice: Seq<u8>,
        orig_payload: Pld,
        out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        final_payload: Pld,
    ) -> bool;

    #[verifier::prophetic]
    spec fn outer(
        ctx: Ctx,
        pre: HardwareThread<C, RM>,
        post: HardwareThread<C, RM>,
        initial_slice: Seq<u8>,
        final_slice: Seq<u8>,
        orig_payload: Pld,
        final_payload: Pld,
        result: R,
    ) -> bool;

    proof fn lift<'scope>(
        ctx: Ctx,
        pre: HardwareThread<C, RM>,
        init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        initial_slice: Seq<u8>,
        orig_payload: Pld,
        out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        final_payload: Pld,
        post: HardwareThread<C, RM>,
        final_slice: Seq<u8>,
    )
        requires
            Self::scoped(
                ctx,
                pre,
                init_scope,
                slice_pptr,
                initial_slice,
                orig_payload,
                out,
                final_payload,
            ),
            HardwareThread::<C, RM>::rslice_mut_scope_reclaimable(out.0, slice_pptr, pre),
            final_slice =~= out.0.rmem_spec()->Some_0.view_any(slice_pptr),
            post.rmem_spec() == pre.rmem_spec(),
            post.cpu_spec() == out.0.cpu_spec().clear_rust_slice_addr_spec(slice_pptr.addr()),
        ensures
            Self::outer(
                ctx,
                pre,
                post,
                initial_slice,
                final_slice,
                orig_payload,
                final_payload,
                out.1,
            ),
    ;
}

pub struct NoopRSlicePost;

pub struct NoopRSliceMutPost;

pub struct PayloadSliceFinalEq;

pub struct FinalSliceEq;

impl<Ctx, C: Cpu, RM: RmemStack, Pld, R> RSlicePost<Ctx, C, RM, Pld, R> for NoopRSlicePost {
    #[verifier::prophetic]
    open spec fn scoped<'scope>(
        _ctx: Ctx,
        _pre: HardwareThread<C, RM>,
        _init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        _slice_pptr: ErasedPPtr,
        _initial_slice: Seq<u8>,
        _orig_payload: Pld,
        _out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        _final_payload: Pld,
    ) -> bool {
        true
    }

    #[verifier::prophetic]
    open spec fn outer(
        _ctx: Ctx,
        _pre: HardwareThread<C, RM>,
        _post: HardwareThread<C, RM>,
        _initial_slice: Seq<u8>,
        _final_slice: Seq<u8>,
        _orig_payload: Pld,
        _final_payload: Pld,
        _result: R,
    ) -> bool {
        true
    }

    proof fn lift<'scope>(
        _ctx: Ctx,
        _pre: HardwareThread<C, RM>,
        _init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        _slice_pptr: ErasedPPtr,
        _initial_slice: Seq<u8>,
        _orig_payload: Pld,
        _out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        _final_payload: Pld,
        _post: HardwareThread<C, RM>,
        _final_slice: Seq<u8>,
    ) {
    }
}

impl<Ctx, C: Cpu, RM: RmemStack, Pld, R> RSliceMutPost<Ctx, C, RM, Pld, R> for NoopRSliceMutPost {
    #[verifier::prophetic]
    open spec fn scoped<'scope>(
        _ctx: Ctx,
        _pre: HardwareThread<C, RM>,
        _init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        _slice_pptr: ErasedPPtr,
        _initial_slice: Seq<u8>,
        _orig_payload: Pld,
        _out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        _final_payload: Pld,
    ) -> bool {
        true
    }

    #[verifier::prophetic]
    open spec fn outer(
        _ctx: Ctx,
        _pre: HardwareThread<C, RM>,
        _post: HardwareThread<C, RM>,
        _initial_slice: Seq<u8>,
        _final_slice: Seq<u8>,
        _orig_payload: Pld,
        _final_payload: Pld,
        _result: R,
    ) -> bool {
        true
    }

    proof fn lift<'scope>(
        _ctx: Ctx,
        _pre: HardwareThread<C, RM>,
        _init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        _slice_pptr: ErasedPPtr,
        _initial_slice: Seq<u8>,
        _orig_payload: Pld,
        _out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        _final_payload: Pld,
        _post: HardwareThread<C, RM>,
        _final_slice: Seq<u8>,
    ) {
    }
}

#[allow(clippy::needless_lifetimes)]
impl<'a, C: Cpu, RM: RmemStack, R> RSlicePost<
    Seq<u8>,
    C,
    RM,
    &'a mut [u8],
    R,
> for PayloadSliceFinalEq {
    #[verifier::prophetic]
    open spec fn scoped<'scope>(
        target: Seq<u8>,
        _pre: HardwareThread<C, RM>,
        _init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        _slice_pptr: ErasedPPtr,
        _initial_slice: Seq<u8>,
        orig_payload: &'a mut [u8],
        _out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        final_payload: &'a mut [u8],
    ) -> bool {
        final_payload@ =~= target
    }

    #[verifier::prophetic]
    open spec fn outer(
        target: Seq<u8>,
        _pre: HardwareThread<C, RM>,
        _post: HardwareThread<C, RM>,
        _initial_slice: Seq<u8>,
        _final_slice: Seq<u8>,
        _orig_payload: &'a mut [u8],
        final_payload: &'a mut [u8],
        _result: R,
    ) -> bool {
        final_payload@ =~= target
    }

    proof fn lift<'scope>(
        target: Seq<u8>,
        pre: HardwareThread<C, RM>,
        init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        initial_slice: Seq<u8>,
        orig_payload: &'a mut [u8],
        out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        final_payload: &'a mut [u8],
        post: HardwareThread<C, RM>,
        final_slice: Seq<u8>,
    ) {
    }
}

#[allow(clippy::needless_lifetimes)]
impl<'a, C: Cpu, RM: RmemStack, R> RSliceMutPost<
    Seq<u8>,
    C,
    RM,
    &'a mut [u8],
    R,
> for PayloadSliceFinalEq {
    #[verifier::prophetic]
    open spec fn scoped<'scope>(
        target: Seq<u8>,
        _pre: HardwareThread<C, RM>,
        _init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        _slice_pptr: ErasedPPtr,
        _initial_slice: Seq<u8>,
        orig_payload: &'a mut [u8],
        _out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        final_payload: &'a mut [u8],
    ) -> bool {
        final_payload@ =~= target
    }

    #[verifier::prophetic]
    open spec fn outer(
        target: Seq<u8>,
        _pre: HardwareThread<C, RM>,
        _post: HardwareThread<C, RM>,
        _initial_slice: Seq<u8>,
        _final_slice: Seq<u8>,
        _orig_payload: &'a mut [u8],
        final_payload: &'a mut [u8],
        _result: R,
    ) -> bool {
        final_payload@ =~= target
    }

    proof fn lift<'scope>(
        target: Seq<u8>,
        pre: HardwareThread<C, RM>,
        init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        initial_slice: Seq<u8>,
        orig_payload: &'a mut [u8],
        out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        final_payload: &'a mut [u8],
        post: HardwareThread<C, RM>,
        final_slice: Seq<u8>,
    ) {
    }
}

impl<C: Cpu, RM: RmemStack, Pld, R> RSliceMutPost<Seq<u8>, C, RM, Pld, R> for FinalSliceEq {
    #[verifier::prophetic]
    open spec fn scoped<'scope>(
        target: Seq<u8>,
        _pre: HardwareThread<C, RM>,
        _init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        _initial_slice: Seq<u8>,
        _orig_payload: Pld,
        out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        _final_payload: Pld,
    ) -> bool {
        out.0.rmem_spec()->Some_0.view_any(slice_pptr) =~= target
    }

    #[verifier::prophetic]
    open spec fn outer(
        target: Seq<u8>,
        _pre: HardwareThread<C, RM>,
        _post: HardwareThread<C, RM>,
        _initial_slice: Seq<u8>,
        final_slice: Seq<u8>,
        _orig_payload: Pld,
        _final_payload: Pld,
        _result: R,
    ) -> bool {
        final_slice =~= target
    }

    proof fn lift<'scope>(
        target: Seq<u8>,
        pre: HardwareThread<C, RM>,
        init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        initial_slice: Seq<u8>,
        orig_payload: Pld,
        out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
        final_payload: Pld,
        post: HardwareThread<C, RM>,
        final_slice: Seq<u8>,
    ) {
    }
}

impl<C: Cpu, RM: RmemStack> HardwareThread<C, RM> {
    pub open spec fn wf(&self) -> bool {
        &&& self.cpu_spec().wf()
        &&& self.rmem_spec() is Some
        &&& self.rmem_spec()->Some_0.wf()
    }

    pub open(crate) spec fn cpu_spec(self) -> C {
        self.cpu
    }

    pub open(crate) spec fn rmem_spec(self) -> Option<RM> {
        self.rmem
    }

    pub open spec fn rmem(self) -> RM
        recommends
            self.wf(),
    {
        self.rmem_spec()->Some_0
    }

    pub open spec fn rslice_mut_scope_ready<'scope>(
        scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        reg: C::Reg,
        pre: Self,
        s: Seq<u8>,
    ) -> bool {
        &&& pre.wf()
        &&& scope.wf()
        &&& scope.cpu_spec() == pre.cpu_spec().set_reg_spec(
            reg,
            RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr, offset: 0 }),
        )
        &&& scope.cpu_spec().get_reg_spec(reg) == RegVal::RustMutSlicePtr(
            RustSliceCursor { slice_pptr, offset: 0 },
        )
        &&& scope.rmem_spec()->Some_0.tail == pre.rmem_spec()->Some_0
        &&& scope.rmem_spec()->Some_0.addr == slice_pptr.addr()
        &&& scope.rmem_spec()->Some_0.rp().matches_pptr(slice_pptr)
        &&& scope.rmem_spec()->Some_0.rp().is_init()
        &&& scope.rmem_spec()->Some_0.rp().is_mut()
        &&& scope.rmem_spec()->Some_0.view_any(slice_pptr) == s
    }

    pub open spec fn rslice_mut_scope_reclaimable<'scope>(
        scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        pre: Self,
    ) -> bool {
        &&& pre.wf()
        &&& scope.wf()
        &&& scope.rmem_spec()->Some_0.wf()
        &&& scope.rmem_spec()->Some_0.tail == pre.rmem_spec()->Some_0
        &&& scope.rmem_spec()->Some_0.addr == slice_pptr.addr()
        &&& scope.rmem_spec()->Some_0.rp().matches_pptr(slice_pptr)
        &&& scope.rmem_spec()->Some_0.rp().is_init()
        &&& scope.rmem_spec()->Some_0.rp().is_mut()
    }

    #[verifier::prophetic]
    pub open spec fn rslice_mut_scope_finishable<'scope>(
        scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        pre: Self,
        init_scope: HardwareThread<C, RmemCons<'scope, RM>>,
    ) -> bool {
        &&& pre.wf()
        &&& scope.wf()
        &&& init_scope.wf()
        &&& Self::rslice_mut_scope_reclaimable(scope, slice_pptr, pre)
        &&& RmemCons::mut_preserved_any(
            scope.rmem_spec()->Some_0,
            init_scope.rmem_spec()->Some_0,
            slice_pptr,
        )
    }

    pub open spec fn rslice_scope_ready<'scope>(
        scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        reg: C::Reg,
        pre: Self,
        s: Seq<u8>,
    ) -> bool {
        &&& pre.wf()
        &&& scope.wf()
        &&& scope.cpu_spec() == pre.cpu_spec().set_reg_spec(
            reg,
            RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr, offset: 0 }),
        )
        &&& scope.cpu_spec().get_reg_spec(reg) == RegVal::RustSharedSlicePtr(
            RustSliceCursor { slice_pptr, offset: 0 },
        )
        &&& scope.rmem_spec()->Some_0.tail == pre.rmem_spec()->Some_0
        &&& scope.rmem_spec()->Some_0.addr == slice_pptr.addr()
        &&& scope.rmem_spec()->Some_0.rp().matches_pptr(slice_pptr)
        &&& scope.rmem_spec()->Some_0.rp().is_init()
        &&& !scope.rmem_spec()->Some_0.rp().is_mut()
        &&& scope.rmem_spec()->Some_0.view_any(slice_pptr) == s
    }

    pub open spec fn rslice_scope_finishable<'scope>(
        scope: HardwareThread<C, RmemCons<'scope, RM>>,
        slice_pptr: ErasedPPtr,
        pre: Self,
    ) -> bool {
        &&& pre.wf()
        &&& scope.wf()
        &&& scope.rmem_spec()->Some_0.tail == pre.rmem_spec()->Some_0
        &&& scope.rmem_spec()->Some_0.addr == slice_pptr.addr()
        &&& scope.rmem_spec()->Some_0.rp().matches_pptr(slice_pptr)
        &&& scope.rmem_spec()->Some_0.rp().is_init()
        &&& !scope.rmem_spec()->Some_0.rp().is_mut()
    }

    #[allow(unused_variables)]
    pub fn bind_foreign_ptr(&mut self, reg: C::Reg, ptr: ForeignPtr, cap: &ErasedArc)
        requires
            old(self).wf(),
            old(self).cpu_spec().ready(),
            ptr.cap() == *cap,
        ensures
            final(self).wf(),
            final(self).cpu_spec() == old(self).cpu_spec().set_reg_spec(
                reg,
                RegVal::ForeignMemPtr(ptr),
            ),
            final(self).cpu_spec().get_reg_spec(reg) == RegVal::ForeignMemPtr(ptr),
            forall|r: C::Reg|
                r != reg ==> final(self).cpu_spec().get_reg_spec(r) == old(
                    self,
                ).cpu_spec().get_reg_spec(r),
            final(self).rmem_spec() == old(self).rmem_spec(),
    {
        self.cpu.bind_reg(reg, RegVal::foreign_mem_ptr(ptr));
    }

    #[allow(unused_variables)]
    pub fn bind_foreign_ptr_from_session<T: DomainSession>(
        &mut self,
        reg: C::Reg,
        ptr: ForeignPtr,
        sess: &BoundSession<T>,
    )
        requires
            old(self).wf(),
            old(self).cpu_spec().ready(),
            ptr.cap() == sess.cap(),
        ensures
            final(self).wf(),
            final(self).cpu_spec() == old(self).cpu_spec().set_reg_spec(
                reg,
                RegVal::ForeignMemPtr(ptr),
            ),
            final(self).cpu_spec().get_reg_spec(reg) == RegVal::ForeignMemPtr(ptr),
            forall|r: C::Reg|
                r != reg ==> final(self).cpu_spec().get_reg_spec(r) == old(
                    self,
                ).cpu_spec().get_reg_spec(r),
            final(self).rmem_spec() == old(self).rmem_spec(),
    {
        self.cpu.bind_reg(reg, RegVal::foreign_mem_ptr(ptr));
    }

    pub fn inject_rslice_mut<'a>(self, reg: C::Reg, s: &'a mut [u8]) -> (res: (
        HardwareThread<C, RmemCons<'a, RM>>,
        ErasedPPtr,
    ))
        requires
            self.wf(),
            self.cpu_spec().ready(),
        ensures
            res.0.wf(),
            res.0.cpu_spec() == self.cpu_spec().set_reg_spec(
                reg,
                RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr: res.1, offset: 0 }),
            ),
            res.0.cpu_spec().get_reg_spec(reg) == RegVal::RustMutSlicePtr(
                RustSliceCursor { slice_pptr: res.1, offset: 0 },
            ),
            res.0.rmem_spec()->Some_0.tail == self.rmem_spec()->Some_0,
            res.0.rmem_spec()->Some_0.addr == res.1.addr(),
            res.0.rmem_spec()->Some_0.rp().matches_pptr(res.1),
            res.0.rmem_spec()->Some_0.rp().is_init(),
            res.0.rmem_spec()->Some_0.rp().is_mut(),
            res.0.rmem_spec()->Some_0.view_any(res.1) == old(s)@,
            final(res.0.rmem_spec()->Some_0.rp().mut_value())@ =~= final(s)@,
    {
        let mut cpu = self.cpu;
        let rmem = match self.rmem {
            Option::Some(rmem) => rmem,
            Option::None => unreached(),
        };

        let (rmem, pptr) = RmemCons::push_mut(rmem, s);
        cpu.bind_reg(reg, RegVal::rust_mut_slice_ptr(pptr, 0));
        (HardwareThread { cpu, rmem: Option::Some(rmem) }, pptr)
    }

    pub fn inject_rslice<'a>(self, reg: C::Reg, s: &'a [u8]) -> (res: (
        HardwareThread<C, RmemCons<'a, RM>>,
        ErasedPPtr,
    ))
        requires
            self.wf(),
            self.cpu_spec().ready(),
        ensures
            res.0.wf(),
            res.0.cpu_spec() == self.cpu_spec().set_reg_spec(
                reg,
                RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr: res.1, offset: 0 }),
            ),
            res.0.cpu_spec().get_reg_spec(reg) == RegVal::RustSharedSlicePtr(
                RustSliceCursor { slice_pptr: res.1, offset: 0 },
            ),
            res.0.rmem_spec()->Some_0.tail == self.rmem_spec()->Some_0,
            res.0.rmem_spec()->Some_0.addr == res.1.addr(),
            res.0.rmem_spec()->Some_0.rp().matches_pptr(res.1),
            res.0.rmem_spec()->Some_0.rp().is_init(),
            !res.0.rmem_spec()->Some_0.rp().is_mut(),
            res.0.rmem_spec()->Some_0.view_any(res.1) == s@,
    {
        let mut cpu = self.cpu;
        let rmem = match self.rmem {
            Option::Some(rmem) => rmem,
            Option::None => unreached(),
        };

        let (rmem, pptr) = RmemCons::push_shared(rmem, s);
        cpu.bind_reg(reg, RegVal::rust_shared_slice_ptr(pptr, 0));
        (HardwareThread { cpu, rmem: Option::Some(rmem) }, pptr)
    }

    pub fn transform_with_rslice<'scope, Ctx, Post, Pld, R, Body>(
        self,
        reg: C::Reg,
        s: &'scope [u8],
        ctx: Ghost<Ctx>,
        payload: &mut Pld,
        orig_payload: Ghost<Pld>,
        body: Body,
    ) -> (result: (Self, Ghost<Seq<u8>>, R)) where
        Post: RSlicePost<Ctx, C, RM, Pld, R>,
        Body: FnOnce(HardwareThread<C, RmemCons<'scope, RM>>, ErasedPPtr, &mut Pld) -> (
            HardwareThread<C, RmemCons<'scope, RM>>,
            R,
        ),

        requires
            self.wf(),
            self.cpu_spec().ready(),
            *old(payload) == orig_payload@,
            forall|scope: HardwareThread<C, RmemCons<'scope, RM>>, pptr: ErasedPPtr, pld: &mut Pld|
                #![trigger body.requires((scope, pptr, pld))]
                (Self::rslice_scope_ready(scope, pptr, reg, self, s@) && *pld == orig_payload@)
                    ==> body.requires((scope, pptr, pld)),
            forall|
                scope: HardwareThread<C, RmemCons<'scope, RM>>,
                pptr: ErasedPPtr,
                pld: &mut Pld,
                out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
            |
                #![trigger body.ensures((scope, pptr, pld), out)]
                (Self::rslice_scope_ready(scope, pptr, reg, self, s@) && body.ensures(
                    (scope, pptr, pld),
                    out,
                )) ==> (Self::rslice_scope_finishable(out.0, pptr, self) && Post::scoped(
                    ctx@,
                    self,
                    scope,
                    pptr,
                    s@,
                    orig_payload@,
                    out,
                    *final(pld),
                )),
        ensures
            result.0.wf(),
            result.0.rmem_spec() == self.rmem_spec(),
            Post::outer(
                ctx@,
                self,
                result.0,
                s@,
                result.1@,
                orig_payload@,
                *final(payload),
                result.2,
            ),
    {
        let ghost pre_self = self;
        let ghost initial_slice = s@;
        let _ = (ctx, orig_payload);
        let (scope, pptr) = self.inject_rslice(reg, s);
        let ghost init_scope = scope;
        let (scope, result) = body(scope, pptr, payload);
        let ptr_addr = pptr.addr();
        let (mut restored, _recovered) = scope.reclaim_rslice(pptr);
        restored.cpu.clear_rust_slice_addr(ptr_addr);
        proof {
            Post::lift(
                ctx@,
                pre_self,
                init_scope,
                pptr,
                initial_slice,
                orig_payload@,
                (scope, result),
                *final(payload),
                restored,
                _recovered@,
            );
        }
        (restored, Ghost(_recovered@), result)
    }

    pub fn transform_with_rslice_mut<'scope, Ctx, Post, Pld, R, Body>(
        self,
        reg: C::Reg,
        s: &'scope mut [u8],
        ctx: Ghost<Ctx>,
        payload: &mut Pld,
        orig_payload: Ghost<Pld>,
        body: Body,
    ) -> (result: (Self, Ghost<Seq<u8>>, R)) where
        Post: RSliceMutPost<Ctx, C, RM, Pld, R>,
        Body: FnOnce(HardwareThread<C, RmemCons<'scope, RM>>, ErasedPPtr, &mut Pld) -> (
            HardwareThread<C, RmemCons<'scope, RM>>,
            R,
        ),

        requires
            self.wf(),
            self.cpu_spec().ready(),
            *old(payload) == orig_payload@,
            forall|scope: HardwareThread<C, RmemCons<'scope, RM>>, pptr: ErasedPPtr, pld: &mut Pld|
                #![trigger body.requires((scope, pptr, pld))]
                (Self::rslice_mut_scope_ready(scope, pptr, reg, self, old(s)@) && *pld
                    == orig_payload@) ==> body.requires((scope, pptr, pld)),
            forall|
                scope: HardwareThread<C, RmemCons<'scope, RM>>,
                pptr: ErasedPPtr,
                pld: &mut Pld,
                out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
            |
                #![trigger body.ensures((scope, pptr, pld), out)]
                Self::rslice_mut_scope_ready(scope, pptr, reg, self, old(s)@) && body.ensures(
                    (scope, pptr, pld),
                    out,
                ) ==> (Self::rslice_mut_scope_finishable(out.0, pptr, self, scope) && Post::scoped(
                    ctx@,
                    self,
                    scope,
                    pptr,
                    old(s)@,
                    orig_payload@,
                    out,
                    *final(pld),
                )),
        ensures
            result.0.wf(),
            result.0.rmem_spec() == self.rmem_spec(),
            final(s)@ =~= result.1@,
            Post::outer(
                ctx@,
                self,
                result.0,
                old(s)@,
                result.1@,
                orig_payload@,
                *final(payload),
                result.2,
            ),
    {
        let ghost pre_self = self;
        let ghost initial_slice = old(s)@;
        let _ = (ctx, orig_payload);
        let (scope, pptr) = self.inject_rslice_mut(reg, s);
        let ghost init_scope = scope;
        let (scope, result) = body(scope, pptr, payload);
        let ptr_addr = pptr.addr();
        let (mut restored, _recovered) = scope.reclaim_rslice_mut(pptr);
        restored.cpu.clear_rust_slice_addr(ptr_addr);
        proof {
            Post::lift(
                ctx@,
                pre_self,
                init_scope,
                pptr,
                initial_slice,
                orig_payload@,
                (scope, result),
                *final(payload),
                restored,
                _recovered@,
            );
        }
        (restored, Ghost(_recovered@), result)
    }

    pub fn with_rslice_mut<'scope, Ctx, Post, Pld, R, Body>(
        &mut self,
        reg: C::Reg,
        s: &'scope mut [u8],
        ctx: Ghost<Ctx>,
        payload: &mut Pld,
        orig_payload: Ghost<Pld>,
        body: Body,
    ) -> (result: (Ghost<Seq<u8>>, R)) where
        Post: RSliceMutPost<Ctx, C, RM, Pld, R>,
        Body: FnOnce(HardwareThread<C, RmemCons<'scope, RM>>, ErasedPPtr, &mut Pld) -> (
            HardwareThread<C, RmemCons<'scope, RM>>,
            R,
        ),

        requires
            old(self).wf(),
            old(self).cpu_spec().ready(),
            *old(payload) == orig_payload@,
            forall|scope: HardwareThread<C, RmemCons<'scope, RM>>, pptr: ErasedPPtr, pld: &mut Pld|
                #![trigger body.requires((scope, pptr, pld))]
                (Self::rslice_mut_scope_ready(scope, pptr, reg, *old(self), old(s)@) && *pld
                    == orig_payload@) ==> body.requires((scope, pptr, pld)),
            forall|
                scope: HardwareThread<C, RmemCons<'scope, RM>>,
                pptr: ErasedPPtr,
                pld: &mut Pld,
                out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
            |
                #![trigger body.ensures((scope, pptr, pld), out)]
                (Self::rslice_mut_scope_ready(scope, pptr, reg, *old(self), old(s)@)
                    && body.ensures((scope, pptr, pld), out)) ==> (
                Self::rslice_mut_scope_finishable(out.0, pptr, *old(self), scope) && Post::scoped(
                    ctx@,
                    *old(self),
                    scope,
                    pptr,
                    old(s)@,
                    orig_payload@,
                    out,
                    *final(pld),
                )),
        ensures
            final(self).wf(),
            final(self).rmem_spec() == old(self).rmem_spec(),
            final(s)@ =~= result.0@,
            Post::outer(
                ctx@,
                *old(self),
                *final(self),
                old(s)@,
                result.0@,
                orig_payload@,
                *final(payload),
                result.1,
            ),
    {
        let mut extracted = HardwareThread { cpu: self.cpu, rmem: Option::None };
        core::mem::swap(self, &mut extracted);
        let (mut new, final_slice, result) = extracted.transform_with_rslice_mut::<
            Ctx,
            Post,
            Pld,
            R,
            Body,
        >(reg, s, ctx, payload, orig_payload, body);
        core::mem::swap(self, &mut new);
        (final_slice, result)
    }

    pub fn with_rslice<'scope, Ctx, Post, Pld, R, Body>(
        &mut self,
        reg: C::Reg,
        s: &'scope [u8],
        ctx: Ghost<Ctx>,
        payload: &mut Pld,
        orig_payload: Ghost<Pld>,
        body: Body,
    ) -> (result: (Ghost<Seq<u8>>, R)) where
        Post: RSlicePost<Ctx, C, RM, Pld, R>,
        Body: FnOnce(HardwareThread<C, RmemCons<'scope, RM>>, ErasedPPtr, &mut Pld) -> (
            HardwareThread<C, RmemCons<'scope, RM>>,
            R,
        ),

        requires
            old(self).wf(),
            old(self).cpu_spec().ready(),
            *old(payload) == orig_payload@,
            forall|scope: HardwareThread<C, RmemCons<'scope, RM>>, pptr: ErasedPPtr, pld: &mut Pld|
                #![trigger body.requires((scope, pptr, pld))]
                (Self::rslice_scope_ready(scope, pptr, reg, *old(self), s@) && *pld
                    == orig_payload@) ==> body.requires((scope, pptr, pld)),
            forall|
                scope: HardwareThread<C, RmemCons<'scope, RM>>,
                pptr: ErasedPPtr,
                pld: &mut Pld,
                out: (HardwareThread<C, RmemCons<'scope, RM>>, R),
            |
                #![trigger body.ensures((scope, pptr, pld), out)]
                (Self::rslice_scope_ready(scope, pptr, reg, *old(self), s@) && body.ensures(
                    (scope, pptr, pld),
                    out,
                )) ==> (Self::rslice_scope_finishable(out.0, pptr, *old(self)) && Post::scoped(
                    ctx@,
                    *old(self),
                    scope,
                    pptr,
                    s@,
                    orig_payload@,
                    out,
                    *final(pld),
                )),
        ensures
            final(self).wf(),
            final(self).rmem_spec() == old(self).rmem_spec(),
            Post::outer(
                ctx@,
                *old(self),
                *final(self),
                s@,
                result.0@,
                orig_payload@,
                *final(payload),
                result.1,
            ),
    {
        let mut extracted = HardwareThread { cpu: self.cpu, rmem: Option::None };
        core::mem::swap(self, &mut extracted);
        let (mut new, final_slice, result) = extracted.transform_with_rslice::<
            Ctx,
            Post,
            Pld,
            R,
            Body,
        >(reg, s, ctx, payload, orig_payload, body);
        core::mem::swap(self, &mut new);
        (final_slice, result)
    }
}

impl<'a, C: Cpu, Tail: RmemStack> HardwareThread<C, RmemCons<'a, Tail>> {
    pub fn reclaim_rslice_mut(self, pptr: ErasedPPtr) -> (res: (
        HardwareThread<C, Tail>,
        &'a mut [u8],
    ))
        requires
            self.rmem_spec() is Some,
            self.rmem_spec()->Some_0.wf(),
            self.rmem_spec()->Some_0.addr == pptr.addr(),
            self.rmem_spec()->Some_0.rp().matches_pptr(pptr),
            self.rmem_spec()->Some_0.rp().is_init(),
            self.rmem_spec()->Some_0.rp().is_mut(),
        ensures
            res.0.cpu_spec() == self.cpu_spec(),
            res.0.rmem_spec() == Option::Some(self.rmem_spec()->Some_0.tail),
            res.1@ == self.rmem_spec()->Some_0.rp().view(),
            final(res.1)@ =~= final(self.rmem_spec()->Some_0.rp().mut_value())@,
    {
        let cpu = self.cpu;
        let rmem = match self.rmem {
            Option::Some(rmem) => rmem,
            Option::None => unreached(),
        };

        let (rmem, s) = rmem.reclaim_mut(pptr);
        (HardwareThread { cpu, rmem: Option::Some(rmem) }, s)
    }

    pub fn reclaim_rslice(self, pptr: ErasedPPtr) -> (res: (HardwareThread<C, Tail>, &'a [u8]))
        requires
            self.rmem_spec() is Some,
            self.rmem_spec()->Some_0.wf(),
            self.rmem_spec()->Some_0.addr == pptr.addr(),
            self.rmem_spec()->Some_0.rp().matches_pptr(pptr),
            self.rmem_spec()->Some_0.rp().is_init(),
            !self.rmem_spec()->Some_0.rp().is_mut(),
        ensures
            res.0.cpu_spec() == self.cpu_spec(),
            res.0.rmem_spec() == Option::Some(self.rmem_spec()->Some_0.tail),
            res.1@ == self.rmem_spec()->Some_0.rp().view(),
    {
        let cpu = self.cpu;
        let rmem = match self.rmem {
            Option::Some(rmem) => rmem,
            Option::None => unreached(),
        };

        let (rmem, s) = rmem.reclaim_shared(pptr);
        (HardwareThread { cpu, rmem: Option::Some(rmem) }, s)
    }
}

} // verus!
