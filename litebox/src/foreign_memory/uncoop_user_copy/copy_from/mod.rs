// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use vstd::prelude::*;

use true_tales::amd64::Amd64Thread;
#[cfg(verus_only)]
use true_tales::amd64::{Reg, cpu_ready, df_clear, df_unchanged};
use true_tales::fmem::capability::BoundSession;
use true_tales::fmem::extent::AddressExtent;
use true_tales::fmem::ptr::ForeignPtr;
#[cfg(verus_only)]
use true_tales::fmem::session::DomainSession;
#[cfg(verus_only)]
use true_tales::machine::cpu::Cpu;
use true_tales::rmem::rmem_stack::{RmemNil, RmemStack};

#[cfg(verus_only)]
use crate::foreign_memory::domains::uncoop_user_fault::UNCOOP_FAULT_REGION;
use crate::foreign_memory::domains::uncoop_user_fault::{UncoopFaultDomain, UncoopFaultSession};
use crate::foreign_memory::domains::{ExportedPointer, ForeignMemoryRuntime};
use crate::foreign_memory::thread::HardwareThreadProvider;

use super::CopyError;

mod model;
mod native;
mod proofs;

use model::copy_from_uncoop_user_model;
use native::copy_from_uncoop_user_native;

verus! {

broadcast use true_tales::amd64::group_amd64_frames;

// Verus cannot capture `dst` mutably, so this helper carries it as explicit
// context.
pub(super) fn copy_from_uncoop_user_scoped<P>(
    context: (
        ForeignMemoryRuntime,
        &mut [u8],
        ExportedPointer<UncoopFaultDomain>,
    ),
    hardware_thread: &mut Amd64Thread<RmemNil>,
) -> (result: Result<(), CopyError>)
where
    P: HardwareThreadProvider<HardwareThread = Amd64Thread<RmemNil>>,
    requires
        context.0.wf(),
        P::thread_invariant(*old(hardware_thread)),
        forall|thread: Amd64Thread<RmemNil>|
            #![auto]
            P::thread_invariant(thread) == {
                &&& thread.wf()
                &&& cpu_ready(thread.cpu_spec())
                &&& df_clear(thread.cpu_spec())
            },
    ensures
        P::thread_invariant(*final(hardware_thread)),
{
    let _ = core::marker::PhantomData::<P>;
    let (runtime, dst, src) = context;
    runtime.copy_from_uncoop_user_with_thread(dst, src, hardware_thread)
}

// Shared, verified dispatch function with a common set of pre- and
// post-conditions for _both_ the modeled assembly and the native,
// `#[external_body]` implementation.
pub(super) fn copy_from_uncoop_user_helper<RM: RmemStack>(
    dst: &mut [u8],
    src: ForeignPtr,
    _extent: AddressExtent,
    sess: &mut BoundSession<UncoopFaultSession>,
    hw: &mut Amd64Thread<RM>,
) -> (res: Result<(), CopyError>)
    requires
        old(dst)@.len() > 0,
        old(hw).wf(),
        cpu_ready(old(hw).cpu_spec()),
        // `rep movsb` reads DF; Rust guarantees it clear on `asm!` entry.
        df_clear(old(hw).cpu_spec()),
        old(sess).cap() == src.cap(),
        UncoopFaultSession::wf(old(sess).st()),
        old(sess).st().region == src.region(),
        src.region() == UNCOOP_FAULT_REGION,
        src.cursor().addr() + old(dst)@.len() <= usize::MAX,
        UncoopFaultSession::address_extent(
            old(sess).st(),
            src.region(),
            src.cursor().addr(),
        ) == Some(_extent),
        _extent.spec_contains_range(old(dst)@.len() as usize),
        UncoopFaultSession::load_disposition(
            old(sess).st(),
            src.region(),
            src.cursor().addr(),
            old(dst)@.len() as usize,
        ).is_invalid() == false,
    ensures
        UncoopFaultSession::wf(final(sess).st()),
        final(hw).wf(),
        cpu_ready(final(hw).cpu_spec()),
        // Clobber list:
        df_unchanged(old(hw).cpu_spec(), final(hw).cpu_spec()),
        !old(hw).cpu_spec().get_reg_spec(Reg::Rax).is_slice_ptr()
            ==> final(hw).cpu_spec().get_reg_spec(Reg::Rax) == old(hw).cpu_spec().get_reg_spec(
            Reg::Rax,
        ),
        !old(hw).cpu_spec().get_reg_spec(Reg::Rdx).is_slice_ptr()
            ==> final(hw).cpu_spec().get_reg_spec(Reg::Rdx) == old(hw).cpu_spec().get_reg_spec(
            Reg::Rdx,
        ),
        final(hw).rmem_spec() == old(hw).rmem_spec(),
        final(dst)@.len() == old(dst)@.len(),
{
    if cfg!(any(miri, feature = "modeled_backend")) {
        copy_from_uncoop_user_model(dst, src, sess, hw)
    } else {
        copy_from_uncoop_user_native(dst, src, hw)
    }
}

} // verus!
