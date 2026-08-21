// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![allow(
    clippy::wildcard_imports,
    clippy::bool_comparison,
    clippy::manual_let_else,
    clippy::result_unit_err
)]

use vstd::prelude::*;

use true_tales::amd64::*;
use true_tales::fmem::capability::BoundSession;
use true_tales::fmem::ptr::ForeignPtr;
#[cfg(verus_only)]
use true_tales::fmem::session::DomainSession;
#[cfg(verus_only)]
use true_tales::machine::cpu::Cpu;
use true_tales::rmem::rmem_stack::*;

use super::super::CopyError;
use super::proofs::{CopyRangePost, FallibleErrPost};
#[cfg(verus_only)]
use super::proofs::{
    copy_range_body_post, copy_range_body_pre, copy_range_pre_fn, copy_scope_ensures,
    copy_scope_pre, establish_copy_range_pre, finish_copy_scope, prepare_session_load,
};
#[cfg(verus_only)]
use crate::foreign_memory::domains::uncoop_user_fault::UNCOOP_FAULT_REGION;
use crate::foreign_memory::domains::uncoop_user_fault::UncoopFaultSession;
#[cfg(verus_only)]
use crate::foreign_memory::fault_range::FaultRangePost;
#[cfg(verus_only)]
use crate::foreign_memory::fault_range::fault_cleared;
use crate::foreign_memory::fault_range::fault_range;

verus! {

broadcast use true_tales::amd64::group_amd64_frames;

pub open spec fn copy_from_uncoop_user_model_pre<RM: RmemStack>(
    dst: Seq<u8>,
    src: ForeignPtr,
    session: BoundSession<UncoopFaultSession>,
    hardware_thread: Amd64Thread<RM>,
) -> bool {
    &&& hardware_thread.wf()
    &&& cpu_ready(hardware_thread.cpu_spec())
    &&& df_clear(hardware_thread.cpu_spec())
    &&& dst.len() > 0
    &&& session.cap() == src.cap()
    &&& UncoopFaultSession::wf(session.st())
    &&& session.st().region == src.region()
    &&& src.region() == UNCOOP_FAULT_REGION
    &&& src.cursor().addr() + dst.len() <= usize::MAX
}

pub open spec fn copy_from_uncoop_user_model_post<RM: RmemStack>(
    initial_dst: Seq<u8>,
    initial_session: BoundSession<UncoopFaultSession>,
    initial_hardware_thread: Amd64Thread<RM>,
    final_dst: Seq<u8>,
    final_session: BoundSession<UncoopFaultSession>,
    final_hardware_thread: Amd64Thread<RM>,
) -> bool {
    &&& UncoopFaultSession::wf(final_session.st())
    &&& final_hardware_thread.wf()
    &&& cpu_ready(final_hardware_thread.cpu_spec())
    &&& df_unchanged(
        initial_hardware_thread.cpu_spec(),
        final_hardware_thread.cpu_spec(),
    )
    &&& !initial_hardware_thread.cpu_spec().get_reg_spec(Reg::Rax).is_slice_ptr()
        ==> final_hardware_thread.cpu_spec().get_reg_spec(Reg::Rax)
            == initial_hardware_thread.cpu_spec().get_reg_spec(Reg::Rax)
    &&& !initial_hardware_thread.cpu_spec().get_reg_spec(Reg::Rdx).is_slice_ptr()
        ==> final_hardware_thread.cpu_spec().get_reg_spec(Reg::Rdx)
            == initial_hardware_thread.cpu_spec().get_reg_spec(Reg::Rdx)
    &&& final_hardware_thread.rmem_spec() == initial_hardware_thread.rmem_spec()
    &&& final_dst.len() == initial_dst.len()
}

pub(super) fn copy_from_uncoop_user_model<RM: RmemStack>(
    dst: &mut [u8],
    src: ForeignPtr,
    sess: &mut BoundSession<UncoopFaultSession>,
    hw: &mut Amd64Thread<RM>,
) -> (res: Result<(), CopyError>)
    requires
        copy_from_uncoop_user_model_pre(old(dst)@, src, *old(sess), *old(hw)),
    ensures
        copy_from_uncoop_user_model_post(
            old(dst)@,
            *old(sess),
            *old(hw),
            final(dst)@,
            *final(sess),
            *final(hw),
        ),
{
    let len: usize = dst.len();

    let ghost dst_orig = dst@;
    let ghost hw_pre_dst = *hw;
    let ghost s0 = sess.st();
    let ghost sess0 = *sess;

    proof {
        prepare_session_load(s0, src, len);
    }

    let (_dst_final, res) = hw.with_rslice_mut::<
        (),
        FallibleErrPost,
        BoundSession<UncoopFaultSession>,
        Result<(), CopyError>,
        _,
    >(
        Reg::Rdi,
        dst,
        Ghost(()),
        sess,
        Ghost(sess0),
        |mut hw_dst, dst_pptr, open_sess| -> (out: (Amd64Thread<_>, Result<(), CopyError>))
            requires
                copy_scope_pre(
                    hw_dst,
                    dst_pptr,
                    *old(open_sess),
                    hw_pre_dst,
                    dst_orig,
                    s0,
                    src,
                    len,
                ),
            ensures
                copy_scope_ensures(
                    hw_dst,
                    *final(open_sess),
                    out,
                    dst_pptr,
                    hw_pre_dst,
                    dst_orig,
                ),
            {
                let ghost init_hw = hw_dst;
                let _ = dst_pptr;

                // ========== setup (translated from asm!() clobbers) ==========
                hw_dst.bind_foreign_ptr_from_session(Reg::Rsi, src, open_sess);
                hw_dst.reg_int_load_imm64(Reg::Rcx, len as u64);

                // ========== Precondition assertions: ==========
                proof {
                    establish_copy_range_pre(
                        hw_dst,
                        *open_sess,
                        init_hw,
                        dst_pptr,
                        hw_pre_dst,
                        dst_orig,
                        s0,
                        src,
                        len,
                    );
                }

                let ghost pre = copy_range_pre_fn::<RmemCons<'_, RM>, UncoopFaultSession>();
                let ghost range_pre_hw = hw_dst;
                let ghost range_pre_session = *open_sess;

                // ======= 2: rep movsb  3:  under ex_table_entry!("2b","3b") =======
                let r = fault_range::<_, _, (), CopyRangePost, _>(
                    &mut hw_dst,
                    open_sess,
                    Ghost(()),
                    Ghost(pre),
                    |h: &mut Amd64Thread<_>, s: &mut BoundSession<_>| -> (out: Result<(), Fault>)
                        requires
                            copy_range_body_pre(*old(h), *old(s)),
                        ensures
                            copy_range_body_post(
                                *old(h),
                                *old(s),
                                *final(h),
                                *final(s),
                                out,
                            ),
                        {
                            h.rep_movsb::<UncoopFaultSession, UncoopFaultSession>(
                                Option::Some(s),
                                Option::None,
                            )
                        },
                );
                // =================================================================

                // Clobber list assertions
                proof {
                    finish_copy_scope(
                        hw_dst,
                        *open_sess,
                        range_pre_hw,
                        range_pre_session,
                        r,
                        dst_pptr,
                        hw_pre_dst,
                        init_hw,
                        dst_orig,
                    );
                }

                // The fixup's `label { return Err(Fault) }`, and the fallthrough's
                // `Ok(())`. `CopyError` is not `Fault`, so this is the one
                // place the range's result has to be re-tagged.
                let out = match r {
                    Result::Ok(()) => Ok(()),
                    Result::Err(_) => Err(CopyError::Fault),
                };

                (hw_dst, out)
            },
    );

    res
}

} // verus!
