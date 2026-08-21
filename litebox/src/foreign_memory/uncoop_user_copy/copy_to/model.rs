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
#[cfg(verus_only)]
use true_tales::machine::hardware_thread::RSlicePost;
use true_tales::rmem::rmem_stack::*;

use super::super::CopyError;
use super::proofs::{CopyRangePost, CopyToPost};
#[cfg(verus_only)]
use super::proofs::{
    copy_range_body_post, copy_range_body_pre, copy_range_pre_fn, copy_scope_ensures,
    copy_scope_pre, establish_copy_range_pre, finish_copy_scope, prepare_session_store,
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

pub open spec fn copy_to_uncoop_user_model_pre<RM: RmemStack>(
    dst: ForeignPtr,
    src: Seq<u8>,
    session: BoundSession<UncoopFaultSession>,
    hardware_thread: Amd64Thread<RM>,
) -> bool {
    &&& hardware_thread.wf()
    &&& cpu_ready(hardware_thread.cpu_spec())
    &&& df_clear(hardware_thread.cpu_spec())
    &&& src.len() > 0
    &&& session.cap() == dst.cap()
    &&& UncoopFaultSession::wf(session.st())
    &&& session.st().region == dst.region()
    &&& dst.region() == UNCOOP_FAULT_REGION
    &&& dst.cursor().addr() + src.len() <= usize::MAX
}

pub open spec fn copy_to_uncoop_user_model_post<RM: RmemStack>(
    initial_session: BoundSession<UncoopFaultSession>,
    initial_hardware_thread: Amd64Thread<RM>,
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
    &&& final_hardware_thread.rmem_spec() == initial_hardware_thread.rmem_spec()
}

pub(super) fn copy_to_uncoop_user_model<RM: RmemStack>(
    dst: ForeignPtr,
    src: &[u8],
    sess: &mut BoundSession<UncoopFaultSession>,
    hw: &mut Amd64Thread<RM>,
) -> (res: Result<(), CopyError>)
    requires
        copy_to_uncoop_user_model_pre(dst, src@, *old(sess), *old(hw)),
    ensures
        copy_to_uncoop_user_model_post(
            *old(sess),
            *old(hw),
            *final(sess),
            *final(hw),
        ),
{
    let len = src.len();
    let ghost src_orig = src@;
    let ghost hw_pre = *hw;
    let ghost s0 = sess.st();
    let ghost sess0 = *sess;

    proof {
        prepare_session_store(s0, dst, len);
    }

    let (_src_final, res) = hw.with_rslice::<
        (),
        CopyToPost,
        BoundSession<UncoopFaultSession>,
        Result<(), CopyError>,
        _,
    >(
        Reg::Rsi,
        src,
        Ghost(()),
        sess,
        Ghost(sess0),
        |mut hw_src, _src_pptr, open_sess| -> (out: (Amd64Thread<_>, Result<(), CopyError>))
            requires
                copy_scope_pre(
                    hw_src,
                    _src_pptr,
                    *old(open_sess),
                    hw_pre,
                    src_orig,
                    s0,
                    dst,
                    len,
                ),
            ensures
                copy_scope_ensures(
                    hw_src,
                    sess0,
                    *final(open_sess),
                    out,
                    _src_pptr,
                    hw_pre,
                    src_orig,
                ),
            {
                let ghost init_hw = hw_src;
                hw_src.bind_foreign_ptr_from_session(Reg::Rdi, dst, open_sess);
                hw_src.reg_int_load_imm64(Reg::Rcx, len as u64);

                proof {
                    establish_copy_range_pre(
                        hw_src,
                        *open_sess,
                        init_hw,
                        _src_pptr,
                        hw_pre,
                        src_orig,
                        s0,
                        dst,
                        len,
                    );
                }

                let ghost pre = copy_range_pre_fn::<RmemCons<'_, RM>, UncoopFaultSession>();
                let ghost range_pre_hw = hw_src;
                let ghost range_pre_session = *open_sess;

                let r = fault_range::<_, _, (), CopyRangePost, _>(
                    &mut hw_src,
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
                                Option::None,
                                Option::Some(s),
                            )
                        },
                );

                proof {
                    finish_copy_scope(
                        hw_src,
                        *open_sess,
                        range_pre_hw,
                        range_pre_session,
                        r,
                        _src_pptr,
                        hw_pre,
                        init_hw,
                        src_orig,
                    );
                }

                let result = match r {
                    Result::Ok(()) => Ok(()),
                    Result::Err(_) => Err(CopyError::Fault),
                };
                (hw_src, result)
            },
    );

    res
}

} // verus!
