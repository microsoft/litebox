// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use vstd::prelude::*;

use true_tales::amd64::Amd64Thread;
#[cfg(verus_only)]
use true_tales::amd64::{cpu_ready, df_clear, df_unchanged};
#[cfg(verus_only)]
use true_tales::fmem::capability::BoundSession;
#[cfg(verus_only)]
use true_tales::fmem::erasure::DynState;
use true_tales::fmem::session::DomainSession;
#[cfg(verus_only)]
use true_tales::machine::cpu::Cpu;
use true_tales::rmem::rmem_stack::RmemNil;

#[cfg(verus_only)]
use crate::foreign_memory::domains::uncoop_user_fault::UncoopFaultSession;
use crate::foreign_memory::domains::uncoop_user_fault::{UNCOOP_FAULT_REGION, UncoopFaultDomain};
use crate::foreign_memory::domains::{ExportedPointer, ForeignMemoryRuntime};
use crate::foreign_memory::thread::HardwareThreadProvider;

mod copy_from;
mod copy_to;

use copy_from::{copy_from_uncoop_user_helper, copy_from_uncoop_user_scoped};
use copy_to::{copy_to_uncoop_user_helper, copy_to_uncoop_user_scoped};

verus! {

pub enum CopyError {
    OffsetOverflow,
    WrongRegion,
    InvalidForeignPointer,
    Fault,
}

// TODO: Native page-table-backed sessions must keep the checked extent stable
// through a pinned address-space envelope or generation; session liveness alone
// does not prevent the address space from being rebound while a copy is active.
impl ForeignMemoryRuntime {
    pub fn copy_from_uncoop_user_with_thread(
        &self,
        dst: &mut [u8],
        src: ExportedPointer<UncoopFaultDomain>,
        hardware_thread: &mut Amd64Thread<RmemNil>,
    ) -> (res: Result<(), CopyError>)
        requires
            self.wf(),
            old(hardware_thread).wf(),
            cpu_ready(old(hardware_thread).cpu_spec()),
            df_clear(old(hardware_thread).cpu_spec()),
        ensures
            final(hardware_thread).wf(),
            cpu_ready(final(hardware_thread).cpu_spec()),
            df_clear(final(hardware_thread).cpu_spec()),
            df_unchanged(
                old(hardware_thread).cpu_spec(),
                final(hardware_thread).cpu_spec(),
            ),
            final(hardware_thread).rmem_spec() == old(hardware_thread).rmem_spec(),
    {
        if dst.is_empty() {
            return Ok(());
        }
        if src.raw_region().raw != UNCOOP_FAULT_REGION.raw {
            return Err(CopyError::WrongRegion);
        }
        if src.cursor().addr().checked_add(dst.len()).is_none() {
            return Err(CopyError::OffsetOverflow);
        }
        let Result::Ok(routed) = self.resolve(src) else {
            return Err(CopyError::InvalidForeignPointer);
        };
        let ptr = src.foreign_pointer(&routed);

        let mut sess = routed.open();
        assert(sess.cap() == ptr.cap());

        let a = ptr.cursor().addr();
        let Ok(extent) = sess.check_address_extent(ptr.region(), a) else {
            sess.close();
            return Err(CopyError::WrongRegion);
        };
        if !extent.contains_range(dst.len()) {
            sess.close();
            return Err(CopyError::Fault);
        }
        let disposition = sess.check_load_disposition(ptr.region(), a, dst.len());
        if disposition.is_invalid() {
            sess.close();
            return Err(CopyError::WrongRegion);
        }
        proof {
            BoundSession::<UncoopFaultSession>::lemma_interfere_refl(sess.st());
            match disposition {
                true_tales::fmem::session::AccessDisposition::Invalid => {
                    assert(false);
                },
                true_tales::fmem::session::AccessDisposition::Infallible => {
                    assert(
                        BoundSession::<UncoopFaultSession>::load_disposition(
                            sess.st(),
                            ptr.region(),
                            a,
                            dst.len(),
                        ).is_infallible()
                    );
                },
                true_tales::fmem::session::AccessDisposition::AlwaysFaults => {
                    assert(
                        BoundSession::<UncoopFaultSession>::load_disposition(
                            sess.st(),
                            ptr.region(),
                            a,
                            dst.len(),
                        ).is_always_faulting()
                    );
                },
                true_tales::fmem::session::AccessDisposition::MayFault => {
                    assert(
                        BoundSession::<UncoopFaultSession>::load_disposition(
                            sess.st(),
                            ptr.region(),
                            a,
                            dst.len(),
                        ).is_invalid() == false
                    );
                },
            }
        }
        assert(UncoopFaultSession::load_disposition(
            sess.st(),
            ptr.region(),
            a,
            dst.len(),
        ).is_invalid() == false);
        assert(sess.st().region == ptr.region());

        let res = copy_from_uncoop_user_helper(dst, ptr, extent, &mut sess, hardware_thread);
        sess.close();
        res
    }

    pub fn copy_from_uncoop_user<P>(
        &self,
        hardware_threads: &P,
        dst: &mut [u8],
        src: ExportedPointer<
        UncoopFaultDomain,
    >,
    ) -> (res: Result<(), CopyError>)
    where
        P: HardwareThreadProvider<HardwareThread = Amd64Thread<RmemNil>>,
        requires
            self.wf(),
            forall|thread: Amd64Thread<RmemNil>|
                #![auto]
                P::thread_invariant(thread) == {
                    &&& thread.wf()
                    &&& cpu_ready(thread.cpu_spec())
                    &&& df_clear(thread.cpu_spec())
                },
    {
        let runtime = self.clone();
        hardware_threads.with_thread(
            (runtime, dst, src),
            copy_from_uncoop_user_scoped::<P>,
        )
    }

    pub fn copy_to_uncoop_user_with_thread(
        &self,
        dst: ExportedPointer<UncoopFaultDomain>,
        src: &[u8],
        hardware_thread: &mut Amd64Thread<RmemNil>,
    ) -> (res: Result<(), CopyError>)
        requires
            self.wf(),
            old(hardware_thread).wf(),
            cpu_ready(old(hardware_thread).cpu_spec()),
            df_clear(old(hardware_thread).cpu_spec()),
        ensures
            final(hardware_thread).wf(),
            cpu_ready(final(hardware_thread).cpu_spec()),
            df_clear(final(hardware_thread).cpu_spec()),
            df_unchanged(
                old(hardware_thread).cpu_spec(),
                final(hardware_thread).cpu_spec(),
            ),
            final(hardware_thread).rmem_spec() == old(hardware_thread).rmem_spec(),
    {
        if src.is_empty() {
            return Ok(());
        }
        if dst.raw_region().raw != UNCOOP_FAULT_REGION.raw {
            return Err(CopyError::WrongRegion);
        }
        if dst.cursor().addr().checked_add(src.len()).is_none() {
            return Err(CopyError::OffsetOverflow);
        }
        let Result::Ok(routed) = self.resolve(dst) else {
            return Err(CopyError::InvalidForeignPointer);
        };
        let ptr = dst.foreign_pointer(&routed);

        let mut sess = routed.open();
        assert(sess.cap() == ptr.cap());

        let a = ptr.cursor().addr();
        let Ok(extent) = sess.check_address_extent(ptr.region(), a) else {
            sess.close();
            return Err(CopyError::WrongRegion);
        };
        if !extent.contains_range(src.len()) {
            sess.close();
            return Err(CopyError::Fault);
        }
        let disposition = sess.check_store_disposition(ptr.region(), a, src.len());
        if disposition.is_invalid() {
            sess.close();
            return Err(CopyError::WrongRegion);
        }
        proof {
            BoundSession::<UncoopFaultSession>::lemma_interfere_refl(sess.st());
            match disposition {
                true_tales::fmem::session::AccessDisposition::Invalid => {
                    assert(false);
                },
                true_tales::fmem::session::AccessDisposition::Infallible => {
                    assert(
                        BoundSession::<UncoopFaultSession>::store_disposition(
                            sess.st(),
                            ptr.region(),
                            a,
                            src.len(),
                        ).is_infallible()
                    );
                },
                true_tales::fmem::session::AccessDisposition::AlwaysFaults => {
                    assert(
                        BoundSession::<UncoopFaultSession>::store_disposition(
                            sess.st(),
                            ptr.region(),
                            a,
                            src.len(),
                        ).is_always_faulting()
                    );
                },
                true_tales::fmem::session::AccessDisposition::MayFault => {
                    assert(
                        BoundSession::<UncoopFaultSession>::store_disposition(
                            sess.st(),
                            ptr.region(),
                            a,
                            src.len(),
                        ).is_invalid() == false
                    );
                },
            }
        }
        assert(UncoopFaultSession::store_disposition(
            sess.st(),
            ptr.region(),
            a,
            src.len(),
        ).is_invalid() == false);
        assert(sess.st().region == ptr.region());

        let res = copy_to_uncoop_user_helper(ptr, src, extent, &mut sess, hardware_thread);
        sess.close();
        res
    }

    pub fn copy_to_uncoop_user<P>(
        &self,
        hardware_threads: &P,
    dst: ExportedPointer<
    UncoopFaultDomain,
    >,
    src: &[u8],
    ) -> (res: Result<(), CopyError>)
    where
        P: HardwareThreadProvider<HardwareThread = Amd64Thread<RmemNil>>,
        requires
            self.wf(),
            forall|thread: Amd64Thread<RmemNil>|
                #![auto]
                P::thread_invariant(thread) == {
                    &&& thread.wf()
                    &&& cpu_ready(thread.cpu_spec())
                    &&& df_clear(thread.cpu_spec())
                },
    {
        let runtime = self.clone();
        hardware_threads.with_thread(
            (runtime, dst, src),
            copy_to_uncoop_user_scoped::<P>,
        )
    }
}

} // verus!

#[cfg(all(test, feature = "modeled_backend"))]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::foreign_memory::domains::uncoop_user_fault::UncoopUserFaultRegistration;
    use true_tales::fmem::backing::TransactionalVec;

    const BASE: usize = 0x1000;

    fn setup(
        bytes: Vec<u8>,
    ) -> (
        ForeignMemoryRuntime,
        UncoopUserFaultRegistration,
        Arc<TransactionalVec>,
        Amd64Thread<RmemNil>,
    ) {
        let runtime = ForeignMemoryRuntime::new();
        let (registration, backing) = runtime.inject_uncoop_user_fault_modeled(BASE, bytes);
        (runtime, registration, backing, Amd64Thread::new())
    }

    fn retire(registration: UncoopUserFaultRegistration, backing: Arc<TransactionalVec>) {
        let retired = registration.retire().unwrap();
        assert!(retired.is_dead());
        drop(backing);
    }

    #[test]
    fn rejects_wrong_region_and_stale_pointer() {
        let (runtime, registration, backing, mut thread) = setup(vec![1]);
        let wrong = registration.pointer_at(1, BASE);
        let mut byte = [0];
        assert!(matches!(
            runtime.copy_from_uncoop_user_with_thread(&mut byte, wrong, &mut thread),
            Err(CopyError::WrongRegion)
        ));

        let stale = registration.pointer();
        let retired = registration.retire().unwrap();
        assert!(retired.is_dead());
        assert!(matches!(
            runtime.copy_from_uncoop_user_with_thread(&mut byte, stale, &mut thread),
            Err(CopyError::InvalidForeignPointer)
        ));
        drop(backing);
    }

    #[test]
    fn rejects_invalid_load_ranges_before_dispatch() {
        let (runtime, registration, backing, mut thread) = setup(vec![1, 2]);
        let mut bytes = [0; 2];

        let before = registration.pointer_at(UNCOOP_FAULT_REGION.raw, BASE - 1);
        assert!(matches!(
            runtime.copy_from_uncoop_user_with_thread(&mut bytes[..1], before, &mut thread),
            Err(CopyError::Fault)
        ));

        let end = registration.pointer().checked_advance(2).unwrap();
        assert!(matches!(
            runtime.copy_from_uncoop_user_with_thread(&mut bytes[..1], end, &mut thread),
            Err(CopyError::Fault)
        ));

        let crossing = registration.pointer().checked_advance(1).unwrap();
        assert!(matches!(
            runtime.copy_from_uncoop_user_with_thread(&mut bytes, crossing, &mut thread),
            Err(CopyError::Fault)
        ));

        let overflow = registration.pointer_at(UNCOOP_FAULT_REGION.raw, usize::MAX);
        assert!(matches!(
            runtime.copy_from_uncoop_user_with_thread(&mut bytes[..1], overflow, &mut thread),
            Err(CopyError::OffsetOverflow)
        ));

        retire(registration, backing);
    }

    #[test]
    fn rejects_invalid_store_ranges_before_dispatch() {
        let (runtime, registration, backing, mut thread) = setup(vec![0, 0]);

        let before = registration.pointer_at(UNCOOP_FAULT_REGION.raw, BASE - 1);
        assert!(matches!(
            runtime.copy_to_uncoop_user_with_thread(before, &[1], &mut thread),
            Err(CopyError::Fault)
        ));

        let end = registration.pointer().checked_advance(2).unwrap();
        assert!(matches!(
            runtime.copy_to_uncoop_user_with_thread(end, &[1], &mut thread),
            Err(CopyError::Fault)
        ));

        let crossing = registration.pointer().checked_advance(1).unwrap();
        assert!(matches!(
            runtime.copy_to_uncoop_user_with_thread(crossing, &[1, 2], &mut thread),
            Err(CopyError::Fault)
        ));

        retire(registration, backing);
    }

    #[test]
    fn accepts_exact_boundary_and_empty_ranges() {
        let (runtime, registration, backing, mut thread) = setup(vec![1, 2]);
        let pointer = registration.pointer();
        let mut bytes = [0; 2];

        assert!(
            runtime
                .copy_from_uncoop_user_with_thread(&mut bytes, pointer, &mut thread)
                .is_ok()
        );
        assert!(
            runtime
                .copy_to_uncoop_user_with_thread(pointer, &[3, 4], &mut thread)
                .is_ok()
        );

        let end = pointer.checked_advance(2).unwrap();
        assert!(
            runtime
                .copy_from_uncoop_user_with_thread(&mut [], end, &mut thread)
                .is_ok()
        );
        assert!(
            runtime
                .copy_to_uncoop_user_with_thread(end, &[], &mut thread)
                .is_ok()
        );

        retire(registration, backing);
    }
}
