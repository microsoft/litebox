// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process clones (see `litebox_common_vm_abi`, `CloneKind::Process`), for
//! Linux's `fork`.
//!
//! A `Clone` of the kind stops the calling thread ([`Suspended::Forking`]):
//! the scheduler makes the clone ([`Inner::fork`]) only once the thread's run
//! ended, which saved the state to copy. The clone runs nothing until the
//! kernel adopts it ([`Inner::adopt`]) as the runner of a child that the parent
//! starts with it (`StartChildWithExistingRunner`), making the clone's broker
//! handshake before it runs, so that the broker's worker, suspended in the
//! start, never waits for the clone. A process has at most one clone to adopt,
//! its latest, which ends once the process makes another, or exits.
//!
//! The scheduler adds the clone once it is made, as another CPU may adopt it
//! while the thread that made it runs on, and forgets it once dead, but
//! neither claims nor runs it until it is adopted (see `claim`). Until then,
//! only its parent's holder touches it, to make, adopt, or end it, through
//! the clone's claim once made: so on one CPU at a time, where alone its
//! address space is current while it is made.

use crate::claim::{Claim, Owned};
use crate::memory::copy_to_user;
use crate::thread::{self, Thread};
use crate::{
    Dead, Inner, SpawnError, State, Suspended, new_thread, pin_broker_memory, release_address_space,
};
use alloc::sync::{Arc, Weak};
use core::cell::{Cell, RefCell};
use litebox::shim::ContinueOperation;
use litebox_broker_core::BrokerError;
use litebox_broker_vm_kernel::PendingRunnerAssociation;
use litebox_common_linux::PtRegs;
use litebox_common_vm_abi::{CloneReply, CloneRequest, NewThread, Placement, Status};
use litebox_platform_vm_kernel::AddressSpaceId;
use zerocopy::IntoBytes as _;

impl Inner {
    /// Checks a `Clone` of a process clone, which the scheduler makes once
    /// the calling thread's run ends ([`Self::fork`]).
    pub(crate) fn check_fork(&self, r: &CloneRequest) -> Result<(), Status> {
        if !matches!(*self.state.borrow(), State::Serving { .. }) {
            return Err(Status::Denied);
        }
        let thread = NewThread {
            regs: r.regs,
            fs_base: r.fs_base,
            gs_base: r.gs_base,
            upcall_stack: r.upcall_stack,
        };
        if thread != NewThread::default() {
            return Err(Status::InvalidArgument);
        }
        if self.started_runner_config.is_none() {
            return Err(Status::Unsupported);
        }
        Ok(())
    }

    /// The process clone `thread` asked for, made once the thread's run
    /// ended, so that its state is saved, as `own` owns it, for the scheduler
    /// to add; `None` if it cannot be made, and the call then fails. Only
    /// under the process's claim; its other threads may run meanwhile, on
    /// other CPUs, whose writable translations, but shared memory's, the copy
    /// shoots down (see
    /// [`VmKernel::clone_address_space`](litebox_platform_vm_kernel::VmKernel::clone_address_space)).
    pub(crate) fn fork(
        &self,
        thread: &Thread,
        slot: u64,
        own: impl FnOnce(Self) -> Arc<Owned>,
    ) -> Option<Arc<Owned>> {
        match self.clone_process(thread, slot) {
            Ok(clone) => {
                let clone = own(clone);
                let id = self.next_clone.get();
                self.next_clone.set(id + 1);
                log::debug!("process clone {id} made");
                // Only once made: a call making none leaves the pending clone.
                end_pending(
                    self.pending_clone
                        .replace(Some((id, Arc::downgrade(&clone)))),
                );
                thread.suspended.set(Suspended::Cloned { slot, thread: id });
                Some(clone)
            }
            Err(status) => {
                log::warn!("failed to clone a runner process: {status:?}");
                thread.suspended.set(Suspended::Woken(Err(status)));
                None
            }
        }
    }

    /// A copy of the process, with fresh broker memory, and of `thread` (see
    /// [`Thread::cloned`]). Leaves the kernel's address space current if it
    /// makes one (see the crate docs).
    fn clone_process(&self, thread: &Thread, slot: u64) -> Result<Self, Status> {
        let platform = self.platform;
        let address_space = platform
            .clone_address_space(self.address_space)
            .map_err(|_| Status::NoMemory)?;
        // Safety: the kernel holds no references into user memory.
        unsafe { platform.switch_address_space(address_space) }
            .expect("a freshly cloned address space is registered");
        let mappings = self.mappings.duplicate();
        // `Replace`: the duplicated record lists the broker's memory, which
        // the clone does not map.
        let broker = pin_broker_memory(platform, address_space, &mappings, Placement::Replace)
            .map_err(|error| match error {
                SpawnError::Map(status) => status,
                _ => Status::NoMemory,
            })
            .map(|(shared_memory, control_ring)| {
                self.broker
                    .broker()
                    .associate_clone(shared_memory, control_ring)
            })
            .inspect_err(|_| {
                // Safety: nothing references the clone's memory, and it never
                // ran.
                unsafe { release_address_space(platform, address_space) };
            })?;
        // Safety: the kernel holds no references into user memory.
        unsafe { platform.switch_address_space(AddressSpaceId::KERNEL) }
            .expect("the kernel address space always exists");
        Ok(Self {
            platform,
            address_space,
            identity: self.identity,
            entry: self.entry,
            gate: self.gate.clone(),
            executable: self.executable.clone(),
            mappings,
            broker,
            timer: self.timer,
            started_runner_config: self.started_runner_config.clone(),
            state: RefCell::new(State::Cloned {
                upcall_entry: self.upcall_entry(),
            }),
            lockdown: Cell::new(self.lockdown.get()),
            entries: Cell::new(0),
            reflected: Cell::new(0),
            armed_deadline: Cell::new(None),
            notified: Cell::new(false),
            shared: Cell::new(false),
            threads: RefCell::new(alloc::vec![new_thread(Thread::cloned(thread, slot))]),
            next_thread: Cell::new(thread::MAIN + 1),
            broker_requester: Cell::new(thread::MAIN),
            worker: Cell::new(None),
            pending_clone: RefCell::new(None),
            next_clone: Cell::new(1),
        })
    }

    /// A process clone not adopted yet (see the module docs), which runs
    /// nothing.
    pub(crate) fn is_cloned(&self) -> bool {
        matches!(*self.state.borrow(), State::Cloned { .. })
    }

    /// Resumes `thread` from its `Clone` of a process clone, which returns
    /// `id` at `slot`. If that write fails, the call fails, and the clone,
    /// which the process cannot know of without its ID, ends as any unadopted
    /// one does (see the module docs); a clone that cannot get its own ID is
    /// killed.
    pub(crate) fn resume_cloned(
        &self,
        thread: &Thread,
        ctx: &mut PtRegs,
        slot: u64,
        id: u64,
    ) -> ContinueOperation {
        match copy_to_user(slot, CloneReply { thread: id }.as_bytes()) {
            Ok(()) => self.resume_call(thread, ctx, Ok(())),
            Err(status) if id != thread::MAIN => self.resume_call(thread, ctx, Err(status)),
            Err(_) => self.kill_and_stop("cannot write the process clone's reply"),
        }
    }

    /// Has the process's clone `id` run as `launch`, a child the process
    /// started with it, or fails `launch`. Makes the clone's broker handshake
    /// (see [`Association::adopt`](litebox_broker_vm_kernel::Association::adopt)),
    /// so that the start does not wait for the clone to run; a clone whose
    /// handshake fails ends without running. Either way, `launch` is done
    /// with, which wakes the CPU whose worker waits for it (see
    /// `PendingRunnerAssociation`'s `Drop`). Only under the process's claim.
    pub(crate) fn adopt(&self, id: u64, launch: PendingRunnerAssociation) {
        let pending = self
            .pending_clone
            .borrow_mut()
            .take_if(|(pending, _)| *pending == id);
        // Not if it ended.
        let clone = pending.and_then(|(_, clone)| clone.upgrade());
        let adoptable = clone.as_ref().map(claim_clone).and_then(|claim| {
            let upcall_entry = match *claim.state.borrow() {
                State::Cloned { upcall_entry } => Some(upcall_entry),
                _ => None,
            }?;
            Some((claim, upcall_entry))
        });
        let Some((claim, upcall_entry)) = adoptable else {
            log::warn!("a process started a child with a process clone it has not");
            launch.fail(BrokerError::PolicyDenied);
            return;
        };
        if let Err(error) = claim.broker.adopt(launch) {
            log::warn!("failed to adopt process clone {id}: {error:?}");
            end(&claim);
            return;
        }
        *claim.state.borrow_mut() = State::Serving { upcall_entry };
        log::debug!("process clone {id} adopted");
        // Runnable: for any CPU to take, once released.
        claim.share();
    }
}

/// The claim of a process clone not adopted yet, for its parent's holder,
/// the caller: free, as only that one takes it (see `claim`).
fn claim_clone(clone: &Arc<Owned>) -> Claim<'_> {
    clone
        .try_claim()
        .expect("only its parent claims a process clone not adopted yet")
}

/// Ends the clone taken from a process's `pending_clone`, if any, under the
/// process's claim. The upgraded reference may be the clone's last, if
/// another CPU forgot the dead clone meanwhile (see `sched`): freeing it here
/// then leaves the kernel's address space current (see
/// `release_address_space`), so callers stop the process's run, or are
/// between runs; and freeing takes no claim.
pub(crate) fn end_pending(pending: Option<(u64, Weak<Owned>)>) {
    if let Some(clone) = pending.and_then(|(_, clone)| clone.upgrade()) {
        end(&claim_clone(&clone));
    }
}

/// Ends `clone`, which was not adopted, under its claim.
fn end(clone: &Inner) {
    if !clone.is_dead() {
        log::debug!("ending a process clone that was not adopted");
        clone.die(Dead::Killed("process clone not adopted"));
    }
}
