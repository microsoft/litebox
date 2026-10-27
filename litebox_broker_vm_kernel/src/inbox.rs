// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An association's inbox ([`Inbox`]): the operations the kernel posts to the
//! broker for a process, the binding of the one broker thread that drains
//! them, and the association's stack, which its threads run on in turn.
//!
//! A post sets its operation's bit, and binds the inbox if no thread is bound
//! ([`Posted::Bound`]); posts coalesce. The end is taken first, drops the
//! operations not yet started, and is final. A thread that finds nothing left
//! finishes, still bound; the kernel, off its stack, puts the stack back and
//! unbinds the inbox in one step with its check that nothing was posted
//! meanwhile ([`Inbox::finished`]), so that no post is lost.

use crate::{Binding, PendingRunnerAssociation};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use litebox_broker_core::BrokerError;
use litebox_broker_protocol::process::ProcessExitStatus;
use litebox_common_vm_abi::{Status, WireFrame};
use litebox_platform_vm_kernel::cpu;
use litebox_platform_vm_kernel::kthread::{self, Stack};
use litebox_platform_vm_kernel::preempt::KernelMutex;

#[cfg(test)]
mod tests;

/// An operation posted to an inbox (see the [module](self) docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    /// A call may have published requests.
    Submitted,
    /// The process's handshake, at most one.
    Handshake,
    /// The adoption of the process clone it is.
    Adopt,
    End,
}

impl Op {
    const fn bit(self) -> u32 {
        match self {
            Self::Submitted => 1 << 0,
            Self::Handshake => 1 << 1,
            Self::Adopt => 1 << 2,
            Self::End => 1 << 3,
        }
    }
}

const BOUND: u32 = 1 << 4;
/// Sticky: a handshake was posted, so another is refused.
const HANDSHAKEN: u32 = 1 << 5;
/// Sticky: the end was posted, so nothing more is.
const ENDING: u32 = 1 << 6;
const OPS: u32 = Op::Submitted.bit() | Op::Handshake.bit() | Op::Adopt.bit() | Op::End.bit();

/// An inbox's state word.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Word(u32);

impl Word {
    /// After posting `op`, and whether that bound the inbox; `None` if refused.
    fn post(self, op: Op) -> Option<(Self, bool)> {
        let refused = self.0 & ENDING != 0 || (op == Op::Handshake && self.0 & HANDSHAKEN != 0);
        if refused {
            return None;
        }
        let sticky = match op {
            Op::Handshake => HANDSHAKEN,
            Op::End => ENDING,
            Op::Submitted | Op::Adopt => 0,
        };
        Some((
            Self(self.0 | op.bit() | sticky | BOUND),
            self.0 & BOUND == 0,
        ))
    }

    /// The operation the bound thread takes next, if any.
    fn next(self) -> Option<Op> {
        [Op::End, Op::Adopt, Op::Handshake, Op::Submitted]
            .into_iter()
            .find(|op| self.0 & op.bit() != 0)
    }

    /// After the bound thread took `op`; the end takes the rest too.
    fn take(self, op: Op) -> Self {
        match op {
            Op::End => Self(self.0 & !OPS),
            op => Self(self.0 & !op.bit()),
        }
    }

    /// Unbound, if nothing is left to take.
    fn unbound(self) -> Option<Self> {
        (self.0 & OPS == 0).then_some(Self(self.0 & !BOUND))
    }

    /// Whether no thread is bound, and nothing posted.
    fn is_idle(self) -> bool {
        self.0 & (BOUND | OPS) == 0
    }

    fn is_ending(self) -> bool {
        self.0 & ENDING != 0
    }

    fn is_handshaken(self) -> bool {
        self.0 & HANDSHAKEN != 0
    }
}

/// What [`Inbox::post`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Posted {
    /// It bound the inbox: the poster has a thread started for it.
    Bound(Binding),
    /// A thread is bound, which takes it.
    Pending,
    /// The end was posted (or, for a handshake, one was): nothing more is.
    Refused,
}

/// The broker's runtime, as inboxes see it: it counts those bound, and shuts
/// down, after which none is posted to.
pub(crate) trait Bindings {
    fn bind(&self);
    fn unbind(&self);
    fn is_stopping(&self) -> bool;
}

/// What the kernel and the bound thread share is atomic, or kernel-grade.
pub(crate) struct Inbox<R, S> {
    word: AtomicU32,
    /// How many times a bound thread finished (see [`Binding`]), counted
    /// just before the kernel tries to unbind the inbox.
    ended: AtomicU64,
    /// The stack, while no thread runs on it; only the kernel takes it.
    stack: KernelMutex<Option<Stack>>,
    /// [`Op::Handshake`]'s request.
    handshake: KernelMutex<Option<WireFrame>>,
    /// The handshake's reply, which the caller takes.
    reply: KernelMutex<Option<Result<WireFrame, Status>>>,
    /// [`Op::Adopt`]'s start.
    adopt: KernelMutex<Option<PendingRunnerAssociation>>,
    /// [`Op::End`]'s status.
    exit: KernelMutex<Option<ProcessExitStatus>>,
    /// The association's broker side, while no thread has it: the bound
    /// thread puts it back before it finishes, unless it ended it.
    side: KernelMutex<Option<S>>,
    /// The process stopped: the kernel's unbind wakes the boot CPU.
    stopped: AtomicBool,
    /// Serving, or the adoption, failed the association.
    failed: AtomicBool,
    /// The handshake activated the association.
    active: AtomicBool,
    pub(crate) runtime: Arc<R>,
}

impl<R: Bindings, S> Inbox<R, S> {
    /// Idle, with the association's broker `side`, and `stack`.
    pub(crate) fn new(runtime: Arc<R>, side: S, stack: Stack) -> Self {
        Self {
            word: AtomicU32::new(0),
            ended: AtomicU64::new(0),
            stack: KernelMutex::new(Some(stack)),
            handshake: KernelMutex::new(None),
            reply: KernelMutex::new(None),
            adopt: KernelMutex::new(None),
            exit: KernelMutex::new(None),
            side: KernelMutex::new(Some(side)),
            stopped: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            active: AtomicBool::new(false),
            runtime,
        }
    }

    /// Posts `op`, with what it carries in the inbox already.
    pub(crate) fn post(&self, op: Op) -> Posted {
        debug_assert!(
            !self.runtime.is_stopping(),
            "a post to an inbox as the broker shuts down"
        );
        let mut word = Word(self.word.load(Ordering::SeqCst));
        loop {
            let Some((posted, bound)) = word.post(op) else {
                return Posted::Refused;
            };
            match self
                .word
                .compare_exchange(word.0, posted.0, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) if bound => {
                    self.runtime.bind();
                    return Posted::Bound(Binding(self.ended.load(Ordering::SeqCst)));
                }
                Ok(_) => return Posted::Pending,
                Err(current) => word = Word(current),
            }
        }
    }

    /// Posts the handshake, with `request`, which a refusal takes back.
    pub(crate) fn post_handshake(&self, request: WireFrame) -> Posted {
        *self.handshake.lock() = Some(request);
        let posted = self.post(Op::Handshake);
        if posted == Posted::Refused {
            *self.handshake.lock() = None;
        }
        posted
    }

    /// Posts the adoption of `launch`, which a refusal fails.
    pub(crate) fn post_adopt(&self, launch: PendingRunnerAssociation) -> Posted {
        *self.adopt.lock() = Some(launch);
        let posted = self.post(Op::Adopt);
        if posted == Posted::Refused {
            let launch = self.adopt.lock().take();
            if let Some(launch) = launch {
                launch.fail(BrokerError::PeerClosed);
            }
        }
        posted
    }

    /// Posts the end, with `status`.
    pub(crate) fn post_end(&self, status: ProcessExitStatus) -> Posted {
        *self.exit.lock() = Some(status);
        self.post(Op::End)
    }

    /// The handshake's reply, once made, which the caller takes.
    pub(crate) fn take_reply(&self) -> Option<Result<WireFrame, Status>> {
        self.reply.lock().take()
    }

    pub(crate) fn has_reply(&self) -> bool {
        self.reply.lock().is_some()
    }

    /// Mirrors whether the process stopped (see [`Self::finished`]); only the
    /// kernel does.
    pub(crate) fn set_stopped(&self, stopped: bool) {
        debug_assert!(
            !kthread::in_kthread(),
            "a broker thread mirrors whether a process stopped"
        );
        self.stopped.store(stopped, Ordering::SeqCst);
    }

    pub(crate) fn has_failed(&self) -> bool {
        self.failed.load(Ordering::SeqCst)
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// For the bound thread: takes the next operation, if any.
    pub(crate) fn take(&self) -> Option<Op> {
        let mut word = Word(self.word.load(Ordering::SeqCst));
        loop {
            let op = word.next()?;
            match self.word.compare_exchange(
                word.0,
                word.take(op).0,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Some(op),
                Err(current) => word = Word(current),
            }
        }
    }

    /// For the bound thread: the broker side, until [`Self::put_side`].
    pub(crate) fn take_side(&self) -> Option<S> {
        self.side.lock().take()
    }

    /// For the bound thread, before it finishes: the broker side, unless it
    /// ended it.
    pub(crate) fn put_side(&self, side: Option<S>) {
        *self.side.lock() = side;
    }

    /// For the bound thread, which took the end: the status it carries, and
    /// the adoption not started; the handshake not started is dropped.
    pub(crate) fn take_end(&self) -> (Option<ProcessExitStatus>, Option<PendingRunnerAssociation>) {
        *self.handshake.lock() = None;
        let exit = self.exit.lock().take();
        (exit, self.adopt.lock().take())
    }

    /// For the bound thread, which took the adoption: its start.
    pub(crate) fn take_adopt(&self) -> Option<PendingRunnerAssociation> {
        self.adopt.lock().take()
    }

    /// For the bound thread, which took the handshake: its request.
    pub(crate) fn take_handshake(&self) -> Option<WireFrame> {
        self.handshake.lock().take()
    }

    /// For the bound thread: the handshake's reply, for the kernel to take.
    pub(crate) fn reply(&self, reply: Result<WireFrame, Status>) {
        *self.reply.lock() = Some(reply);
    }

    /// For the bound thread: serving, or the adoption, failed the association.
    pub(crate) fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
    }

    /// For the bound thread: the handshake activated the association.
    pub(crate) fn activate(&self) {
        self.active.store(true, Ordering::SeqCst);
    }

    /// For the kernel, to start a thread for the bound inbox: its stack.
    pub(crate) fn take_stack(&self) -> Stack {
        debug_assert!(
            !kthread::in_kthread(),
            "a broker thread takes an association's stack"
        );
        self.stack
            .lock()
            .take()
            .expect("a bound inbox with no thread keeps its stack")
    }

    /// For the kernel, once the bound thread finished, off its stack: takes
    /// the stack back. Whether the inbox stays bound, as something was posted
    /// since. What the thread did is seen by whoever sees the inbox unbound.
    pub(crate) fn finished(&self, stack: Stack) -> bool {
        debug_assert!(
            !kthread::in_kthread(),
            "a broker thread takes an association's stack back"
        );
        self.ended.fetch_add(1, Ordering::SeqCst);
        let mut slot = self.stack.lock();
        let mut stack = Some(stack);
        let mut word = Word(self.word.load(Ordering::SeqCst));
        loop {
            let Some(unbound) = word.unbound() else {
                *slot = stack;
                return true;
            };
            if word.is_ending() {
                // The end ran, so no thread runs on it again; and nothing is
                // posted after it.
                drop(stack.take());
            }
            match self
                .word
                .compare_exchange(word.0, unbound.0, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(current) => word = Word(current),
            }
        }
        *slot = stack;
        drop(slot);
        self.runtime.unbind();
        if self.stopped.load(Ordering::SeqCst) {
            cpu::wake(cpu::CpuId::BOOT);
        }
        false
    }

    /// Whether `binding` ended (see [`Binding`]).
    pub(crate) fn has_ended(&self, binding: Binding) -> bool {
        self.ended.load(Ordering::SeqCst) > binding.0
    }

    /// Whether no thread is bound, and nothing posted: read before the ring's
    /// words, as the bound thread writes them before the kernel unbinds it.
    pub(crate) fn is_idle(&self) -> bool {
        Word(self.word.load(Ordering::SeqCst)).is_idle()
    }

    pub(crate) fn is_ending(&self) -> bool {
        Word(self.word.load(Ordering::SeqCst)).is_ending()
    }

    pub(crate) fn is_handshaken(&self) -> bool {
        Word(self.word.load(Ordering::SeqCst)).is_handshaken()
    }
}

impl<R, S> Drop for Inbox<R, S> {
    fn drop(&mut self) {
        debug_assert!(
            self.stack.lock().is_none(),
            "an association's stack is freed before its inbox drops"
        );
    }
}
