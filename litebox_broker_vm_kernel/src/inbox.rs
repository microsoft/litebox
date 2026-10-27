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

use crate::{Binding, Runtime};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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

/// What the kernel and the bound thread share is atomic, or kernel-grade.
pub(crate) struct Inbox {
    word: AtomicU32,
    /// How many times a bound thread finished (see [`Binding`]), counted
    /// just before the kernel tries to unbind the inbox.
    ended: AtomicU64,
    /// The stack, while no thread runs on it; only the kernel takes it.
    stack: KernelMutex<Option<Stack>>,
    /// What the operations carry, and the handshake's reply.
    pub(crate) mailbox: KernelMutex<Mailbox>,
    /// The association's broker side, while no thread has it: the bound
    /// thread puts it back before it finishes, unless it ended it.
    pub(crate) side: KernelMutex<Option<crate::Side>>,
    /// The process stopped: the kernel's unbind wakes the boot CPU.
    pub(crate) stopped: AtomicBool,
    /// Serving, or the adoption, failed the association.
    pub(crate) failed: AtomicBool,
    /// The handshake activated the association.
    pub(crate) active: AtomicBool,
    pub(crate) runtime: Arc<Runtime>,
}

/// What an inbox's operations carry (see [`Inbox::mailbox`]).
#[derive(Default)]
pub(crate) struct Mailbox {
    /// [`Op::Handshake`]'s request, then its reply, which the caller takes.
    pub(crate) handshake: Option<WireFrame>,
    pub(crate) reply: Option<Result<WireFrame, Status>>,
    /// [`Op::Adopt`]'s start.
    pub(crate) adopt: Option<crate::PendingRunnerAssociation>,
    /// [`Op::End`]'s status.
    pub(crate) exit: Option<ProcessExitStatus>,
}

impl Inbox {
    /// Idle, with `stack`.
    pub(crate) fn new(runtime: Arc<Runtime>, stack: Stack) -> Self {
        Self {
            word: AtomicU32::new(0),
            ended: AtomicU64::new(0),
            stack: KernelMutex::new(Some(stack)),
            mailbox: KernelMutex::default(),
            side: KernelMutex::new(None),
            stopped: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            active: AtomicBool::new(false),
            runtime,
        }
    }

    /// Posts `op`, with what it carries in the mailbox already.
    pub(crate) fn post(&self, op: Op) -> Posted {
        debug_assert!(
            !self.runtime.stopping.load(Ordering::SeqCst),
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
                    self.runtime.bound.fetch_add(1, Ordering::SeqCst);
                    return Posted::Bound(Binding(self.ended.load(Ordering::SeqCst)));
                }
                Ok(_) => return Posted::Pending,
                Err(current) => word = Word(current),
            }
        }
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
        self.runtime.bound.fetch_sub(1, Ordering::SeqCst);
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

impl Drop for Inbox {
    fn drop(&mut self) {
        debug_assert!(
            self.stack.lock().is_none(),
            "an association's stack is freed before its inbox drops"
        );
    }
}
