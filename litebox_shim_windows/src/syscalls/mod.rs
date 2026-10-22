// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub(crate) mod apphelp;
pub(crate) mod condrv;
mod dispatch;
pub(crate) mod event;
pub(crate) mod file;
pub(crate) mod file_path;
pub(crate) mod gdi;
pub(crate) mod iocp;
pub(crate) mod ksecdd;
pub(crate) mod license;
pub(crate) mod lpc;
pub(crate) mod mm;
pub(crate) mod mutant;
pub(crate) mod nls;
pub(crate) mod object_manager;
pub(crate) mod process;
pub(crate) mod registry;
pub(crate) mod section;
pub(crate) mod semaphore;
pub(crate) mod symlink;
pub(crate) mod sysinfo;
pub(crate) mod thread;
pub(crate) mod timer;
pub(crate) mod token;
pub(crate) mod trace;
pub(crate) mod wait;
pub(crate) mod wait_completion_packet;
pub(crate) mod wnf;
pub(crate) mod worker_factory;

use litebox::platform::{RawConstPointer as _, RawPointerProvider};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub(crate) enum WaitAcquireResult {
    Acquired,
    Abandoned,
}

/// Returns `SUCCESS` for `Ok(())` and the failure status otherwise.
pub(crate) fn status_from_result(result: Result<(), NtStatus>) -> NtStatus {
    match result {
        Ok(()) => NtStatus::SUCCESS,
        Err(status) => status,
    }
}

const FIRST_STACK_ARGUMENT_OFFSET: usize = 0x28;
const HANDLE_SHIFT: u32 = 2;
const HANDLE_TAG_MASK: usize = (1usize << HANDLE_SHIFT) - 1;

#[repr(transparent)]
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub(crate) struct Handle(usize);

impl Handle {
    #[must_use]
    pub(crate) const fn from_raw(raw: usize) -> Self {
        Self(raw)
    }

    #[must_use]
    pub(crate) fn from_raw_fd(raw_fd: usize) -> Option<Self> {
        raw_fd
            .checked_add(1)?
            .checked_mul(1usize << HANDLE_SHIFT)
            .map(Self)
    }

    #[must_use]
    pub(crate) fn raw_fd(self) -> Option<usize> {
        if self.0 & HANDLE_TAG_MASK != 0 {
            return None;
        }
        (self.0 >> HANDLE_SHIFT).checked_sub(1)
    }

    #[must_use]
    pub(crate) const fn as_raw(self) -> usize {
        self.0
    }

    #[must_use]
    pub(crate) const fn is_null(self) -> bool {
        self.as_raw() == 0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProcessHandle(Handle);

impl ProcessHandle {
    pub(crate) const CURRENT: Self = Self::from_raw(usize::MAX);

    #[must_use]
    pub(crate) const fn from_raw(raw: usize) -> Self {
        Self(Handle::from_raw(raw))
    }

    #[must_use]
    pub(crate) const fn is_null(self) -> bool {
        self.0.is_null()
    }

    #[must_use]
    pub(crate) fn is_current(self) -> bool {
        self == Self::CURRENT
    }

    #[must_use]
    pub(crate) const fn as_handle(self) -> Handle {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ThreadHandle(Handle);

impl ThreadHandle {
    pub(crate) const CURRENT: Self = Self::from_raw(usize::MAX - 1);

    #[must_use]
    pub(crate) const fn from_raw(raw: usize) -> Self {
        Self(Handle::from_raw(raw))
    }

    #[must_use]
    pub(crate) fn is_current(self) -> bool {
        self == Self::CURRENT
    }

    #[must_use]
    pub(crate) fn is_null(self) -> bool {
        self.0.is_null()
    }

    #[must_use]
    pub(crate) const fn as_handle(self) -> Handle {
        self.0
    }
}

fn win_syscall_arg<Platform: RawPointerProvider>(
    pt_regs: &litebox_common_linux::PtRegs,
    idx: usize,
) -> Option<usize> {
    match idx {
        0 => Some(pt_regs.r10),
        1 => Some(pt_regs.rdx),
        2 => Some(pt_regs.r8),
        3 => Some(pt_regs.r9),
        idx => {
            // The first stack argument sits after the return address and x64 shadow space.
            let stack_offset = FIRST_STACK_ARGUMENT_OFFSET
                .checked_add((idx - 4).checked_mul(size_of::<usize>())?)?;
            let stack_address = pt_regs.rsp.checked_add(stack_offset)?;
            let stack_arg = Platform::RawConstPointer::<usize>::from_usize(stack_address);
            stack_arg.read_at_offset(0)
        }
    }
}

fn win_sys_req_arg<Platform: RawPointerProvider, T: ReinterpretTruncatedFromUsize>(
    pt_regs: &litebox_common_linux::PtRegs,
    idx: usize,
) -> Option<T> {
    Some(T::reinterpret_truncated_from_usize(win_syscall_arg::<
        Platform,
    >(pt_regs, idx)?))
}

fn win_sys_req_ptr<
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes,
    P: ReinterpretUsizeAsPtr<T>,
>(
    pt_regs: &litebox_common_linux::PtRegs,
    idx: usize,
) -> Option<P> {
    Some(P::reinterpret_usize_as_ptr(win_syscall_arg::<Platform>(
        pt_regs, idx,
    )?))
}

trait ReinterpretTruncatedFromUsize: Sized {
    fn reinterpret_truncated_from_usize(value: usize) -> Self;
}

impl ReinterpretTruncatedFromUsize for usize {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        value
    }
}

impl ReinterpretTruncatedFromUsize for u64 {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        value as u64
    }
}

impl ReinterpretTruncatedFromUsize for isize {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        value.cast_signed()
    }
}

impl ReinterpretTruncatedFromUsize for NtStatus {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        Self::from_raw(value.trunc())
    }
}

/// A Windows `BOOLEAN` argument: only the low byte is significant.
impl ReinterpretTruncatedFromUsize for bool {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        u8::reinterpret_truncated_from_usize(value) != 0
    }
}

impl ReinterpretTruncatedFromUsize for Handle {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        Self::from_raw(value)
    }
}

impl ReinterpretTruncatedFromUsize for ProcessHandle {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        Self::from_raw(value)
    }
}

impl ReinterpretTruncatedFromUsize for ThreadHandle {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        Self::from_raw(value)
    }
}

macro_rules! reinterpret_truncated_unsigned {
    ($($ty:ty),* $(,)?) => {
        $(
            impl ReinterpretTruncatedFromUsize for $ty {
                fn reinterpret_truncated_from_usize(value: usize) -> Self {
                    value.trunc()
                }
            }
        )*
    };
}

macro_rules! reinterpret_truncated_signed {
    ($($sty:ty),* $(,)?) => {
        $(
            impl ReinterpretTruncatedFromUsize for $sty {
                fn reinterpret_truncated_from_usize(value: usize) -> Self {
                    value.cast_signed().trunc()
                }
            }
        )*
    };
}

reinterpret_truncated_unsigned!(u8, u16, u32);
reinterpret_truncated_signed!(i8, i16, i32);

trait ReinterpretUsizeAsPtr<T>: Sized {
    fn reinterpret_usize_as_ptr(value: usize) -> Self;
}

impl<T: zerocopy::FromBytes, P: litebox::platform::RawConstPointer<T>>
    ReinterpretUsizeAsPtr<core::marker::PhantomData<((), T)>> for P
{
    fn reinterpret_usize_as_ptr(value: usize) -> Self {
        P::from_usize(value)
    }
}

impl<T: zerocopy::FromBytes, P: litebox::platform::RawConstPointer<T>>
    ReinterpretUsizeAsPtr<core::marker::PhantomData<(bool, T)>> for Option<P>
{
    fn reinterpret_usize_as_ptr(value: usize) -> Self {
        if value == 0 {
            None
        } else {
            Some(P::from_usize(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_encodes_raw_fds_and_rejects_invalid_values() {
        let first_handle = Handle::from_raw_fd(0).expect("raw fd 0 should encode");
        assert_eq!(first_handle, Handle::from_raw(1usize << HANDLE_SHIFT));
        assert_eq!(first_handle.raw_fd(), Some(0));

        let max_raw_fd = (usize::MAX >> HANDLE_SHIFT) - 1;
        for raw_fd in [1, 42, max_raw_fd] {
            let handle = Handle::from_raw_fd(raw_fd).expect("raw fd should encode");
            assert_eq!(handle.raw_fd(), Some(raw_fd));
        }

        assert_eq!(Handle::from_raw(0).raw_fd(), None);

        for tag in 1..=HANDLE_TAG_MASK {
            assert_eq!(Handle::from_raw(tag).raw_fd(), None);
            assert_eq!(
                Handle::from_raw((2usize << HANDLE_SHIFT) | tag).raw_fd(),
                None
            );
        }

        assert_eq!(Handle::from_raw_fd(usize::MAX >> HANDLE_SHIFT), None);
        assert_eq!(Handle::from_raw_fd(usize::MAX), None);
    }
}
