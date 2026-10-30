// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest memory as the buffers that LiteBox objects read into and write from.
//!
//! A guest buffer is the concatenation of guest iovecs, which objects copy
//! into and out of directly, without staging the bytes in a kernel buffer.

use core::{marker::PhantomData, ops::Range};

use litebox_common_linux::{IoReadVec, IoWriteVec, errno::Errno};
use litebox_platform::buffer::{Buffer, Fault, RawBytes, ReadBuffer, WriteBuffer};

use crate::{ShimPlatform, UserPtr, UserPtrMut};

/// Linux's `SSIZE_MAX`, which bounds the total length of an iovec array.
const SSIZE_MAX: usize = isize::MAX as usize;

/// Returns the total length of iovecs of `lengths`, which Linux rejects with
/// `EINVAL` above `SSIZE_MAX`.
fn total_length(lengths: impl IntoIterator<Item = usize>) -> Result<usize, Errno> {
    lengths.into_iter().try_fold(0usize, |total, length| {
        total
            .checked_add(length)
            .filter(|&total| total <= SSIZE_MAX)
            .ok_or(Errno::EINVAL)
    })
}

/// Calls `copy` on each part, within one iovec of `iovs`, of the `length`
/// bytes `offset` bytes into their concatenation, with the iovec's base, the
/// part's offset in that iovec, and the part's range within the bytes.
fn for_each_part<Base: Copy>(
    iovs: impl IntoIterator<Item = (Base, usize)>,
    mut offset: usize,
    length: usize,
    mut copy: impl FnMut(Base, usize, Range<usize>) -> Option<()>,
) -> Result<(), Fault> {
    let mut done = 0;
    for (base, iov_length) in iovs {
        if done == length {
            break;
        }
        if offset >= iov_length {
            offset -= iov_length;
            continue;
        }
        let part = (iov_length - offset).min(length - done);
        copy(base, offset, done..done + part).ok_or(Fault)?;
        done += part;
        offset = 0;
    }
    assert_eq!(done, length, "the bytes exceed their iovecs");
    Ok(())
}

/// Asserts that the `length` bytes at `offset` lie within a guest buffer of
/// `buffer_length` bytes.
fn assert_within(buffer_length: usize, offset: usize, length: usize) {
    assert!(
        offset
            .checked_add(length)
            .is_some_and(|end| end <= buffer_length),
        "{length} bytes at {offset} exceed a guest buffer of {buffer_length} bytes"
    );
}

/// Guest memory, scattered across iovecs, that a read fills.
pub(crate) struct GuestReadBuffer<'a, Platform> {
    iovs: &'a [IoReadVec],
    length: usize,
    platform: PhantomData<fn(Platform)>,
}

impl<'a, Platform: ShimPlatform> GuestReadBuffer<'a, Platform> {
    /// Returns the buffer of `iovs`, failing with `EINVAL` if their total
    /// length exceeds `SSIZE_MAX`.
    pub(crate) fn new(iovs: &'a [IoReadVec]) -> Result<Self, Errno> {
        Ok(Self {
            iovs,
            length: total_length(iovs.iter().map(|iov| iov.iov_len))?,
            platform: PhantomData,
        })
    }

    /// Returns the buffer of `iov` alone.
    pub(crate) fn single(iov: &'a IoReadVec) -> Self {
        Self {
            iovs: core::slice::from_ref(iov),
            length: iov.iov_len,
            platform: PhantomData,
        }
    }

    fn parts(&self) -> impl Iterator<Item = (UserPtrMut<u8>, usize)> + 'a {
        self.iovs.iter().map(|iov| (iov.iov_base, iov.iov_len))
    }
}

impl<Platform: ShimPlatform> Buffer for GuestReadBuffer<'_, Platform> {
    fn len(&self) -> usize {
        self.length
    }
}

impl<Platform: ShimPlatform> ReadBuffer for GuestReadBuffer<'_, Platform> {
    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        assert_within(self.length, offset, source.len());
        for_each_part(self.parts(), offset, source.len(), |base, at, range| {
            base.copy_from_slice::<Platform>(at, &source[range])
        })
    }

    fn copy_from_raw_at(&mut self, offset: usize, source: RawBytes<'_>) -> Result<(), Fault> {
        assert_within(self.length, offset, source.len());
        for_each_part(self.parts(), offset, source.len(), |base, at, range| {
            let part = source.subrange(range);
            // SAFETY: Raw bytes are readable for their length and never
            // referenced.
            unsafe { base.copy_from_raw::<Platform>(at, part.as_ptr(), part.len()) }
        })
    }
}

/// Guest memory, gathered from iovecs, that a write drains.
pub(crate) struct GuestWriteBuffer<'a, Platform> {
    iovs: &'a [IoWriteVec],
    length: usize,
    platform: PhantomData<fn(Platform)>,
}

impl<'a, Platform: ShimPlatform> GuestWriteBuffer<'a, Platform> {
    /// Returns the buffer of `iovs`, failing with `EINVAL` if their total
    /// length exceeds `SSIZE_MAX`.
    pub(crate) fn new(iovs: &'a [IoWriteVec]) -> Result<Self, Errno> {
        Ok(Self {
            iovs,
            length: total_length(iovs.iter().map(|iov| iov.iov_len))?,
            platform: PhantomData,
        })
    }

    /// Returns the buffer of `iov` alone.
    pub(crate) fn single(iov: &'a IoWriteVec) -> Self {
        Self {
            iovs: core::slice::from_ref(iov),
            length: iov.iov_len,
            platform: PhantomData,
        }
    }

    fn parts(&self) -> impl Iterator<Item = (UserPtr<u8>, usize)> + 'a {
        self.iovs.iter().map(|iov| (iov.iov_base, iov.iov_len))
    }
}

impl<Platform: ShimPlatform> Buffer for GuestWriteBuffer<'_, Platform> {
    fn len(&self) -> usize {
        self.length
    }
}

impl<Platform: ShimPlatform> WriteBuffer for GuestWriteBuffer<'_, Platform> {
    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        assert_within(self.length, offset, destination.len());
        for_each_part(
            self.parts(),
            offset,
            destination.len(),
            |base, at, range| base.copy_to_slice::<Platform>(at, &mut destination[range]),
        )
    }

    fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
        assert_within(self.length, offset, destination.len());
        for_each_part(
            self.parts(),
            offset,
            destination.len(),
            |base, at, range| {
                let part = destination.subrange(range);
                // SAFETY: Raw bytes are writable for their length and never
                // referenced.
                unsafe { base.copy_to_raw::<Platform>(at, part.as_ptr(), part.len()) }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::tests::TestPlatform;

    fn read_iov(bytes: &mut [u8]) -> IoReadVec {
        IoReadVec {
            iov_base: UserPtrMut::from_ptr(bytes.as_mut_ptr()),
            iov_len: bytes.len(),
        }
    }

    fn write_iov(bytes: &[u8]) -> IoWriteVec {
        IoWriteVec {
            iov_base: UserPtr::from_ptr(bytes.as_ptr()),
            iov_len: bytes.len(),
        }
    }

    #[test]
    fn reads_scatter_across_iovecs_and_sub_buffers() {
        let (mut a, mut b, mut c) = ([0u8; 2], [0u8; 0], [0u8; 3]);
        let iovs = [read_iov(&mut a), read_iov(&mut b), read_iov(&mut c)];
        let mut buffer = GuestReadBuffer::<TestPlatform>::new(&iovs).unwrap();
        assert_eq!(buffer.len(), 5);
        buffer.copy_from_slice_at(1, &[1, 2]).unwrap();
        let mut raw = [3, 4];
        (&mut buffer)
            .sub_buffer(2, 3)
            .copy_from_raw_at(1, (&mut raw[..]).into())
            .unwrap();
        assert_eq!((a, c), ([0, 1], [2, 3, 4]));
    }

    #[test]
    fn writes_gather_across_iovecs() {
        let (a, b, c) = ([1u8, 2], [], [3u8, 4, 5]);
        let iovs = [write_iov(&a), write_iov(&b), write_iov(&c)];
        let buffer = GuestWriteBuffer::<TestPlatform>::new(&iovs).unwrap();
        let mut gathered = [0; 3];
        buffer.copy_to_slice_at(1, &mut gathered).unwrap();
        assert_eq!(gathered, [2, 3, 4]);
        let mut raw = [0; 4];
        buffer.copy_to_raw_at(1, (&mut raw[..]).into()).unwrap();
        assert_eq!(raw, [2, 3, 4, 5]);
    }

    #[test]
    fn inaccessible_memory_faults() {
        let _ = crate::syscalls::tests::init_platform();
        // The faulting read is recovered only on a LiteBox-managed thread.
        <TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let iov = IoWriteVec {
                iov_base: UserPtr::from_usize(0xdead_beef),
                iov_len: 4,
            };
            let buffer = GuestWriteBuffer::<TestPlatform>::single(&iov);
            assert_eq!(buffer.copy_to_slice_at(0, &mut [0; 4]), Err(Fault));
        });
    }

    #[test]
    fn iovecs_above_ssize_max_are_invalid() {
        let iovs = [
            IoWriteVec {
                iov_base: UserPtr::from_usize(0),
                iov_len: SSIZE_MAX,
            },
            IoWriteVec {
                iov_base: UserPtr::from_usize(0),
                iov_len: 1,
            },
        ];
        assert!(matches!(
            GuestWriteBuffer::<TestPlatform>::new(&iovs),
            Err(Errno::EINVAL)
        ));
    }

    #[test]
    #[should_panic(expected = "exceed a guest buffer")]
    fn copies_past_the_end_panic() {
        let mut bytes = [0u8; 2];
        let iov = read_iov(&mut bytes);
        let _ = GuestReadBuffer::<TestPlatform>::single(&iov).copy_from_slice_at(1, &[0; 2]);
    }
}
