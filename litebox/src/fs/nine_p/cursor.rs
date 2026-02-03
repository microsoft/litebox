// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Write cursor utilities for 9P protocol encoding

use alloc::vec::Vec;
use core::cmp::min;

/// A cursor for writing to a buffer with position tracking.
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct Cursor<T> {
    inner: T,
    pos: u64,
}

impl<T> Cursor<T> {
    /// Create a new cursor wrapping the given inner value.
    pub const fn new(inner: T) -> Cursor<T> {
        Cursor { pos: 0, inner }
    }

    /// Consume the cursor and return the inner value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// A trait for writing bytes to a buffer.
pub(crate) trait Write {
    /// Write a buffer to the output.
    ///
    /// Returns the number of bytes written.
    fn write(&mut self, buf: &[u8]) -> Result<usize, super::Error>;

    /// Write all bytes from a buffer to the output.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), super::Error> {
        let mut written = 0;
        while written < buf.len() {
            let n = self.write(&buf[written..])?;
            if n == 0 {
                return Err(super::Error::Io);
            }
            written += n;
        }
        Ok(())
    }
}

impl Write for &mut [u8] {
    fn write(&mut self, buf: &[u8]) -> Result<usize, super::Error> {
        let amt = min(self.len(), buf.len());
        let (a, b) = core::mem::take(self).split_at_mut(amt);
        a.copy_from_slice(&buf[..amt]);
        *self = b;
        Ok(amt)
    }
}

// Non-resizing write implementation
#[inline]
fn slice_write(pos_mut: &mut u64, slice: &mut [u8], buf: &[u8]) -> Result<usize, super::Error> {
    let pos = min(*pos_mut, slice.len() as u64);
    let amt = (&mut slice[(pos as usize)..]).write(buf)?;
    *pos_mut += amt as u64;
    Ok(amt)
}

impl Write for Cursor<&mut [u8]> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, super::Error> {
        slice_write(&mut self.pos, self.inner, buf)
    }
}

fn reserve_and_pad(
    pos_mut: &mut u64,
    vec: &mut Vec<u8>,
    buf_len: usize,
) -> Result<usize, super::Error> {
    let pos: usize = (*pos_mut)
        .try_into()
        .map_err(|_| super::Error::InvalidInput)?;

    // For safety reasons, we don't want these numbers to overflow
    // otherwise our allocation won't be enough
    let desired_cap = pos.saturating_add(buf_len);
    if desired_cap > vec.capacity() {
        // We want our vec's total capacity
        // to have room for (pos+buf_len) bytes. Reserve allocates
        // based on additional elements from the length, so we need to
        // reserve the difference
        vec.reserve(desired_cap - vec.len());
    }
    // Pad if pos is above the current len.
    if pos > vec.len() {
        let diff = pos - vec.len();
        // Unfortunately, `resize()` would suffice but the optimiser does not
        // realise the `reserve` it does can be eliminated. So we do it manually
        // to eliminate that extra branch
        let spare = vec.spare_capacity_mut();
        debug_assert!(spare.len() >= diff);
        // Safety: we have allocated enough capacity for this.
        // And we are only writing, not reading
        unsafe {
            spare
                .get_unchecked_mut(..diff)
                .fill(core::mem::MaybeUninit::new(0));
            vec.set_len(pos);
        }
    }

    Ok(pos)
}

/// # Safety
/// The caller must ensure that `vec.capacity() >= pos + buf.len()`
unsafe fn vec_write_unchecked(pos: usize, vec: &mut Vec<u8>, buf: &[u8]) -> usize {
    debug_assert!(vec.capacity() >= pos + buf.len());
    // SAFETY: The caller guarantees that vec.capacity() >= pos + buf.len(),
    // so this pointer arithmetic and copy is safe.
    unsafe {
        vec.as_mut_ptr().add(pos).copy_from(buf.as_ptr(), buf.len());
    }
    pos + buf.len()
}

fn vec_write(pos_mut: &mut u64, vec: &mut Vec<u8>, buf: &[u8]) -> Result<usize, super::Error> {
    let buf_len = buf.len();
    let mut pos = reserve_and_pad(pos_mut, vec, buf_len)?;

    // Write the buf then progress the vec forward if necessary
    // Safety: we have ensured that the capacity is available
    // and that all bytes get written up to pos
    unsafe {
        pos = vec_write_unchecked(pos, vec, buf);
        if pos > vec.len() {
            vec.set_len(pos);
        }
    };

    // Bump us forward
    *pos_mut += buf_len as u64;
    Ok(buf_len)
}

impl Write for Cursor<&mut Vec<u8>> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, super::Error> {
        vec_write(&mut self.pos, self.inner, buf)
    }
}

impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, super::Error> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }
}
