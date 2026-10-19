// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Copying bytes between a caller's buffer and the shared buffers a broker
//! object reads into or writes from.
//!
//! An operation passes its caller the shared bytes it transfers one contiguous
//! part at a time, in order: each part of the bytes the broker read to a
//! [`CopyFromFn`], which copies from it, or each part of the bytes to write to
//! a [`CopyToFn`], which copies to it. Their names give the direction relative
//! to that part, the closure's argument, not to the caller's buffer, as they do
//! on the broker. The caller copies between each part and its own buffer,
//! continuing where the previous part left off, so the bytes move between its
//! buffer and the broker's with no copy in between.
//!
//! An operation whose [`CopyFromFn`] or [`CopyToFn`] fails fails with
//! [`BrokerLocalError::CopyFailed`](crate::BrokerLocalError::CopyFailed). A
//! write that fails sends nothing, but a read that fails has already
//! consumed the bytes it read.

use litebox_broker_transport::shared_memory::SharedBytes;

/// Reports that a [`CopyFromFn`] or [`CopyToFn`] could not copy a part, such as
/// because the caller's buffer is inaccessible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyFailed;

/// Copies from each part of the bytes the broker read, in turn, to the
/// caller's buffer.
pub type CopyFromFn<'a> = dyn FnMut(SharedBytes<'_>) -> Result<(), CopyFailed> + 'a;

/// Copies to each part of the bytes to write, in turn, from the caller's
/// buffer.
pub type CopyToFn<'a> = dyn FnMut(SharedBytes<'_>) -> Result<(), CopyFailed> + 'a;

/// Returns a [`CopyFromFn`] that copies the parts it is passed, one after another,
/// into `destination`.
///
/// # Panics
///
/// The [`CopyFromFn`] panics if the parts overflow `destination`.
pub fn copy_to_slice(
    destination: &mut [u8],
) -> impl FnMut(SharedBytes<'_>) -> Result<(), CopyFailed> + '_ {
    let mut offset = 0;
    move |part| {
        let end = offset + part.len();
        part.copy_to_slice(&mut destination[offset..end]);
        offset = end;
        Ok(())
    }
}

/// Returns a [`CopyToFn`] that fills the parts it is passed, one after another, from
/// `source`.
///
/// # Panics
///
/// The [`CopyToFn`] panics if the parts overflow `source`.
pub fn copy_from_slice(
    source: &[u8],
) -> impl FnMut(SharedBytes<'_>) -> Result<(), CopyFailed> + '_ {
    let mut offset = 0;
    move |part| {
        let end = offset + part.len();
        part.copy_from_slice(&source[offset..end]);
        offset = end;
        Ok(())
    }
}
