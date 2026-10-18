// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Copying bytes between a caller's buffer and the shared buffers a broker
//! object reads into or writes from.
//!
//! An operation lends its caller the shared bytes it transfers one contiguous
//! part at a time, in order: each part of the bytes the broker read to a
//! [`Copier`], which copies them out, or each part of the bytes to write to a
//! [`Filler`], which fills it. The caller copies between each part and its
//! own buffer, continuing where the previous part left off, so the bytes move
//! between its buffer and the broker's with no copy in between.
//!
//! An operation whose copier or filler fails fails with
//! [`BrokerLocalError::CopyFailed`](crate::BrokerLocalError::CopyFailed). A
//! write that fails sends nothing, but a read that fails has already
//! consumed the bytes it read.

use litebox_broker_transport::shared_memory::SharedBytes;

/// Reports that a [`Copier`] or [`Filler`] could not copy a part, such as
/// because the caller's buffer is inaccessible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyFailed;

/// Copies out each part of the bytes the broker read, in turn.
pub type Copier<'a> = dyn FnMut(SharedBytes<'_>) -> Result<(), CopyFailed> + 'a;

/// Fills each part of the bytes to write, in turn.
pub type Filler<'a> = dyn FnMut(SharedBytes<'_>) -> Result<(), CopyFailed> + 'a;

/// Returns a copier that copies the parts it is lent, one after another,
/// into `destination`.
///
/// # Panics
///
/// The copier panics if the parts overflow `destination`.
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

/// Returns a filler that fills the parts it is lent, one after another, from
/// `source`.
///
/// # Panics
///
/// The filler panics if the parts overflow `source`.
pub fn fill_from_slice(
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
