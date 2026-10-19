// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test-only helpers for broker-local associations.

use alloc::sync::Arc;

use litebox_broker_protocol::{ProcessId, ThreadId};
use litebox_broker_transport::channel::LocalCallChannel;
use litebox_broker_transport::shared_memory::{AsSharedBytes, SharedBytes};

use crate::{BrokerLocal, CopyFailed};

const TEST_PROCESS_ID: ProcessId = ProcessId(1);
const TEST_THREAD_ID: ThreadId = ThreadId(2);

/// Constructs an active broker-local association without exercising protocol negotiation.
///
/// Tests that specifically cover negotiation should use [`BrokerLocal::negotiate`] instead.
///
/// # Panics
///
/// Panics if `shared_memory` does not have the broker protocol's required size.
pub fn test_broker_local<Channel>(
    channel: Channel,
    shared_memory: Arc<dyn AsSharedBytes>,
) -> BrokerLocal<Channel>
where
    Channel: LocalCallChannel,
{
    test_broker_local_with_process_id(channel, TEST_PROCESS_ID, shared_memory)
}

/// Constructs an active broker-local association with a specific process ID.
///
/// This is intended for fixtures backed by a real broker process whose allocated identity must be
/// preserved. Ordinary fake-channel tests should use [`test_broker_local`].
///
/// # Panics
///
/// Panics if `shared_memory` does not have the broker protocol's required size.
pub fn test_broker_local_with_process_id<Channel>(
    channel: Channel,
    process_id: ProcessId,
    shared_memory: Arc<dyn AsSharedBytes>,
) -> BrokerLocal<Channel>
where
    Channel: LocalCallChannel,
{
    BrokerLocal::new(channel, process_id, TEST_THREAD_ID, shared_memory)
}

/// Returns a [`CopyFromFn`](crate::CopyFromFn) that copies the parts it is
/// passed, one after another, into `destination`.
///
/// # Panics
///
/// The closure panics if the parts overflow `destination`.
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

/// Returns a [`CopyToFn`](crate::CopyToFn) that fills the parts it is passed,
/// one after another, from `source`.
///
/// # Panics
///
/// The closure panics if the parts overflow `source`.
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
