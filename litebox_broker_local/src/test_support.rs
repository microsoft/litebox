// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test-only construction helpers for active broker-local associations.

use alloc::sync::Arc;

use litebox_broker_protocol::{ProcessId, ThreadId};
use litebox_broker_transport::channel::LocalCallChannel;
use litebox_broker_transport::shared_memory::SharedMemory;

use crate::BrokerLocal;

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
    shared_memory: Arc<dyn SharedMemory>,
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
    shared_memory: Arc<dyn SharedMemory>,
) -> BrokerLocal<Channel>
where
    Channel: LocalCallChannel,
{
    BrokerLocal::new(channel, process_id, TEST_THREAD_ID, shared_memory)
}
