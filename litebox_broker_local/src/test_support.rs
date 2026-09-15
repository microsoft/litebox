// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test-only construction helpers for active broker-local associations.

use alloc::sync::Arc;

use litebox_broker_protocol::ProcessId;
use litebox_broker_transport::channel::LocalCallChannel;
use litebox_broker_transport::shared_memory::SharedMemory;

use crate::BrokerLocal;

/// Constructs an active broker-local association without exercising protocol negotiation.
///
/// Tests that specifically cover negotiation should use [`BrokerLocal::negotiate`] instead.
///
/// # Panics
///
/// Panics if `shared_memory` does not have the broker protocol's required size.
pub fn broker_local<Channel>(
    channel: Channel,
    process_id: ProcessId,
    shared_memory: Arc<dyn SharedMemory>,
) -> BrokerLocal<Channel>
where
    Channel: LocalCallChannel,
{
    BrokerLocal::new(channel, process_id, shared_memory)
}
