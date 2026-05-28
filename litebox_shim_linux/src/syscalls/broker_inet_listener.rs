// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed TCP listener file support.

use alloc::sync::Arc;

use litebox_common_linux::broker_inet_listener_provider::BrokerInetListenerProvider;

static BROKER_INET_LISTENER_PROVIDER: once_cell::race::OnceBox<
    Arc<dyn BrokerInetListenerProvider>,
> = once_cell::race::OnceBox::new();

pub fn set_broker_inet_listener_provider(
    provider: Arc<dyn BrokerInetListenerProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerInetListenerProvider>>> {
    BROKER_INET_LISTENER_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_inet_listener_provider() -> Option<Arc<dyn BrokerInetListenerProvider>> {
    BROKER_INET_LISTENER_PROVIDER.get().cloned()
}
