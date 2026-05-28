// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed inotify file support.

use alloc::sync::Arc;

use litebox_common_linux::broker_inotify_provider::BrokerInotifyProvider;

static BROKER_INOTIFY_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerInotifyProvider>> =
    once_cell::race::OnceBox::new();

pub fn set_broker_inotify_provider(
    provider: Arc<dyn BrokerInotifyProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerInotifyProvider>>> {
    BROKER_INOTIFY_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_inotify_provider() -> Option<Arc<dyn BrokerInotifyProvider>> {
    BROKER_INOTIFY_PROVIDER.get().cloned()
}
