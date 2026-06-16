// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use thiserror::Error;

/// Errors returned by a broker-host receive/send loop.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrokerHostError<E> {
    #[error("broker association setup failed")]
    AssociationSetup,
    #[error("broker channel failed: {0}")]
    Channel(#[source] E),
}

/// Broker-host receive/send loop result type.
pub type Result<T, E> = core::result::Result<T, BrokerHostError<E>>;
