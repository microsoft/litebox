// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;

/// Errors returned by a broker-host receive/send loop.
#[derive(Debug)]
#[non_exhaustive]
pub enum BrokerHostError<E> {
    /// The host could not authenticate the peer or allocate broker association state.
    AssociationSetup,
    /// The concrete channel failed.
    Channel(E),
}

impl<E: fmt::Display> fmt::Display for BrokerHostError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssociationSetup => f.write_str("broker association setup failed"),
            Self::Channel(error) => write!(f, "broker channel failed: {error}"),
        }
    }
}

impl<E> core::error::Error for BrokerHostError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::AssociationSetup => None,
            Self::Channel(error) => Some(error),
        }
    }
}

/// Broker-host receive/send loop result type.
pub type Result<T, E> = core::result::Result<T, BrokerHostError<E>>;
