// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;

/// Broker authority error category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BrokerError {
    /// Policy denied the operation.
    PolicyDenied,
    /// The referenced object does not exist.
    UnknownObject,
    /// The referenced object generation is stale.
    StaleHandle,
    /// The referenced object type does not match the operation.
    WrongObjectType,
    /// The caller lacks the required broker rights.
    InvalidRights,
    /// Broker-side resource exhaustion.
    ResourceExhausted,
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyDenied => f.write_str("broker policy denied the operation"),
            Self::UnknownObject => f.write_str("unknown broker object"),
            Self::StaleHandle => f.write_str("stale broker handle"),
            Self::WrongObjectType => f.write_str("wrong broker object type"),
            Self::InvalidRights => f.write_str("invalid broker rights"),
            Self::ResourceExhausted => f.write_str("broker resource exhausted"),
        }
    }
}

impl core::error::Error for BrokerError {}
