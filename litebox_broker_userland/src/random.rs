// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host randomness for userland brokers.

use litebox_broker_core::random::{RandomProvider, RandomProviderError};

/// Fills random requests from the host operating system's generator.
pub struct UserlandRandomProvider;

impl RandomProvider for UserlandRandomProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        getrandom::fill(output).map_err(|_| RandomProviderError)
    }
}
