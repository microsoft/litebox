// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::random::{RandomProvider, RandomProviderError};

pub(super) struct UserlandRandomProvider;

impl RandomProvider for UserlandRandomProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        getrandom::fill(output).map_err(|_| RandomProviderError)
    }
}
