// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::process::ResourceLimit;

use super::primitive::{Decoder, Encoder};
use super::{Wire, WireError};

impl Wire for ResourceLimit {
    const MAX_SIZE: usize = u64::MAX_SIZE + u64::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        self.soft().encode(encoder);
        self.hard().encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let soft = u64::decode(decoder)?;
        let hard = u64::decode(decoder)?;
        Self::new(soft, hard).ok_or(WireError::InvalidTag)
    }
}
