// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::authority::{DomainId, Principal, Privileges, Scope};

use super::primitive::{Decoder, Encoder};
use super::{Wire, WireError};

wire_newtype!(DomainId: u32);
wire_flags!(Privileges: u32);

impl Wire for Principal {
    const MAX_SIZE: usize = DomainId::MAX_SIZE + u32::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        self.domain.encode(encoder);
        self.id.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        Ok(Self {
            domain: DomainId::decode(decoder)?,
            id: u32::decode(decoder)?,
        })
    }
}

// Tags are pinned; append new scopes after the existing ones.
const SCOPE_ACCESS: u8 = 0;
const SCOPE_IDENTITY: u8 = 1;

impl Wire for Scope {
    const MAX_SIZE: usize = u8::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Access => SCOPE_ACCESS,
            Self::Identity => SCOPE_IDENTITY,
        }
        .encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        match u8::decode(decoder)? {
            SCOPE_ACCESS => Ok(Self::Access),
            SCOPE_IDENTITY => Ok(Self::Identity),
            _ => Err(WireError::InvalidTag),
        }
    }
}
