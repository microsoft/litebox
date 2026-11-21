// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::segment::{SegmentAttachmentCount, SegmentAttachmentCounts};

use super::primitive::{Decoder, Encoder};
use super::{Wire, WireError};

impl Wire for SegmentAttachmentCounts {
    const MAX_SIZE: usize =
        u8::MAX_SIZE + Self::CAPACITY * <SegmentAttachmentCount as Wire>::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        let counts = self.as_slice();
        u8::try_from(counts.len()).unwrap().encode(encoder);
        for count in counts {
            count.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let len = usize::from(u8::decode(decoder)?);
        let mut counts = [SegmentAttachmentCount::default(); Self::CAPACITY];
        for count in counts.get_mut(..len).ok_or(WireError::InvalidTag)? {
            *count = SegmentAttachmentCount::decode(decoder)?;
        }
        Ok(Self::new(&counts[..len]).unwrap())
    }
}
