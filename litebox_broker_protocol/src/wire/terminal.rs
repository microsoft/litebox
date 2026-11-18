// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::terminal::{InputFlags, LocalFlags, OutputFlags, TerminalEvents};

use super::primitive::{Decoder, Encoder};
use super::{Wire, WireError};

wire_flags!(InputFlags: u16);
wire_flags!(OutputFlags: u16);
wire_flags!(LocalFlags: u16);

impl Wire for TerminalEvents {
    const MAX_SIZE: usize = <u8 as Wire>::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        self.bits().encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        Self::from_bits(u8::decode(decoder)?)
            .filter(|events| !events.is_empty())
            .ok_or(WireError::InvalidTag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::{
        ChangeTiming, GUEST_ATTRIBUTES_LEN, TerminalOperation, TerminalResponse, TerminalSettings,
        WindowSize,
    };

    #[test]
    fn controls_and_responses_round_trip_and_reject_bad_tags() {
        let mut guest_attributes = [0; GUEST_ATTRIBUTES_LEN];
        guest_attributes[0] = 0xa5;
        guest_attributes[GUEST_ATTRIBUTES_LEN - 1] = 0x5a;
        let attributed = TerminalSettings {
            guest_attributes,
            ..TerminalSettings::default()
        };
        for operation in [
            TerminalOperation::GetSettings,
            TerminalOperation::SetSettings {
                settings: attributed,
                timing: ChangeTiming::Now,
            },
            TerminalOperation::SetSettings {
                settings: TerminalSettings::default(),
                timing: ChangeTiming::AfterOutput,
            },
            TerminalOperation::SetSettings {
                settings: TerminalSettings::default(),
                timing: ChangeTiming::AfterOutputAndFlushInput,
            },
            TerminalOperation::GetWindowSize,
            TerminalOperation::SetWindowSize(WindowSize {
                rows: 41,
                columns: 120,
                x_pixels: 1,
                y_pixels: 2,
            }),
            TerminalOperation::Flush {
                input: true,
                output: false,
            },
            TerminalOperation::Drain,
            TerminalOperation::GetSubsidiaryIndex,
            TerminalOperation::GetSubsidiaryLock,
            TerminalOperation::SetSubsidiaryLock(false),
            TerminalOperation::SetSubsidiaryLock(true),
        ] {
            let mut e = Encoder::default();
            operation.encode(&mut e);
            let bytes = e.finish();
            let mut d = Decoder::new(&bytes);
            assert_eq!(TerminalOperation::decode(&mut d), Ok(operation));
            assert_eq!(d.finish(), Ok(()));
            for end in 0..bytes.len() {
                assert!(TerminalOperation::decode(&mut Decoder::new(&bytes[..end])).is_err());
            }
        }
        for response in [
            TerminalResponse::Settings(attributed),
            TerminalResponse::WindowSize(WindowSize::default()),
            TerminalResponse::Done,
            TerminalResponse::SubsidiaryIndex(0x1234_5678),
            TerminalResponse::SubsidiaryLock(false),
            TerminalResponse::SubsidiaryLock(true),
        ] {
            let mut e = Encoder::default();
            response.encode(&mut e);
            let bytes = e.finish();
            let mut d = Decoder::new(&bytes);
            assert_eq!(TerminalResponse::decode(&mut d), Ok(response));
            assert_eq!(d.finish(), Ok(()));
            for end in 0..bytes.len() {
                assert!(TerminalResponse::decode(&mut Decoder::new(&bytes[..end])).is_err());
            }
        }
        assert_eq!(
            TerminalResponse::decode(&mut Decoder::new(&[5])),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            TerminalResponse::decode(&mut Decoder::new(&[4, 2])),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            TerminalOperation::decode(&mut Decoder::new(&[8, 2])),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            TerminalOperation::decode(&mut Decoder::new(&[4, 2, 0])),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            TerminalOperation::decode(&mut Decoder::new(&[255])),
            Err(WireError::InvalidTag)
        );
        let mut e = Encoder::default();
        TerminalOperation::SetSettings {
            settings: TerminalSettings::default(),
            timing: ChangeTiming::Now,
        }
        .encode(&mut e);
        let mut bytes = e.finish();
        bytes[2] |= 0x80;
        assert_eq!(
            TerminalOperation::decode(&mut Decoder::new(&bytes)),
            Err(WireError::InvalidTag)
        );
    }
}
