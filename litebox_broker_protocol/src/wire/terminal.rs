// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    WireError,
    primitive::{Decoder, Encoder},
};
use crate::terminal::{
    ChangeTiming, ControlCharacters, InputFlags, LocalFlags, OutputFlags, TerminalError,
    TerminalOperation, TerminalResponse, TerminalSettings, WindowSize,
};

fn boolean(decoder: &mut Decoder<'_>) -> Result<bool, WireError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_settings(e: &mut Encoder, s: TerminalSettings) {
    e.u16(s.input.bits());
    e.u16(s.output.bits());
    e.u16(s.local.bits());
    let c = s.characters;
    for byte in [
        c.interrupt,
        c.quit,
        c.erase,
        c.kill,
        c.end_of_file,
        c.end_of_line,
        c.end_of_line2,
        c.start,
        c.stop,
        c.word_erase,
        c.literal_next,
        c.reprint,
        s.minimum_read,
    ] {
        e.u8(byte);
    }
}

fn decode_settings(d: &mut Decoder<'_>) -> Result<TerminalSettings, WireError> {
    Ok(TerminalSettings {
        input: InputFlags::from_bits(d.u16()?).ok_or(WireError::InvalidTag)?,
        output: OutputFlags::from_bits(d.u16()?).ok_or(WireError::InvalidTag)?,
        local: LocalFlags::from_bits(d.u16()?).ok_or(WireError::InvalidTag)?,
        characters: ControlCharacters {
            interrupt: d.u8()?,
            quit: d.u8()?,
            erase: d.u8()?,
            kill: d.u8()?,
            end_of_file: d.u8()?,
            end_of_line: d.u8()?,
            end_of_line2: d.u8()?,
            start: d.u8()?,
            stop: d.u8()?,
            word_erase: d.u8()?,
            literal_next: d.u8()?,
            reprint: d.u8()?,
        },
        minimum_read: d.u8()?,
    })
}

fn encode_size(e: &mut Encoder, size: WindowSize) {
    for value in [size.rows, size.columns, size.x_pixels, size.y_pixels] {
        e.u16(value);
    }
}

fn decode_size(d: &mut Decoder<'_>) -> Result<WindowSize, WireError> {
    Ok(WindowSize {
        rows: d.u16()?,
        columns: d.u16()?,
        x_pixels: d.u16()?,
        y_pixels: d.u16()?,
    })
}

pub(super) fn encode_operation(e: &mut Encoder, operation: TerminalOperation) {
    match operation {
        TerminalOperation::GetSettings => e.u8(0),
        TerminalOperation::SetSettings { settings, timing } => {
            e.u8(1);
            encode_settings(e, settings);
            e.u8(match timing {
                ChangeTiming::Now => 0,
                ChangeTiming::AfterOutput => 1,
                ChangeTiming::AfterOutputAndFlushInput => 2,
            });
        }
        TerminalOperation::GetWindowSize => e.u8(2),
        TerminalOperation::SetWindowSize(size) => {
            e.u8(3);
            encode_size(e, size);
        }
        TerminalOperation::Flush { input, output } => {
            e.u8(4);
            e.u8(u8::from(input));
            e.u8(u8::from(output));
        }
        TerminalOperation::Drain => e.u8(5),
    }
}

pub(super) fn decode_operation(d: &mut Decoder<'_>) -> Result<TerminalOperation, WireError> {
    Ok(match d.u8()? {
        0 => TerminalOperation::GetSettings,
        1 => TerminalOperation::SetSettings {
            settings: decode_settings(d)?,
            timing: match d.u8()? {
                0 => ChangeTiming::Now,
                1 => ChangeTiming::AfterOutput,
                2 => ChangeTiming::AfterOutputAndFlushInput,
                _ => return Err(WireError::InvalidTag),
            },
        },
        2 => TerminalOperation::GetWindowSize,
        3 => TerminalOperation::SetWindowSize(decode_size(d)?),
        4 => TerminalOperation::Flush {
            input: boolean(d)?,
            output: boolean(d)?,
        },
        5 => TerminalOperation::Drain,
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_response(e: &mut Encoder, result: Result<TerminalResponse, TerminalError>) {
    match result {
        Ok(TerminalResponse::Settings(settings)) => {
            e.u8(0);
            encode_settings(e, settings);
        }
        Ok(TerminalResponse::WindowSize(size)) => {
            e.u8(1);
            encode_size(e, size);
        }
        Ok(TerminalResponse::Done) => e.u8(2),
        Err(error) => {
            e.u8(3);
            e.u8(match error {
                TerminalError::NotTerminal => 0,
                TerminalError::Unsupported => 1,
                TerminalError::InvalidSettings => 2,
                TerminalError::Io => 3,
            });
        }
    }
}

pub(super) fn decode_response(
    d: &mut Decoder<'_>,
) -> Result<Result<TerminalResponse, TerminalError>, WireError> {
    Ok(match d.u8()? {
        0 => Ok(TerminalResponse::Settings(decode_settings(d)?)),
        1 => Ok(TerminalResponse::WindowSize(decode_size(d)?)),
        2 => Ok(TerminalResponse::Done),
        3 => Err(match d.u8()? {
            0 => TerminalError::NotTerminal,
            1 => TerminalError::Unsupported,
            2 => TerminalError::InvalidSettings,
            3 => TerminalError::Io,
            _ => return Err(WireError::InvalidTag),
        }),
        _ => return Err(WireError::InvalidTag),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_and_responses_round_trip_and_reject_bad_tags() {
        for operation in [
            TerminalOperation::GetSettings,
            TerminalOperation::SetSettings {
                settings: TerminalSettings::default(),
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
        ] {
            let mut e = Encoder::default();
            encode_operation(&mut e, operation);
            let bytes = e.finish();
            let mut d = Decoder::new(&bytes);
            assert_eq!(decode_operation(&mut d), Ok(operation));
            assert_eq!(d.finish(), Ok(()));
            for end in 0..bytes.len() {
                assert!(decode_operation(&mut Decoder::new(&bytes[..end])).is_err());
            }
        }
        for response in [
            Ok(TerminalResponse::Settings(TerminalSettings::default())),
            Ok(TerminalResponse::WindowSize(WindowSize::default())),
            Ok(TerminalResponse::Done),
            Err(TerminalError::NotTerminal),
            Err(TerminalError::Unsupported),
            Err(TerminalError::InvalidSettings),
            Err(TerminalError::Io),
        ] {
            let mut e = Encoder::default();
            encode_response(&mut e, response);
            let bytes = e.finish();
            assert_eq!(decode_response(&mut Decoder::new(&bytes)), Ok(response));
        }
        assert_eq!(
            decode_operation(&mut Decoder::new(&[4, 2, 0])),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_operation(&mut Decoder::new(&[255])),
            Err(WireError::InvalidTag)
        );
        let mut e = Encoder::default();
        encode_operation(
            &mut e,
            TerminalOperation::SetSettings {
                settings: TerminalSettings::default(),
                timing: ChangeTiming::Now,
            },
        );
        let mut bytes = e.finish();
        bytes[2] |= 0x80;
        assert_eq!(
            decode_operation(&mut Decoder::new(&bytes)),
            Err(WireError::InvalidTag)
        );
    }
}
