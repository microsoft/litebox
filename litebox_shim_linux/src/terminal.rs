// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux terminal ABI translation. The broker owns the shared line discipline.

use litebox_broker_protocol::terminal::{
    ControlCharacters, InputFlags, LocalFlags, OutputFlags, TerminalSettings,
};
use litebox_common_linux::{Termios, errno::Errno};

const INPUT: &[(u32, InputFlags)] = &[
    (0x20, InputFlags::STRIP_HIGH_BIT),
    (0x40, InputFlags::NEWLINE_TO_CARRIAGE_RETURN),
    (0x80, InputFlags::IGNORE_CARRIAGE_RETURN),
    (0x100, InputFlags::CARRIAGE_RETURN_TO_NEWLINE),
    (0x400, InputFlags::SOFTWARE_FLOW_CONTROL),
    (0x800, InputFlags::RESTART_OUTPUT_ON_INPUT),
    (0x4000, InputFlags::UTF8_ERASE),
];
const OUTPUT: &[(u32, OutputFlags)] = &[
    (1, OutputFlags::PROCESS),
    (4, OutputFlags::NEWLINE_TO_CRLF),
    (8, OutputFlags::CARRIAGE_RETURN_TO_NEWLINE),
    (0x10, OutputFlags::OMIT_CARRIAGE_RETURN_AT_COLUMN_ZERO),
    (0x20, OutputFlags::NEWLINE_RETURNS_CARRIAGE),
];
const LOCAL: &[(u32, LocalFlags)] = &[
    (1, LocalFlags::GENERATE_EVENTS),
    (2, LocalFlags::CANONICAL),
    (8, LocalFlags::ECHO),
    (0x10, LocalFlags::ECHO_ERASE),
    (0x20, LocalFlags::ECHO_KILL),
    (0x40, LocalFlags::ECHO_NEWLINE),
    (0x80, LocalFlags::NO_FLUSH_ON_EVENT),
    (0x200, LocalFlags::ECHO_CONTROL),
    (0x800, LocalFlags::ECHO_KILL_ERASE),
    (0x8000, LocalFlags::EXTENDED_EDITING),
];
// The virtual endpoint transports eight-bit bytes, not a configurable UART:
// CS8 | CREAD | B38400. Hardware configuration is deliberately unsupported.
const CONTROL: u32 = 0x30 | 0x80 | 0xf;

pub(crate) fn to_linux(settings: TerminalSettings) -> Termios {
    let c = settings.characters;
    Termios {
        c_iflag: INPUT
            .iter()
            .filter(|(_, f)| settings.input.contains(*f))
            .map(|(b, _)| *b)
            .sum(),
        c_oflag: OUTPUT
            .iter()
            .filter(|(_, f)| settings.output.contains(*f))
            .map(|(b, _)| *b)
            .sum(),
        c_lflag: LOCAL
            .iter()
            .filter(|(_, f)| settings.local.contains(*f))
            .map(|(b, _)| *b)
            .sum(),
        c_cflag: CONTROL,
        c_line: 0,
        c_cc: [
            c.interrupt,
            c.quit,
            c.erase,
            c.kill,
            c.end_of_file,
            0,
            settings.minimum_read,
            0,
            c.start,
            c.stop,
            0,
            c.end_of_line,
            c.reprint,
            0,
            c.word_erase,
            c.literal_next,
            c.end_of_line2,
            0,
            0,
        ],
    }
}

pub(crate) fn from_linux(termios: &Termios) -> Result<TerminalSettings, Errno> {
    if termios.c_line != 0
        || termios.c_cflag != CONTROL
        || termios.c_iflag & !INPUT.iter().map(|(b, _)| *b).sum::<u32>() != 0
        || termios.c_oflag & !OUTPUT.iter().map(|(b, _)| *b).sum::<u32>() != 0
        || termios.c_lflag & !LOCAL.iter().map(|(b, _)| *b).sum::<u32>() != 0
        || [5, 7, 10, 13, 17, 18]
            .iter()
            .any(|&index| termios.c_cc[index] != 0)
        || termios.c_cc[6] > 1
    {
        log_unsupported!("terminal settings {:?}", termios);
        return Err(Errno::EINVAL);
    }
    let mut input = InputFlags::empty();
    let mut output = OutputFlags::empty();
    let mut local = LocalFlags::empty();
    for &(bit, flag) in INPUT {
        if termios.c_iflag & bit != 0 {
            input |= flag;
        }
    }
    for &(bit, flag) in OUTPUT {
        if termios.c_oflag & bit != 0 {
            output |= flag;
        }
    }
    for &(bit, flag) in LOCAL {
        if termios.c_lflag & bit != 0 {
            local |= flag;
        }
    }
    let c = termios.c_cc;
    Ok(TerminalSettings {
        input,
        output,
        local,
        characters: ControlCharacters {
            interrupt: c[0],
            quit: c[1],
            erase: c[2],
            kill: c[3],
            end_of_file: c[4],
            start: c[8],
            stop: c[9],
            end_of_line: c[11],
            reprint: c[12],
            word_erase: c[14],
            literal_next: c[15],
            end_of_line2: c[16],
        },
        minimum_read: c[6],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_settings_round_trip() {
        let settings = TerminalSettings::default();
        assert_eq!(from_linux(&to_linux(settings)), Ok(settings));
        let mut raw = to_linux(settings);
        raw.c_iflag = 0;
        raw.c_oflag = 0;
        raw.c_lflag = 0;
        assert!(from_linux(&raw).is_ok());
    }

    #[test]
    fn unsupported_modes_are_not_silently_accepted() {
        for (index, value) in [(5, 1), (6, 2), (10, 26), (13, 15)] {
            let mut settings = to_linux(TerminalSettings::default());
            settings.c_cc[index] = value;
            assert_eq!(from_linux(&settings), Err(Errno::EINVAL));
        }
        let mut settings = to_linux(TerminalSettings::default());
        settings.c_lflag |= 0x100; // TOSTOP requires job control.
        assert_eq!(from_linux(&settings), Err(Errno::EINVAL));
    }
}
