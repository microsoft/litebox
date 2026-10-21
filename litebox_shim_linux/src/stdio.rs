// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Standard input/output streams.

use litebox_broker_protocol::fs::{FileAccessMode, FileMode as Mode, FileOpenFlags};

use crate::syscalls::file::{FileSubsystem, FilesState};
use crate::{GlobalState, ShimPlatform};

impl<Platform: ShimPlatform> FilesState<Platform> {
    pub(crate) fn initialize_stdio_in_shared_descriptors_table(
        &self,
        global: &GlobalState<Platform>,
        context: &litebox::fs::Context,
    ) {
        let stdin = global
            .litebox
            .open_file(
                context,
                "/dev/stdin",
                FileAccessMode::ReadOnly,
                FileOpenFlags::NONE,
                Mode::empty(),
            )
            .unwrap();
        let stdout = global
            .litebox
            .open_file(
                context,
                "/dev/stdout",
                FileAccessMode::WriteOnly,
                FileOpenFlags::NONE,
                Mode::empty(),
            )
            .unwrap();
        let stderr = global
            .litebox
            .open_file(
                context,
                "/dev/stderr",
                FileAccessMode::WriteOnly,
                FileOpenFlags::NONE,
                Mode::empty(),
            )
            .unwrap();
        let mut rds = self.raw_descriptor_store.write();
        for (raw_fd, file) in [(0, stdin), (1, stdout), (2, stderr)] {
            let fd = global
                .litebox
                .descriptor_table_mut()
                .insert::<FileSubsystem<Platform>>(file);
            let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
            assert!(success);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ffi::CStr;

    use litebox::event::Events;
    use litebox_broker_protocol::fs::FileMode as Mode;
    use litebox_broker_protocol::terminal::TerminalSettings;
    use litebox_common_linux::{
        EpollCreateFlags, EpollEvent, EpollOp, FcntlArg, FileDescriptorFlags, IoctlArg, OFlags,
        Termios, Termios2, Winsize, errno::Errno,
    };

    use crate::{
        UserPtr, UserPtrMut,
        syscalls::{test_broker, tests::init_platform},
    };

    fn termios() -> Termios {
        Termios {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; 19],
        }
    }

    #[test]
    fn test_stdio() {
        let task = init_platform();

        // Check that the stdio streams are in the file table
        let stdin_stat = task.sys_fstat(0).unwrap();
        let stdout_stat = task.sys_fstat(1).unwrap();
        let stderr_stat = task.sys_fstat(2).unwrap();

        // Check that the stdio stat are consistent
        let stdin = task
            .sys_open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let stdout = task
            .sys_open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let stderr = task
            .sys_open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .unwrap();
        assert_eq!(
            stdin_stat,
            task.sys_fstat(i32::try_from(stdin).unwrap()).unwrap()
        );
        assert_eq!(
            stdout_stat,
            task.sys_fstat(i32::try_from(stdout).unwrap()).unwrap()
        );
        assert_eq!(
            stderr_stat,
            task.sys_fstat(i32::try_from(stderr).unwrap()).unwrap()
        );

        // test sys_stat is working with symbolic links
        assert_eq!(task.sys_stat("/proc/self/fd/0").unwrap(), stdin_stat);
        assert_eq!(task.sys_stat("/proc/self/fd/1").unwrap(), stdout_stat);
        assert_eq!(task.sys_stat("/proc/self/fd/2").unwrap(), stderr_stat);

        let mut buf: [u8; 128] = [0; 128];
        let size = task.sys_readlink("/proc/self/fd/0", &mut buf).unwrap();
        assert_eq!("/dev/stdin", core::str::from_utf8(&buf[..size]).unwrap());
        let size = task.sys_readlink("/proc/self/fd/1", &mut buf).unwrap();
        assert_eq!("/dev/stdout", core::str::from_utf8(&buf[..size]).unwrap());
        let size = task.sys_readlink("/proc/self/fd/2", &mut buf).unwrap();
        assert_eq!("/dev/stderr", core::str::from_utf8(&buf[..size]).unwrap());
    }

    #[test]
    fn test_stdio_flags_with_dup() {
        let task = init_platform();

        let stdin = 0;
        let flags = task.sys_fcntl(stdin, FcntlArg::GETFL).unwrap();

        let stdin2 = i32::try_from(task.sys_dup(stdin, None, None).unwrap()).unwrap();
        assert_eq!(flags, task.sys_fcntl(stdin2, FcntlArg::GETFL).unwrap());

        let mut stdio_path: [u8; 32] = [0; 32];
        task.sys_readlink("/proc/self/fd/0", &mut stdio_path)
            .expect("Failed to read link");
        let path =
            CStr::from_bytes_until_nul(stdio_path.as_slice()).expect("Failed to convert to CStr");
        let stdin3 = i32::try_from(
            task.sys_open(path.to_str().unwrap(), OFlags::RDONLY, Mode::empty())
                .expect("Failed to open stdin"),
        )
        .expect("Failed to convert to i32");
        let stdin3_flags = task.sys_fcntl(stdin3, FcntlArg::GETFL).unwrap();

        // duplicated fd shares the same status flags while the newly-opened file does not
        // (even though they point to the same file)
        let new_flags = flags | OFlags::NONBLOCK.bits();
        task.sys_fcntl(
            stdin2,
            FcntlArg::SETFL(OFlags::from_bits(new_flags).unwrap()),
        )
        .expect("Failed to set flags");
        assert_eq!(new_flags, task.sys_fcntl(stdin2, FcntlArg::GETFL).unwrap());
        assert_eq!(new_flags, task.sys_fcntl(stdin, FcntlArg::GETFL).unwrap());
        // not affected by the `SETFL` above
        assert_eq!(
            stdin3_flags,
            task.sys_fcntl(stdin3, FcntlArg::GETFL).unwrap()
        );

        // duplicated fd does not share the same close-on-exec flag
        task.sys_fcntl(stdin, FcntlArg::SETFD(FileDescriptorFlags::FD_CLOEXEC))
            .expect("Failed to set close-on-exec flag");
        assert_eq!(
            FileDescriptorFlags::FD_CLOEXEC.bits(),
            task.sys_fcntl(stdin, FcntlArg::GETFD).unwrap()
        );
        assert_eq!(
            FileDescriptorFlags::empty().bits(),
            task.sys_fcntl(stdin2, FcntlArg::GETFD).unwrap()
        );
        assert_eq!(
            FileDescriptorFlags::empty().bits(),
            task.sys_fcntl(stdin3, FcntlArg::GETFD).unwrap()
        );
    }

    #[test]
    fn test_stdio_terminal_query_uses_broker() {
        let task = init_platform();
        let mut termios = termios();

        assert_eq!(
            task.sys_ioctl(1, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios)),),
            Ok(0)
        );
        assert_eq!(
            task.sys_ioctl(0, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios)),),
            Err(Errno::ENOTTY)
        );

        for (path, flags, expected) in [
            ("/dev/stdin", OFlags::RDONLY, Err(Errno::ENOTTY)),
            ("/dev/stdout", OFlags::WRONLY, Ok(0)),
            ("/dev/stdout", OFlags::RDONLY, Ok(0)),
            ("/dev/stderr", OFlags::WRONLY, Ok(0)),
            ("/dev/./stdout", OFlags::WRONLY, Ok(0)),
        ] {
            let fd = i32::try_from(task.sys_open(path, flags, Mode::empty()).unwrap()).unwrap();
            assert_eq!(
                task.sys_ioctl(fd, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios)),),
                expected
            );
            // Like Linux, a change needs only an open descriptor, whatever its access mode.
            assert_eq!(task.sys_ioctl(fd, IoctlArg::TCFLSH(0)), expected);
        }

        let path = i32::try_from(
            task.sys_open("/dev/stdout", OFlags::PATH, Mode::empty())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            task.sys_ioctl(
                path,
                IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios))
            ),
            Err(Errno::EBADF)
        );
        assert_eq!(task.sys_ioctl(path, IoctlArg::FIOCLEX), Err(Errno::EBADF));

        // Like Linux, the descriptor is checked before the request's argument.
        for (fd, expected) in [
            (1, Errno::EINVAL),
            (2, Errno::EINVAL),
            (0, Errno::ENOTTY),
            (path, Errno::EBADF),
        ] {
            assert_eq!(task.sys_ioctl(fd, IoctlArg::TCFLSH(3)), Err(expected));
        }

        // A terminal the broker cannot take over keeps default settings and an unknown size.
        let mut raw = Termios::from(TerminalSettings::default());
        raw.c_lflag = 0;
        assert_eq!(
            task.sys_ioctl(2, IoctlArg::TCSETS(UserPtr::from_ptr(&raw mut raw))),
            Ok(0)
        );
        assert_eq!(
            task.sys_ioctl(2, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios))),
            Ok(0)
        );
        assert_eq!(
            TerminalSettings::try_from(&termios),
            Ok(TerminalSettings::default())
        );
        let mut size = Winsize {
            row: 1,
            col: 1,
            xpixel: 1,
            ypixel: 1,
        };
        assert_eq!(
            task.sys_ioctl(2, IoctlArg::TIOCGWINSZ(UserPtrMut::from_ptr(&raw mut size))),
            Ok(0)
        );
        assert_eq!((size.row, size.col), (0, 0));
    }

    #[test]
    fn test_stdio_termios2_matches_termios() {
        let task = init_platform();
        let mut termios2 = Termios2 {
            termios: termios(),
            c_ispeed: 0,
            c_ospeed: 0,
        };
        let mut termios = termios();
        assert_eq!(
            task.sys_ioctl(
                1,
                IoctlArg::TCGETS2(UserPtrMut::from_ptr(&raw mut termios2))
            ),
            Ok(0)
        );
        assert_eq!((termios2.c_ispeed, termios2.c_ospeed), (38400, 38400));
        assert_eq!(
            task.sys_ioctl(1, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios))),
            Ok(0)
        );
        assert_eq!(
            TerminalSettings::try_from(&termios2),
            TerminalSettings::try_from(&termios)
        );

        // Like glibc 2.42's `tcsetattr`, set the input speed explicitly.
        termios2.termios.c_cflag |= 0xf << 16;
        termios2.termios.c_lflag &= !0x8; // ECHO
        assert_eq!(
            task.sys_ioctl(
                1,
                IoctlArg::TCSETSW2(UserPtr::from_ptr(&raw const termios2))
            ),
            Ok(0)
        );
        assert_eq!(
            task.sys_ioctl(1, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios))),
            Ok(0)
        );
        assert_eq!(termios.c_lflag & 0x8, 0);
        assert_eq!(
            task.sys_ioctl(
                0,
                IoctlArg::TCGETS2(UserPtrMut::from_ptr(&raw mut termios2))
            ),
            Err(Errno::ENOTTY)
        );
    }

    #[test]
    fn test_dev_tty_reaches_the_controlling_terminal() {
        let task = init_platform();
        let tty = i32::try_from(
            task.sys_open("/dev/tty", OFlags::RDWR, Mode::empty())
                .unwrap(),
        )
        .unwrap();
        let rdev = task.sys_fstat(tty).unwrap().st_rdev;
        assert_eq!(rdev, 0x500);

        // The controlling terminal is the one behind standard output.
        let mut tty_termios = termios();
        assert_eq!(
            task.sys_ioctl(
                tty,
                IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut tty_termios))
            ),
            Ok(0)
        );
        tty_termios.c_lflag &= !0x8; // ECHO
        assert_eq!(
            task.sys_ioctl(
                tty,
                IoctlArg::TCSETS(UserPtr::from_ptr(&raw const tty_termios))
            ),
            Ok(0)
        );
        let mut stdout_termios = termios();
        assert_eq!(
            task.sys_ioctl(
                1,
                IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut stdout_termios))
            ),
            Ok(0)
        );
        assert_eq!(stdout_termios.c_lflag & 0x8, 0);

        assert_eq!(task.sys_write(tty, b"prompt", None), Ok(6));
        assert_eq!(
            test_broker::stdio()
                .terminal_writes()
                .last()
                .map(std::vec::Vec::as_slice),
            Some(&b"prompt"[..])
        );
        test_broker::stdio().push_terminal_input(b"x");
        let mut buf = [0; 4];
        assert_eq!(task.sys_read(tty, &mut buf, None), Ok(1));
        assert_eq!(buf[0], b'x');
    }

    #[test]
    fn test_unknown_ioctl_fails_with_enotty() {
        let task = init_platform();
        let mut byte = 0u8;
        let mut unknown = || IoctlArg::Raw {
            cmd: 0x54ff,
            arg: UserPtrMut::from_ptr(&raw mut byte),
        };
        let (pipe, _writer) = task.sys_pipe2(OFlags::empty()).unwrap();
        let path = task
            .sys_open("/dev/stdout", OFlags::PATH, Mode::empty())
            .unwrap();
        // Like Linux, the descriptor is checked before the request.
        for (fd, expected) in [
            (0, Errno::ENOTTY),
            (1, Errno::ENOTTY),
            (i32::try_from(pipe).unwrap(), Errno::ENOTTY),
            (i32::try_from(path).unwrap(), Errno::EBADF),
            (99, Errno::EBADF),
            (-1, Errno::EBADF),
        ] {
            assert_eq!(task.sys_ioctl(fd, unknown()), Err(expected));
        }
    }

    #[test]
    fn test_open_devices_nonblocking() {
        let task = init_platform();
        for (path, access) in [
            ("/dev/stdin", OFlags::RDONLY),
            ("/dev/stdout", OFlags::WRONLY),
            ("/dev/stderr", OFlags::WRONLY),
            ("/dev/urandom", OFlags::RDONLY),
        ] {
            let fd = i32::try_from(
                task.sys_open(path, access | OFlags::NONBLOCK, Mode::empty())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                task.sys_fcntl(fd, FcntlArg::GETFL),
                Ok((access | OFlags::NONBLOCK).bits())
            );
            task.sys_close(fd).unwrap();
        }

        let fd = i32::try_from(
            task.sys_open(
                "/dev/stdin",
                OFlags::RDONLY | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut buf = [0; 1];
        assert_eq!(task.sys_read(fd, &mut buf, None), Err(Errno::EAGAIN));
        // Standard input opened at startup is a different open file description.
        assert_eq!(
            task.sys_fcntl(0, FcntlArg::GETFL),
            Ok(OFlags::RDONLY.bits())
        );
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_stdin_read_waits_for_input() {
        let task = init_platform();
        let reads = test_broker::stdio().blocked_input_reads();
        // The reader reads again after it starts listening for input, so pushing input once
        // its first read has blocked tests the wait without depending on timing.
        let input = std::thread::spawn(move || {
            while test_broker::stdio().blocked_input_reads() == reads {
                std::thread::yield_now();
            }
            test_broker::stdio().push_input(b"hi");
        });

        let mut buf = [0; 4];
        assert_eq!(task.sys_read(0, &mut buf, None), Ok(2));
        assert_eq!(&buf[..2], b"hi");
        input.join().unwrap();
    }

    #[test]
    fn test_stdin_nonblocking_read() {
        let task = init_platform();
        let mut buf = [0; 4];
        let flags = OFlags::from_bits_retain(task.sys_fcntl(0, FcntlArg::GETFL).unwrap());

        task.sys_fcntl(0, FcntlArg::SETFL(flags | OFlags::NONBLOCK))
            .unwrap();
        assert_eq!(task.sys_read(0, &mut buf, None), Err(Errno::EAGAIN));

        let disable = 0i32;
        let arg = IoctlArg::FIONBIO(UserPtr::from_usize(&raw const disable as usize));
        assert_eq!(task.sys_ioctl(0, arg), Ok(0));
        assert_eq!(task.sys_fcntl(0, FcntlArg::GETFL), Ok(flags.bits()));

        let enable = 1i32;
        let arg = IoctlArg::FIONBIO(UserPtr::from_usize(&raw const enable as usize));
        assert_eq!(task.sys_ioctl(0, arg), Ok(0));
        assert_eq!(task.sys_read(0, &mut buf, None), Err(Errno::EAGAIN));

        test_broker::stdio().push_input(b"x");
        assert_eq!(task.sys_read(0, &mut buf, None), Ok(1));
        assert_eq!(buf[0], b'x');
        assert_eq!(task.sys_read(0, &mut buf, None), Err(Errno::EAGAIN));
    }

    #[test]
    fn test_stdout_blocking_write_is_complete() {
        let task = init_platform();
        let len = usize::try_from(litebox_broker_protocol::fs::MAX_FILE_TRANSFER_SIZE).unwrap() + 1;
        let buf = std::vec![b'x'; len];

        assert_eq!(task.sys_write(1, &buf, None), Ok(len));
        let writes = test_broker::stdio().terminal_writes();
        assert!(writes.len() > 1);
        assert_eq!(writes.iter().map(std::vec::Vec::len).sum::<usize>(), len);
    }

    #[test]
    fn test_stdio_epoll_readiness() {
        let task = init_platform();
        let epfd =
            i32::try_from(task.sys_epoll_create(EpollCreateFlags::empty()).unwrap()).unwrap();
        let add = |fd: i32, events: Events| {
            let event = EpollEvent::new(events.bits(), u64::try_from(fd).unwrap());
            task.sys_epoll_ctl(
                epfd,
                EpollOp::EpollCtlAdd,
                fd,
                UserPtr::from_usize(&raw const event as usize),
            )
        };
        let wait = |timeout: i32| {
            let mut events = [EpollEvent::new(0, 0); 2];
            let ready = task
                .sys_epoll_pwait(
                    epfd,
                    UserPtrMut::from_usize(events.as_mut_ptr() as usize),
                    2,
                    timeout,
                    None,
                    0,
                )
                .unwrap();
            events[..ready]
                .iter()
                .map(|event| (event.data, event.events))
                .collect::<std::vec::Vec<_>>()
        };

        add(0, Events::IN).unwrap();
        assert_eq!(wait(0), []);

        test_broker::stdio().push_input(b"x");
        assert_eq!(wait(-1), [(0, Events::IN.bits())]);

        let mut buf = [0; 1];
        assert_eq!(task.sys_read(0, &mut buf, None), Ok(1));
        add(1, Events::IN | Events::OUT).unwrap();
        assert_eq!(wait(0), [(1, Events::OUT.bits())]);
    }
}
