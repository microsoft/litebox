// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Standard input/output streams.

#[cfg(test)]
mod tests {
    extern crate std;

    use core::{ffi::CStr, time::Duration};

    use litebox::event::Events;
    use litebox_broker_protocol::fs::FileMode as Mode;
    use litebox_common_linux::{
        EpollCreateFlags, EpollEvent, EpollOp, FcntlArg, FileDescriptorFlags, IoctlArg, OFlags,
        Termios, errno::Errno,
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
            ("/dev/stderr", OFlags::WRONLY, Err(Errno::ENOTTY)),
            ("/dev/./stdout", OFlags::WRONLY, Ok(0)),
        ] {
            let fd = i32::try_from(task.sys_open(path, flags, Mode::empty()).unwrap()).unwrap();
            assert_eq!(
                task.sys_ioctl(fd, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios)),),
                expected
            );
        }
    }

    /// Pushes `input` to standard input after the caller has had time to start waiting.
    fn push_input_later(input: &'static [u8]) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            test_broker::stdio().push_input(input);
        })
    }

    #[test]
    fn test_stdin_read_waits_for_input() {
        let task = init_platform();
        let input = push_input_later(b"hi");

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
        let writes = test_broker::stdio().writes();
        assert!(writes.len() > 1);
        assert_eq!(
            writes.iter().map(|(_, bytes)| bytes.len()).sum::<usize>(),
            len
        );
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
        assert!(wait(0).is_empty());

        let input = push_input_later(b"x");
        assert_eq!(wait(-1), [(0, Events::IN.bits())]);
        input.join().unwrap();

        let mut buf = [0; 1];
        assert_eq!(task.sys_read(0, &mut buf, None), Ok(1));
        add(1, Events::IN | Events::OUT).unwrap();
        assert_eq!(wait(0), [(1, Events::OUT.bits())]);
    }
}
