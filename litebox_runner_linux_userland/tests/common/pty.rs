// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![allow(
    dead_code,
    reason = "shared test helpers are not used by every test binary"
)]

pub struct Pty {
    master: std::fs::File,
    slave: Option<std::fs::File>,
}

impl Pty {
    pub fn open() -> Self {
        use std::os::fd::FromRawFd;

        let mut master = -1;
        let mut slave = -1;
        // SAFETY: master and slave are valid out-pointers, and the optional name/termios/winsize
        // pointers are null because the test does not need to customize the PTY.
        let rc = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "openpty failed: {}", std::io::Error::last_os_error());

        // SAFETY: master is an owned file descriptor returned by openpty above.
        let flags = unsafe { libc::fcntl(master, libc::F_GETFL) };
        assert_ne!(
            flags,
            -1,
            "fcntl(F_GETFL) failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: master is an owned file descriptor returned by openpty above, and flags were read
        // from the same descriptor.
        let rc = unsafe { libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert_eq!(
            rc,
            0,
            "fcntl(F_SETFL) failed: {}",
            std::io::Error::last_os_error()
        );

        Self {
            // SAFETY: openpty returned these owned file descriptors and they are not used elsewhere.
            master: unsafe { std::fs::File::from_raw_fd(master) },
            // SAFETY: openpty returned these owned file descriptors and they are not used elsewhere.
            slave: Some(unsafe { std::fs::File::from_raw_fd(slave) }),
        }
    }

    pub fn slave_stdio(
        &self,
    ) -> (
        std::process::Stdio,
        std::process::Stdio,
        std::process::Stdio,
    ) {
        let slave = self.slave.as_ref().expect("PTY slave is already closed");
        let stdin = slave.try_clone().expect("failed to clone pty slave");
        let stdout = slave.try_clone().expect("failed to clone pty slave");
        let stderr = slave.try_clone().expect("failed to clone pty slave");
        (
            std::process::Stdio::from(stdin),
            std::process::Stdio::from(stdout),
            std::process::Stdio::from(stderr),
        )
    }

    pub fn close_slave(&mut self) {
        drop(self.slave.take());
    }

    pub fn write_all(&mut self, bytes: &[u8]) {
        use std::io::Write;

        self.master
            .write_all(bytes)
            .expect("failed to write to pty");
    }

    pub fn wait_for_output(&mut self, output: &mut Vec<u8>, needle: &[u8]) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            self.read_available(output);
            if output.windows(needle.len()).any(|window| window == needle) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {:?}; output so far:\n{}",
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(output)
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    pub fn wait_for_child_exit(
        &mut self,
        child: &mut std::process::Child,
        output: &mut Vec<u8>,
    ) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            self.read_available(output);
            if let Some(status) = child.try_wait().expect("failed to wait for child process") {
                self.read_available(output);
                return status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "timed out waiting for child process to exit; output so far:\n{}",
                    String::from_utf8_lossy(output)
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn read_available(&mut self, output: &mut Vec<u8>) {
        use std::io::Read;

        let mut buf = [0; 4096];
        loop {
            match self.master.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) => panic!("failed to read from pty: {e}"),
            }
        }
    }
}
