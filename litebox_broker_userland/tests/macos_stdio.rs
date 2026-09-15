// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    macos::run();
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos {
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_POOL_SIZE, SharedBufferSequence, SharedBufferSlotIndex,
    };
    use litebox_broker_protocol::stdio::{StdioOutputStream, StdioStream};
    use litebox_broker_transport::control_ring::ControlRing;
    use litebox_broker_transport_macos_userland::unix_socket::UnixStreamLocalSetupChannel;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const STDERR: &[u8] = b"broker stderr\0\xff\n";

    pub fn run() {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.first().is_some_and(|arg| arg == "--unstable") {
            child(&args);
        } else {
            rejects_networking_permissions();
            for sandboxed in [false, true] {
                parent(sandboxed);
            }
            disconnect_parent();
            for program in ["hello_world_dyn", "hello_thread"] {
                guest_parent(program);
            }
            let rejected = Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
                .args(["-Z", "--in-process-runner", "guest"])
                .output()
                .unwrap();
            assert!(!rejected.status.success());
            assert!(String::from_utf8_lossy(&rejected.stderr).contains("separate broker process"));
        }
    }

    fn rejects_networking_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let missing_runner = directory.path().join("missing-runner");
        let cases: &[&[&str]] = &[
            &["--allow-tcp-destination", "127.0.0.0/8:80"],
            &["--allow-udp-destination", "127.0.0.0/8:53"],
            &[
                "--allow-tcp-destination",
                "127.0.0.0/8:80",
                "--allow-udp-destination",
                "127.0.0.0/8:53",
            ],
        ];
        for permissions in cases {
            let output = Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
                .args(*permissions)
                .arg("--runner")
                .arg(&missing_runner)
                .arg("guest")
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            let error = String::from_utf8_lossy(&output.stderr);
            // A nonexistent runner makes this fail if validation is deferred
            // until after spawn, rather than rejecting the permissions first.
            assert!(
                error.contains("the macOS broker does not support host networking"),
                "{permissions:?}: {error}"
            );
            assert!(output.stdout.is_empty());
        }
    }

    struct Guard(Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    fn parent(sandboxed: bool) {
        let mut broker = Guard(
            Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
                .arg("--runner")
                .arg(std::env::current_exe().unwrap())
                .arg(if sandboxed { "seatbelt" } else { "plain" })
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let input: Vec<u8> = (0..200_000)
            .map(|n| u8::try_from(n % 256).unwrap())
            .collect();
        let sent = input.clone();
        let mut stdin = broker.0.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            stdin.write_all(&sent).unwrap();
        });
        let mut stdout = broker.0.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let mut stderr = broker.0.stderr.take().unwrap();
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = broker.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "broker/runner hung (seatbelt={sandboxed})"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let stderr = errors.join().unwrap();
        assert!(
            status.success(),
            "broker failed (seatbelt={sandboxed}): {}",
            String::from_utf8_lossy(&stderr)
        );
        writer.join().unwrap();
        assert_eq!(reader.join().unwrap(), input);
        assert_eq!(stderr, STDERR);
    }

    fn disconnect_parent() {
        let mut broker = Guard(
            Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
                .arg("--runner")
                .arg(std::env::current_exe().unwrap())
                .arg("disconnect")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        // Keep stdin open without writing: a broker blocked reading the host
        // stream must still shut down when its child disappears.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = broker.0.try_wait().unwrap() {
                let mut error = String::new();
                broker
                    .0
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut error)
                    .unwrap();
                // A cancelled read may race with the final response send. An
                // explicit closed-peer error is expected; hanging on stdin is not.
                assert!(
                    status.success()
                        || (status.code() == Some(1)
                            && error.contains("runner closed the active broker association")),
                    "unexpected broker failure after disconnect: {error}"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "runner disconnect did not cancel stdin"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn guest_parent(program: &str) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("root");
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../litebox_runner_linux_on_macos_userland/tests/test-bins");
        for (source, destination) in [
            (program, format!("bin/{program}")),
            ("ld-linux-aarch64.so.1", "lib/ld-linux-aarch64.so.1".into()),
            ("libc.so.6", "lib/aarch64-linux-gnu/libc.so.6".into()),
        ] {
            let destination = root.join(destination);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::copy(fixtures.join(source), destination).unwrap();
        }
        let archive = directory.path().join("root.tar");
        assert!(
            Command::new("tar")
                .env("COPYFILE_DISABLE", "1")
                .args(["--format=ustar", "-cf"])
                .arg(&archive)
                .arg("-C")
                .arg(&root)
                .args(["bin", "lib"])
                .status()
                .unwrap()
                .success()
        );
        let mut broker = Guard(
            Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
                .arg("--fs-initial-files")
                .arg(archive)
                .arg("--runner")
                .arg(std::env::current_exe().unwrap())
                .arg("guest")
                .arg(format!("/bin/{program}"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = broker.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "guest {program} hung");
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = String::new();
        broker
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        let mut stderr = String::new();
        broker
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(status.success(), "guest {program} failed: {stderr}");
        assert!(stderr.is_empty(), "{stderr}");
        if program == "hello_world_dyn" {
            assert!(
                stdout.contains("argv[0] = /bin/hello_world_dyn"),
                "{stdout}"
            );
            assert!(
                stdout.contains("envp[0] = LD_LIBRARY_PATH=/lib/aarch64-linux-gnu"),
                "{stdout}"
            );
        } else {
            assert!(stdout.contains("Hello from thread"), "{stdout}");
            assert!(stdout.contains("All threads finished!"), "{stdout}");
        }
    }

    fn sequence(length: usize) -> SharedBufferSequence {
        SharedBufferSequence::new(&[SharedBufferSlotIndex(0)], length.try_into().unwrap()).unwrap()
    }

    fn child(args: &[std::ffi::OsString]) {
        assert_eq!(args[1], "--broker-control-channel");
        let directory = std::path::Path::new(&args[2]).parent().unwrap();
        assert_eq!(
            std::fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        if args[3] == "guest" {
            let code = litebox_runner_linux_on_macos_userland::run(
                litebox_runner_linux_on_macos_userland::CliArgs {
                    program_and_arguments: vec![args[4].to_str().unwrap().to_owned()],
                    environment_variables: vec!["LD_LIBRARY_PATH=/lib/aarch64-linux-gnu".into()],
                    forward_environment_variables: false,
                    unstable: true,
                    broker_control_channel: Some(args[2].clone().into()),
                },
            )
            .unwrap();
            std::process::exit(code);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let setup = UnixStreamLocalSetupChannel::connect_with_setup_deadline(
            std::path::Path::new(&args[2]),
            deadline,
        )
        .unwrap();
        let (local, ()) = BrokerLocal::negotiate(setup, |mut setup| {
            let pool = setup.receive_shared_memory(SHARED_BUFFER_POOL_SIZE, Some(deadline))?;
            let control = setup.receive_control_ring(Some(deadline))?;
            // The actual untrusted child receives writable descriptors. Verify
            // it cannot shrink either broker-owned mapping, even before Seatbelt.
            for memory in [&pool, &control] {
                let file = std::fs::File::from(memory.as_fd().try_clone_to_owned()?);
                assert!(file.set_len(0).is_err());
                assert!(file.set_len(64 * 1024 * 1024).is_err());
            }
            let ring =
                ControlRing::new(control).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
            let (calls, _notifications, _shutdown) = setup.into_active(ring, || {})?;
            Ok((calls, Arc::new(pool), ()))
        })
        .unwrap();

        if args[3] == "disconnect" {
            std::thread::spawn(move || {
                let _ = local.read_stdio(sequence(1), &mut [0]);
            });
            std::thread::sleep(Duration::from_millis(100));
            std::process::exit(0);
        }
        if args[3] == "seatbelt" {
            confine();
        }
        // Direct standard descriptors are /dev/null, not the host streams.
        assert_eq!(std::io::stdin().read(&mut [0]).unwrap(), 0);
        std::io::stdout()
            .write_all(b"must not escape through inherited stdout")
            .ok();
        for stream in [StdioStream::Stdin, StdioStream::Stdout, StdioStream::Stderr] {
            assert!(!local.is_stdio_terminal(stream).unwrap());
        }
        assert_eq!(local.read_stdio(sequence(0), &mut []).unwrap(), 0);
        assert_eq!(
            local
                .write_stdio(StdioOutputStream::Stdout, sequence(0), &[])
                .unwrap(),
            0
        );
        let mut buffer = [0; 3333];
        loop {
            let count = local
                .read_stdio(sequence(buffer.len()), &mut buffer)
                .unwrap();
            if count == 0 {
                break;
            }
            let mut remaining = &buffer[..count];
            while !remaining.is_empty() {
                let written = local
                    .write_stdio(
                        StdioOutputStream::Stdout,
                        sequence(remaining.len()),
                        remaining,
                    )
                    .unwrap();
                assert!(written > 0);
                remaining = &remaining[written..];
            }
        }
        assert_eq!(local.read_stdio(sequence(1), &mut [0]).unwrap(), 0);
        assert_eq!(
            local
                .write_stdio(StdioOutputStream::Stderr, sequence(STDERR.len()), STDERR)
                .unwrap(),
            STDERR.len()
        );
        drop(local);
    }

    fn confine() {
        unsafe extern "C" {
            fn sandbox_init(
                profile: *const std::ffi::c_char,
                flags: u64,
                error: *mut *mut std::ffi::c_char,
            ) -> i32;
            fn sandbox_free_error(error: *mut std::ffi::c_char);
        }
        // This test profile is deliberately not a production guest policy. It
        // proves that already-negotiated stdio needs no host file/network access.
        let profile =
            c"(version 1)(deny default)(allow file-read* file-write* (literal \"/dev/null\"))";
        let mut error = std::ptr::null_mut();
        // SAFETY: profile is a NUL-terminated literal and error is writable storage.
        let result = unsafe { sandbox_init(profile.as_ptr(), 0, &raw mut error) };
        if result != 0 {
            let message = if error.is_null() {
                "unknown Seatbelt error".into()
            } else {
                // SAFETY: sandbox_init returned an allocated error string.
                let message = unsafe { std::ffi::CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { sandbox_free_error(error) };
                message
            };
            panic!("sandbox_init failed: {message}");
        }
        assert!(std::fs::File::open("/etc/hosts").is_err());
        assert!(std::net::TcpListener::bind("127.0.0.1:0").is_err());
    }
}
