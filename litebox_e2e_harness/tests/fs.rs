// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::fs::{Mode, OFlags};
use litebox_e2e_harness::HarnessRunner;

#[test]
fn guest_writes_and_reads_back_a_file() {
    let runner = HarnessRunner::new();
    runner.run(|api| {
        let path: &[u8] = b"/tmp/hello\0";
        let data: &[u8] = b"Hello, harness!";

        let fd = api
            .open(path.as_ptr(), OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("open(O_CREAT | O_WRONLY) failed");
        let written = api
            .write(fd, data.as_ptr(), data.len())
            .expect("write failed");
        assert_eq!(written, data.len(), "write returned wrong byte count");
        api.close(fd).expect("close after write failed");

        let fd = api
            .open(path.as_ptr(), OFlags::RDONLY, Mode::empty())
            .expect("open(O_RDONLY) failed");
        let mut buf = [0u8; 32];
        let n = api
            .read(fd, buf.as_mut_ptr(), buf.len())
            .expect("read failed");
        assert_eq!(n, data.len(), "read returned wrong byte count");
        assert_eq!(&buf[..n], data, "read returned wrong bytes");
        api.close(fd).expect("close after read failed");
    });
}

#[test]

fn racing_reads_into_shared_buffer_is_ub() {
    #[derive(Copy, Clone)]
    struct SendSyncPtr(*mut u8);
    unsafe impl Send for SendSyncPtr {}
    unsafe impl Sync for SendSyncPtr {}

    let (read_buf_ptr, read_buf_len, read_buf_cap) = Vec::into_raw_parts(vec![0; 4096]);
    let read_buf_ptr_wrapped = SendSyncPtr(read_buf_ptr);

    let runner = HarnessRunner::new();
    runner.run(move |api| {
        let paths: [&'static [u8]; 2] = [b"/tmp/race_a\0", b"/tmp/race_b\0"];

        let mut payload = vec![0u8; read_buf_len];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap();
        }
        for path in paths {
            let fd = api
                .open(path.as_ptr(), OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("open(O_CREAT | O_WRONLY) failed");
            let written = api
                .write(fd, payload.as_ptr(), payload.len())
                .expect("write failed");
            assert_eq!(written, payload.len());
            api.close(fd).expect("close after seed write failed");
        }
        for path in paths {
            api.spawn_thread(move |api| {
                let read_buf_ptr_wrapped_moved = read_buf_ptr_wrapped;
                let read_buf_ptr = read_buf_ptr_wrapped_moved.0;
                let fd = api
                    .open(path.as_ptr(), OFlags::RDONLY, Mode::empty())
                    .expect("child: open(O_RDONLY) failed");
                for _ in 0..16 {
                    std::thread::yield_now();
                    let _ = api
                        .read(fd, read_buf_ptr, read_buf_len)
                        .expect("child: read failed");
                }
                api.close(fd).expect("child: close failed");
            })
            .expect("spawn_thread failed");
        }
    });

    std::mem::drop(runner);

    let _ = unsafe { Vec::from_raw_parts(read_buf_ptr, read_buf_len, read_buf_cap) };
}
