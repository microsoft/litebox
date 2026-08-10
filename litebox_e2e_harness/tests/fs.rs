// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tests exercising the harness's Linux-like file I/O syscalls
//! (`open`/`close`/`read`/`write`) end-to-end through the LiteBox core's
//! in-memory file system.

use litebox::fs::{Mode, OFlags};
use litebox_e2e_harness::HarnessRunner;

#[test]
fn guest_writes_and_reads_back_a_file() {
    const PATH_OFFSET: usize = 0x100;
    const DATA_OFFSET: usize = 0x200;
    const READ_OFFSET: usize = 0x300;
    const PATH: &[u8] = b"/tmp/hello\0";
    const DATA: &[u8] = b"Hello, harness!";

    let mut image = vec![0; 0x400];
    image[PATH_OFFSET..PATH_OFFSET + PATH.len()].copy_from_slice(PATH);
    image[DATA_OFFSET..DATA_OFFSET + DATA.len()].copy_from_slice(DATA);

    let runner = HarnessRunner::with_process_memory(image);
    runner.run(|api| {
        let path = api.process_pointer::<i8>(PATH_OFFSET);
        let data = api.process_pointer::<u8>(DATA_OFFSET);
        let read = api.process_pointer::<u8>(READ_OFFSET);

        let fd = api
            .open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("open(O_CREAT | O_WRONLY) failed");
        let written = api.write(fd, data, DATA.len()).expect("write failed");
        assert_eq!(written, DATA.len(), "write returned wrong byte count");
        api.close(fd).expect("close after write failed");

        let fd = api
            .open(path, OFlags::RDONLY, Mode::empty())
            .expect("open(O_RDONLY) failed");
        let n = api.read(fd, read, 32).expect("read failed");
        assert_eq!(n, DATA.len(), "read returned wrong byte count");
        assert!(
            api.memory_matches(read, &DATA[..n]),
            "read returned wrong bytes"
        );
        api.close(fd).expect("close after read failed");
    });
}

#[test]
fn concurrent_reads_share_process_memory() {
    const PATH_A_OFFSET: usize = 0x100;
    const PATH_B_OFFSET: usize = 0x120;
    const PAYLOAD_OFFSET: usize = 0x1000;
    const READ_OFFSET: usize = 0x3000;
    const PAYLOAD_LEN: usize = 4096;
    const PATH_A: &[u8] = b"/tmp/race_a\0";
    const PATH_B: &[u8] = b"/tmp/race_b\0";

    let mut image = vec![0; 0x4000];
    image[PATH_A_OFFSET..PATH_A_OFFSET + PATH_A.len()].copy_from_slice(PATH_A);
    image[PATH_B_OFFSET..PATH_B_OFFSET + PATH_B.len()].copy_from_slice(PATH_B);
    for (i, byte) in image[PAYLOAD_OFFSET..PAYLOAD_OFFSET + PAYLOAD_LEN]
        .iter_mut()
        .enumerate()
    {
        *byte = u8::try_from(i & 0xff).unwrap();
    }

    let runner = HarnessRunner::with_process_memory(image);
    runner.run(move |api| {
        let paths = [
            api.process_pointer::<i8>(PATH_A_OFFSET),
            api.process_pointer::<i8>(PATH_B_OFFSET),
        ];
        let payload = api.process_pointer::<u8>(PAYLOAD_OFFSET);
        let shared = api.process_pointer::<u8>(READ_OFFSET);

        for path in paths {
            let fd = api
                .open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("open(O_CREAT | O_WRONLY) failed");
            let written = api.write(fd, payload, PAYLOAD_LEN).expect("write failed");
            assert_eq!(written, PAYLOAD_LEN);
            api.close(fd).expect("close after seed write failed");
        }

        for path in paths {
            api.spawn_thread(move |api| {
                let fd = api
                    .open(path, OFlags::RDONLY, Mode::empty())
                    .expect("child: open(O_RDONLY) failed");
                for _ in 0..16 {
                    std::thread::yield_now();
                    let _ = api
                        .read(fd, shared, PAYLOAD_LEN)
                        .expect("child: read failed");
                }
                api.close(fd).expect("child: close failed");
            })
            .expect("spawn_thread failed");
        }
    });
}
