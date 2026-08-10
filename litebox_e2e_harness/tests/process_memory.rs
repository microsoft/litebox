// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! End-to-end demonstration of a Vec-backed Linux process address space.

use litebox::fs::{Mode, OFlags};
use litebox_e2e_harness::HarnessRunner;

#[test]
fn vec_backed_process_memory_drives_linux_syscalls() {
    const PATH_OFFSET: usize = 0x100;
    const COPY_PATH_OFFSET: usize = 0x180;
    const DATA_OFFSET: usize = 0x200;
    const COPY_OFFSET: usize = 0x300;
    const OBSERVED_OFFSET: usize = 0x400;
    const COPY_OBSERVED_OFFSET: usize = 0x500;
    const PATH: &[u8] = b"/tmp/true-tales\0";
    const COPY_PATH: &[u8] = b"/tmp/true-tales-copy\0";
    const DATA: &[u8] = b"copied from modeled userspace";

    let mut image = vec![0; 0x1000];
    image[PATH_OFFSET..PATH_OFFSET + PATH.len()].copy_from_slice(PATH);
    image[COPY_PATH_OFFSET..COPY_PATH_OFFSET + COPY_PATH.len()].copy_from_slice(COPY_PATH);
    image[DATA_OFFSET..DATA_OFFSET + DATA.len()].copy_from_slice(DATA);

    let runner = HarnessRunner::with_process_memory(image);
    runner.run(|api| {
        let path = api.process_pointer::<i8>(PATH_OFFSET);
        let copy_path = api.process_pointer::<i8>(COPY_PATH_OFFSET);
        let data = api.process_pointer::<u8>(DATA_OFFSET);

        let fd = api
            .open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("open from modeled process memory failed");
        assert_eq!(
            api.write(fd, data, DATA.len())
                .expect("write from modeled process memory failed"),
            DATA.len()
        );
        api.close(fd).expect("close after modeled write failed");

        let observed = api.process_pointer::<u8>(OBSERVED_OFFSET);
        let fd = api
            .open(path, OFlags::RDONLY, Mode::empty())
            .expect("verification open failed");
        assert_eq!(
            api.read(fd, observed, DATA.len())
                .expect("verification read failed"),
            DATA.len()
        );
        assert!(api.memory_matches(observed, DATA));
        api.close(fd).expect("close after verification read failed");

        let copied = api.process_pointer::<u8>(COPY_OFFSET);
        let fd = api
            .open(path, OFlags::RDONLY, Mode::empty())
            .expect("source open for modeled read failed");
        assert_eq!(
            api.read(fd, copied, DATA.len())
                .expect("read into modeled process memory failed"),
            DATA.len()
        );
        api.close(fd).expect("close after modeled read failed");

        let fd = api
            .open(copy_path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("copy destination open failed");
        assert_eq!(
            api.write(fd, copied, DATA.len())
                .expect("write from copied modeled process memory failed"),
            DATA.len()
        );
        api.close(fd)
            .expect("close after copied modeled write failed");

        let copied_observed = api.process_pointer::<u8>(COPY_OBSERVED_OFFSET);
        let fd = api
            .open(copy_path, OFlags::RDONLY, Mode::empty())
            .expect("copied file verification open failed");
        assert_eq!(
            api.read(fd, copied_observed, DATA.len())
                .expect("copied file verification read failed"),
            DATA.len()
        );
        assert!(api.memory_matches(copied_observed, DATA));
        api.close(fd)
            .expect("close after copied verification failed");
    });
}
