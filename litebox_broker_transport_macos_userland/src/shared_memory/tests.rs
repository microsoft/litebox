// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_broker_transport::control_ring::{ControlRingDirection, memory_permits_byte_range};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use std::io::{IoSlice, Write};
use std::time::Duration;

#[test]
fn mappings_share_bytes_and_validate_ranges() {
    let memory = MacosSharedMemory::create(64).unwrap();
    let peer =
        MacosSharedMemory::from_received_fd(memory.as_fd().try_clone_to_owned().unwrap(), 64)
            .unwrap();
    memory.write(0, b"shared").unwrap();
    let mut bytes = [0; 6];
    peer.read(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"shared");
    peer.write(1, b"X").unwrap();
    memory.read(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"sXared");
    assert_eq!(
        memory.read(usize::MAX, &mut bytes),
        Err(SharedMemoryError::InvalidRange)
    );
    assert_eq!(
        memory.write(63, b"xx"),
        Err(SharedMemoryError::InvalidRange)
    );
    assert_eq!(
        memory.load_u64_acquire(0),
        Err(SharedMemoryError::InvalidRange)
    );
    assert!(MacosSharedMemory::create(0).is_err());
    assert!(MacosSharedMemory::create(usize::MAX).is_err());
}

#[test]
fn received_descriptor_cannot_resize_the_broker_mapping() {
    let memory = MacosSharedMemory::create(16384).unwrap();
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    send_shared_memory(&mut sender, &memory, None).unwrap();
    let peer = receive_shared_memory(&mut receiver, 16384, None).unwrap();
    for length in [0, 1, 16384, 32768] {
        // SAFETY: a live received descriptor, deliberately exercising hostile resize.
        assert_eq!(
            unsafe { libc::ftruncate(peer.as_fd().as_raw_fd(), length) },
            -1
        );
        assert_eq!(Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }
    memory.write(16383, &[42]).unwrap();
    let mut byte = [0];
    peer.read(16383, &mut byte).unwrap();
    assert_eq!(byte, [42]);
    assert!(
        rustix::io::fcntl_getfd(peer.as_fd())
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
}

#[test]
fn control_words_are_atomic_disjoint_and_wrap() {
    let memory = MacosSharedMemory::create_control_ring().unwrap();
    let peer = MacosSharedMemory::control_ring_from_received_fd(
        memory.as_fd().try_clone_to_owned().unwrap(),
    )
    .unwrap();
    let epoch = ControlRingDirection::Requests.producer_epoch_offset();
    let word = (0..CONTROL_RING_MEMORY_SIZE)
        .find(|&offset| memory.policy.permits_u64(offset))
        .unwrap();
    let body = (0..CONTROL_RING_MEMORY_SIZE)
        .find(|&offset| memory_permits_byte_range(offset, 1))
        .unwrap();
    memory
        .store_u64_and_increment_u32_release(word, 123, epoch)
        .unwrap();
    assert_eq!(peer.load_u64_acquire(word), Ok(123));
    assert_eq!(peer.load_u32_acquire(epoch), Ok(1));
    assert_eq!(
        peer.write(epoch, &[0]),
        Err(SharedMemoryError::InvalidRange)
    );
    assert_eq!(
        peer.read(word, &mut [0]),
        Err(SharedMemoryError::InvalidRange)
    );
    assert_eq!(
        peer.store_u64_and_increment_u32_release(word, 0, body),
        Err(SharedMemoryError::InvalidRange)
    );
    assert_eq!(peer.load_u64_acquire(word), Ok(123));
    assert!(peer.wake_one(body).is_err());
    // Deliberately bypass the typed API as a hostile mapping alias could do.
    // SAFETY: checked address, private source, no Rust references into the mapping.
    unsafe {
        copy_bytes(
            u32::MAX.to_ne_bytes().as_ptr(),
            peer.word32(epoch).unwrap(),
            4,
        );
    };
    memory.increment_u32_release(epoch).unwrap();
    assert_eq!(peer.load_u32_acquire(epoch), Ok(0));
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..10000 {
                memory.increment_u32_release(epoch).unwrap();
            }
        });
        scope.spawn(|| {
            for _ in 0..10000 {
                peer.increment_u32_release(epoch).unwrap();
            }
        });
    });
    assert_eq!(memory.load_u32_acquire(epoch), Ok(20000));
}

#[test]
fn waits_recheck_without_peer_cooperation() {
    let memory = MacosSharedMemory::create_control_ring().unwrap();
    let start = Instant::now();
    memory
        .wait_while_equal(ControlRingDirection::Requests.producer_epoch_offset(), 0)
        .unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn wake_one_promptly_unblocks_a_separate_mapping() {
    use std::sync::mpsc::{self, RecvTimeoutError};

    let waker = MacosSharedMemory::create_control_ring().unwrap();
    let waiter = MacosSharedMemory::control_ring_from_received_fd(
        waker.as_fd().try_clone_to_owned().unwrap(),
    )
    .unwrap();
    assert_ne!(waker.address, waiter.address);
    let epoch = ControlRingDirection::Requests.producer_epoch_offset();
    waker.increment_u32_release(epoch).unwrap();
    let (started, ready) = mpsc::sync_channel(1);
    let (completed, completion) = mpsc::sync_channel(1);

    std::thread::scope(|scope| {
        let thread = scope.spawn(|| {
            let address = waiter.word32(epoch).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            assert_eq!(waiter.load_u32_acquire(epoch), Ok(1));
            started.send(()).unwrap();
            let result = loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break Err(Error::from_raw_os_error(libc::ETIMEDOUT));
                }
                // Use the native wait with a long timeout, not the transport's
                // 100-ms fallback. Keep the epoch unchanged: only a real wake
                // through the other mapping can satisfy this test promptly.
                // SAFETY: address is a checked, aligned word in the live waiter
                // mapping; the shared wait uses its backing object as the key.
                let result = unsafe {
                    os_sync_wait_on_address_with_timeout(
                        address.cast(),
                        1,
                        4,
                        OS_SYNC_SHARED,
                        OS_CLOCK_MACH_ABSOLUTE_TIME,
                        remaining.as_nanos().try_into().unwrap(),
                    )
                };
                if result >= 0 {
                    break Ok(());
                }
                let error = Error::last_os_error();
                if !matches!(
                    error.raw_os_error(),
                    Some(libc::EINTR | libc::EFAULT | libc::ENOMEM)
                ) {
                    break Err(error);
                }
                assert_eq!(waiter.load_u32_acquire(epoch), Ok(1));
            };
            let _ = completed.send(result);
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            completion.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            // Repeating the wake also covers the waiter being descheduled
            // between its ready notification and entering the kernel wait.
            waker.wake_one(epoch).unwrap();
            match completion.recv_timeout(Duration::from_millis(2)) {
                Ok(result) => {
                    result.unwrap();
                    break;
                }
                Err(RecvTimeoutError::Timeout) => assert!(
                    Instant::now() < deadline,
                    "cross-mapping wake did not unblock the waiter"
                ),
                Err(error) => panic!("waiter disconnected: {error}"),
            }
        }
        thread.join().unwrap();
        assert_eq!(waker.load_u32_acquire(epoch), Ok(1));
    });
}

#[test]
fn descriptor_transfer_rejects_missing_multiple_truncated_and_wrong_size() {
    let memory = MacosSharedMemory::create(16384).unwrap();
    for count in [0, 2, 8] {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        if count == 0 {
            sender.write_all(&[0]).unwrap();
        } else {
            let fds = vec![memory.as_fd(); count];
            let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
            rustix::net::sendmsg(
                &sender,
                &[IoSlice::new(&[0])],
                &mut control,
                SendFlags::empty(),
            )
            .unwrap();
        }
        assert_eq!(
            receive_shared_memory(&mut receiver, 16384, None)
                .err()
                .unwrap()
                .kind(),
            ErrorKind::InvalidData
        );
    }
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    send_shared_memory(&mut sender, &memory, None).unwrap();
    assert_eq!(
        receive_shared_memory(&mut receiver, 32768, None)
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidData
    );
    let fd: OwnedFd = std::fs::File::open("/dev/zero").unwrap().into();
    assert!(MacosSharedMemory::from_received_fd(fd, 16384).is_err());
}

#[test]
fn eof_deadlines_and_closed_peer_are_errors() {
    let (mut receiver, sender) = UnixStream::pair().unwrap();
    drop(sender);
    assert_eq!(
        receive_shared_memory(&mut receiver, 64, None)
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnexpectedEof
    );
    let (mut receiver, _sender) = UnixStream::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(
        receive_shared_memory(&mut receiver, 64, Some(Instant::now()))
            .err()
            .unwrap()
            .kind(),
        ErrorKind::TimedOut
    );
    assert_eq!(
        receiver.read_timeout().unwrap(),
        Some(Duration::from_secs(2))
    );
    let memory = MacosSharedMemory::create(64).unwrap();
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    drop(receiver);
    assert!(send_shared_memory(&mut sender, &memory, None).is_err());
}
