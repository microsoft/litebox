// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach IPC, MIG, Mach VM, and process-syscall behavior, driven through the
//! syscall dispatcher like guest code.

use super::*;
use litebox_common_macos::{
    errno::Errno,
    mach::{
        MACH_PORT_QLIMIT_KERNEL, MachMsgHeader, MachMsgPortDescriptor, MachPortOptions, mpo,
        msg_return, msg_type, msgh_bits, port_right,
    },
    syscall::{MachPortName, mach_trap, nr},
};

const CARRY: u64 = 1 << 29;

pub(super) fn trap(task: &Task<Platform>, number: u32, args: &[usize]) -> usize {
    let mut ctx = PtRegs::default();
    ctx.regs[16] = 0u32.wrapping_sub(number) as usize;
    ctx.regs[..args.len()].copy_from_slice(args);
    task.handle_syscall_request(&mut ctx);
    ctx.regs[0]
}

pub(super) fn kr(task: &Task<Platform>, number: u32, args: &[usize]) -> KernReturn {
    KernReturn::from_raw(i32::try_from(trap(task, number, args)).unwrap())
}

pub(super) fn bsd(task: &Task<Platform>, number: usize, args: &[usize]) -> Result<usize, usize> {
    let mut ctx = PtRegs::default();
    ctx.regs[16] = number;
    ctx.regs[..args.len()].copy_from_slice(args);
    task.handle_syscall_request(&mut ctx);
    if ctx.pstate & CARRY == 0 {
        Ok(ctx.regs[0])
    } else {
        Err(ctx.regs[0])
    }
}

pub(super) fn new_task() -> Task<Platform> {
    task(MacosShimBuilder::new(Platform::new()).build())
}

/// `mach_msg2` with a scalar buffer, as libsyscall packs it.
#[expect(clippy::too_many_arguments)]
fn msg2(
    task: &Task<Platform>,
    buffer: &mut [u8],
    options: u64,
    header: MachMsgHeader,
    send_size: u32,
    descriptors: u32,
    receive_name: u32,
    receive_size: u32,
) -> u32 {
    buffer[..24].copy_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    msg2_at(
        task,
        buffer.as_mut_ptr() as usize,
        options,
        header,
        send_size,
        descriptors,
        receive_name,
        receive_size,
    )
}

/// `mach_msg2` with the message buffer at guest address `data`.
#[expect(clippy::too_many_arguments)]
fn msg2_at(
    task: &Task<Platform>,
    data: usize,
    options: u64,
    header: MachMsgHeader,
    send_size: u32,
    descriptors: u32,
    receive_name: u32,
    receive_size: u32,
) -> u32 {
    let pack =
        |low: u32, high: u32| usize::try_from(u64::from(high) << 32 | u64::from(low)).unwrap();
    let result = trap(
        task,
        mach_trap::MACH_MSG2,
        &[
            data,
            usize::try_from(options).unwrap(),
            pack(header.bits, send_size),
            pack(header.remote_port, header.local_port),
            pack(header.voucher_port, header.id.cast_unsigned()),
            pack(descriptors, receive_name),
            pack(receive_size, 0),
            0,
        ],
    );
    u32::try_from(result).unwrap()
}

fn header_of(buffer: &[u8]) -> MachMsgHeader {
    zerocopy::FromBytes::read_from_bytes(&buffer[..24]).unwrap()
}

fn construct(task: &Task<Platform>, flags: u32) -> u32 {
    let options = MachPortOptions {
        flags,
        ..Default::default()
    };
    let mut name = 0u32;
    let own = trap(task, mach_trap::TASK_SELF, &[]);
    assert_eq!(
        kr(
            task,
            mach_trap::MACH_PORT_CONSTRUCT,
            &[
                own,
                core::ptr::from_ref(&options) as usize,
                0x1234,
                core::ptr::from_mut(&mut name) as usize,
            ],
        ),
        KernReturn::SUCCESS
    );
    name
}

#[test]
fn self_traps_name_one_send_right_per_object() {
    let task = new_task();
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    // The first name in a fresh space, like a native task's mach_task_self().
    assert_eq!(own, 0x103);
    assert_eq!(trap(&task, mach_trap::TASK_SELF, &[]), own);
    let thread = trap(&task, mach_trap::THREAD_SELF, &[]);
    let host = trap(&task, mach_trap::HOST_SELF, &[]);
    assert!(thread != own && host != own && host != thread);
    // Each trap added a user reference: two deallocations release the name,
    // after which it no longer names the task.
    for _ in 0..2 {
        assert_eq!(
            kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[own, own]),
            KernReturn::SUCCESS
        );
    }
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[own, host]),
        KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed())
    );
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    // ipc_entry_claim reuses the released index with the next generation.
    assert_eq!(own, 0x113);
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[own, 0x103]),
        KernReturn::INVALID_NAME
    );
    // A name that is not a task port is not a valid target.
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[host, own]),
        KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed())
    );
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[own, 0xdead_0003]),
        KernReturn::INVALID_NAME
    );
    // MACH_PORT_NULL and MACH_PORT_DEAD deallocate trivially.
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[own, 0]),
        KernReturn::SUCCESS
    );
}

#[test]
fn port_rights_follow_xnu_reference_rules() {
    let task = new_task();
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let receive = construct(&task, mpo::INSERT_SEND_RIGHT) as usize;
    // Send references: add, reject underflow, drop to zero (receive remains).
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_MOD_REFS,
            &[own, receive, port_right::SEND as usize, 2]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_MOD_REFS,
            &[
                own,
                receive,
                port_right::SEND as usize,
                (-4i32).cast_unsigned() as usize
            ]
        ),
        KernReturn::INVALID_VALUE
    );
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_MOD_REFS,
            &[
                own,
                receive,
                port_right::SEND as usize,
                (-3i32).cast_unsigned() as usize
            ]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[own, receive]),
        KernReturn::INVALID_RIGHT
    );
    // MAKE_SEND inserts a send right under the receive right's name only.
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_INSERT_RIGHT,
            &[own, receive, receive, msg_type::MAKE_SEND as usize]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_INSERT_RIGHT,
            &[own, 0x7_0003, receive, msg_type::MAKE_SEND as usize]
        ),
        KernReturn::RIGHT_EXISTS
    );
    // Destroying the receive right with the send right's reference.
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_DESTRUCT,
            &[own, receive, (-1i32).cast_unsigned() as usize, 0]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[own, receive]),
        KernReturn::INVALID_NAME
    );

    // A guarded port needs its guard; other port types and bad options fail.
    let guarded = construct(&task, mpo::CONTEXT_AS_GUARD) as usize;
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DESTRUCT, &[own, guarded, 0, 1]),
        KernReturn::INVALID_ARGUMENT
    );
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_MOD_REFS,
            &[
                own,
                guarded,
                port_right::RECEIVE as usize,
                (-1i32).cast_unsigned() as usize
            ]
        ),
        KernReturn::INVALID_RIGHT
    );
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_DESTRUCT,
            &[own, guarded, 0, 0x1234]
        ),
        KernReturn::SUCCESS
    );
    for flags in [mpo::SERVICE_PORT, 0x4_0000, mpo::QLIMIT] {
        let options = MachPortOptions {
            flags,
            qlimit: 4096,
            ..Default::default()
        };
        let mut name = 0u32;
        assert_ne!(
            kr(
                &task,
                mach_trap::MACH_PORT_CONSTRUCT,
                &[
                    own,
                    core::ptr::from_ref(&options) as usize,
                    0,
                    core::ptr::from_mut(&mut name) as usize
                ]
            ),
            KernReturn::SUCCESS
        );
        assert_eq!(name, 0);
    }
    // Dead names come from mach_port_allocate.
    let mut dead = 0u32;
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_ALLOCATE,
            &[
                own,
                port_right::DEAD_NAME as usize,
                core::ptr::from_mut(&mut dead) as usize
            ]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_DEALLOCATE,
            &[own, dead as usize]
        ),
        KernReturn::SUCCESS
    );
}

#[test]
fn mach_msg_queues_messages_and_send_once_notifications() {
    const ID: i32 = 0x4242;
    let task = new_task();
    let port = construct(&task, mpo::INSERT_SEND_RIGHT);
    let reply = u32::try_from(trap(&task, mach_trap::MACH_REPLY_PORT, &[])).unwrap();
    let mut buffer = [0u8; 256];
    buffer[24..28].copy_from_slice(&7u32.to_ne_bytes());
    let send = MachMsgHeader {
        bits: msgh_bits::ports(msg_type::COPY_SEND, msg_type::MAKE_SEND_ONCE),
        size: 0,
        remote_port: port,
        local_port: reply,
        voucher_port: 0,
        id: ID,
    };
    assert_eq!(
        msg2(&task, &mut buffer, 1, send, 28, 0, 0, 0),
        msg_return::SUCCESS
    );
    // An audit trailer (MACH_RCV_TRAILER_ELEMENTS(3)) is too large for 40 bytes.
    let audit_trailer = 3 << 24;
    let receive_header = MachMsgHeader::default();
    assert_eq!(
        msg2(
            &task,
            &mut buffer,
            2 | 4 | audit_trailer,
            receive_header,
            0,
            0,
            port,
            40
        ),
        msg_return::RCV_TOO_LARGE
    );
    assert_eq!(header_of(&buffer).size, 28);
    buffer.fill(0);
    assert_eq!(
        msg2(
            &task,
            &mut buffer,
            2 | audit_trailer,
            receive_header,
            0,
            0,
            port,
            256
        ),
        msg_return::SUCCESS
    );
    let received = header_of(&buffer);
    assert_eq!(received.id, ID);
    assert_eq!(received.size, 28);
    assert_eq!(received.local_port, port);
    assert_eq!(
        received.bits,
        msgh_bits::ports(msg_type::PORT_SEND_ONCE, msg_type::PORT_SEND)
    );
    assert_eq!(buffer[24..28], 7u32.to_ne_bytes());
    // The trailer: format 0, 52 bytes, seqno 0, sender uid/gid, audit pid.
    let trailer = &buffer[28..80];
    assert_eq!(trailer[4..8], 52u32.to_ne_bytes());
    assert_eq!(trailer[12..16], 1000u32.to_ne_bytes());
    assert_eq!(trailer[40..44], 2u32.to_ne_bytes());
    // Dropping the received send-once right notifies the reply port.
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_DEALLOCATE,
            &[own, received.remote_port as usize]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        msg2(&task, &mut buffer, 2, receive_header, 0, 0, reply, 256),
        msg_return::SUCCESS
    );
    // MACH_NOTIFY_SEND_ONCE.
    assert_eq!(header_of(&buffer).id, 0o107);
    // Empty queue with a zero timeout; bad names; bad destinations.
    assert_eq!(
        msg2(
            &task,
            &mut buffer,
            2 | 0x100,
            receive_header,
            0,
            0,
            reply,
            256
        ),
        msg_return::RCV_TIMED_OUT
    );
    assert_eq!(
        msg2(&task, &mut buffer, 2, receive_header, 0, 0, 0x99_0003, 256),
        msg_return::RCV_INVALID_NAME
    );
    let bad = MachMsgHeader {
        remote_port: 0x99_0003,
        ..send
    };
    assert_eq!(
        msg2(&task, &mut buffer, 1, bad, 24, 0, 0, 0),
        msg_return::SEND_INVALID_DEST
    );
    assert_eq!(
        msg2(&task, &mut buffer, 1, send, 20, 0, 0, 0),
        msg_return::SEND_MSG_TOO_SMALL
    );
}

/// [`mig_call_on`] with a new reply port.
pub(super) fn mig_call(
    task: &Task<Platform>,
    remote: u32,
    id: i32,
    body: &[u8],
    complex: bool,
) -> Vec<u8> {
    let reply = u32::try_from(trap(task, mach_trap::MACH_REPLY_PORT, &[])).unwrap();
    mig_call_on(task, reply, remote, id, body, complex)
}

/// Send a MIG request to `remote` with reply port `reply` and return the
/// reply, asserting its kernel-reply header.
fn mig_call_on(
    task: &Task<Platform>,
    reply: u32,
    remote: u32,
    id: i32,
    body: &[u8],
    complex: bool,
) -> Vec<u8> {
    let mut buffer = vec![0u8; 512];
    buffer[24..24 + body.len()].copy_from_slice(body);
    let mut bits = msgh_bits::ports(msg_type::COPY_SEND, msg_type::MAKE_SEND_ONCE);
    let descriptors = if complex {
        bits |= msgh_bits::COMPLEX;
        u32::from_ne_bytes(body[..4].try_into().unwrap())
    } else {
        0
    };
    let header = MachMsgHeader {
        bits,
        size: 0,
        remote_port: remote,
        local_port: reply,
        voucher_port: 0,
        id,
    };
    let size = u32::try_from(24 + body.len()).unwrap();
    assert_eq!(
        msg2(task, &mut buffer, 3, header, size, descriptors, reply, 512),
        msg_return::SUCCESS
    );
    let received = header_of(&buffer);
    assert_eq!(received.id, id.wrapping_add(100));
    assert_eq!(
        received.remote_port, 0,
        "kernel replies carry no reply port"
    );
    // ipc_object_copyout_dest: the consumed send-once destination reads as
    // the reply port's own receive name.
    assert_eq!(received.local_port, reply);
    buffer.truncate(received.size as usize);
    buffer
}

pub(super) fn ndr(fields: &[u32]) -> Vec<u8> {
    let mut body = litebox_common_macos::mach::NDR_RECORD.to_vec();
    for field in fields {
        body.extend_from_slice(&field.to_ne_bytes());
    }
    body
}

pub(super) fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[test]
fn mig_server_answers_host_and_task_routines() {
    let task = new_task();
    let own = u32::try_from(trap(&task, mach_trap::TASK_SELF, &[])).unwrap();
    let host = u32::try_from(trap(&task, mach_trap::HOST_SELF, &[])).unwrap();
    // host_info(HOST_PRIORITY_INFO, count 8): RetCode, count, 8 priorities.
    let reply = mig_call(&task, host, 200, &ndr(&[5, 8]), false);
    assert_eq!((word(&reply, 32), word(&reply, 36)), (0, 8));
    assert_eq!(word(&reply, 40), 80);
    // Too small a count fails like host_info's own check.
    let reply = mig_call(&task, host, 200, &ndr(&[5, 2]), false);
    assert_eq!(word(&reply, 32), KernReturn::FAILURE.raw().cast_unsigned());
    // task_info(TASK_AUDIT_TOKEN): pid in val[5].
    let reply = mig_call(&task, own, 3405, &ndr(&[15, 8]), false);
    assert_eq!((word(&reply, 32), word(&reply, 36)), (0, 8));
    assert_eq!(word(&reply, 40 + 5 * 4), 2);
    // task_get_special_port(TASK_BOOTSTRAP_PORT) is unset: a null MOVE_SEND.
    let reply = mig_call(&task, own, 3409, &ndr(&[4]), false);
    assert_ne!(header_of(&reply).bits & msgh_bits::COMPLEX, 0);
    assert_eq!((word(&reply, 24), word(&reply, 28)), (1, 0));
    assert_eq!(u32::from(reply[24 + 4 + 10]), msg_type::MOVE_SEND);
    // host_get_clock_service(SYSTEM_CLOCK) returns a send right.
    let reply = mig_call(&task, host, 206, &ndr(&[0]), false);
    assert!(litebox_common_macos::mach::port_name_is_valid(word(
        &reply, 28
    )));
    // semaphore_create, then semaphore_signal/wait traps on its name.
    let reply = mig_call(&task, own, 3418, &ndr(&[0, 1]), false);
    let semaphore = word(&reply, 28) as usize;
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_WAIT, &[semaphore]),
        KernReturn::SUCCESS
    );
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL, &[semaphore]),
        KernReturn::SUCCESS
    );
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_WAIT, &[semaphore]),
        KernReturn::SUCCESS
    );
    // Unknown routines get MIG_BAD_ID.
    let reply = mig_call(&task, own, 3499, &ndr(&[]), false);
    assert_eq!(
        word(&reply, 32).cast_signed(),
        litebox_common_macos::mach::mig::BAD_ID
    );
    // Restartable ranges register once.
    let mut ranges = ndr(&[1]);
    ranges.extend_from_slice(&0x1_0000u64.to_ne_bytes());
    ranges.extend_from_slice(&[16, 0, 8, 0, 0, 0, 0, 0]);
    let reply = mig_call(&task, own, 8000, &ranges, false);
    assert_eq!(word(&reply, 32), 0);
    let reply = mig_call(&task, own, 8000, &ranges, false);
    assert_eq!(
        word(&reply, 32),
        KernReturn::NOT_SUPPORTED.raw().cast_unsigned()
    );
}

const SEND: u64 = 0x1;
const RECEIVE: u64 = 0x2;
const RCV_LARGE: u64 = 0x4;
const SEND_TIMEOUT: u64 = 0x10;
const RCV_TIMEOUT: u64 = 0x100;

fn mod_refs(task: &Task<Platform>, name: u32, right: u32, delta: i32) -> KernReturn {
    let own = trap(task, mach_trap::TASK_SELF, &[]);
    kr(
        task,
        mach_trap::MACH_PORT_MOD_REFS,
        &[
            own,
            name as usize,
            right as usize,
            delta.cast_unsigned() as usize,
        ],
    )
}

/// A simple message from `remote_type` of `remote` and `local_type` of
/// `local`, with a four-byte body.
fn simple_send(
    task: &Task<Platform>,
    remote_type: u32,
    remote: u32,
    local_type: u32,
    local: u32,
) -> u32 {
    let header = MachMsgHeader {
        bits: msgh_bits::ports(remote_type, local_type),
        size: 0,
        remote_port: remote,
        local_port: local,
        voucher_port: 0,
        id: 7,
    };
    msg2(task, &mut [0u8; 64], SEND, header, 28, 0, 0, 0)
}

/// A complex message to `remote` carrying `name` with `disposition` in one
/// port descriptor.
fn send_port(task: &Task<Platform>, remote: u32, name: u32, disposition: u32) -> u32 {
    let mut buffer = [0u8; 64];
    buffer[24..28].copy_from_slice(&1u32.to_ne_bytes());
    let descriptor = MachMsgPortDescriptor {
        name,
        disposition: u8::try_from(disposition).unwrap(),
        ..Default::default()
    };
    buffer[28..40].copy_from_slice(zerocopy::IntoBytes::as_bytes(&descriptor));
    let header = MachMsgHeader {
        bits: msgh_bits::ports(msg_type::MAKE_SEND, 0) | msgh_bits::COMPLEX,
        size: 0,
        remote_port: remote,
        local_port: 0,
        voucher_port: 0,
        id: 9,
    };
    msg2(task, &mut buffer, SEND, header, 40, 1, 0, 0)
}

fn receive_now(task: &Task<Platform>, port: u32, buffer: &mut [u8]) -> u32 {
    let size = u32::try_from(buffer.len()).unwrap();
    msg2(
        task,
        buffer,
        RECEIVE | RCV_TIMEOUT,
        MachMsgHeader::default(),
        0,
        0,
        port,
        size,
    )
}

#[test]
fn aliased_destination_and_reply_copy_in_jointly() {
    let task = new_task();
    // One send reference to the task port: MOVE_SEND plus COPY_SEND of the
    // same name needs only that reference (DEST_EXTRA_COPY).
    let own = u32::try_from(trap(&task, mach_trap::TASK_SELF, &[])).unwrap();
    assert_eq!(
        simple_send(&task, msg_type::MOVE_SEND, own, msg_type::COPY_SEND, own),
        msg_return::SUCCESS
    );
    assert_eq!(
        mod_refs(&task, own, port_right::SEND, 0),
        KernReturn::INVALID_NAME,
        "the only reference moved"
    );

    // MOVE_SEND twice needs two references; with one, nothing moves.
    let port = construct(&task, mpo::INSERT_SEND_RIGHT);
    assert_eq!(
        simple_send(&task, msg_type::MOVE_SEND, port, msg_type::MOVE_SEND, port),
        msg_return::SEND_INVALID_DEST
    );
    assert_eq!(
        mod_refs(&task, port, port_right::SEND, -1),
        KernReturn::SUCCESS
    );
    assert_eq!(
        mod_refs(&task, port, port_right::SEND, 2),
        KernReturn::INVALID_RIGHT
    );
    assert_eq!(
        simple_send(&task, msg_type::MAKE_SEND, port, msg_type::MAKE_SEND, port),
        msg_return::SUCCESS
    );
    let mut buffer = [0u8; 128];
    assert_eq!(receive_now(&task, port, &mut buffer), msg_return::SUCCESS);
    // The receiver gets the reply send right under its receive name.
    assert_eq!(header_of(&buffer).remote_port, port);
    assert_eq!(
        mod_refs(&task, port, port_right::SEND, 1),
        KernReturn::SUCCESS
    );
    assert_eq!(
        simple_send(&task, msg_type::MOVE_SEND, port, msg_type::MOVE_SEND, port),
        msg_return::SUCCESS
    );
    assert_eq!(
        mod_refs(&task, port, port_right::SEND, 0),
        KernReturn::INVALID_RIGHT,
        "both references moved"
    );
    // COPY_SEND twice moves nothing.
    assert_eq!(receive_now(&task, port, &mut buffer), msg_return::SUCCESS);
    assert_eq!(
        simple_send(&task, msg_type::COPY_SEND, port, msg_type::COPY_SEND, port),
        msg_return::SUCCESS
    );
    assert_eq!(
        mod_refs(&task, port, port_right::SEND, 0),
        KernReturn::SUCCESS
    );
}

#[test]
fn long_receive_right_chain_is_destroyed_without_recursion() {
    const CHAIN: usize = 100_000;
    let task = new_task();
    let counts = || task.global.ipc.lock().live_counts();
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let before = counts();
    // Each port's queue holds a message carrying the previous port's
    // receive right.
    let mut previous = construct(&task, 0);
    for _ in 0..CHAIN {
        let holder = construct(&task, 0);
        assert_eq!(
            send_port(&task, holder, previous, msg_type::MOVE_RECEIVE),
            msg_return::SUCCESS
        );
        previous = holder;
    }
    assert_eq!(counts().0, before.0 + CHAIN + 1);
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_DESTRUCT,
            &[own, previous as usize, 0, 0]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(counts(), before);
}

#[test]
fn send_once_messages_stop_at_the_kernel_queue_limit() {
    let task = new_task();
    let port = construct(&task, 0);
    let header = MachMsgHeader {
        bits: msgh_bits::ports(msg_type::MAKE_SEND_ONCE, 0),
        size: 0,
        remote_port: port,
        local_port: 0,
        voucher_port: 0,
        id: 1,
    };
    let mut buffer = [0u8; 64];
    // Send-once messages pass the queue limit of 5, up to the hard limit.
    for _ in 0..MACH_PORT_QLIMIT_KERNEL {
        assert_eq!(
            msg2(&task, &mut buffer, SEND | SEND_TIMEOUT, header, 24, 0, 0, 0),
            msg_return::SUCCESS
        );
    }
    assert_eq!(
        msg2(&task, &mut buffer, SEND | SEND_TIMEOUT, header, 24, 0, 0, 0),
        msg_return::SEND_TIMED_OUT
    );
    assert_eq!(
        msg2(&task, &mut buffer, SEND, header, 24, 0, 0, 0),
        msg_return::SEND_NO_BUFFER
    );
    // A failed send keeps the sender's rights.
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let once = 0x7_0003;
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_INSERT_RIGHT,
            &[own, once, port as usize, msg_type::MAKE_SEND_ONCE as usize]
        ),
        KernReturn::SUCCESS
    );
    let moved = MachMsgHeader {
        bits: msgh_bits::ports(msg_type::MOVE_SEND_ONCE, 0),
        remote_port: u32::try_from(once).unwrap(),
        ..header
    };
    assert_eq!(
        msg2(&task, &mut buffer, SEND, moved, 24, 0, 0, 0),
        msg_return::SEND_NO_BUFFER
    );
    assert_eq!(
        mod_refs(
            &task,
            u32::try_from(once).unwrap(),
            port_right::SEND_ONCE,
            0
        ),
        KernReturn::SUCCESS
    );
}

#[test]
fn unread_mig_replies_stop_at_the_kernel_queue_limit() {
    let task = new_task();
    let own = u32::try_from(trap(&task, mach_trap::TASK_SELF, &[])).unwrap();
    let reply = u32::try_from(trap(&task, mach_trap::MACH_REPLY_PORT, &[])).unwrap();
    let mut buffer = [0u8; 64];
    buffer[24..32].copy_from_slice(&litebox_common_macos::mach::NDR_RECORD);
    let request = MachMsgHeader {
        bits: msgh_bits::ports(msg_type::COPY_SEND, msg_type::MAKE_SEND_ONCE),
        size: 0,
        remote_port: own,
        local_port: reply,
        voucher_port: 0,
        id: 3499,
    };
    for _ in 0..MACH_PORT_QLIMIT_KERNEL + 3 {
        assert_eq!(
            msg2(&task, &mut buffer, SEND, request, 32, 0, 0, 0),
            msg_return::SUCCESS
        );
    }
    // Replies past the hard limit were destroyed, without notifications.
    for _ in 0..MACH_PORT_QLIMIT_KERNEL {
        assert_eq!(receive_now(&task, reply, &mut buffer), msg_return::SUCCESS);
        assert_eq!(header_of(&buffer).id, 3599);
    }
    assert_eq!(
        receive_now(&task, reply, &mut buffer),
        msg_return::RCV_TIMED_OUT
    );
}

#[test]
fn overflowing_guest_pointers_and_ids_fail_without_panicking() {
    let task = new_task();
    let port = construct(&task, mpo::INSERT_SEND_RIGHT);
    let header = MachMsgHeader {
        bits: msgh_bits::ports(msg_type::COPY_SEND, 0),
        size: 0,
        remote_port: port,
        local_port: 0,
        voucher_port: 0,
        id: 7,
    };
    assert_eq!(
        msg2_at(&task, usize::MAX - 8, SEND, header, 28, 0, 0, 0),
        msg_return::SEND_INVALID_DATA
    );
    assert_eq!(
        simple_send(&task, msg_type::COPY_SEND, port, 0, 0),
        msg_return::SUCCESS
    );
    assert_eq!(
        msg2_at(
            &task,
            usize::MAX - 1,
            RECEIVE | RCV_LARGE,
            MachMsgHeader::default(),
            0,
            0,
            port,
            16
        ),
        msg_return::RCV_INVALID_DATA
    );
    // MIG reply ids wrap like the generated C.
    let own = u32::try_from(trap(&task, mach_trap::TASK_SELF, &[])).unwrap();
    let reply = mig_call(&task, own, i32::MAX, &ndr(&[]), false);
    assert_eq!(header_of(&reply).id, i32::MAX.wrapping_add(100));
}

#[test]
fn received_destination_rights_are_consumed() {
    let task = new_task();
    let port = construct(&task, mpo::INSERT_SEND_RIGHT);
    let mut buffer = [0u8; 128];
    for _ in 0..3 {
        assert_eq!(
            simple_send(&task, msg_type::COPY_SEND, port, 0, 0),
            msg_return::SUCCESS
        );
        assert_eq!(receive_now(&task, port, &mut buffer), msg_return::SUCCESS);
        assert_eq!(header_of(&buffer).local_port, port);
    }
    // Still exactly the one send reference INSERT_SEND_RIGHT made.
    assert_eq!(
        mod_refs(&task, port, port_right::SEND, -1),
        KernReturn::SUCCESS
    );
    assert_eq!(
        mod_refs(&task, port, port_right::SEND, -1),
        KernReturn::INVALID_RIGHT
    );
    // A destructive RCV_TOO_LARGE also reports the receive name.
    assert_eq!(
        simple_send(&task, msg_type::MAKE_SEND_ONCE, port, 0, 0),
        msg_return::SUCCESS
    );
    let mut small = [0u8; 24];
    assert_eq!(
        receive_now(&task, port, &mut small),
        msg_return::RCV_TOO_LARGE
    );
    assert_eq!(header_of(&small).local_port, port);
    assert_eq!(
        receive_now(&task, port, &mut buffer),
        msg_return::RCV_TIMED_OUT,
        "the consumed send-once right sent no notification"
    );
}

#[test]
fn generated_names_skip_inserted_names() {
    let task = new_task();
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let port = construct(&task, 0);
    // The next generated index is 3: take it explicitly.
    assert_eq!(port, 0x203);
    let inserted = 0x303;
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_INSERT_RIGHT,
            &[
                own,
                inserted,
                port as usize,
                msg_type::MAKE_SEND_ONCE as usize
            ]
        ),
        KernReturn::SUCCESS
    );
    let generated = trap(&task, mach_trap::MACH_REPLY_PORT, &[]);
    assert_eq!(generated, 0x403);
    // The inserted send-once right survived: releasing it notifies `port`.
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[own, inserted]),
        KernReturn::SUCCESS
    );
    let mut buffer = [0u8; 128];
    assert_eq!(receive_now(&task, port, &mut buffer), msg_return::SUCCESS);
    assert_eq!(header_of(&buffer).id, 0o107);
    // A different generation of a used index is refused.
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_INSERT_RIGHT,
            &[own, 0x407, port as usize, msg_type::MAKE_SEND as usize]
        ),
        KernReturn::FAILURE
    );
}

#[test]
fn inserted_names_need_roll_bits_and_a_nonzero_index() {
    let task = new_task();
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let port = construct(&task, 0);
    let insert = |name: usize| {
        kr(
            &task,
            mach_trap::MACH_PORT_INSERT_RIGHT,
            &[own, name, port as usize, msg_type::MAKE_SEND_ONCE as usize],
        )
    };
    // ipc_entry_alloc_name: the low two bits must be set, index 0 is
    // reserved.
    for name in [0xf0, 0x500, 0x501, 0x502] {
        assert_eq!(insert(name), KernReturn::INVALID_VALUE, "{name:#x}");
    }
    assert_eq!(insert(0x03), KernReturn::FAILURE);
    assert_eq!(insert(0xf3), KernReturn::FAILURE);
    // The refused rights were destroyed: each sent a send-once notification.
    let mut buffer = [0u8; 128];
    for _ in 0..6 {
        assert_eq!(receive_now(&task, port, &mut buffer), msg_return::SUCCESS);
    }
    let generated = trap(&task, mach_trap::MACH_REPLY_PORT, &[]);
    assert_ne!(generated >> 8, 0);
    assert_eq!(generated & 0x3, 0x3);
}

#[test]
fn released_inserted_names_come_back_with_a_new_generation() {
    let task = new_task();
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let port = construct(&task, 0);
    // An index above every generated one.
    let inserted = 0x5003;
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_INSERT_RIGHT,
            &[
                own,
                inserted,
                port as usize,
                msg_type::MAKE_SEND_ONCE as usize
            ]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        kr(&task, mach_trap::MACH_PORT_DEALLOCATE, &[own, inserted]),
        KernReturn::SUCCESS
    );
    // Generate names until index 0x50 is reached again: the stale name is
    // never handed out.
    let generated: Vec<usize> = (0..0x60)
        .map(|_| trap(&task, mach_trap::MACH_REPLY_PORT, &[]))
        .collect();
    assert_eq!(generated[0], 0x5013);
    assert!(generated.iter().all(|&name| name != inserted));
    assert!(generated.iter().any(|&name| name >> 8 > 0x50));
}

#[test]
fn destroyed_ports_and_released_names_are_reclaimed() {
    let task = new_task();
    let own = u32::try_from(trap(&task, mach_trap::TASK_SELF, &[])).unwrap();
    let reply = u32::try_from(trap(&task, mach_trap::MACH_REPLY_PORT, &[])).unwrap();
    let counts = || task.global.ipc.lock().live_counts();
    let cycle = || {
        let port = trap(&task, mach_trap::MACH_REPLY_PORT, &[]);
        assert_eq!(
            kr(
                &task,
                mach_trap::MACH_PORT_DESTRUCT,
                &[own as usize, port, 0, 0]
            ),
            KernReturn::SUCCESS
        );
        let created = mig_call_on(&task, reply, own, 3418, &ndr(&[0, 0]), false);
        let semaphore = word(&created, 28);
        let mut destroy = 1u32.to_ne_bytes().to_vec();
        destroy.extend_from_slice(zerocopy::IntoBytes::as_bytes(&MachMsgPortDescriptor {
            name: semaphore,
            disposition: u8::try_from(msg_type::MOVE_SEND).unwrap(),
            ..Default::default()
        }));
        let destroyed = mig_call_on(&task, reply, own, 3419, &destroy, true);
        assert_eq!(word(&destroyed, 32), 0);
        port
    };
    let first = cycle();
    let before = counts();
    for _ in 0..1000 {
        cycle();
    }
    assert_eq!(counts(), before);
    // The name index is reused with a new generation.
    assert_eq!(cycle() & !0xff, first & !0xff);
}

#[test]
fn semaphore_create_accepts_exactly_the_user_policies() {
    let task = new_task();
    let own = u32::try_from(trap(&task, mach_trap::TASK_SELF, &[])).unwrap();
    for (policy, accepted) in [
        (0, true),
        (1, false),
        (2, true),
        (3, false),
        (4, true),
        (6, true),
        (8, false),
    ] {
        let reply = mig_call(&task, own, 3418, &ndr(&[policy, 0]), false);
        let complex = header_of(&reply).bits & msgh_bits::COMPLEX != 0;
        assert_eq!(complex, accepted, "policy {policy}");
        if !accepted {
            assert_eq!(
                word(&reply, 32),
                KernReturn::INVALID_ARGUMENT.raw().cast_unsigned()
            );
        }
    }
}

#[test]
fn moving_a_receive_right_drops_its_guard() {
    let task = new_task();
    let carrier = construct(&task, 0);
    let guarded = construct(&task, mpo::CONTEXT_AS_GUARD);
    assert_eq!(
        send_port(&task, carrier, guarded, msg_type::MOVE_RECEIVE),
        msg_return::SUCCESS
    );
    let mut buffer = [0u8; 128];
    assert_eq!(
        receive_now(&task, carrier, &mut buffer),
        msg_return::SUCCESS
    );
    let moved = word(&buffer, 28);
    // Unguarded now, so mod_refs may destroy it.
    assert_eq!(
        mod_refs(&task, moved, port_right::RECEIVE, -1),
        KernReturn::SUCCESS
    );
    // MPO_IMMOVABLE_RECEIVE rights cannot move at all.
    let immovable = construct(&task, mpo::CONTEXT_AS_GUARD | mpo::IMMOVABLE_RECEIVE);
    assert_eq!(
        send_port(&task, carrier, immovable, msg_type::MOVE_RECEIVE),
        msg_return::SEND_INVALID_RIGHT
    );
    assert_eq!(
        receive_now(&task, carrier, &mut buffer),
        msg_return::RCV_TIMED_OUT
    );
}

#[test]
fn mach_vm_map_follows_xnu_placement_rules() {
    use litebox_common_macos::{
        VmProtection,
        syscall::{MachVmAddressMask, MachVmFlags, MachVmProtection},
        user_pointers::UserPtrMut,
    };

    let task = new_task();
    let own = MachPortName(u32::try_from(trap(&task, mach_trap::TASK_SELF, &[])).unwrap());
    let slot = core::cell::Cell::new(0usize);
    let address = UserPtrMut::from_ptr(slot.as_ptr());
    let map = |at: usize, size: usize, mask: usize, flags: MachVmFlags, protection| {
        slot.set(at);
        task.sys_mach_vm_map(
            own,
            address,
            size,
            MachVmAddressMask(mask),
            flags,
            MachVmProtection::new(protection, false),
        )
    };
    let rw = VmProtection::READ | VmProtection::WRITE;
    // ANYWHERE with an alignment mask.
    assert_eq!(
        map(0, PAGE_SIZE, 0x3f_ffff, MachVmFlags::ANYWHERE, rw),
        KernReturn::SUCCESS
    );
    let aligned = slot.get();
    assert_eq!(aligned & 0x3f_ffff, 0);
    // A 1 TiB alignment maps one page, never the alignment slack.
    let huge = (1usize << 40) - 1;
    assert_eq!(
        map(0, PAGE_SIZE, huge, MachVmFlags::ANYWHERE, rw),
        KernReturn::SUCCESS
    );
    let huge_aligned = slot.get();
    assert_eq!(huge_aligned & huge, 0);
    let around: Vec<_> = task
        .global
        .mm
        .mappings()
        .into_iter()
        .filter(|(range, _)| range.start < huge_aligned + huge && huge_aligned < range.end)
        .map(|(range, _)| range)
        .collect();
    assert_eq!(around, vec![huge_aligned..huge_aligned + PAGE_SIZE]);
    assert_eq!(
        task.sys_mach_vm_deallocate(own, huge_aligned, PAGE_SIZE),
        KernReturn::SUCCESS
    );
    // A PROT_NONE reservation succeeds where free and fails where occupied.
    assert_eq!(
        map(
            aligned + 4 * PAGE_SIZE,
            PAGE_SIZE,
            0,
            MachVmFlags::empty(),
            VmProtection::empty()
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        map(aligned, PAGE_SIZE, 0, MachVmFlags::empty(), rw),
        KernReturn::NO_SPACE
    );
    // OVERWRITE replaces it; ANYWHERE|OVERWRITE is invalid; a misaligned
    // FIXED start fails the mask check.
    assert_eq!(
        map(
            aligned,
            PAGE_SIZE,
            0,
            MachVmFlags::OVERWRITE,
            VmProtection::READ
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        map(
            0,
            PAGE_SIZE,
            0,
            MachVmFlags::ANYWHERE | MachVmFlags::OVERWRITE,
            rw
        ),
        KernReturn::INVALID_ARGUMENT
    );
    assert_eq!(
        map(
            aligned + PAGE_SIZE,
            PAGE_SIZE,
            0x3f_ffff,
            MachVmFlags::empty(),
            rw
        ),
        KernReturn::NO_SPACE
    );
    assert_eq!(
        map(0, 0, 0, MachVmFlags::ANYWHERE, rw),
        KernReturn::INVALID_ARGUMENT
    );
    // Kernel-only and unsupported hardware flags are rejected.
    assert_eq!(
        map(
            0,
            PAGE_SIZE,
            0,
            MachVmFlags::ANYWHERE | MachVmFlags::TPRO,
            rw
        ),
        KernReturn::INVALID_ARGUMENT
    );
    assert_eq!(
        map(0, PAGE_SIZE, 0, MachVmFlags::from_bits_retain(0x200), rw),
        KernReturn::INVALID_ARGUMENT
    );
    // mach_vm_allocate of zero bytes succeeds with address 0; a foreign
    // target is not a task.
    slot.set(7);
    assert_eq!(
        task.sys_mach_vm_allocate(own, address, 0, MachVmFlags::ANYWHERE),
        KernReturn::SUCCESS
    );
    assert_eq!(slot.get(), 0);
    assert_eq!(
        task.sys_mach_vm_allocate(
            MachPortName(0x55_0003),
            address,
            PAGE_SIZE,
            MachVmFlags::ANYWHERE
        ),
        KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed())
    );
    assert_eq!(
        task.sys_mach_vm_deallocate(own, aligned, PAGE_SIZE),
        KernReturn::SUCCESS
    );
}

#[test]
fn mach_vm_anywhere_placement_honours_non_contiguous_masks() {
    use litebox_common_macos::{
        syscall::{MachVmAddressMask, MachVmFlags, MachVmProtection},
        user_pointers::UserPtrMut,
    };

    let task = new_task();
    let own = MachPortName(u32::try_from(trap(&task, mach_trap::TASK_SELF, &[])).unwrap());
    let slot = core::cell::Cell::new(0usize);
    let address = UserPtrMut::from_ptr(slot.as_ptr());
    let rw = VmProtection::READ | VmProtection::WRITE;
    for mask in [0x8000, 0x1_0000] {
        let effective = mask | (PAGE_SIZE - 1);
        // A hint that is a multiple of `effective + 1` but has mask bits set.
        let hints = [0, 0x2_0001_c000, 0x2_0005_0000];
        for hint in hints {
            slot.set(hint);
            assert_eq!(
                task.sys_mach_vm_map(
                    own,
                    address,
                    PAGE_SIZE,
                    MachVmAddressMask(mask),
                    MachVmFlags::ANYWHERE,
                    MachVmProtection::new(rw, false),
                ),
                KernReturn::SUCCESS
            );
            assert_eq!(slot.get() & effective, 0, "mask {mask:#x} hint {hint:#x}");
        }
    }
}

#[test]
fn mach_vm_fixed_realigns_an_unaligned_start() {
    use litebox_common_macos::{syscall::MachVmFlags, user_pointers::UserPtrMut};

    let task = new_task();
    let own = MachPortName(u32::try_from(trap(&task, mach_trap::TASK_SELF, &[])).unwrap());
    let slot = core::cell::Cell::new(0usize);
    let address = UserPtrMut::from_ptr(slot.as_ptr());
    let allocate = |at: usize, size: usize, flags: MachVmFlags| {
        slot.set(at);
        task.sys_mach_vm_allocate(own, address, size, flags)
    };
    assert_eq!(
        allocate(0, 2 * PAGE_SIZE, MachVmFlags::ANYWHERE),
        KernReturn::SUCCESS
    );
    let base = slot.get();
    let sentinel = base + PAGE_SIZE;
    UserPtrMut::<u8>::from_usize(sentinel)
        .write_at_offset::<Platform>(0, 0xa5)
        .unwrap();
    // FIXED|OVERWRITE of one page from inside the first page replaces only
    // the first page.
    assert_eq!(
        allocate(base + 1, PAGE_SIZE, MachVmFlags::OVERWRITE),
        KernReturn::SUCCESS
    );
    assert_eq!(slot.get(), base);
    assert_eq!(read_guest(sentinel, 1), Some(vec![0xa5]));
    // Without OVERWRITE, a free first page suffices.
    assert_eq!(
        task.sys_mach_vm_deallocate(own, base, PAGE_SIZE),
        KernReturn::SUCCESS
    );
    assert_eq!(
        allocate(base + 1, PAGE_SIZE, MachVmFlags::empty()),
        KernReturn::SUCCESS
    );
    assert_eq!(read_guest(sentinel, 1), Some(vec![0xa5]));
}

#[test]
fn process_and_security_syscalls_match_an_unsigned_process() {
    let task = new_task();
    let status = 0xffff_ffffu32;
    let mut out = status;
    assert_eq!(bsd(&task, nr::ISSETUGID, &[]), Ok(0));
    // csops(CS_OPS_STATUS) on itself: no flags; other pids are invisible.
    assert_eq!(
        bsd(
            &task,
            nr::CSOPS,
            &[0, 0, core::ptr::from_mut(&mut out) as usize, 4]
        ),
        Ok(0)
    );
    assert_eq!(out, 0);
    assert_eq!(
        bsd(&task, nr::CSOPS, &[77, 0, 0, 0]),
        Err(Errno::ESRCH.raw())
    );
    assert_eq!(
        bsd(&task, nr::CSOPS, &[0, 16, 0, 4]),
        Err(Errno::EINVAL.raw())
    );
    // SIP fully enabled; Rosetta and MAC policies absent.
    let mask = 0x1u32;
    assert_eq!(
        bsd(
            &task,
            nr::CSRCTL,
            &[0, core::ptr::from_ref(&mask) as usize, 4]
        ),
        Err(Errno::EPERM.raw())
    );
    assert_eq!(bsd(&task, nr::CSRCTL, &[0, 0, 4]), Err(Errno::EINVAL.raw()));
    assert_eq!(
        bsd(&task, nr::CROSSARCH_TRAP, &[0]),
        Err(Errno::ENOTSUP.raw())
    );
    assert_eq!(
        bsd(&task, nr::CROSSARCH_TRAP, &[9]),
        Err(Errno::EINVAL.raw())
    );
    let policy = c"AMFI";
    assert_eq!(
        bsd(&task, nr::MAC_SYSCALL, &[policy.as_ptr() as usize, 0x5a, 0]),
        Err(Errno::ENOPOLICY.raw())
    );
    // sigprocmask keeps SIGKILL/SIGSTOP unmaskable.
    let all = u32::MAX;
    let mut old = 0u32;
    assert_eq!(
        bsd(
            &task,
            nr::SIGPROCMASK,
            &[3, core::ptr::from_ref(&all) as usize, 0]
        ),
        Ok(0)
    );
    assert_eq!(
        bsd(
            &task,
            nr::SIGPROCMASK,
            &[1, 0, core::ptr::from_mut(&mut old) as usize]
        ),
        Ok(0)
    );
    assert_eq!(old, !((1 << 8) | (1 << 16)));
    assert_eq!(
        bsd(
            &task,
            nr::SIGPROCMASK,
            &[9, core::ptr::from_ref(&all) as usize, 0]
        ),
        Err(Errno::EINVAL.raw())
    );
    // map_with_linking_np leaves fixups to dyld.
    assert_eq!(
        bsd(&task, nr::MAP_WITH_LINKING_NP, &[0; 4]),
        Err(Errno::EINVAL.raw())
    );
    // csops_audittoken requires a token.
    assert_eq!(
        bsd(
            &task,
            nr::CSOPS_AUDITTOKEN,
            &[0, 0, core::ptr::from_mut(&mut out) as usize, 4, 0]
        ),
        Err(Errno::EINVAL.raw())
    );
    // abort_with_payload ends the guest with SIGABRT.
    let reason = c"test abort";
    assert!(
        bsd(
            &task,
            nr::ABORT_WITH_PAYLOAD,
            &[1, 2, 0, 0, reason.as_ptr() as usize, 0]
        )
        .is_ok()
    );
    assert_eq!(task.process.exit_status(), Some(128 + 6));
}

#[test]
fn terminate_with_payload_kills_only_the_guest_itself() {
    let task = new_task();
    let reason = c"test terminate";
    let terminate = |pid: usize| {
        bsd(
            &task,
            nr::TERMINATE_WITH_PAYLOAD,
            &[pid, 1, 2, 0, 0, reason.as_ptr() as usize],
        )
    };
    // terminate_with_payload_internal: EINVAL before any process lookup.
    for pid in [0, (-1isize).cast_unsigned(), 0xffff_ffff] {
        assert_eq!(terminate(pid), Err(Errno::EINVAL.raw()));
    }
    assert_eq!(terminate(77), Err(Errno::ESRCH.raw()));
    assert_eq!(task.process.exit_status(), None);
    // The guest itself is killed with SIGKILL, unlike abort_with_payload's SIGABRT.
    assert!(terminate(task.params.pid.cast_unsigned() as usize).is_ok());
    assert_eq!(task.process.exit_status(), Some(128 + 9));
}
