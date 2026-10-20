// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach IPC, MIG, Mach VM, and process-syscall behavior, driven through the
//! syscall dispatcher like guest code.

use super::*;
use litebox_common_macos::{
    errno::Errno,
    mach::{MachMsgHeader, MachPortOptions, mpo, msg_return, msg_type, msgh_bits, port_right},
    syscall::{MachPortName, mach_trap, nr},
};

const CARRY: u64 = 1 << 29;

fn trap(task: &Task<Platform>, number: u32, args: &[usize]) -> usize {
    let mut ctx = PtRegs::default();
    ctx.regs[16] = 0u32.wrapping_sub(number) as usize;
    ctx.regs[..args.len()].copy_from_slice(args);
    task.handle_syscall_request(&mut ctx);
    ctx.regs[0]
}

fn kr(task: &Task<Platform>, number: u32, args: &[usize]) -> KernReturn {
    KernReturn::from_raw(i32::try_from(trap(task, number, args)).unwrap())
}

fn bsd(task: &Task<Platform>, number: usize, args: &[usize]) -> Result<usize, usize> {
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

fn new_task() -> Task<Platform> {
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
    let pack =
        |low: u32, high: u32| usize::try_from(u64::from(high) << 32 | u64::from(low)).unwrap();
    buffer[..24].copy_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    let result = trap(
        task,
        mach_trap::MACH_MSG2,
        &[
            buffer.as_mut_ptr() as usize,
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
    assert_ne!(own, 0x103, "a released name is not reused");
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
    assert_eq!(trailer[40..44], 1u32.to_ne_bytes());
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

/// Send a MIG request to `remote` and receive its reply.
fn mig_call(task: &Task<Platform>, remote: u32, id: i32, body: &[u8], complex: bool) -> Vec<u8> {
    let reply = u32::try_from(trap(task, mach_trap::MACH_REPLY_PORT, &[])).unwrap();
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
    assert_eq!(received.id, id + 100);
    assert_eq!(
        received.remote_port, 0,
        "kernel replies carry no reply port"
    );
    buffer.truncate(received.size as usize);
    buffer
}

fn ndr(fields: &[u32]) -> Vec<u8> {
    let mut body = litebox_common_macos::mach::NDR_RECORD.to_vec();
    for field in fields {
        body.extend_from_slice(&field.to_ne_bytes());
    }
    body
}

fn word(bytes: &[u8], offset: usize) -> u32 {
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
    assert_eq!(word(&reply, 40 + 5 * 4), 1);
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
