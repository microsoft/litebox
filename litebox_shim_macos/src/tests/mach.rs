// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process-syscall behavior, driven through the syscall dispatcher like guest
//! code.

use super::*;
use litebox_common_macos::{errno::Errno, syscall::nr};

const CARRY: u64 = 1 << 29;

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
        bsd(&task, nr::CROSSARCH_TRAP, &[1]),
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
