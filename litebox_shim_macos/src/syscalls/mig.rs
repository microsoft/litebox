// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed MIG server for the guest's kernel objects (task, thread, host,
//! clock, semaphore).
//!
//! Each routine decodes its `__Request__*_t` layout, checks it like MIG's
//! generated `__MIG_check__Request__*` (size, complex bit, descriptor
//! dispositions), and builds the `__Reply__*_t` layout. Unknown routines get
//! a `MIG_BAD_ID` reply, like `ipc_kobject_server`.

use super::mach::AnonymousMapRequest;
use super::mach_ipc::{KernelObject, Message, Right, error_reply};
use crate::{ShimPlatform, Task};
use alloc::vec::Vec;
use litebox_common_macos::{
    KernReturn, TaskParams, VmProtection,
    mach::{MachMsgPortDescriptor, NDR_RECORD, PORT_DESCRIPTOR, mig, msg_type},
    syscall::MachVmFlags,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub(crate) const MACH_NOTIFY_SEND_ONCE: i32 = 0o107;

/// `clock_id_t` of a clock kernel object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClockId {
    /// `SYSTEM_CLOCK` (`REALTIME_CLOCK`).
    System,
    /// `CALENDAR_CLOCK`.
    Calendar,
}

/// MIG routine ids (`msgh_id`) served here.
mod routine {
    pub const CLOCK_GET_TIME: i32 = 1000;
    pub const HOST_INFO: i32 = 200;
    pub const HOST_GET_CLOCK_SERVICE: i32 = 206;
    pub const MACH_PORTS_LOOKUP: i32 = 3404;
    pub const TASK_INFO: i32 = 3405;
    pub const TASK_GET_SPECIAL_PORT: i32 = 3409;
    pub const TASK_SET_SPECIAL_PORT: i32 = 3410;
    pub const SEMAPHORE_CREATE: i32 = 3418;
    pub const SEMAPHORE_DESTROY: i32 = 3419;
    pub const THREAD_INFO: i32 = 3612;
    pub const THREAD_POLICY: i32 = 3616;
    pub const MACH_VM_ALLOCATE: i32 = 4800;
    pub const MACH_VM_DEALLOCATE: i32 = 4801;
    pub const MACH_VM_MAP: i32 = 4811;
    pub const MACH_VM_DEFERRED_RECLAMATION_BUFFER_ALLOCATE: i32 = 4822;
    pub const TASK_RESTARTABLE_RANGES_REGISTER: i32 = 8000;
    pub const TASK_RESTARTABLE_RANGES_SYNCHRONIZE: i32 = 8001;
}

/// `task_restartable_range_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub(crate) struct RestartableRange {
    pub location: u64,
    pub length: u16,
    pub recovery_offset: u16,
    pub flags: u32,
}

/// `TASK_RESTARTABLE_OFFSET_MAX`.
const RESTARTABLE_OFFSET_MAX: u16 = 4096;
/// The MIG array bound of `task_restartable_range_array_t`.
const RESTARTABLE_RANGES_MAX: usize = 64;

/// `_ranges_validate`: sorted, in bounds, and non-overlapping.
fn validate_restartable_ranges(ranges: &mut [RestartableRange]) -> KernReturn {
    ranges.sort_by_key(|range| range.location);
    if ranges.is_empty() {
        return KernReturn::INVALID_ARGUMENT;
    }
    for index in 0..ranges.len() {
        let range = ranges[index];
        if range.length > RESTARTABLE_OFFSET_MAX
            || range.recovery_offset > RESTARTABLE_OFFSET_MAX
            || range.flags != 0
        {
            return KernReturn::INVALID_ARGUMENT;
        }
        let (Some(end), Some(_)) = (
            range.location.checked_add(u64::from(range.length)),
            range.location.checked_add(u64::from(range.recovery_offset)),
        ) else {
            return KernReturn::INVALID_ARGUMENT;
        };
        if ranges
            .get(index + 1)
            .is_some_and(|next| end > next.location)
        {
            return KernReturn::INVALID_ARGUMENT;
        }
    }
    KernReturn::SUCCESS
}

/// `SYNC_POLICY_FIFO | SYNC_POLICY_LIFO | SYNC_POLICY_PREPOST`.
const SYNC_POLICY_USER_MASK: i32 = 0x2 | 0x4;

/// `VM_RECLAIM_NOT_SUPPORTED`: `err_vm_reclaim(2)`.
const VM_RECLAIM_NOT_SUPPORTED: i32 = (0x8 << 26) | (1 << 14) | 2;

/// A message body that starts with the NDR record.
pub(crate) fn ndr_body(fields: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(NDR_RECORD.len() + fields.len());
    body.extend_from_slice(&NDR_RECORD);
    body.extend_from_slice(fields);
    body
}

/// The task's `audit_token_t`: auid, euid, egid, ruid, rgid, pid, asid,
/// pidversion. The guest is the only member of audit session 0.
pub(crate) fn audit_token(params: &TaskParams) -> [u32; 8] {
    [
        params.uid,
        params.euid,
        params.egid,
        params.uid,
        params.gid,
        params.pid.cast_unsigned(),
        0,
        1,
    ]
}

/// Bytes after the header and NDR record of a simple request.
fn simple_request<T: FromBytes + KnownLayout + Immutable>(request: &Message) -> Option<T> {
    if request.complex {
        return None;
    }
    let fields = request.body.get(NDR_RECORD.len()..)?;
    T::read_from_bytes(fields).ok()
}

/// A reply with `RetCode` and typed out-fields.
fn kern_reply(code: KernReturn, fields: &[u8]) -> Message {
    let mut body = Vec::with_capacity(4 + fields.len());
    body.extend_from_slice(&code.raw().to_ne_bytes());
    body.extend_from_slice(fields);
    Message::reply(ndr_body(&body))
}

/// A successful reply carrying ports: `mach_msg_body_t` plus one `MOVE_SEND`
/// port descriptor per right, `None` for `MACH_PORT_NULL`. Failures are
/// `mig_reply_error_t`.
fn ports_reply(rights: &[Option<Right>]) -> Message {
    let mut reply = Message::reply(
        u32::try_from(rights.len())
            .expect("small")
            .to_ne_bytes()
            .to_vec(),
    );
    reply.complex = true;
    let descriptor = MachMsgPortDescriptor {
        name: 0,
        pad1: 0,
        pad2: 0,
        disposition: u8::try_from(msg_type::MOVE_SEND).expect("fits"),
        descriptor_type: PORT_DESCRIPTOR,
    };
    for right in rights {
        reply.ports.push((reply.body.len(), *right));
        reply.body.extend_from_slice(descriptor.as_bytes());
    }
    reply
}

/// `CountInOut` arrays: copy at most the caller's count of `integer_t`s.
fn info_reply(code: KernReturn, info: &[u32], max_count: u32) -> Message {
    if code != KernReturn::SUCCESS {
        return error_reply(code.raw());
    }
    let count = u32::try_from(info.len()).expect("small").min(max_count);
    let mut fields = Vec::with_capacity(4 + info.len() * 4);
    fields.extend_from_slice(&count.to_ne_bytes());
    for word in &info[..count as usize] {
        fields.extend_from_slice(&word.to_ne_bytes());
    }
    kern_reply(KernReturn::SUCCESS, &fields)
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct FlavorCountRequest {
    flavor: i32,
    count: u32,
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct IntRequest {
    value: i32,
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct SemaphoreCreateRequest {
    policy: i32,
    value: i32,
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed(4))]
struct VmAllocateRequest {
    address: u64,
    size: u64,
    flags: i32,
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed(4))]
struct VmDeallocateRequest {
    address: u64,
    size: u64,
}

/// `__Request__mach_vm_map_t` after its port descriptor.
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed(4))]
struct VmMapRequest {
    ndr: [u8; 8],
    address: u64,
    size: u64,
    mask: u64,
    flags: i32,
    offset: u64,
    copy: u32,
    current_protection: i32,
    max_protection: i32,
    inheritance: u32,
}

/// `host_info` flavors.
mod host_flavor {
    pub const SCHED_INFO: i32 = 3;
    pub const PRIORITY_INFO: i32 = 5;
    pub const SEMAPHORE_TRAPS: i32 = 7;
    pub const MACH_MSG_TRAP: i32 = 8;
    pub const PREFERRED_USER_ARCH: i32 = 12;
}

/// `task_info` flavors.
mod task_flavor {
    pub const SECURITY_TOKEN: i32 = 13;
    pub const AUDIT_TOKEN: i32 = 15;
}

/// `thread_info` flavors.
mod thread_flavor {
    pub const IDENTIFIER_INFO: i32 = 4;
    /// `THREAD_IDENTIFIER_INFO_COUNT`.
    pub const IDENTIFIER_INFO_COUNT: u32 = 6;
}

/// `task_get_special_port` selectors.
mod special_port {
    pub const KERNEL: i32 = 1;
    pub const HOST: i32 = 2;
    pub const NAME: i32 = 3;
    pub const BOOTSTRAP: i32 = 4;
    pub const INSPECT: i32 = 5;
    pub const READ: i32 = 6;
    pub const ACCESS: i32 = 9;
    pub const DEBUG_CONTROL: i32 = 10;
    pub const RESOURCE_NOTIFY: i32 = 11;
}

/// XNU `osfmk/kern/sched.h` priorities, returned by `HOST_PRIORITY_INFO`.
const MINPRI_KERNEL: u32 = 80;
const MINPRI_RESERVED: u32 = 64;
const MAXPRI_RESERVED: u32 = 79;
const BASEPRI_DEFAULT: u32 = 31;
const DEPRESSPRI: u32 = 0;
const IDLEPRI: u32 = 0;
const MINPRI_USER: u32 = 0;

/// XNU `osfmk/mach/machine.h`.
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
/// The scheduler quantum (`sched_info.min_quantum`), in milliseconds.
const SCHED_QUANTUM_MS: u32 = 10;

impl<P: ShimPlatform> Task<P> {
    /// Every routine served here replies.
    pub(crate) fn serve_mig(&self, object: KernelObject, mut request: Message) -> Message {
        let reply = match (object, request.id) {
            (KernelObject::Clock(clock), routine::CLOCK_GET_TIME) => {
                self.mig_clock_get_time(clock, &request)
            }
            (KernelObject::Host, routine::HOST_INFO) => self.mig_host_info(&request),
            (KernelObject::Host, routine::HOST_GET_CLOCK_SERVICE) => {
                self.mig_host_get_clock_service(&request)
            }
            (KernelObject::Task, routine::TASK_INFO) => self.mig_task_info(&request),
            (KernelObject::Task, routine::MACH_PORTS_LOOKUP) => {
                // _kernelrpc_mach_ports_lookup3: no ports were registered
                // with mach_ports_register.
                if request.complex || !request.body.is_empty() {
                    error_reply(mig::BAD_ARGUMENTS)
                } else {
                    ports_reply(&[None, None, None])
                }
            }
            (KernelObject::Task, routine::MACH_VM_DEFERRED_RECLAMATION_BUFFER_ALLOCATE) => {
                // vm_reclaim is disabled for this task, like a kernel without
                // CONFIG_DEFERRED_RECLAIM enabled.
                error_reply(VM_RECLAIM_NOT_SUPPORTED)
            }
            (KernelObject::Task, routine::TASK_GET_SPECIAL_PORT) => {
                self.mig_task_get_special_port(&request)
            }
            (KernelObject::Task, routine::TASK_SET_SPECIAL_PORT) => {
                self.mig_task_set_special_port(&mut request)
            }
            (KernelObject::Task, routine::SEMAPHORE_CREATE) => self.mig_semaphore_create(&request),
            (KernelObject::Task, routine::SEMAPHORE_DESTROY) => {
                self.mig_semaphore_destroy(&request)
            }
            (KernelObject::Task, routine::MACH_VM_ALLOCATE) => self.mig_vm_allocate(&request),
            (KernelObject::Task, routine::MACH_VM_DEALLOCATE) => self.mig_vm_deallocate(&request),
            (KernelObject::Task, routine::MACH_VM_MAP) => self.mig_vm_map(&request),
            (KernelObject::Thread(thread), routine::THREAD_INFO) => {
                self.mig_thread_info(thread, &request)
            }
            (KernelObject::Thread(thread), routine::THREAD_POLICY) => {
                self.mig_thread_policy(thread, &request)
            }
            (KernelObject::Task, routine::TASK_RESTARTABLE_RANGES_REGISTER) => {
                self.mig_restartable_ranges_register(&request)
            }
            (KernelObject::Task, routine::TASK_RESTARTABLE_RANGES_SYNCHRONIZE) => {
                // Without signal delivery no thread is ever redirected out of
                // a range, so there is nothing to synchronize with.
                if request.complex || !request.body.is_empty() {
                    error_reply(mig::BAD_ARGUMENTS)
                } else {
                    kern_reply(KernReturn::SUCCESS, &[])
                }
            }
            _ => {
                self.log_unsupported_once(
                    "MIG routine",
                    format_args!("msgh_id {} to {object:?}", request.id),
                );
                error_reply(mig::BAD_ID)
            }
        };
        self.global.ipc.lock().destroy_message(request);
        reply
    }

    /// `clock_get_time` (`osfmk/kern/clock_oldops.c`): the system clock's
    /// `rtclock_gettime` reads the uptime, the calendar clock's
    /// `calend_gettime` the time of day. The reply's `mach_timespec_t` has
    /// 32-bit seconds.
    fn mig_clock_get_time(&self, clock: ClockId, request: &Message) -> Message {
        if request.complex || !request.body.is_empty() {
            return error_reply(mig::BAD_ARGUMENTS);
        }
        let platform = self.global.platform;
        let since = match clock {
            ClockId::System => {
                let timebase = platform.mach_timebase_info();
                let nanoseconds = u128::from(platform.mach_absolute_time())
                    * u128::from(timebase.numer)
                    / u128::from(timebase.denom.max(1));
                core::time::Duration::from_nanos(u64::try_from(nanoseconds).unwrap_or(u64::MAX))
            }
            ClockId::Calendar => {
                use litebox_platform::time::{SystemTime as _, TimeProvider};
                platform
                    .current_time()
                    .duration_since(&<P as TimeProvider>::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
            }
        };
        let seconds: u32 = litebox::utils::TruncateExt::trunc(since.as_secs());
        let mut fields = seconds.to_ne_bytes().to_vec();
        fields.extend_from_slice(&since.subsec_nanos().to_ne_bytes());
        kern_reply(KernReturn::SUCCESS, &fields)
    }

    fn mig_host_info(&self, request: &Message) -> Message {
        let Some(FlavorCountRequest { flavor, count }) = simple_request(request) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        // host_info_out[68]
        let count = count.min(68);
        let (code, info): (KernReturn, Vec<u32>) = match flavor {
            host_flavor::SCHED_INFO => (
                KernReturn::SUCCESS,
                alloc::vec![SCHED_QUANTUM_MS, SCHED_QUANTUM_MS],
            ),
            host_flavor::PRIORITY_INFO => (
                KernReturn::SUCCESS,
                alloc::vec![
                    MINPRI_KERNEL,
                    MINPRI_KERNEL,
                    MINPRI_RESERVED,
                    BASEPRI_DEFAULT,
                    DEPRESSPRI,
                    IDLEPRI,
                    MINPRI_USER,
                    MAXPRI_RESERVED,
                ],
            ),
            host_flavor::SEMAPHORE_TRAPS | host_flavor::MACH_MSG_TRAP => {
                (KernReturn::SUCCESS, Vec::new())
            }
            host_flavor::PREFERRED_USER_ARCH => (
                KernReturn::SUCCESS,
                alloc::vec![CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL],
            ),
            _ => {
                self.log_unsupported_once("host_info flavor", format_args!("{flavor}"));
                (KernReturn::INVALID_ARGUMENT, Vec::new())
            }
        };
        if code == KernReturn::SUCCESS && (count as usize) < info.len() {
            return error_reply(KernReturn::FAILURE.raw());
        }
        info_reply(code, &info, count)
    }

    /// `thread_info`. Only `THREAD_IDENTIFIER_INFO` is supported; the
    /// scheduling flavors report host state the guest does not see.
    fn mig_thread_info(&self, thread: crate::ThreadId, request: &Message) -> Message {
        let Some(FlavorCountRequest { flavor, count }) = simple_request(request) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        // thread_info_out[THREAD_INFO_MAX]
        let count = count.min(32);
        let Some(target) = self.guest_thread(thread) else {
            return error_reply(KernReturn::TERMINATED.raw());
        };
        if flavor != thread_flavor::IDENTIFIER_INFO {
            self.log_unsupported_once("thread_info flavor", format_args!("{flavor}"));
            return error_reply(KernReturn::INVALID_ARGUMENT.raw());
        }
        if count < thread_flavor::IDENTIFIER_INFO_COUNT {
            return error_reply(KernReturn::INVALID_ARGUMENT.raw());
        }
        let handle = target.tsd_base.load(core::sync::atomic::Ordering::Relaxed) as u64;
        // thread_dispatchqaddr: the TSD base plus the registered offset.
        let dispatch_queue = if handle == 0 {
            0
        } else {
            let offset = (*self.global.pthread_registration.lock())
                .map_or(0, |registration| registration.dispatch_queue_offset);
            handle.wrapping_add(offset)
        };
        // The out-count stays the caller's, as thread_info_internal leaves it.
        let mut info = alloc::vec![0u32; count as usize];
        for (index, value) in [target.id, handle, dispatch_queue].into_iter().enumerate() {
            info[2 * index] = litebox::utils::TruncateExt::<u32>::trunc(value);
            info[2 * index + 1] = litebox::utils::TruncateExt::<u32>::trunc(value >> 32);
        }
        info_reply(KernReturn::SUCCESS, &info, count)
    }

    /// `thread_policy`: `policy`, a `policy_base_t` array of at most 5
    /// integers, and `set_limit`, packed after the array's used elements.
    fn mig_thread_policy(&self, thread: crate::ThreadId, request: &Message) -> Message {
        const BASE_MAX: usize = 5;
        let fields = (!request.complex)
            .then(|| request.body.get(NDR_RECORD.len()..))
            .flatten();
        let Some((header, rest)) = fields.and_then(|fields| fields.split_first_chunk::<8>()) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        let policy = i32::from_ne_bytes(header[..4].try_into().expect("4 bytes"));
        let count = u32::from_ne_bytes(header[4..].try_into().expect("4 bytes")) as usize;
        if count > BASE_MAX || rest.len() != count * 4 + 4 {
            return error_reply(mig::BAD_ARGUMENTS);
        }
        let (base, set_limit) = rest.split_at(count * 4);
        let base: Vec<i32> = base
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| i32::from_ne_bytes(*word))
            .collect();
        let set_limit = u32::from_ne_bytes(set_limit.try_into().expect("4 bytes")) != 0;
        kern_reply(self.thread_policy(thread, policy, &base, set_limit), &[])
    }

    /// `task_restartable_ranges_register`. Guest signals are never delivered,
    /// so nothing ever interrupts a range; the ranges are recorded so that
    /// the one-shot rule holds.
    fn mig_restartable_ranges_register(&self, request: &Message) -> Message {
        const ENTRY: usize = size_of::<RestartableRange>();
        let fields = (!request.complex)
            .then(|| request.body.get(NDR_RECORD.len()..))
            .flatten();
        let Some((count, entries)) = fields.and_then(|fields| fields.split_first_chunk::<4>())
        else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        let count = u32::from_ne_bytes(*count) as usize;
        if count > RESTARTABLE_RANGES_MAX || entries.len() != count * ENTRY {
            return error_reply(mig::BAD_ARGUMENTS);
        }
        let mut ranges: Vec<RestartableRange> = entries
            .as_chunks::<ENTRY>()
            .0
            .iter()
            .map(|entry| RestartableRange::read_from_bytes(entry).expect("entry size"))
            .collect();
        let mut code = validate_restartable_ranges(&mut ranges);
        if code == KernReturn::SUCCESS {
            let mut registered = self.global.restartable_ranges.lock();
            if registered.is_some() {
                // Release kernels allow one registration per task.
                code = KernReturn::NOT_SUPPORTED;
            } else {
                *registered = Some(ranges);
            }
        }
        kern_reply(code, &[])
    }

    fn mig_host_get_clock_service(&self, request: &Message) -> Message {
        let Some(IntRequest { value: clock_id }) = simple_request(request) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        let clock = match clock_id {
            0 => ClockId::System,
            1 => ClockId::Calendar,
            _ => return error_reply(KernReturn::INVALID_ARGUMENT.raw()),
        };
        match self
            .global
            .ipc
            .lock()
            .kernel_send_right(KernelObject::Clock(clock))
        {
            Ok(right) => ports_reply(&[Some(right)]),
            Err(code) => error_reply(code.raw()),
        }
    }

    fn mig_task_info(&self, request: &Message) -> Message {
        let Some(FlavorCountRequest { flavor, count }) = simple_request(request) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        // task_info_out[94]
        let count = count.min(94);
        let params = &self.params;
        let info: Vec<u32> = match flavor {
            task_flavor::SECURITY_TOKEN => alloc::vec![params.euid, params.egid],
            task_flavor::AUDIT_TOKEN => audit_token(params).to_vec(),
            _ => {
                self.log_unsupported_once("task_info flavor", format_args!("{flavor}"));
                return error_reply(KernReturn::INVALID_ARGUMENT.raw());
            }
        };
        if (count as usize) < info.len() {
            return error_reply(KernReturn::INVALID_ARGUMENT.raw());
        }
        info_reply(KernReturn::SUCCESS, &info, count)
    }

    fn mig_task_get_special_port(&self, request: &Message) -> Message {
        let Some(IntRequest { value: which }) = simple_request(request) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        let mut ipc = self.global.ipc.lock();
        let right = match which {
            special_port::KERNEL
            | special_port::NAME
            | special_port::INSPECT
            | special_port::READ => ipc.kernel_send_right(KernelObject::Task).ok(),
            // The host port unless the task replaced it.
            special_port::HOST => match ipc.special_port(which) {
                Some(right) => Some(right),
                None => ipc.kernel_send_right(KernelObject::Host).ok(),
            },
            // No launchd, task_for_pid server, debugger, or resource-notify
            // service exists for this guest: until the task sets one, the
            // port is MACH_PORT_NULL.
            special_port::BOOTSTRAP
            | special_port::ACCESS
            | special_port::DEBUG_CONTROL
            | special_port::RESOURCE_NOTIFY => ipc.special_port(which),
            _ => return error_reply(KernReturn::INVALID_ARGUMENT.raw()),
        };
        ports_reply(&[right])
    }

    /// `task_set_special_port`: the request carries one send right.
    fn mig_task_set_special_port(&self, request: &mut Message) -> Message {
        if !request.complex || request.ports.len() != 1 || request.body.len() != 28 {
            return error_reply(mig::BAD_ARGUMENTS);
        }
        let (offset, _) = request.ports[0];
        if request.body[offset + 10] != u8::try_from(msg_type::MOVE_SEND).expect("fits") {
            return error_reply(mig::TYPE_ERROR);
        }
        let which = i32::from_ne_bytes(request.body[24..28].try_into().expect("4 bytes"));
        let code = match which {
            // Settable only with SIP disabled.
            special_port::KERNEL | special_port::HOST => KernReturn::NO_ACCESS,
            special_port::BOOTSTRAP
            | special_port::DEBUG_CONTROL
            | special_port::RESOURCE_NOTIFY
            | special_port::ACCESS => {
                let mut ipc = self.global.ipc.lock();
                if which == special_port::ACCESS && ipc.special_port(which).is_some() {
                    // The task access port is never overwritten.
                    KernReturn::NO_ACCESS
                } else {
                    // The request's right moves into the task.
                    let right = request.ports[0].1.take();
                    ipc.set_special_port(which, right);
                    KernReturn::SUCCESS
                }
            }
            _ => KernReturn::INVALID_ARGUMENT,
        };
        kern_reply(code, &[])
    }

    fn mig_semaphore_create(&self, request: &Message) -> Message {
        let Some(SemaphoreCreateRequest { policy, value }) = simple_request(request) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        // semaphore_create: only SYNC_POLICY_USER_MASK (FIFO, LIFO, PREPOST)
        // bits; a negative value is invalid.
        if value < 0 || policy & !SYNC_POLICY_USER_MASK != 0 {
            return error_reply(KernReturn::INVALID_ARGUMENT.raw());
        }
        let id = self.global.semaphores.lock().create(policy, value);
        let right = self
            .global
            .ipc
            .lock()
            .kernel_send_right(KernelObject::Semaphore(id));
        match right {
            Ok(right) => ports_reply(&[Some(right)]),
            Err(code) => {
                self.global.semaphores.lock().destroy(id);
                error_reply(code.raw())
            }
        }
    }

    fn mig_semaphore_destroy(&self, request: &Message) -> Message {
        // One port descriptor carrying a send right to the semaphore.
        let right = match (request.complex, request.ports.as_slice()) {
            (true, [(_, right)]) if request.body.len() == 16 => *right,
            _ => return error_reply(mig::BAD_ARGUMENTS),
        };
        let destroyed = {
            let mut ipc = self.global.ipc.lock();
            match right {
                Some(Right::Send(port)) => match ipc.kernel_object(port) {
                    Some(KernelObject::Semaphore(id)) => {
                        ipc.destroy_port(port);
                        Some(id)
                    }
                    _ => None,
                },
                _ => None,
            }
        };
        let code = match destroyed {
            Some(id) => {
                self.global.semaphores.lock().destroy(id);
                KernReturn::SUCCESS
            }
            None => KernReturn::INVALID_ARGUMENT,
        };
        kern_reply(code, &[])
    }

    fn mig_vm_allocate(&self, request: &Message) -> Message {
        let Some(VmAllocateRequest {
            address,
            size,
            flags,
        }) = simple_request(request)
        else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        let flags = MachVmFlags::from_bits_retain(flags);
        if !MachVmFlags::USER_ALLOCATE.contains(flags) {
            return error_reply(KernReturn::INVALID_ARGUMENT.raw());
        }
        let result = self.mach_vm_map_anonymous(AnonymousMapRequest {
            address: usize::try_from(address).unwrap_or(usize::MAX),
            size: usize::try_from(size).unwrap_or(usize::MAX),
            mask: 0,
            flags,
            protection: VmProtection::READ | VmProtection::WRITE,
            zero_size_succeeds: true,
        });
        match result {
            Ok(address) => kern_reply(KernReturn::SUCCESS, &(address as u64).to_ne_bytes()),
            Err(code) => error_reply(code.raw()),
        }
    }

    fn mig_vm_deallocate(&self, request: &Message) -> Message {
        let Some(VmDeallocateRequest { address, size }) = simple_request(request) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        let code = self.mach_vm_deallocate(
            usize::try_from(address).unwrap_or(usize::MAX),
            usize::try_from(size).unwrap_or(usize::MAX),
        );
        kern_reply(code, &[])
    }

    fn mig_vm_map(&self, request: &Message) -> Message {
        // A memory-object port descriptor, then the scalar arguments.
        let object = match (request.complex, request.ports.as_slice()) {
            (true, [(_, right)]) => *right,
            _ => return error_reply(mig::BAD_ARGUMENTS),
        };
        let Some(fields) = request.body.get(16..) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        let Ok(map) = VmMapRequest::read_from_bytes(fields) else {
            return error_reply(mig::BAD_ARGUMENTS);
        };
        if object.is_some() {
            self.log_unsupported_once("mach_vm_map with a memory object", format_args!(""));
            return error_reply(KernReturn::INVALID_ARGUMENT.raw());
        }
        let flags = MachVmFlags::from_bits_retain(map.flags);
        let (Some(current), Some(maximum)) = (
            VmProtection::from_bits(map.current_protection),
            VmProtection::from_bits(map.max_protection),
        ) else {
            return error_reply(KernReturn::INVALID_ARGUMENT.raw());
        };
        if !MachVmFlags::USER_MAP.contains(flags)
            || !maximum.contains(current)
            || map.inheritance > 2
        {
            return error_reply(KernReturn::INVALID_ARGUMENT.raw());
        }
        if maximum != VmProtection::all() {
            // Maximum protections are not tracked outside the shared cache:
            // a later mprotect beyond `maximum` would succeed.
            self.log_unsupported_once(
                "mach_vm_map maximum protection below VM_PROT_ALL",
                format_args!("{maximum:?}"),
            );
        }
        let result = self.mach_vm_map_anonymous(AnonymousMapRequest {
            address: usize::try_from(map.address).unwrap_or(usize::MAX),
            size: usize::try_from(map.size).unwrap_or(usize::MAX),
            mask: usize::try_from(map.mask).unwrap_or(usize::MAX),
            flags,
            protection: current,
            zero_size_succeeds: false,
        });
        match result {
            Ok(address) => kern_reply(KernReturn::SUCCESS, &(address as u64).to_ne_bytes()),
            Err(code) => error_reply(code.raw()),
        }
    }
}
