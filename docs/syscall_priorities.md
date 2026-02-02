# Syscall Implementation Priorities

This document tracks syscall implementation priorities and notes for LiteBox.

## Architecture Notes

LiteBox is a **single-process library OS**. This architectural decision affects the priority
of certain syscalls that are primarily useful for inter-process communication or
multi-process scenarios.

## Low Priority Syscalls

The following syscalls are considered low priority due to LiteBox's single-process nature:

| Syscall | Reason |
|---------|--------|
| `memfd_create` | Creates anonymous memory-backed file descriptors primarily used for inter-process data sharing. Since LiteBox is a single-process libos, the IPC use case does not apply. |
| `shmget`, `shmat`, `shmdt`, `shmctl` | System V shared memory - designed for IPC between processes |
| `mq_open`, `mq_send`, `mq_receive`, etc. | POSIX message queues - IPC mechanism |
| `semget`, `semop`, `semctl` | System V semaphores - primarily for inter-process synchronization |

## Notes

- Syscalls may still be implemented with stub/minimal functionality if commonly called by
  applications even when the full semantics aren't needed.
- Priority can be elevated if a specific application requires a syscall.
