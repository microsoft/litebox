# Design: Implement `shutdown` Syscall

## Overview

This document describes the plan to implement the Linux `shutdown` syscall in LiteBox's Linux shim.

## Background

The `shutdown` syscall allows a process to shut down part or all of a full-duplex connection on a socket. It's commonly used for:
- Graceful TCP connection termination (half-close)
- Signaling end-of-data to the peer while still receiving
- Proper cleanup of socket resources

**Syscall signature:**
```c
int shutdown(int sockfd, int how);
```

**Parameters:**
- `sockfd`: File descriptor of the socket
- `how`: One of:
  - `SHUT_RD` (0): Shutdown read side
  - `SHUT_WR` (1): Shutdown write side
  - `SHUT_RDWR` (2): Shutdown both sides

**Returns:** 0 on success, -1 on error with errno set

## Current State

- LiteBox already has `shutdown_read()` and `shutdown_write()` methods on `StreamSocketChannel`
- `NetworkProxy` wraps socket channels but doesn't expose shutdown
- Unix sockets have internal shutdown tracking but no syscall interface
- The syscall is not parsed or dispatched

## Implementation Plan

### 1. Add `SockShutdownCmd` enum to `litebox_common_linux/src/lib.rs`
- Define enum with `Read`, `Write`, `ReadWrite` variants
- Add helper methods `shut_read()` and `shut_write()`

### 2. Add `Shutdown` variant to `SyscallRequest` enum
- Add parsing in `try_from_raw()` for `Sysno::shutdown`

### 3. Add `shutdown()` method to `NetworkProxy`
- File: `litebox/src/net/socket_channel.rs`
- Dispatch to `StreamSocketChannel::shutdown_read/write`
- Handle datagram sockets (no-op for UDP)

### 4. Add `shutdown()` method to `UnixSocket`
- File: `litebox_shim_linux/src/syscalls/unix.rs`
- Implement for stream sockets (connected state)
- Return `ENOTCONN` for unconnected sockets
- Return `EOPNOTSUPP` for datagram sockets (or implement if needed)

### 5. Implement `sys_shutdown` in `Task`
- File: `litebox_shim_linux/src/syscalls/net.rs`
- Use `with_socket()` helper to dispatch to INET or Unix handler

### 6. Add syscall dispatch
- File: `litebox_shim_linux/src/lib.rs`
- Add `SyscallRequest::Shutdown` case in `do_syscall()`

### 7. Add tests
- Unit tests in `litebox_shim_linux/src/syscalls/net.rs`
- C test file `litebox_runner_linux_userland/tests/shutdown_test.c`

## Files to Modify

1. `litebox_common_linux/src/lib.rs` - Add enum and syscall variant
2. `litebox/src/net/socket_channel.rs` - Add NetworkProxy::shutdown()
3. `litebox_shim_linux/src/syscalls/unix.rs` - Add UnixSocket::shutdown()
4. `litebox_shim_linux/src/syscalls/net.rs` - Add sys_shutdown()
5. `litebox_shim_linux/src/lib.rs` - Add dispatch

## Test Strategy

### Unit Tests
- Test shutdown on TCP stream socket
- Test shutdown on UDP socket (should succeed with no-op)
- Test shutdown with invalid fd (EBADF)
- Test shutdown with invalid `how` value (EINVAL)

### Integration Tests (C)
- Create connected TCP socket pair
- Test SHUT_WR: write after shutdown fails, read still works
- Test SHUT_RD: read returns 0 (EOF), write still works
- Test SHUT_RDWR: both operations fail
- Test on Unix domain sockets

## Error Handling

| Error | Condition |
|-------|-----------|
| EBADF | Invalid file descriptor |
| EINVAL | Invalid `how` argument |
| ENOTCONN | Socket not connected (for connection-oriented sockets) |
| ENOTSOCK | File descriptor is not a socket |

## References

- Linux man page: `man 2 shutdown`
- Asterinas implementation: `/workspace/asterinas/kernel/src/syscall/shutdown.rs`
- Linux source: `/workspace/linux/net/socket.c`
