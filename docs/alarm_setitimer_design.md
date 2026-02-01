# Design: alarm, setitimer, getitimer Syscalls

## Overview

This document describes the design for implementing the `alarm`, `setitimer`, and `getitimer` Linux syscalls in `litebox_shim_linux`.

## Syscall Signatures

```c
// Set an alarm clock for delivery of SIGALRM
unsigned int alarm(unsigned int seconds);

// Set value of an interval timer
int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);

// Get value of an interval timer
int getitimer(int which, struct itimerval *curr_value);
```

## Data Structures

### `struct itimerval`
```c
struct itimerval {
    struct timeval it_interval;  // Interval for periodic timer
    struct timeval it_value;     // Time until next expiration
};

struct timeval {
    time_t      tv_sec;   // seconds
    suseconds_t tv_usec;  // microseconds
};
```

### Timer Types (which parameter)
- `ITIMER_REAL` (0): Wall clock time, delivers `SIGALRM`
- `ITIMER_VIRTUAL` (1): User CPU time, delivers `SIGVTALRM` - **NOT IMPLEMENTED**
- `ITIMER_PROF` (2): User + system CPU time, delivers `SIGPROF` - **NOT IMPLEMENTED**

**Decision**: Only `ITIMER_REAL` is implemented. `ITIMER_VIRTUAL` and `ITIMER_PROF` require tracking CPU time per-process, which is complex and rarely used. Returns `EINVAL` for unsupported timer types.

## Timer Delivery Mechanism

**Decision**: Timers are checked on syscall boundaries rather than using a background thread.

**Rationale**:
1. **Simplicity**: No need for additional threads or complex synchronization
2. **Consistency**: Matches the existing signal delivery model in LiteBox
3. **Sufficient accuracy**: Most applications using `alarm`/`setitimer` don't require sub-millisecond precision
4. **Safety**: Avoids potential race conditions with async signal delivery

**Trade-offs**:
- Very short timers (< syscall interval) may be delayed
- If the process blocks in a long syscall, the timer won't fire until it returns
- This matches behavior of some other sandbox/emulation systems

## Implementation Details

### State Storage

Add to `Task` struct in `litebox_shim_linux/src/syscalls/signal/mod.rs`:
```rust
/// Interval timer state for ITIMER_REAL
real_timer: Cell<Option<IntervalTimer>>,
```

```rust
struct IntervalTimer {
    /// When the timer should next fire (absolute monotonic time)
    expiration: Instant,
    /// Interval for repeating timers (None = one-shot)
    interval: Option<Duration>,
}
```

### `alarm(seconds)` Implementation

1. If `seconds == 0`: Cancel any existing timer, return remaining seconds
2. Otherwise: Set a one-shot timer to fire after `seconds`, return remaining seconds from previous timer
3. Equivalent to `setitimer(ITIMER_REAL, {it_value={seconds,0}, it_interval={0,0}}, &old)`

### `setitimer(which, new_value, old_value)` Implementation

1. Validate `which == ITIMER_REAL`, else return `EINVAL`
2. If `old_value != NULL`: Write current timer state
3. If `new_value.it_value == {0, 0}`: Disarm timer
4. Otherwise: Arm timer with specified value and interval
5. Return 0 on success

### `getitimer(which, curr_value)` Implementation

1. Validate `which == ITIMER_REAL`, else return `EINVAL`
2. Calculate remaining time until expiration
3. Write to `curr_value`
4. Return 0 on success

### Timer Expiration Check

In `check_for_signals()` or at syscall entry/exit:
```rust
fn check_timer_expiration(&self) {
    if let Some(timer) = self.real_timer.get() {
        if Instant::now() >= timer.expiration {
            self.send_sigalrm();
            // If interval timer, reset expiration
            if let Some(interval) = timer.interval {
                self.real_timer.set(Some(IntervalTimer {
                    expiration: timer.expiration + interval,
                    interval: timer.interval,
                }));
            } else {
                self.real_timer.set(None);
            }
        }
    }
}
```

### Signal Delivery

Add `send_sigalrm()` method to `Task` (similar to existing `send_sigpipe()`):
```rust
pub(crate) fn send_sigalrm(&self) {
    let siginfo = Siginfo {
        signo: Signal::SIGALRM.as_i32(),
        errno: 0,
        code: SI_KERNEL,
        data: SiginfoData::new_zeroed(),
    };
    self.send_signal(Signal::SIGALRM, siginfo);
}
```

## Architecture Support

### x86_64
- `alarm` (syscall 37)
- `setitimer` (syscall 38)
- `getitimer` (syscall 36)

### x86 (32-bit)
- `alarm` (syscall 27)
- `setitimer` (syscall 104)
- `getitimer` (syscall 105)

Both architectures use the same `struct itimerval` layout (timeval uses `long` for both fields).

## Error Handling

| Error | Condition |
|-------|-----------|
| `EFAULT` | Invalid pointer for `new_value`, `old_value`, or `curr_value` |
| `EINVAL` | Invalid `which` value (not `ITIMER_REAL`) |
| `EINVAL` | Invalid `tv_usec` value (>= 1,000,000) |

## Test Plan

### Rust Unit Tests
1. `test_alarm_basic` - Set alarm, verify SIGALRM queued after expiration check
2. `test_alarm_cancel` - Cancel alarm with `alarm(0)`
3. `test_alarm_remaining` - Verify return value is remaining seconds
4. `test_setitimer_oneshot` - One-shot timer
5. `test_setitimer_interval` - Repeating interval timer
6. `test_setitimer_disarm` - Disarm with zero value
7. `test_getitimer_remaining` - Get remaining time
8. `test_setitimer_invalid_which` - EINVAL for unsupported timer types

### C Integration Tests
1. Basic alarm signal delivery
2. Alarm cancellation
3. setitimer with interval
4. getitimer accuracy
5. Signal handler invocation

## Files to Modify

1. `litebox_common_linux/src/lib.rs` - Add `GetITimer` syscall variant, `ITimerVal` struct
2. `litebox_shim_linux/src/lib.rs` - Add dispatch cases
3. `litebox_shim_linux/src/syscalls/signal/mod.rs` - Add timer state, `send_sigalrm()`, timer check
4. `litebox_shim_linux/src/syscalls/process.rs` - Implement `sys_alarm`, `sys_setitimer`, `sys_getitimer`
5. `litebox_shim_linux/src/syscalls/tests.rs` - Add unit tests
6. `litebox_runner_linux_userland/tests/alarm_test.c` - C integration tests

## References

- Linux man pages: alarm(2), setitimer(2), getitimer(2)
- Linux source: `/workspace/linux/kernel/time/itimer.c`
- Asterinas implementation: `/workspace/asterinas/`
