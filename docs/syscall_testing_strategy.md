# LiteBox Syscall Testing Strategy

This document outlines the testing strategy for implementing and validating new syscalls in LiteBox, including how to use test failures to drive code corrections.

---

## Executive Summary

The testing strategy follows a **Test-Driven Development (TDD)** approach:
1. Write tests that define expected behavior (validated against native Linux)
2. Run tests to see them fail
3. Implement the syscall
4. Use failure messages to correct implementation
5. Iterate until all tests pass
6. Add regression tests for any bugs found

---

## Current Test Infrastructure

### Test Layers

| Layer | Location | Purpose |
|-------|----------|---------|
| **Unit Tests** | `litebox_shim_linux/src/syscalls/tests.rs` | Direct syscall method testing |
| **Integration Tests** | `litebox_runner_linux_userland/tests/` | Run real programs in sandbox |
| **C Test Programs** | `litebox_runner_linux_userland/tests/*.c` | Syscall behavior verification |

### Test Execution Flow

```
C source file (.c)
    ↓ gcc compile (static or dynamic)
    ↓ litebox_syscall_rewriter (rewrite syscall instructions)
    ↓ ldd (find dependencies)
    ↓ tar (create rootfs)
    ↓ litebox_runner_linux_userland (execute in sandbox)
    ↓ Assert exit code == 0
```

### Running Tests

```bash
# Run all tests
cargo nextest run

# Run specific package tests
cargo nextest run -p litebox_shim_linux
cargo nextest run -p litebox_runner_linux_userland

# Run single test with output
cargo nextest run test_name -- --nocapture

# Run doc tests (separate from nextest)
cargo test --doc

# Run 32-bit tests
cargo nextest run --target=i686-unknown-linux-gnu
```

---

## Test-Driven Development Process

### Step 1: Write Tests First

Before implementing a syscall, write tests that define expected behavior.

#### Unit Test Template

Add to `litebox_shim_linux/src/syscalls/tests.rs`:

```rust
#[test]
fn test_my_syscall_basic() {
    let task = init_platform(None);

    // Setup: create necessary resources
    let fd = task.sys_open("/test_file", OFlags::RDWR | OFlags::CREAT, Mode::from_bits(0o644).unwrap())
        .expect("open should succeed");

    // Test: call the syscall
    let result = task.sys_my_syscall(fd, args...);

    // Verify: check return value
    assert!(result.is_ok(), "my_syscall should succeed");
    assert_eq!(result.unwrap(), expected_value);

    // Cleanup
    task.sys_close(fd).unwrap();
}

#[test]
fn test_my_syscall_ebadf() {
    let task = init_platform(None);

    // Test with invalid fd
    let result = task.sys_my_syscall(-1, args...);

    assert_eq!(result, Err(Errno::EBADF), "should return EBADF for invalid fd");
}

#[test]
fn test_my_syscall_efault() {
    let task = init_platform(None);

    // Test with invalid pointer (null)
    let null_ptr = MutPtr::from_usize(0);
    let result = task.sys_my_syscall(null_ptr);

    assert_eq!(result, Err(Errno::EFAULT), "should return EFAULT for null pointer");
}
```

#### C Integration Test Template

Create `litebox_runner_linux_userland/tests/my_syscall.c`:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

// Test helper macro
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        exit(1); \
    } \
} while(0)

#define TEST_ERRNO(expected) do { \
    if (errno != expected) { \
        fprintf(stderr, "FAIL: Expected errno %d (%s), got %d (%s)\n", \
                expected, strerror(expected), errno, strerror(errno)); \
        exit(1); \
    } \
} while(0)

void test_basic_functionality() {
    // Test normal operation
    int result = my_syscall(...);
    TEST_ASSERT(result >= 0, "my_syscall should succeed");
    printf("PASS: test_basic_functionality\n");
}

void test_error_ebadf() {
    // Test EBADF error
    errno = 0;
    int result = my_syscall(-1, ...);
    TEST_ASSERT(result == -1, "should return -1 on error");
    TEST_ERRNO(EBADF);
    printf("PASS: test_error_ebadf\n");
}

void test_error_efault() {
    // Test EFAULT error
    errno = 0;
    int result = my_syscall(NULL, ...);
    TEST_ASSERT(result == -1, "should return -1 on error");
    TEST_ERRNO(EFAULT);
    printf("PASS: test_error_efault\n");
}

int main() {
    printf("Starting my_syscall tests...\n");

    test_basic_functionality();
    test_error_ebadf();
    test_error_efault();

    printf("All tests passed!\n");
    return 0;
}
```

### Step 2: Validate Against Native Linux

Before implementing, verify your test expectations are correct:

```bash
# Compile test program
gcc -o test_my_syscall tests/my_syscall.c

# Run on native Linux
./test_my_syscall

# If tests fail on native Linux, fix the test expectations!
```

### Step 3: Run Tests and Analyze Failures

```bash
# Run the test
cargo nextest run test_my_syscall -- --nocapture

# Expected output for unimplemented syscall:
# WARNING: unsupported: my_syscall(...)
# thread 'test_my_syscall' panicked at 'assertion failed: result.is_ok()'
```

### Step 4: Implement the Syscall

Based on test failures, implement the syscall:

1. **Add to `SyscallRequest` enum** in `litebox_common_linux/src/lib.rs`:
   ```rust
   MySyscall {
       fd: i32,
       buf: Platform::RawMutPointer<u8>,
       count: usize,
   },
   ```

2. **Parse in `try_from_raw`**:
   ```rust
   Sysno::my_syscall => sys_req!(MySyscall { fd, buf:*, count }),
   ```

3. **Handle in `do_syscall`** in `litebox_shim_linux/src/lib.rs`:
   ```rust
   SyscallRequest::MySyscall { fd, buf, count } => {
       syscall!(sys_my_syscall(fd, buf, count))
   }
   ```

4. **Implement `sys_my_syscall`** in appropriate module:
   ```rust
   impl Task {
       pub(crate) fn sys_my_syscall(
           &self,
           fd: i32,
           buf: MutPtr<u8>,
           count: usize,
       ) -> Result<usize, Errno> {
           // Implementation here
       }
   }
   ```

### Step 5: Iterate Based on Test Failures

Common failure patterns and fixes:

| Failure Message | Likely Cause | Fix |
|-----------------|--------------|-----|
| `ENOSYS` returned | Syscall not in `do_syscall` match | Add match arm |
| `EBADF` unexpected | FD lookup failed | Check descriptor table logic |
| `EFAULT` unexpected | Pointer validation failed | Check pointer read/write |
| `EINVAL` unexpected | Argument validation failed | Check argument bounds |
| Wrong return value | Logic error | Debug with `eprintln!` |
| Panic in handler | Unhandled case | Add missing match arm |

### Step 6: Add Regression Tests

For any bug found during development:

```rust
#[test]
fn test_my_syscall_regression_issue_123() {
    // This test reproduces issue #123
    // The bug was: [description]
    let task = init_platform(None);

    // Specific sequence that triggered the bug
    // ...

    // Verify the fix
    assert!(result.is_ok());
}
```

---

## Test Categories

### 1. Positive/Happy Path Tests

Test normal operation with valid inputs:

```rust
#[test]
fn test_read_basic() {
    // Open file, read some bytes, verify content
}
```

### 2. Error Condition Tests

Test all documented errno values:

```rust
#[test]
fn test_read_ebadf() { /* invalid fd */ }

#[test]
fn test_read_efault() { /* bad buffer pointer */ }

#[test]
fn test_read_eisdir() { /* read from directory */ }

#[test]
fn test_read_einval() { /* invalid arguments */ }
```

### 3. Boundary Condition Tests

Test limits and edge cases:

```rust
#[test]
fn test_read_zero_bytes() { /* count = 0 */ }

#[test]
fn test_read_max_size() { /* very large count */ }

#[test]
fn test_read_empty_file() { /* EOF handling */ }
```

### 4. Concurrency Tests

Test thread safety:

```c
// tests/concurrent_read.c
void* reader_thread(void* arg) {
    // Multiple threads reading same fd
}

int main() {
    // Create threads, wait for completion
    // Verify no corruption
}
```

### 5. Signal Interaction Tests

Test EINTR and signal handling:

```c
// tests/read_signal.c
volatile sig_atomic_t alarm_fired = 0;

void handler(int sig) {
    alarm_fired = 1;
}

void test_read_eintr() {
    signal(SIGALRM, handler);
    alarm(1);

    int ret = read(fd, buf, size);
    if (ret == -1 && errno == EINTR) {
        printf("PASS: read returned EINTR\n");
    }
}
```

---

## Debugging Test Failures

### Enable Debug Output

```rust
// In litebox_shim_linux, add debug prints
if cfg!(debug_assertions) {
    eprintln!("sys_my_syscall: fd={}, count={}", fd, count);
}
```

### Use log_unsupported Macro

```rust
log_unsupported!("my_syscall: unhandled flag {:?}", flags);
```

### Run Single Test with Full Output

```bash
cargo nextest run test_name -- --nocapture 2>&1 | tee test.log
```

### Compare with strace

Run the same test on native Linux with strace:

```bash
strace -f ./test_program 2>&1 | grep my_syscall
```

Compare syscall arguments and return values with LiteBox output.

---

## Continuous Integration

### CI Configuration (`.github/workflows/ci.yml`)

Tests automatically run on:
- Every push and PR
- Linux x86_64 and i686
- Windows (platform tests)
- LVBS/SNP targets

### Nextest Configuration (`.config/nextest.toml`)

```toml
[profile.ci]
fail-fast = false
retries = 2
slow-timeout = { period = "10m" }

# TUN tests need exclusive access
[[profile.ci.overrides]]
filter = "test(/tun/)"
test-threads = 1
```

---

## Test Checklist for New Syscalls

Before submitting a PR for a new syscall:

- [ ] Unit tests for happy path
- [ ] Unit tests for all documented errno values
- [ ] Unit tests for boundary conditions
- [ ] C integration test program
- [ ] Test validated against native Linux
- [ ] Test passes on both x86_64 and i686
- [ ] Test passes in CI
- [ ] No new warnings from `cargo clippy`
- [ ] Documentation updated if needed

---

## Example: Testing `fsync` Implementation

### Step 1: Write Tests

**Unit test** (`litebox_shim_linux/src/syscalls/tests.rs`):

```rust
#[test]
fn test_fsync_basic() {
    let task = init_platform(None);

    let fd = task.sys_openat(AT_FDCWD, "/test_file",
        OFlags::RDWR | OFlags::CREAT, Mode::from_bits(0o644).unwrap())
        .expect("open should succeed");

    // Write some data
    task.sys_write(fd, b"test data", None).expect("write should succeed");

    // fsync should succeed
    let result = task.sys_fsync(fd);
    assert!(result.is_ok(), "fsync should succeed on valid fd");

    task.sys_close(fd).unwrap();
}

#[test]
fn test_fsync_ebadf() {
    let task = init_platform(None);

    let result = task.sys_fsync(-1);
    assert_eq!(result, Err(Errno::EBADF));
}

#[test]
fn test_fsync_einval() {
    let task = init_platform(None);

    // fsync on a pipe should return EINVAL (or EROFS depending on impl)
    let (read_fd, _write_fd) = task.sys_pipe2(OFlags::empty()).unwrap();

    let result = task.sys_fsync(read_fd as i32);
    assert!(result.is_err(), "fsync on pipe should fail");
}
```

**C test** (`tests/fsync_test.c`):

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
    // Test basic fsync
    int fd = open("/tmp/fsync_test", O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        perror("open failed");
        return 1;
    }

    write(fd, "test data", 9);

    if (fsync(fd) != 0) {
        perror("fsync failed");
        return 1;
    }
    printf("PASS: fsync succeeded\n");

    close(fd);

    // Test EBADF
    errno = 0;
    if (fsync(-1) == 0 || errno != EBADF) {
        fprintf(stderr, "FAIL: fsync(-1) should return EBADF\n");
        return 1;
    }
    printf("PASS: fsync(-1) returned EBADF\n");

    printf("All fsync tests passed!\n");
    return 0;
}
```

### Step 2: Run and Fail

```bash
$ cargo nextest run test_fsync -- --nocapture

# Expected failure:
# WARNING: unsupported: fsync(fd = 3)
# assertion `left == right` failed
#   left: Err(ENOSYS)
#   right: Ok(())
```

### Step 3: Implement

```rust
// In litebox_shim_linux/src/syscalls/file.rs
impl Task {
    pub(crate) fn sys_fsync(&self, fd: i32) -> Result<(), Errno> {
        // For now, stub as success (data is already in memory)
        // TODO: Actually sync to backing store when persistent storage is added

        // Validate fd exists
        let files = self.files.borrow();
        let _desc = files.file_descriptors.read()
            .get_fd(fd as u32)
            .ok_or(Errno::EBADF)?;

        Ok(())
    }
}
```

### Step 4: Run and Pass

```bash
$ cargo nextest run test_fsync -- --nocapture

# test test_fsync_basic ... ok
# test test_fsync_ebadf ... ok
```

---

## Advanced Testing

### Fuzzing with cargo-fuzz

```bash
# Setup
cargo install cargo-fuzz

# Create fuzz target
mkdir -p fuzz/fuzz_targets
```

```rust
// fuzz/fuzz_targets/fuzz_read.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into syscall arguments
    // Call syscall handler
    // Verify no panics
});
```

### LTP Integration

Consider running a subset of Linux Test Project tests:

```bash
# Build LTP statically
cd ltp
./configure --disable-metadata
make -j$(nproc)

# Run specific syscall tests through LiteBox
./litebox_runner_linux_userland ./ltp/testcases/kernel/syscalls/read/read01
```

---

## References

- [gVisor Syscall Test Suite](https://github.com/google/gvisor/tree/master/test/syscalls)
- [Linux Test Project](https://github.com/linux-test-project/ltp)
- [syzkaller Fuzzer](https://github.com/google/syzkaller)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
