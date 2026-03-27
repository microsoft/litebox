# Host PTY Identity for Sandbox Stdio

## Problem Statement

Claude Code's interactive TUI mode renders inside the LiteBox Linux sandbox but
ignores all keyboard input. Prompt mode (non-interactive) works fine.

### Root Cause

The sandbox reports stdin as `/dev/tty` (major 5, minor 0) instead of the actual
host PTY slave device (e.g., `/dev/pts/156`, major 136, minor 156). This breaks
Bun/libuv's terminal discovery and reopen flow.

### Evidence

**Native Bun behavior** (from strace of Claude Code interactive mode):

1. `ioctl(0, TIOCGPTN, ...)` → `ENOTTY` (fd 0 is a PTY slave, not a master)
2. Discovers its PTY path (likely via `fstat(0)` → `st_rdev` → construct path,
   or via `ttyname_r(0)`)
3. `openat(AT_FDCWD, "/dev/pts/140", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_CLOEXEC)` → fd 11
4. Reads **all** keyboard input from fd 11:
   `read(11, "hello\r", 262144) = 6`

Native Claude does **not** read interactive input from fd 0 (stdin).

**Sandbox behavior** (from a reduced Python probe inside the IPC/9P sandbox):

| Check                         | Native                      | Sandbox                    |
|-------------------------------|-----------------------------|----------------------------|
| `ttyname(0)`                  | `/dev/pts/156`              | ERROR (ENOTTY)             |
| `readlink(/proc/self/fd/0)`   | `/dev/pts/156`              | `/dev/tty`                 |
| `fstat(0) st_rdev`            | `major=136 minor=156`       | `major=5 minor=0`          |

Because `ttyname_r()` fails in the sandbox, Bun cannot discover and reopen its
controlling terminal. The sandbox strace shows that sandboxed Claude never opens
a specific `/dev/pts/N` and never reads user input on any fd.

Meanwhile, reduced probes confirmed that generic stdin readiness, raw-mode
input, reopened `/dev/tty` reads, and non-PIE remote worker stdio all work
correctly in the sandbox. The problem is specifically that Bun's standard
terminal discovery flow produces no usable fd.

### Current Code Paths That Produce the Wrong Identity

1. `STDIN_NODE_INFO` in `litebox/src/fs/devices.rs` hardcodes `rdev: 0x500`
   (major 5, minor 0 — the generic `/dev/tty` identity).

2. `do_readlink()` in `litebox_shim_linux/src/syscalls/file.rs` returns
   `"/dev/tty"` when readlinking `/proc/self/fd/0` for a tty stdin fd.

3. `Device::Tty` is only opened by the path `/dev/tty` in the device FS.
   There is no mechanism to open the host PTY's actual device path
   (e.g., `/dev/pts/156`) and get a device fd backed by the host stdin.

## Proposed Design

### Goal

Make `fstat(0)`, `readlink("/proc/self/fd/0")`, and `open("/dev/pts/N")` return
results consistent with the actual host terminal, so that Bun's standard
terminal discovery and reopen flow works inside the sandbox.

### Key Constraint

The internal `classify_terminal()` routing must continue to classify
stdin/stdout/stderr as `HostStdio` (not `Pty`). The shim's ioctl handling for
host stdio delegates to the host kernel, whereas the `Pty` path uses the
sandbox's internal PTY buffers. Changing the classification would break all
terminal ioctls.

### Changes by Layer

#### 1. Platform Trait (`litebox/src/platform/mod.rs`)

Add a new method to `StdioProvider`:

```rust
fn host_stdin_tty_device_info(&self) -> Option<HostTtyDeviceInfo> { None }
```

With a new struct:

```rust
pub struct HostTtyDeviceInfo {
    /// Device path on the host, e.g., "/dev/pts/156".
    pub path: String,
    /// st_rdev from fstat() on the host fd, e.g., 0x889c for major 136, minor 156.
    pub rdev: usize,
    /// st_dev from fstat() on the host fd (devpts superblock device number).
    pub dev: u64,
    /// st_ino from fstat() on the host fd (inode within devpts).
    pub ino: u64,
}
```

Returns `None` on non-terminal stdin (pipes, files, Windows). Returns the host
PTY path, `st_rdev`, `st_dev`, and `st_ino` on Linux when stdin is a real PTY
slave. All three identity fields are needed because glibc `ttyname_r` uses
`is_mytty()` which verifies that `st_dev`, `st_ino`, **and** `st_rdev` all
match between `fstat(fd)` and `stat(discovered_path)`.

#### 2. Linux Userland Implementation (`litebox_platform_linux_userland/src/lib.rs`)

Implement `host_stdin_tty_device_info()`:

- Call host `fstat(0)` to get `st_rdev`
- Call host `ttyname_r(0, ...)` to get the device path (e.g., `/dev/pts/156`)
- Cache the result at first call (the host PTY does not change during the
  sandbox process lifetime)
- Return `None` if either call fails (stdin is not a real PTY)

#### 3. Shim `fstat` Override (`litebox_shim_linux/src/syscalls/file.rs`)

In `descriptor_stat()`: after getting `FileStat` from the device FS for a file
descriptor, check if the fd has `HostStdioSourceFd` metadata pointing to stdin
(source_fd == 0) or stdout/stderr, **or** if the fd has a new
`HostPtyDeviceFd` metadata marker (see Section 5). If so, and if
`platform.host_stdin_tty_device_info()` returns `Some(info)`, override
`st_rdev` with `info.rdev`, `st_dev` with `info.dev`, and `st_ino` with
`info.ino`.

All three fields must be overridden because glibc's `is_mytty()` checks:
```c
maybe->st_ino == mytty->st_ino
&& maybe->st_dev == mytty->st_dev
&& S_ISCHR(maybe->st_mode)
&& maybe->st_rdev == mytty->st_rdev
```
Overriding only `st_rdev` would cause `ttyname_r` to fail at the
verification step when it compares `fstat(0)` against `stat("/dev/pts/N")`.

This is a **post-hoc override**: the device FS still internally reports
`rdev=0x500`, which keeps `classify_terminal()` routing `major 5` →
`HostStdio`. Only the guest-visible `fstat()`/`statx()` result changes.

#### 4. Shim `readlink` Override (`litebox_shim_linux/src/syscalls/file.rs`)

In `do_readlink()` for `/proc/self/fd/{0,1,2}`: when the fd is a tty stdio
stream and `host_stdin_tty_device_info()` returns `Some(info)`, return
`info.path` instead of `"/dev/tty"`.

#### 5. Device FS Open and Stat Interception (`litebox/src/fs/devices.rs`)

**Open interception:** In `FileSystem::open()`, the existing
`p if p.starts_with("/dev/pts/")` arm (line 531) matches all `/dev/pts/N`
paths. The host PTY intercept must go **inside this arm**, after parsing the
index but **before** the `pty_manager.get(idx)` lookup. If the parsed path
matches the host PTY device path (queried via the platform through
`self.litebox`), create a `Device::Tty` fd immediately — same as opening
`/dev/tty`. Only fall through to the internal PTY manager lookup if it
doesn't match.

Placing the check before the PTY manager lookup avoids a collision if the
sandbox ever allocates an internal PTY with the same index as the host PTY
minor number.

**Stat interception:** Similarly, in `FileSystem::file_status()`, the
`/dev/pts/N` arm (line 862) must check for the host PTY path before
returning `NoSuchFileOrDirectory`. If the path matches, return a
`Device::Tty` file status — but with the **host PTY rdev** (from the
platform info), not the default `0x500`. This ensures that
`stat("/dev/pts/N")` returns identity fields matching the overridden
`fstat(0)` result, which is required for `ttyname_r`'s `is_mytty`
verification.

**fd metadata for reopened PTY:** When the open intercept creates a
`Device::Tty` fd from a `/dev/pts/N` open, it must attach a
`HostPtyDeviceFd` metadata marker to the fd. This marker causes the
shim's `descriptor_stat()` fstat override to also fire for this fd —
ensuring `fstat(new_fd)` returns the host PTY identity, not the default
`Device::Tty` identity (`rdev=0x500`). Without this, Bun could open
`/dev/pts/N` successfully but then see inconsistent device info if it
calls `fstat` or `ttyname_r` on the new fd.

### What Does NOT Change

- **`classify_terminal()`** — still uses the device FS's internal rdev
  (`major 5` → `HostStdio`). The fstat override only affects what the guest
  sees via `sys_fstat`/`sys_statx`. The `fd_file_status()` path used by
  `classify_terminal()` goes through the device FS, which still reports
  `rdev=0x500` for `Device::Tty` entries.
- **Internal PTY allocation** — sandbox-allocated PTYs via `/dev/ptmx` are
  unaffected. The host PTY check runs before the PTY manager lookup, but
  only matches one specific path.
- **Host stdio read/poll/ioctl paths** — all existing `Device::Tty` routing
  stays the same. A fd opened via the host PTY path uses the same read,
  poll, and ioctl paths as a fd opened via `/dev/tty`.
- **Windows userland** — `host_stdin_tty_device_info()` returns `None` by
  default; no behavior change.

### Data Flow After the Fix

```
Guest: ttyname_r(0)
  1. fstat(0)
     → device FS returns rdev=0x500, dev=64, ino=9
     → shim override: st_rdev=info.rdev, st_dev=info.dev, st_ino=info.ino
     → guest sees st_rdev=0x889c, st_dev=27, st_ino=167          [override]

  2. readlink("/proc/self/fd/0")
     → shim returns info.path instead of "/dev/tty"
     → guest sees "/dev/pts/156"                                   [override]

  3. stat("/dev/pts/156")
     → device FS recognizes host PTY path
     → returns st_rdev=info.rdev, st_dev=info.dev, st_ino=info.ino
     → is_mytty: dev✓ ino✓ rdev✓ → ttyname_r succeeds            [new intercept]

Guest: openat(AT_FDCWD, "/dev/pts/156", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_CLOEXEC)
  → device FS recognizes host PTY path → creates Device::Tty fd
  → attaches HostPtyDeviceFd metadata                              [new intercept]

Guest: fstat(new_fd)
  → device FS returns Device::Tty default (rdev=0x500)
  → shim sees HostPtyDeviceFd metadata → overrides all three fields
  → guest sees host PTY identity                                   [override]

Guest: poll(new_fd, POLLIN)
  → StdinPollable → poll_stdin_readable() → host poll(fd=0)       [existing path]

Guest: read(new_fd, buf, len)
  → Device::Tty → read_from_stdin()                                [existing path]
```

## Validation Plan

1. Rerun the TTY discovery probe in the sandbox — verify `ttyname(0)`,
   `readlink(/proc/self/fd/0)`, and `fstat(0)` now return PTY-consistent values
2. Verify `open("/dev/pts/N")` in the sandbox creates a working tty fd that can
   be read
3. Run existing shim tests (`cargo test -p litebox_shim_linux` for focused tty
   tests) to confirm no regressions
4. Verify `classify_terminal()` still routes stdin to `HostStdio` (not `Pty`)
5. Run real interactive Claude and test keyboard input acceptance

## Risks

1. **Bun's discovery mechanism may differ.** If Bun discovers the PTY path via
   a mechanism other than `fstat` → rdev → path construction or `ttyname_r`,
   this fix won't help. The native strace evidence strongly suggests this is
   the flow, but the critical syscalls (`fstat`, `readlinkat`) were not in the
   strace filter. Mitigation: Claude links against glibc, and we traced glibc's
   `ttyname_r` doing exactly `fstat` → `readlink` → `stat` → verify.

2. **PTY number collision.** ~~The host PTY number could theoretically match a
   sandbox-internal PTY index.~~ **Addressed:** The host PTY path check now
   runs **before** the internal PTY manager lookup, so the host PTY always
   takes priority. This means if the sandbox allocates an internal PTY that
   happens to have the same index as the host PTY minor, the internal PTY's
   `/dev/pts/N` path becomes shadowed. In practice, sandbox workloads allocate
   very few PTYs (starting from index 0), while host PTY minors are typically
   much higher.

3. **Multiple-terminal environments.** If stdout/stderr are connected to
   different terminals than stdin, reporting a single `host_stdin_tty_device_info`
   for all three may be inaccurate. The initial implementation scopes this to
   stdin only, which covers the Bun/Claude case. Extending to per-stream info
   can be done later if needed.

4. **`classify_terminal()` consistency.** The design creates a split between
   "internal rdev for routing" (always `0x500` / major 5) and "guest-visible
   rdev for compat" (host PTY rdev / major 136). This is intentional:
   `classify_terminal()` uses `fd_file_status()` which reads from the device
   FS directly, while the guest sees the overridden value only through
   `sys_fstat()`/`sys_statx()`. If a future refactor unifies these paths,
   the routing distinction must be preserved.

## Review Feedback Incorporated

- **GPT-5.4**: Identified the `stat("/dev/pts/N")` gap — the design now adds
  both `open` and `file_status` interception in the device FS. Also identified
  the PTY number collision risk — the design now checks the host PTY path
  before the internal PTY manager lookup.

- **Claude Opus 4.6**: Found the **critical** `is_mytty` bug — glibc checks
  `st_dev`, `st_ino`, AND `st_rdev` (not just `st_rdev`). The design now
  overrides all three fields and `HostTtyDeviceInfo` carries all three.
  Also identified that the open intercept must go **inside** the existing
  `/dev/pts/N` match arm (not the catch-all `_`), and that reopened fds
  need `HostPtyDeviceFd` metadata for consistent fstat results.
