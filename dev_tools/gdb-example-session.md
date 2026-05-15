# GDB example session: from failing test to root cause

A worked example of debugging a litebox integration-test failure
using `LITEBOX_HARNESS_PAUSE` + `gdb-connect-batch.sh`. The scenario
is realistic: a fd-inheritance bug surfaces as `EBADF` on `read`
inside a guest process.

This is a template — adapt the test ID, breakpoint locations, and
probe commands to your own bug.

## Scenario

Test `litebox::PB.c2p.nonpie-glibc.dpg2` fails:

```
{"test":"PB.c2p.nonpie-glibc.dpg2","agent":"dpg2","result":"FAIL",
 "detail":"Err(\"read failed: EBADF\")"}
```

The test exercises a child-to-parent pipe path where the parent is
PIE-glibc but the child is non-PIE-glibc (so the runner spawns a
non-PIE worker). The `EBADF` suggests the pipe read-end fd didn't
make it across `posix_spawn` into the worker's fd table.

`litebox_audit_query` confirms: the `read(<fd>)` system call returns
`EBADF` because that fd index has no entry in the worker's
`FdTable`. Time to attach gdb.

## Step 1: arrange for the test to pause at start

Set `LITEBOX_HARNESS_PAUSE` so the harness `raise(SIGSTOP)`s itself
right before running our specific failing test. This eliminates the
race between attaching gdb and the bug firing:

```bash
# Inside the docker container (we'll launch it below):
export LITEBOX_HARNESS_PAUSE='harness:test-start=PB.c2p.nonpie-glibc.dpg2'
```

## Step 2: start the docker container with gdbserver listening

```bash
WS=$(pwd)  # workspace root containing target/
docker run --rm -it --cap-add SYS_PTRACE \
  -p 9999:9999 \
  -e LITEBOX_HARNESS_PAUSE='harness:test-start=PB.c2p.nonpie-glibc.dpg2' \
  -v "$WS/target/debug:/opt/litebox:ro" \
  -v "$WS/target/nonpie/debug:/opt/nonpie:ro" \
  litebox-test \
    /opt/litebox/litebox_tool_executor \
      --rootfs / --record-baseline \
      --debug 9999 \
      -- \
    /opt/litebox/litebox_test_harness spawn-tree \
      --filter='litebox::PB.c2p.nonpie-glibc.dpg2'
```

The container output will show:

```
=== GDB DEBUG MODE ===
  gdbserver listening on port 9999
  Connect from host with:
    gdb -ex 'target remote localhost:9999' /opt/litebox/litebox_tool_executor
  Or use: bash dev_tools/gdb-connect.sh --port 9999
  Or non-interactive (transcript only, good for coding agents):
    bash dev_tools/gdb-connect-batch.sh --port 9999 --commands probe.gdb
======================
```

…then later, after spawn-tree has set up the agent matrix:

```
[litebox-pause] tag=harness:test-start filter=PB.c2p.nonpie-glibc.dpg2 \
                pid=42 waiting for SIGCONT (resume with: kill -CONT 42)
```

That `pid=42` is the harness inside the container. The whole process
tree is now stopped (gdbserver has the executor under its control)
waiting for us.

## Step 3: write the probe script

`probe.gdb` (on the host):

```gdb
# Investigate why the non-PIE worker can't read the pipe.
# We're targeting two suspects, both in the runner:
#   1. posix_spawn fd-bridge setup — does the read-end get into the
#      worker's fd_actions list?
#   2. Worker-side FdTable::apply_to_child — does it install the fd?

set logging file probe.log
set logging on

# Capture posix_spawn invocations + their fd-action list.
break litebox_platform_linux_userland::posix_spawn
commands
  silent
  printf "=== posix_spawn called (tid=%d) ===\n", $_thread
  printf "argv0 = "
  print *argv@1
  bt 3
  continue
end

# Capture worker-side fd install.
break litebox_runner_linux_userland::fd::FdTable::apply_to_child
commands
  silent
  printf "=== FdTable::apply_to_child (tid=%d) ===\n", $_thread
  bt 5
  info locals
  continue
end

# Make sure we don't loiter — continue all the way through.
continue
# When the test finishes (or hits a timeout), gdbserver disconnects.
quit
```

## Step 4: drive the probe from a second terminal on the host

```bash
bash dev_tools/gdb-connect-batch.sh \
  --port 9999 \
  --commands probe.gdb \
  --timeout 60 \
  > probe.transcript.txt 2>&1

# Once gdb is attached and breakpoints are set, release the harness:
docker exec <container-name> kill -CONT 42
```

(If you don't know the container name, `docker ps --filter ancestor=litebox-test`.)

The `gdb-connect-batch.sh` script:

- Auto-discovers debug symbols in `target/debug/`.
- Connects to `localhost:9999`.
- Defaults to `set follow-fork-mode parent` (shim-side debugging).
- Pre-loads symbols for the runner and broker.
- Sets `handle SIGSYS nostop noprint pass` so seccomp doesn't stop gdb.
- Runs your probe.gdb in batch mode and exits.
- Times out at 60s if the probe hangs (override with `--timeout`).

## Step 5: read the transcript

```
=== posix_spawn called (tid=1) ===
argv0 = $1 = "/opt/nonpie/litebox_test_harness"
#0  litebox_platform_linux_userland::posix_spawn at ...
#1  litebox_runner_linux_userland::worker_exec at ...
#2  litebox_runner_linux_userland::syscalls::process::handle_clone at ...

=== FdTable::apply_to_child (tid=2) ===
#0  litebox_runner_linux_userland::fd::FdTable::apply_to_child
#1  litebox_runner_linux_userland::syscalls::fd::post_clone_setup
...
fd_inheritance = {3: BridgeFd(...), 4: BridgeFd(...), 5: HostFd(...)}
expected_pipe_read = 6   # ← missing from fd_inheritance!
```

## Step 6: localize the fix

The transcript shows that fd 6 (the pipe read-end) was NOT in the
`fd_inheritance` map handed to `apply_to_child`. So the bug is
upstream of `apply_to_child`: it's in how `worker_exec` collects
the inherited fd set when the spawning process is PIE-glibc but the
child is non-PIE-glibc.

Read the code path:

```bash
$ rg 'fn worker_exec' litebox_runner_linux_userland/src/
$ rg 'fd_inheritance' litebox_runner_linux_userland/src/syscalls/process.rs
```

Find the conditional that excludes fd 6, fix it, write a regression
test, verify on both native and litebox.

## When pause points aren't enough

Pause points freeze one process. If the bug is timing-sensitive
between processes (e.g., a race between the runner and broker), use
gdb breakpoints with `commands ... silent ... <printf> ... continue end`
to log without stopping. Or attach a second `gdb-connect-batch.sh`
with a different probe targeting the broker inferior:

```gdb
# probe-broker.gdb
inferior 2    # switch to broker
break litebox_broker::cwfd::pipe_state::CrossWorkerPipe::handle_incref
commands
  silent
  printf "incref pipe state\n"
  continue
end
continue
quit
```

## Summary

The full debugging round-trip:

1. **Observe** the failure in `cargo test` output / audit log.
2. **Localize** to a suspect subsystem via the failure-shape cookbook
   in `FIX_AGENT_PLAYBOOK.md`.
3. **Pause** the harness before the bug fires
   (`LITEBOX_HARNESS_PAUSE=harness:test-start=<id>`).
4. **Probe** with `gdb-connect-batch.sh --commands probe.gdb`.
5. **Read** the transcript, localize the fix.

No interactive `(gdb)` driving required.
