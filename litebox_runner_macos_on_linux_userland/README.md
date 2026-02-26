# litebox_runner_macos_on_linux_userland

Run x86_64 macOS Mach-O binaries on Linux through LiteBox.

## Runtime file mapping conventions

Dynamic Mach-O programs can request runtime files (for example `/usr/lib/dyld` and dylibs).
Provide them with repeated `--runtime-file guest_path=host_path` flags.

Example:

```bash
cargo run --bin litebox_runner_macos_on_linux_userland -- \
  --runtime-file /usr/lib/dyld=./litebox_runner_macos_on_linux_userland/test_binaries/dyld_stub_macos \
  ./litebox_runner_macos_on_linux_userland/test_binaries/hello_dynamic_macos
```

Notes:
- `guest_path` must be absolute.
- Duplicate guest mappings are rejected.
- Missing runtime files fail fast with a descriptive load error.

## Test binaries

The assembly and Zig-toolchain samples live under `test_binaries/`.

```bash
cd litebox_runner_macos_on_linux_userland/test_binaries
make test-static
make test-dynamic
make test-zig-basic
make test-zig-io
```

`make build-zig-samples` builds `zig_basic_macos` and `zig_io_mm_macos` via `zig cc`.

## Using real macOS runtime files (Docker-OSX)

You can stage runtime files under a local gitignored directory:

- `litebox_runner_macos_on_linux_userland/test_binaries/.macos_runtime/usr/lib/dyld`
- `litebox_runner_macos_on_linux_userland/test_binaries/.macos_runtime/usr/lib/libSystem.B.dylib`

`test_binaries/Makefile` has runtime-aware targets:

```bash
cd litebox_runner_macos_on_linux_userland/test_binaries
make populate-macos-runtime
make test-zig-basic-runtime
make test-zig-io-runtime
make test-zig-runtime
```

`make populate-macos-runtime` is a one-step helper that:
- starts or reuses a Docker-OSX container,
- runs it in headless mode by default (`HEADLESS=true`),
- waits for SSH,
- extracts `dyld` and `libSystem.B.dylib` inside the guest,
- copies them into `.macos_runtime/usr/lib/`.

Environment overrides (optional):
- `DOCKER_OSX_IMAGE` (default: `sickcodes/docker-osx:latest`)
- `DOCKER_OSX_CONTAINER` (default: `litebox-docker-osx`)
- `DOCKER_OSX_SSH_PORT` (default: `50922`)
- `DOCKER_OSX_USER` / `DOCKER_OSX_PASS` (default: `user` / `alpine`)
- `DOCKER_OSX_START_TIMEOUT` (default: `1800`)
- `DOCKER_OSX_KEEP_RUNNING` (`1` keeps a newly created container running)

Prerequisites for `populate-macos-runtime`:
- `docker`, `ssh`, `scp`, `sshpass` installed on host.
- `/dev/kvm` available for Docker-OSX.
- Docker-OSX image bootable in your environment.

To populate files using Docker-OSX (on a machine where Docker-OSX is set up):

```bash
# inside macOS guest shell
mkdir -p /tmp/macos-runtime
cp /usr/lib/dyld /tmp/macos-runtime/dyld
dyld_shared_cache_util -extract /tmp/macos-runtime /System/Library/dyld/dyld_shared_cache_x86_64
```

Then copy out and place files at:

```bash
litebox_runner_macos_on_linux_userland/test_binaries/.macos_runtime/usr/lib/dyld
litebox_runner_macos_on_linux_userland/test_binaries/.macos_runtime/usr/lib/libSystem.B.dylib
```

Notes:
- Use files from a legally licensed macOS environment.
- Avoid committing or redistributing Apple runtime binaries.
- Keep architecture aligned (`x86_64` runtime files for `x86_64` guest programs).

## gdb triage workflow

Use this for syscall and entrypoint crashes.

```bash
gdb --args cargo run --bin litebox_runner_macos_on_linux_userland -- \
  litebox_runner_macos_on_linux_userland/test_binaries/zig_io_mm_macos
```

Inside gdb:

```gdb
set pagination off
run
bt
info registers
x/16i $rip-32
```

Then correlate:
1. Faulting RIP/register state from gdb.
2. `litebox_shim_bsd` syscall diagnostics in stderr.
3. Missing syscall number + argument pattern.

After implementing a fix, rerun the smallest failing sample first, then broader sample targets.
