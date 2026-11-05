# Experimental Linux containers on macOS

`containerd-shim-litebox-v1` implements containerd's runtime v2 task API as
`io.containerd.litebox.v1`. On Apple Silicon it connects **native Darwin containerd
and ctr** to the Linux-on-macOS LiteBox runner. There is no VM, Linux kernel,
Linux namespace, host bind mount, or cgroup in this path:

```text
Darwin ctr -> Darwin containerd -> Darwin containerd-shim-litebox-v1
                                    -> Darwin litebox-broker-userland
                                         -> Linux litebox-guest-service
                                              -> Linux container processes
```

The shim, broker, and runner are native Mach-O programs (the shim embeds the
runner). The guest service is a **Linux AArch64 static PIE**, not a macOS binary.
It speaks ttrpc through the broker's Unix-socket hybrid-vsock bridge; this is a
local transport, not a VM vsock device. Each container has its own broker.

This brings over the guest service and Linux shim from
`sanghle/ulitebox/guest_service_3_shim`. The Windows branch
`sanghle/ulitebox/guest_service_3_shim_windows` uses the same service model, but its
Job Objects and named-pipe transport are not needed on macOS.

## Build

Run these commands from the workspace root on an AArch64 Mac. Install Rust and
Zig (tested with Zig 0.15.2), then:

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --locked --release -p litebox_containerd_shim -p litebox_broker_userland

CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$PWD/litebox_containerd_shim/tools/linux-musl-cc.sh" \
RUSTFLAGS='-C relocation-model=pic -C link-self-contained=no' \
cargo build --locked --release -p litebox_guest_service --target aarch64-unknown-linux-musl

sudo install -m 755 \
    target/release/containerd-shim-litebox-v1 \
    target/release/litebox-broker-userland \
    target/aarch64-unknown-linux-musl/release/litebox-guest-service \
    /usr/local/bin/
```

The linker wrapper uses Zig's musl CRT to produce a real static PIE, including
its self-relocation startup. Simply adding `-pie` to an ordinary static Rust
executable is not sufficient. The same wrapper can compile small Linux C guests.

The shim finds the broker and guest service beside itself. Alternatively set
`LITEBOX_BROKER` and `LITEBOX_GUEST_SERVICE` in **containerd's environment** to
absolute executable paths. `LITEBOX_SHIM_STATE_ROOT` overrides the shim's private
archive/state directory. Broker sockets use a separate short, private directory
under `/tmp/lbx-shim-<uid>` to fit Darwin's 104-byte Unix socket limit even when
containerd's state paths or macOS's `TMPDIR` are long.

Build native containerd/ctr if they are not already installed. No containerd patch
is required by this shim; for example, in a separate containerd v2.2.0 checkout:

```sh
git clone --depth 1 --branch v2.2.0 https://github.com/containerd/containerd.git
cd containerd
CGO_ENABLED=0 go build -o bin/ ./cmd/containerd ./cmd/ctr
sudo install -m 755 bin/containerd bin/ctr /usr/local/bin/
```

## Run native containerd

From the LiteBox workspace, in one terminal:

```sh
sudo env PATH="/usr/local/bin:$PATH" containerd \
    --config "$PWD/litebox_containerd_shim/examples/containerd-macos.toml"
```

The example disables CRI/CNI and advertises `linux/arm64` tasks. Use an isolated
containerd installation/state root if you already run containerd. Upstream
containerd and its Rust shim helper use `/var/run/containerd` for shim sockets,
**even with a custom daemon state directory**; that directory needs administrator
provisioning. The direct task-service tests below do not need root.

A registry-free smoke test:

```sh
ROOTFS=$(mktemp -d /tmp/litebox-rootfs.XXXXXX)
mkdir -p "$ROOTFS/bin"
litebox_containerd_shim/tools/linux-musl-cc.sh -O1 \
    litebox_containerd_shim/tests/guest.c -o "$ROOTFS/bin/guest"

sudo ctr --namespace litebox run --rm --runtime io.containerd.litebox.v1 \
    --rootfs "$ROOTFS" hello /bin/guest exit 0
```

`ctr`'s `--namespace` is only a containerd metadata namespace, not a Linux kernel
namespace. `--net-host` is not necessary on macOS: Linux OCI namespace settings
are ignored, and networking is broker-mediated, with egress denied by default.

For image-based experiments, select **both** the Linux guest platform and the
native directory snapshotter, rather than Darwin images or Linux overlayfs:

```sh
sudo ctr --namespace litebox images pull --local --platform linux/arm64 \
    --snapshotter native docker.io/library/alpine:3.22
sudo ctr --namespace litebox run --rm --platform linux/arm64 \
    --snapshotter native --runtime io.containerd.litebox.v1 \
    docker.io/library/alpine:3.22 hello /bin/echo 'Linux on macOS, without a VM'
```

The native snapshotter describes its snapshot as a `bind` source. The shim reads
that directory directly, without mounting it, builds the broker's root archive,
and restores symlinks through the guest service. An unpacked rootfs works too.

## DNS

On macOS, an image without a configured `/etc/resolv.conf` gets a private copy of
macOS's `/etc/resolv.conf`. Existing image nameservers and explicit resolver or
`/etc` binds take precedence. This does **not** grant DNS egress: allow UDP port
53 for Alpine/musl, and TCP port 53 for glibc's TCP mode or DNS TCP fallback, to
the configured resolver addresses.

If using an older shim without this fallback, or choosing a custom resolver file,
add this to `ctr run`:

```sh
--mount type=bind,src=/etc/resolv.conf,dst=/etc/resolv.conf,options=ro
```

The shim copies this file; it does not create a host bind mount. In the guest,
`cat /etc/resolv.conf` and `nslookup github.com` help distinguish missing resolver
configuration from a blocked/unreachable DNS server. macOS's resolver file does
not describe all scoped/VPN DNS routing shown by `scutil --dns`; such setups may
need an explicit resolver configuration and matching egress rules.

## Scope and limitations

- Apple Silicon only; Linux AArch64 PIE executables. No CPU emulation, x86 Linux,
  or VM fallback. Dynamic Linux programs need their Linux loader/libraries in the
  rootfs and remain subject to the runner's syscall coverage.
- Create/start, exec, wait, signals, stdin/stdout/stderr, terminals/resizing,
  host OCI hooks, `binary://` logging, and delete/daemon-death cleanup are wired.
  Guest signals use **Linux** numbers, not Darwin's.
- The guardian uses a private host process group and a lifeline socket. It kills
  the broker and runners if the shim dies. Guest `setsid`/`setpgid` do not change
  that host group. Orphans are reaped by launchd; no Linux subreaper is needed.
- Guests run as UID/GID 1000. OCI user currently selects `HOME` only. Linux
  namespaces, cgroups, capabilities, seccomp, resource settings, and read-only-root
  settings do **not** create equivalent host isolation. Do not treat this as full
  OCI isolation or a production security boundary.
- Directory binds are broker-served read-write; read-only directory binds are
  refused. File binds are copies. Rootfs changes are private to the broker and
  are discarded on delete, not committed to the containerd snapshot. macOS
  filesystem case-sensitivity also affects image extraction and directory binds.
- Egress is opt-in via `io.litebox.egress.tcp` / `io.litebox.egress.udp`
  annotations, as comma-separated IPv4 `CIDR:PORT[-PORT]` lists. These grant the
  broker host's reachability, including its loopback and metadata services.
  This is not a CNI network. No CRI/Kubernetes integration is claimed.
- `createContainer`/`startContainer` hooks, pause/resume, checkpoints, and resource
  statistics are unsupported. Host hooks execute **macOS** programs as the daemon
  user, not Linux programs inside the guest.

## Tests

With Zig and the Linux musl Rust target installed:

```sh
cargo test --locked -p litebox_containerd_shim -- --test-threads=2
cargo test --locked -p litebox_platform_macos_userland --lib stackless_exit
```

The task-service integration suite launches the native shim/broker against a fake
containerd event service, builds a real static Linux guest service and C guest,
and exercises lifecycle, exec, streams, terminals, native-snapshot directories,
hooks/loggers, and cleanup. It does not need a daemon, VM, root, or namespaces.
The native containerd/ctr commands above are a separate administrative smoke test.
