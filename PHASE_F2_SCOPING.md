# Phase F.2 scoping: remove worker-local inet from linux_userland

Scope: size the work to delete worker-local `litebox::net::Network<Platform>` from the `litebox_shim_linux` linux_userland build path only. SNP/linux-kernel and Windows still need `litebox::net::Network`; LVBS has platform IP hooks but no current `Network::new` construction in this tree.

## Executive summary

- **Top-line estimate:** ~650-900 net LOC if done cleanly in one pass; likely >500 LOC because the current shim type surface assumes local inet fds exist.
- **Recommended phase count:** 3 small phases (F.2.a/F.2.b/F.2.c) plus test cleanup.
- **Session sizing:** doable in ~1 focused session for F.2.a + panic/dead-branch conversion; full deletion plus harness flag cleanup is more realistically 1-2 sessions, not genuinely multi-day unless SNP feature-gating exposes hidden build failures.
- **F.3 unblock:** yes. F.2 should unblock broker `net_proxy` reclaim once linux_userland no longer constructs/drives a worker-local smoltcp stack or emits listen-route transfers from it.
- **Showstoppers:** no fundamental blocker found. Main risk is the fd/type surface (`SocketFd`, `RawFdRef::Net`, `with_socket`) is pervasive enough that deleting it directly will churn many syscall dispatch matches.

## File-by-file inventory in `litebox_shim_linux/`

### `src/lib.rs`

Construction/state:

- `src/lib.rs:30` imports `litebox::net::Network`.
- `src/lib.rs:1045-1046` constructs `let mut net = Network::new(&self.litebox);` and sets `PlatformInteraction::Manual` in `LinuxShimBuilder::build`.
- `src/lib.rs:1088` installs it into `GlobalState`.
- `src/lib.rs:4883` stores it as `net: litebox::sync::Mutex<Platform, Network<Platform>>`.

Direct local-net calls:

- `src/lib.rs:1264-1287` `LinuxShim::perform_network_interaction` locks `self.global.net`, polls smoltcp, emits RST diagnostics, and wakes the network worker.
- `src/lib.rs:1291-1293` `has_pending_network_closes` locks local net.
- `src/lib.rs:1301-1303` `reannounce_listen_ports` locks local net.
- `src/lib.rs:1309+` `tcp_connection` calls `transport::ShimTransport::connect`, which is local-smoltcp-only.
- `src/lib.rs:590-599` `install_broker_bridge_fd` closes an overwritten local-net fd before installing a broker `TcpConn` fd.

Descriptor-surface references:

- `src/lib.rs:2880-2966` `FilesState::run_on_raw_fd` includes `RawFdRef::Net` by probing the raw descriptor store for a `Network<Platform>` fd.
- `src/lib.rs:2974-2992` declares `RawFdRef::Net(&Arc<TypedFd<Network<Platform>>>)`.
- `RawFdRef::Net` has **49 textual arms** across shim syscall files; many are simple errno/stat/dup/close dispatch arms, but read/write/fcntl/epoll/ioctl paths call real local socket helpers.

### `src/transport.rs`

This file is entirely local smoltcp transport plumbing for shim-internal TCP (not guest-visible fd table):

- `src/transport.rs:11-15` imports `NetworkProxy`, `ReceiveFlags`, `SendFlags`, and local `SocketFd`.
- `src/transport.rs:27-39` `SocketDropGuard` closes the local `SocketFd` through `global.net.lock().close`.
- `src/transport.rs:73-111` creates a local TCP socket via `global.net.lock().socket`, initializes a `NetworkProxy`, and loops on `global.net.lock().connect`.
- The rest of `ShimTransport` reads/writes through `NetworkProxy`. For linux_userland this is obsolete when 9P uses broker/shmem; SNP still uses it (`litebox_runner_snp/src/main.rs:206`).

### `src/syscalls/net.rs`

Type aliases/local metadata:

- `src/syscalls/net.rs:64` aliases `SocketFd = litebox::net::SocketFd<Platform>`.
- `src/syscalls/net.rs:300-303` defines local socket metadata wrappers `SocketOFlags` and `SocketProxy`.
- `src/syscalls/net.rs:313-360` `GlobalState::initialize_socket` installs metadata and calls `self.net.lock().set_socket_proxy`.
- `src/syscalls/net.rs:363-379` socket option metadata helpers are local-net-only.

Local-net operation methods on `GlobalState`:

- `setsockopt`: `src/syscalls/net.rs:497-509`, `561-573`, `590-598`, `615-633` set local TCP options.
- `getsockopt`: `src/syscalls/net.rs:761-815` reads local TCP options.
- `try_accept`/`accept`: `src/syscalls/net.rs:832-872` drives smoltcp and accepts local TCP.
- `bind`: `src/syscalls/net.rs:874-880` binds local socket.
- `connect`: `src/syscalls/net.rs:903-975` drives smoltcp and connects local TCP.
- `listen`: `src/syscalls/net.rs:977-979` local listen.
- `shutdown`: `src/syscalls/net.rs:987-1000` local shutdown.
- `sendto`: `src/syscalls/net.rs:1007-1085`; mostly proxy write, but `1020-1048` auto-binds local UDP through `self.net`.
- `receive`: `src/syscalls/net.rs:1092-1164`; drives smoltcp then proxy-reads.
- `close_socket`: `src/syscalls/net.rs:1224-1275` local close/linger behavior.

Guest syscall fallback branches:

- `do_socket(AF_INET)`: `src/syscalls/net.rs:1463-1616` returns broker-backed fds for TCP listener/TcpConn, UDP, and opt-in raw when providers are installed; otherwise falls through to `self.global.net.lock().socket(protocol)` at `1610`.
- `do_socket(AF_INET6)`: `src/syscalls/net.rs:1670-1738`; UDP has a broker path, but TCP stream always falls through to local `Network::socket` at `1728` after IPv6-to-IPv4 mapping setup.
- `do_connect`: `src/syscalls/net.rs:2357-2465` handles broker `TcpConn` and conversion from broker listener to broker TcpConn/external host fd. Remaining local sockets fall through later through `with_socket` into `GlobalState::connect`.
- `do_bind`: `src/syscalls/net.rs:2500-2587` handles broker TcpConn->listener promotion, broker listener, broker dgram, then falls through to local `GlobalState::bind`.
- `do_listen`: `src/syscalls/net.rs:2596-2608` broker listener first, then local `GlobalState::listen`.
- `do_getsockname`/`do_getpeername`: `src/syscalls/net.rs:4437-4449`, `4492-4508` broker branches first, then local net address lookup.
- `sys_shutdown`: `src/syscalls/net.rs:2728` has a `RawFdRef::Net` local shutdown arm.

Worker-exec/listen transfer local-net remnants:

- `src/syscalls/net.rs:2611-2635` `tcp_listen_worker_exec_bridge_spec` looks up a local `Network<Platform>` fd, checks `SO_REUSEPORT`, reads the local port, and emits `tcp_listen` bridge specs.
- `src/syscalls/net.rs:2638-2699` `install_tcp_listen_bridge_fd` creates/binds/listens a local socket for inherited listen-route transfer.
- `src/syscalls/net.rs:2175-2230` `try_install_broker_tcp_accept` accepts local TCP, optionally converts it to broker `TcpConn`, and closes the local accepted socket.

### `src/syscalls/file.rs`

- `src/syscalls/file.rs:49-53` `expected_descriptor_type` maps `SubsystemKind::Net` to `<Network<Platform> as FdEnabledSubsystem>::Entry`.
- Many `RawFdRef::Net` arms handle local socket read/write/fcntl/ioctl/dup/close/status paths. Important real-use arms include:
  - read: `2032`, `3441`, `3647`, `3919`, `4726`, `7395`
  - write: `2271`, `4112`, `7525`
  - flags: `5156`, `5193`
  - dup/close-ish paths: `8443`, `8675`
  - fd passing/control-message handling: `7087`, `7164`
- Many other arms return Linux-shaped errors for non-directory/non-tty/non-seekable fds. These become unreachable/deletable once local net fds cannot exist on linux_userland.

### `src/syscalls/epoll.rs`

- `src/syscalls/epoll.rs:62,126` includes `EpollDescriptor::Socket` / `EpollTarget::Socket` around local `SocketFd`.
- `src/syscalls/epoll.rs:81` registers `RawFdRef::Net` as a socket epoll target.
- `src/syscalls/epoll.rs:595-603` explicitly drives local smoltcp in `drive_network_poll_loop` via `global.net.lock().perform_platform_interaction()`.

### `src/syscalls/unix.rs`

- `src/syscalls/unix.rs:1411-1453` SCM_RIGHTS/Unix transport path distinguishes broker TcpConn fds from local `Network<Platform>` fds; local branch extracts `SocketProxy` and creates `UnixTransport::Tcp`.
- `src/syscalls/unix.rs:1455-1464` consumes either broker TcpConn or local Network raw fd after transfer.
- Other `NetworkProxy` imports around `766`, `822`, `2099`, `2309` support Unix-over-local-TCP transport variants and should be audited with the above branch.

### `src/syscalls/process.rs`

- `src/syscalls/process.rs:9586-9607` scans surviving local `Network<Platform>` fds during worker-exec and emits listen bridge specs via `tcp_listen_worker_exec_bridge_spec`.
- `src/syscalls/process.rs:6676` snapshots local net fd metadata for fork.
- `src/syscalls/process.rs:10664`, `10911`, `11071` classify local net fds during worker exec input/output binding decisions.
- Broker inet snapshot paths already exist separately at `6905-6913`, `7090+`, `9170-9199`, and `9454-9497`.

### `src/syscalls/mm.rs`

- Only `RawFdRef::Net` error/path classification (`ENODEV` for `mmap`, no FS path/CoW backing). Delete/guard with the `RawFdRef::Net` variant.

## `self.global.net.lock()` / local net lock count

A literal grep finds 8 `global.net.lock()` sites, but local-net locking is broader because `GlobalState` methods use `self.net.lock()`:

- `global.net.lock()` sites: `lib.rs:1267`, `1292`, `1302`; `transport.rs:92`; `syscalls/epoll.rs:598`; `syscalls/net.rs:1610`, `1728`, `2631`.
- Multiline lock sites in `transport.rs`: close/socket/connect at `34-38`, `80-84`, `92`.
- `self.net.lock()` sites in `syscalls/net.rs`: set proxy/options, get TCP options, accept/bind/connect/listen/shutdown/send auto-bind/recv drive/close, plus accepted-local conversion and name lookups. These are the real deletion bulk.

## Platform/cfg-gate decision

Current platform split:

- `litebox_platform_multiplex/src/lib.rs:29-38` selects exactly one `Platform` by Cargo feature: `platform_linux_userland`, `platform_windows_userland`, `platform_lvbs`, or `platform_linux_snp`. This is the correct axis; **do not use `target_os = "linux"`** because linux_userland, SNP, and LVBS all build on/for Linux-like targets.
- `litebox_shim_linux/Cargo.toml:21-25` already has `platform_linux_userland` (default) and `platform_linux_snp` features. There is no `platform_lvbs` feature in `litebox_shim_linux`; LVBS uses `litebox_shim_optee`.
- `litebox_runner_linux_userland/Cargo.toml:15-16` uses multiplex `platform_linux_userland` and the default `litebox_shim_linux` feature set.
- `litebox_runner_snp/Cargo.toml:13-15` uses multiplex `platform_linux_snp` and `litebox_shim_linux` with `default-features = false, features = ["platform_linux_snp"]`.
- `litebox_runner_windows_userland/src/lib.rs:578-585` independently constructs `litebox::net::Network` only when `platform.has_network()` and passes it to `litebox_shim_windows` (`src/lib.rs:1284`, `1697`). Leave this alone.
- `litebox_runner_lvbs` / `litebox_shim_optee`: no `Network::new` or `net::Network` construction found. LVBS platform still implements `IPInterfaceProvider` (`litebox_platform_lvbs/src/lib.rs:1130+`), so the core `litebox::net` code should remain available.

Recommendation:

1. Add an explicit shim feature such as `worker_local_inet` (or `shim_worker_local_inet`) in `litebox_shim_linux`.
2. Enable it from `platform_linux_snp`; do **not** enable it for `platform_linux_userland`.
3. Guard the local-net field/type/method surface with `#[cfg(feature = "worker_local_inet")]`, and compile linux_userland without it.

Why not gate directly on `not(feature = "platform_linux_userland")`? It works for today, but a positive capability feature documents the real dependency and prevents future platform features from accidentally inheriting or losing local inet. The feature is compile-time, matching `litebox_platform_multiplex`'s existing design.

## What breaks when linux_userland stops constructing `Network`

Expected compile/runtime breaks:

1. `GlobalState` cannot contain an unconditional `net: Mutex<Network<Platform>>`; every method that accesses it must be cfg-gated or removed from linux_userland.
2. `SocketFd` is currently a public-ish shim type alias used by transport, epoll, file, Unix SCM_RIGHTS, and net syscalls. Linux_userland needs broker fd types to cover all inet operations before `SocketFd` disappears from its build.
3. `RawFdRef::Net` is pervasive. Removing the variant will cause useful exhaustiveness errors at each dispatch arm. Most arms are mechanical deletion; real read/write/epoll/fcntl/socket ioctl arms need broker equivalents or unreachable panic sites.
4. Fallbacks in `do_socket`, `do_bind`, `do_listen`, `do_connect`, name queries, and fd transfer must become explicit linux_userland `unreachable!()`/`panic!()` or errno only where the guest request is genuinely unsupported (raw without provider remains `EPROTONOSUPPORT`). Silent fallback to local net cannot remain.
5. AF_INET6 TCP currently falls through to local net; broker-held TCP needs either an IPv6-mapped broker path or an explicit unsupported result. UDP already has a broker path.
6. `transport.rs` / `LinuxShim::tcp_connection` is still used by SNP and by linux_userland TUN-mode TCP 9P. For linux_userland broker-held-only, either remove TUN TCP-9P support or cfg it under `worker_local_inet`. Shmem/Unix 9P paths are already non-net.
7. `start_network_worker` in linux_userland currently starts whenever `platform.has_network()` and repeatedly calls `shim.perform_network_interaction`. With no local net, it should either disappear for broker-held inet or only compile/run under `worker_local_inet`.
8. Harness/runtime gates (`LITEBOX_BROKER_INET_TCP`, `UDP`, `LISTENER`) currently default on but remain opt-out to worker-local smoltcp. F.2 must remove or invert those opt-outs; tests that deliberately set them to `0` must be deleted/updated to expect broker-required behavior.

## LOC estimate

Approximate net-change estimate by area:

- Feature/cfg plumbing in `litebox_shim_linux` Cargo and imports/state: 30-60 LOC.
- Guard/remove `transport.rs` and `LinuxShim::{tcp_connection,perform_network_interaction,has_pending_network_closes,reannounce_listen_ports}` from linux_userland: 80-140 LOC.
- `syscalls/net.rs` fallback conversion to broker-only/panic sites and AF_INET6 cleanup: 180-260 LOC.
- `RawFdRef::Net` variant and 49 arms across file/mm/net/process/epoll/unix: 220-320 LOC.
- linux_userland runner `start_network_worker`, TUN TCP 9P, fork-restore listen reannounce, env opt-out cleanup: 100-180 LOC.
- Harness/doc/test expectation cleanup for `LITEBOX_BROKER_INET_*` opt-outs and BL/raw comments: 40-80 LOC.

Total: **~650-900 LOC** net, depending on how much unreachable scaffolding is kept for one phase.

## Suggested phased approach

### F.2.a: compile-time capability gate + no construction on linux_userland

- Add `worker_local_inet` feature to `litebox_shim_linux`; enable it from `platform_linux_snp` only.
- Convert `GlobalState.net` to cfg-gated field or an internal `LocalInet` helper behind the feature.
- Make linux_userland build fail loudly at local-net fallbacks with `unreachable!("linux_userland broker-held inet should have handled ...")` while keeping SNP compiling.
- Gate linux_userland runner network worker/TUN TCP-9P calls. Validate targeted `cargo build -p litebox_runner_linux_userland` and `cargo build -p litebox_runner_snp`.

### F.2.b: replace worker-local branches with broker-only dispatch

- Walk compile errors from removing `RawFdRef::Net` under linux_userland.
- For each syscall fallback, either route to broker fd types or add a narrow `unreachable!()` for internal-consistency failures. Follow the repo policy: if reaching the branch means dispatch forgot a broker type, panic loudly; return errno only for valid unsupported runtime cases.
- Remove linux_userland env opt-outs (`LITEBOX_BROKER_INET_TCP/UDP/LISTENER=0`) or make them rejected diagnostics.

### F.2.c: delete dead local-net scaffolding from linux_userland

- Delete now-unreachable linux_userland `SocketFd`/`SocketProxy` metadata, epoll socket variants, Unix `UnixTransport::Tcp` transfer branch, worker-exec `tcp_listen` bridge specs, and local fd read/write arms.
- Keep the same code under `worker_local_inet` for SNP.
- Run focused broker inet harness tests (`BL.listen_basic`, `BL.udp_recvfrom_remote_addr`, `BL.connect_basic`, raw restricted case) and full `cargo test -p litebox_test_harness --test integration` if targeted tests pass.

## Showstoppers / open questions

- No showstopper found.
- AF_INET6 TCP is the biggest semantic open question: broker TCP currently expects IPv4 listener wire in the observed paths. Decide whether to map `::1`/`::` to IPv4 as the local path did, or return `EAFNOSUPPORT`/`ESOCKTNOSUPPORT` for non-v4-mapped addresses.
- Linux_userland TUN mode and TCP 9P-over-smoltcp are incompatible with deleting local net. If these are still supported scenarios, they need to remain behind `worker_local_inet` or be declared out of scope for broker-held linux_userland.
- LVBS does not currently construct `Network::new`; if the background assumption says LVBS depends on `litebox::net`, that dependency is not wired through the same shim path and should be preserved by avoiding core `litebox::net` deletion.
