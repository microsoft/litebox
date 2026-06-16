// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Litebox Broker — standalone 9P2000.L file server and network proxy.
//!
//! Serves files from a host directory with policy enforcement and optional
//! ELF syscall rewriting. Optionally runs broker-side network session and
//! inbound-forward listeners.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Parser;
use tracing::info;

use litebox_broker::policy::{
    AllowAllPolicy, GlobPolicy, ReadOnlyPolicy, ReadOnlyWithWritablePaths,
};
use litebox_broker::sock_compat::IpcListener;
#[cfg(unix)]
use litebox_broker::sock_compat::IpcStream;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;

/// Litebox Broker — policy-enforced file access and network proxy for sandboxed processes.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Address to listen on for 9P server (e.g., `10.0.0.1:5640`).
    #[arg(long, default_value = "10.0.0.1:5640")]
    listen_addr: SocketAddr,

    /// Root directory to expose through the 9P broker.
    #[arg(long, required_unless_present_any = ["network_proxy_fd", "network_proxy_listen"])]
    root_dir: Option<PathBuf>,

    /// Rewrite syscall instructions in ELF files served to the sandbox.
    #[arg(long)]
    rewrite_syscalls: bool,

    /// Restrict the broker to read-only access.
    #[arg(long)]
    read_only: bool,

    /// Allow write operations under these directories (requires --read-only).
    #[arg(long = "writable-path")]
    writable_paths: Vec<PathBuf>,

    /// Run as a network proxy. The value is a file descriptor number for the
    /// IPC socketpair end passed from the runner (Unix only).
    #[arg(long)]
    network_proxy_fd: Option<i32>,

    /// Listen endpoint for network proxy IPC connections.
    /// On Unix: path to a Unix domain socket. On Windows: loopback TCP address
    /// (e.g., 127.0.0.1:9999) or AF_UNIX socket path.
    #[arg(long, conflicts_with = "network_proxy_fd")]
    network_proxy_listen: Option<String>,

    /// Path to a JSON sandbox policy file controlling filesystem and network
    /// access. When provided, the broker enforces the policy on all 9P
    /// operations and network connections.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    policy: Option<PathBuf>,

    /// Path to write structured audit events (JSONL). The broker appends
    /// policy decisions (dns_resolved, tcp_allowed, tcp_denied, etc.) to
    /// this file, which may be shared with the runner's syscall audit log.
    #[arg(long = "audit-log", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    audit_log: Option<PathBuf>,

    /// Forward a host TCP port to the guest virtual network.
    /// Format: HOST_PORT:GUEST_IP:GUEST_PORT (e.g., 2222:10.0.0.2:22).
    /// The broker listens on HOST_PORT and relays connections to the guest.
    #[arg(long = "forward-port", value_name = "HOST:GUEST_IP:GUEST_PORT")]
    forward_port: Vec<String>,

    /// Path to a Unix socket on which to host the broker fd-token /
    /// state-object control plane. Runners connect to this socket via
    /// `--fd-token-broker <path>` to register and materialise broker-
    /// backed shim objects (eventfds today; timerfds, signalfds and
    /// cross-worker SCM_RIGHTS handoff in the future). When omitted,
    /// the control plane is disabled and runners fall back to
    /// purely-local shim emulation.
    #[arg(long = "fd-token-broker-listen", value_name = "PATH",
          value_hint = clap::ValueHint::FilePath)]
    fd_token_broker_listen: Option<PathBuf>,
}

fn parse_forward_specs(specs: &[String]) -> Vec<(u16, std::net::Ipv4Addr, u16)> {
    specs
        .iter()
        .filter_map(|s| litebox_broker::net_proxy::parse_forward_spec(s))
        .collect()
}

fn build_policy(
    cli: &Cli,
    sandbox_policy: &Option<Arc<litebox_broker::sandbox_policy::SandboxPolicy>>,
) -> Arc<dyn litebox_broker::policy::Policy> {
    // If a sandbox policy is loaded, use its FS rules via GlobPolicy.
    if let Some(sp) = sandbox_policy {
        // Determine the rootfs path for stripping host prefixes from paths.
        let root = cli
            .root_dir
            .as_ref()
            .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
            .unwrap_or_default();
        return Arc::new(GlobPolicy::new(Arc::clone(sp), root));
    }
    // Otherwise fall back to the CLI flag-based policies.
    if cli.read_only {
        if cli.writable_paths.is_empty() {
            Arc::new(ReadOnlyPolicy)
        } else {
            let prefixes: Vec<PathBuf> = cli
                .writable_paths
                .iter()
                .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
                .collect();
            info!(?prefixes, "read-only with writable exceptions");
            Arc::new(ReadOnlyWithWritablePaths::new(prefixes))
        }
    } else {
        Arc::new(AllowAllPolicy)
    }
}

/// Load sandbox policy from the `--policy` flag, if provided.
fn load_sandbox_policy(cli: &Cli) -> Option<Arc<litebox_broker::sandbox_policy::SandboxPolicy>> {
    let path = cli.policy.as_ref()?;
    match litebox_broker::sandbox_policy::SandboxPolicy::from_file(path) {
        Ok(policy) => {
            info!(?path, "loaded sandbox policy");
            Some(Arc::new(policy))
        }
        Err(e) => {
            tracing::error!("failed to load sandbox policy from {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

/// Build a `LocalServiceRegistry` when `--root-dir` is provided alongside
/// network proxy flags. The 9P file server is registered on port 5640 so the
/// guest can reach it at `BROKER_IP:5640` without a real TCP listener.
fn build_local_services(
    cli: &Cli,
    elf_cache: Arc<Mutex<litebox_broker::nine_p::server::ElfCache>>,
    sandbox_policy: &Option<Arc<litebox_broker::sandbox_policy::SandboxPolicy>>,
    inotify_dispatcher: Arc<litebox_broker::inotify_dispatcher::InotifyDispatcher>,
    ofd_registry: Arc<litebox_broker::ofd_registry::OfdRegistry>,
    nine_p_session_registry: Arc<litebox_broker::nine_p_session_registry::NinePSessionRegistry>,
) -> Option<litebox_broker::net_proxy::LocalServiceRegistry> {
    let root_dir = cli.root_dir.as_ref()?;
    let root = root_dir.canonicalize().unwrap_or_else(|_| root_dir.clone());
    let policy = build_policy(cli, sandbox_policy);
    let rewrite_syscalls = cli.rewrite_syscalls;

    let mut registry = litebox_broker::net_proxy::LocalServiceRegistry::new();

    // Register TCP spawner for direct LB9P byte-stream connections.
    {
        let root = root.clone();
        let policy = Arc::clone(&policy);
        let elf_cache = Arc::clone(&elf_cache);
        let inotify_dispatcher = Arc::clone(&inotify_dispatcher);
        let ofd_registry = Arc::clone(&ofd_registry);
        let nine_p_session_registry = Arc::clone(&nine_p_session_registry);
        registry.register(
            5640,
            Box::new(move |stream| {
                let root = root.clone();
                let policy = Arc::clone(&policy);
                let elf_cache = Arc::clone(&elf_cache);
                let inotify_dispatcher = Arc::clone(&inotify_dispatcher);
                let ofd_registry = Arc::clone(&ofd_registry);
                let nine_p_session_registry = Arc::clone(&nine_p_session_registry);
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let mut server = litebox_broker::nine_p::server::Server::with_elf_cache(
                        root,
                        policy,
                        rewrite_syscalls,
                        elf_cache,
                        inotify_dispatcher,
                    );
                    // Legacy-pipes Phase 3 (D3): every 9P Server
                    // shares the broker-global OFD registry so
                    // RegisterOfd/CloneOfd can plumb host OFDs
                    // across connections.
                    server.set_ofd_registry(ofd_registry);
                    // Legacy-pipes Phase 3 (D3 step 2d.2): assign
                    // a 9P conn_id and register the Server so a
                    // sibling fd-token-socket can pair via
                    // `BindNinePSession(conn_id)`. The TCP path
                    // here is test scaffolding only (production
                    // shim/runner uses the shmem-ring path
                    // below). Still wire it so test fixtures can
                    // exercise the same flow if needed.
                    let conn_id = litebox_broker::nine_p_session_registry::next_conn_id();
                    server.set_conn_id(conn_id);
                    let server = Arc::new(server);
                    nine_p_session_registry.insert(conn_id, Arc::clone(&server));
                    server.serve(&mut stream);
                    nine_p_session_registry.remove(conn_id);
                    info!(conn_id, "9P local service session ended");
                })
            }),
        );
    }

    // Register shared-memory ring spawner for direct IPC connections.
    #[cfg(any(unix, windows))]
    {
        let root = root.clone();
        let policy = Arc::clone(&policy);
        let elf_cache = Arc::clone(&elf_cache);
        let inotify_dispatcher = Arc::clone(&inotify_dispatcher);
        let ofd_registry = Arc::clone(&ofd_registry);
        let nine_p_session_registry = Arc::clone(&nine_p_session_registry);
        registry.register_ring(
            5640,
            Arc::new(move |writer, reader, conn_id| {
                let root = root.clone();
                let policy = Arc::clone(&policy);
                let elf_cache = Arc::clone(&elf_cache);
                let inotify_dispatcher = Arc::clone(&inotify_dispatcher);
                let ofd_registry = Arc::clone(&ofd_registry);
                let nine_p_session_registry = Arc::clone(&nine_p_session_registry);
                std::thread::spawn(move || {
                    let mut server_inner = litebox_broker::nine_p::server::Server::with_elf_cache(
                        root,
                        policy,
                        rewrite_syscalls,
                        elf_cache,
                        inotify_dispatcher,
                    );
                    server_inner.set_ofd_registry(ofd_registry);
                    server_inner.set_conn_id(conn_id);
                    let server = Arc::new(server_inner);
                    nine_p_session_registry.insert(conn_id, Arc::clone(&server));
                    litebox_broker::nine_p::server::Server::serve_threaded(
                        server, reader, writer, 8,
                    );
                    nine_p_session_registry.remove(conn_id);
                    info!(conn_id, "9P local service session ended (shared memory)");
                })
            }),
        );
    }

    info!("registered 9P file service on virtual port 5640");
    Some(registry)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    litebox_panic_hook::install("broker");
    litebox_timing::init_from_env();
    litebox_timing::emit("broker_main_started_ns");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    litebox_timing::emit("broker_args_parsed_ns");
    let sandbox_policy = load_sandbox_policy(&cli);
    litebox_timing::emit("broker_policy_loaded_ns");

    // Phase B-Step8d: optionally host the fd-token / state-object
    // control listener. Runners connect via `--fd-token-broker <path>`
    // to register broker-backed eventfds (etc.) and to dup/materialise
    // handles for cross-worker SCM_RIGHTS transfer. The two registries
    // are constructed here and shared with the listener thread; their
    // Arc clones survive for the lifetime of the broker process.
    let inotify_dispatcher =
        std::sync::Arc::new(litebox_broker::inotify_dispatcher::InotifyDispatcher::new());
    // Legacy-pipes Phase 3 (D3 step 1+2): broker-global OFD
    // registry. Every `nine_p::Server` shares this Arc so that an
    // `OpenFileId` minted on the parent's 9P session is resolvable
    // by the worker's 9P session (the registry is the only piece
    // of state that crosses connections). Per-connection
    // fd-token-socket → 9P-server pairing is a follow-up: the
    // shim needs to register its 9P session id over the
    // fd-token-socket so the broker can route `RegisterOfd` /
    // `CloneOfd` to the right `Server`. Until that handshake
    // lands, the D3 wire-protocol surface is reachable but the
    // handlers return `SubsystemMismatch` (paired-server lookup
    // returns `None`).
    let ofd_registry = std::sync::Arc::new(litebox_broker::ofd_registry::OfdRegistry::new());
    // Legacy-pipes Phase 3 (D3 step 2d.2): broker-global registry
    // of live 9P sessions, keyed by the monotone `conn_id` assigned
    // at 9P accept time. Used by the fd-token-socket's
    // `BindNinePSession` handler to look up the `Arc<nine_p::Server>`
    // belonging to the same shim host process.
    let nine_p_session_registry =
        std::sync::Arc::new(litebox_broker::nine_p_session_registry::NinePSessionRegistry::new());
    // Make available to the fd-token-socket BindNinePSession handler
    // (which can't easily get the Arc plumbed through its 22 call
    // sites). See module doc for rationale.
    litebox_broker::nine_p_session_registry::set_global(std::sync::Arc::clone(
        &nine_p_session_registry,
    ));
    let shared_state_registry = cli
        .fd_token_broker_listen
        .as_ref()
        .map(|_| std::sync::Arc::new(litebox_broker::state_registry::BrokerStateRegistry::new()));
    let _fd_token_listener: Option<std::thread::JoinHandle<()>> =
        if let Some(path) = cli.fd_token_broker_listen.as_ref() {
            let fd_registry =
                std::sync::Arc::new(litebox_broker::fd_tokens::BrokerFdTokenRegistry::new());
            let state_registry = shared_state_registry
                .as_ref()
                .expect("state registry exists when fd-token listener is configured")
                .clone();
            // Process registry: dedicated BrokerStateRegistry instance for
            // ProcessState entries. Disjoint id space from state_registry
            // keeps allocated guest pids sequential u32s (suitable for
            // /proc/<pid> and audit logs) while reusing the same
            // refcount + tag-checked machinery.
            let process_registry =
                std::sync::Arc::new(litebox_broker::state_registry::BrokerStateRegistry::new());
            match litebox_broker::fd_token_socket::spawn_control_listener(
                path,
                fd_registry,
                state_registry,
                process_registry,
                Arc::clone(&inotify_dispatcher),
            ) {
                Ok(handle) => {
                    info!(path = %path.display(), "fd-token broker listener started");
                    Some(handle)
                }
                Err(e) => {
                    tracing::error!(
                        path = %path.display(),
                        error = %e,
                        "failed to start fd-token broker listener",
                    );
                    None
                }
            }
        } else {
            None
        };

    // Open the audit log file for structured broker events.
    let audit_log =
        cli.audit_log
            .as_ref()
            .and_then(|path| match litebox_broker::audit::AuditLog::open(path) {
                Ok(al) => {
                    info!(?path, "audit log opened");
                    Some(al)
                }
                Err(e) => {
                    tracing::error!("failed to open audit log {}: {e}", path.display());
                    None
                }
            });
    litebox_timing::emit("broker_audit_open_ns");

    // Log policy summary to audit.
    if let (Some(al), Some(sp)) = (&audit_log, &sandbox_policy) {
        al.policy_loaded(
            cli.policy
                .as_ref()
                .map(|p| p.to_str().unwrap_or("<non-utf8>"))
                .unwrap_or("<default>"),
            sp,
        );
    }

    // Network proxy mode (fd passed from runner — Unix only).
    #[cfg(unix)]
    if let Some(fd_num) = cli.network_proxy_fd {
        info!(fd = fd_num, "starting network proxy mode (fd)");
        // Safety: the fd was passed to us by the runner process via fork+exec.
        // We take ownership of it.
        let fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd_num) };
        let ipc = IpcStream::from_owned_fd(fd);
        let elf_cache = litebox_broker::nine_p::server::Server::new_elf_cache();
        let registry = build_local_services(
            &cli,
            elf_cache,
            &sandbox_policy,
            Arc::clone(&inotify_dispatcher),
            Arc::clone(&ofd_registry),
            Arc::clone(&nine_p_session_registry),
        );
        let forwards = parse_forward_specs(&cli.forward_port);
        return litebox_broker::net_proxy::run(
            ipc,
            false,
            registry,
            None,
            sandbox_policy,
            audit_log,
            forwards,
            shared_state_registry.clone(),
        );
    }
    #[cfg(not(unix))]
    if cli.network_proxy_fd.is_some() {
        return Err("--network-proxy-fd is only supported on Unix".into());
    }

    // Network proxy mode (listen for IPC connections).
    if let Some(ref listen_addr) = cli.network_proxy_listen {
        info!(addr = %listen_addr, "starting network proxy mode (listen)");

        // Shared ELF patch cache — persists across connections so that
        // expensive ELF patching is amortized over the broker's lifetime.
        let elf_cache = litebox_broker::nine_p::server::Server::new_elf_cache();

        // Pre-warm the cache before publishing the listener. The tool
        // executor treats the socket path as broker readiness; binding early
        // lets the runner connect and then time out waiting for a handshake
        // response while the broker is still pre-warming.
        if cli.rewrite_syscalls {
            if let Some(ref root_dir) = cli.root_dir {
                let root = root_dir.canonicalize().unwrap_or_else(|_| root_dir.clone());
                litebox_broker::nine_p::server::Server::pre_warm_elf_cache(
                    &elf_cache,
                    &root,
                    &[
                        "/usr/lib/x86_64-linux-gnu/libc.so.6",
                        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                        "/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33",
                        "/usr/lib/x86_64-linux-gnu/libm.so.6",
                        "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
                        "/usr/lib/x86_64-linux-gnu/libdl.so.2",
                        "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
                        // Binaries that test cases exec (caught by the
                        // integration test's runtime-rewrite
                        // assertion — see `run_one_test` in
                        // `litebox_test_harness/tests/integration.rs`).
                        // These live in the docker image so their
                        // mtime is stable across containers.
                        "/usr/bin/bash",
                        "/usr/bin/cat",
                        "/usr/bin/echo",
                        "/usr/bin/grep",
                        "/usr/bin/tr",
                        "/usr/bin/true",
                        // findutils/coreutils binaries the PTYM.* PTY
                        // marker-completion tests exec (`find ... | head`
                        // and `stty` for interactive-readline echo
                        // disable), plus libselinux which `find` links.
                        "/usr/bin/find",
                        "/usr/bin/head",
                        "/usr/bin/stty",
                        "/usr/lib/x86_64-linux-gnu/libselinux.so.1",
                        "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2",
                        "/usr/lib/x86_64-linux-gnu/libtinfo.so.6.4",
                        // Node.js (bundled with the litebox-test image
                        // and several integration scenarios that exec
                        // it: EX6-9 in `coordinator/special_cases/exit.rs`,
                        // plus the Copilot CLI integration suite).
                        "/usr/local/bin/node",
                    ],
                );
            }
        }
        litebox_timing::emit("broker_prewarm_done_ns");

        #[cfg(unix)]
        let listener = IpcListener::bind_unix(std::path::Path::new(listen_addr))?;
        #[cfg(windows)]
        let listener = IpcListener::bind_endpoint(listen_addr)?;

        info!(addr = %listen_addr, "network proxy listening");
        litebox_timing::emit("broker_listen_called_ns");
        let extra_session_slots = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Accept connections, validating the LBNP handshake before entering the
        // proxy event loop.  Stray/slow clients are rejected quickly so they
        // cannot block the real runner from connecting.
        let mut first_accept = true;
        loop {
            let registry = build_local_services(
                &cli,
                Arc::clone(&elf_cache),
                &sandbox_policy,
                Arc::clone(&inotify_dispatcher),
                Arc::clone(&ofd_registry),
                Arc::clone(&nine_p_session_registry),
            );
            let ipc = match litebox_broker::net_proxy::accept_ipc_client(
                &listener,
                registry.as_ref(),
                None,
            ) {
                Ok(Some(s)) => s,
                Ok(None) => continue,
                Err(e) => {
                    tracing::error!("accept_ipc_client error: {e}");
                    continue;
                }
            };
            if first_accept {
                litebox_timing::emit("broker_first_accept_ns");
                first_accept = false;
            }
            info!("network proxy client connected");
            let forwards = parse_forward_specs(&cli.forward_port);
            if let Err(e) = litebox_broker::net_proxy::run_with_session_slots(
                ipc,
                true,
                registry,
                Some(&listener),
                Arc::clone(&extra_session_slots),
                sandbox_policy.clone(),
                audit_log.clone(),
                forwards,
                shared_state_registry.clone(),
            ) {
                tracing::error!("network proxy error: {e}");
            }
            info!("network proxy client disconnected");
        }
        // Unreachable — loop above runs until process exits.
    }

    // 9P file broker mode (original behavior).
    let root_dir = cli
        .root_dir
        .as_ref()
        .expect("--root-dir is required for 9P mode");
    let root = root_dir.canonicalize().expect("root directory must exist");

    let policy = build_policy(&cli, &sandbox_policy);

    info!(
        ?root,
        addr = %cli.listen_addr,
        rewrite = cli.rewrite_syscalls,
        read_only = cli.read_only,
        writable_paths = ?cli.writable_paths,
        "starting 9P file broker"
    );

    let listener = std::net::TcpListener::bind(cli.listen_addr)?;
    info!(addr = %cli.listen_addr, "9P server listening");

    // Accept connections one at a time (9P is single-stream per guest).
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => {
                info!(peer = %s.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap()), "9P client connected");
                s
            }
            Err(e) => {
                tracing::warn!("accept error: {e}");
                continue;
            }
        };

        let mut server = litebox_broker::nine_p::server::Server::new(
            root.clone(),
            Arc::clone(&policy),
            cli.rewrite_syscalls,
            Arc::clone(&inotify_dispatcher),
        );
        server.set_ofd_registry(Arc::clone(&ofd_registry));
        let conn_id = litebox_broker::nine_p_session_registry::next_conn_id();
        server.set_conn_id(conn_id);
        let server = Arc::new(server);
        nine_p_session_registry.insert(conn_id, Arc::clone(&server));
        server.serve(&mut stream);
        nine_p_session_registry.remove(conn_id);
        info!(conn_id, "9P client disconnected");
    }

    Ok(())
}
