// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Litebox Broker — standalone 9P2000.L file server and network proxy.
//!
//! Serves files from a host directory with policy enforcement and optional
//! ELF syscall rewriting. Optionally runs a network proxy that bridges guest
//! TCP/UDP over an IPC pipe using smoltcp.

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
        return Arc::new(GlobPolicy::new(Arc::clone(sp)));
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
) -> Option<litebox_broker::net_proxy::LocalServiceRegistry> {
    let root_dir = cli.root_dir.as_ref()?;
    let root = root_dir.canonicalize().unwrap_or_else(|_| root_dir.clone());
    let policy = build_policy(cli, sandbox_policy);
    let rewrite_syscalls = cli.rewrite_syscalls;

    let mut registry = litebox_broker::net_proxy::LocalServiceRegistry::new();

    // Register TCP spawner for smoltcp bridge connections.
    {
        let root = root.clone();
        let policy = Arc::clone(&policy);
        let elf_cache = Arc::clone(&elf_cache);
        registry.register(
            5640,
            Box::new(move |stream| {
                let root = root.clone();
                let policy = Arc::clone(&policy);
                let elf_cache = Arc::clone(&elf_cache);
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let server = litebox_broker::nine_p::server::Server::with_elf_cache(
                        root,
                        policy,
                        rewrite_syscalls,
                        elf_cache,
                    );
                    server.serve(&mut stream);
                    info!("9P local service session ended");
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
        registry.register_ring(
            5640,
            Arc::new(move |writer, reader| {
                let root = root.clone();
                let policy = Arc::clone(&policy);
                let elf_cache = Arc::clone(&elf_cache);
                std::thread::spawn(move || {
                    let server = Arc::new(litebox_broker::nine_p::server::Server::with_elf_cache(
                        root,
                        policy,
                        rewrite_syscalls,
                        elf_cache,
                    ));
                    litebox_broker::nine_p::server::Server::serve_threaded(
                        server, reader, writer, 8,
                    );
                    info!("9P local service session ended (shared memory)");
                })
            }),
        );
    }

    info!("registered 9P file service on virtual port 5640");
    Some(registry)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let sandbox_policy = load_sandbox_policy(&cli);

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
        let registry = build_local_services(&cli, elf_cache, &sandbox_policy);
        let forwards = parse_forward_specs(&cli.forward_port);
        return litebox_broker::net_proxy::run(
            ipc,
            false,
            registry,
            None,
            sandbox_policy,
            audit_log,
            forwards,
        );
    }
    #[cfg(not(unix))]
    if cli.network_proxy_fd.is_some() {
        return Err("--network-proxy-fd is only supported on Unix".into());
    }

    // Network proxy mode (listen for IPC connections).
    if let Some(ref listen_addr) = cli.network_proxy_listen {
        info!(addr = %listen_addr, "starting network proxy mode (listen)");

        #[cfg(unix)]
        let listener = IpcListener::bind_unix(std::path::Path::new(listen_addr))?;
        #[cfg(windows)]
        let listener = IpcListener::bind_endpoint(listen_addr)?;

        info!(addr = %listen_addr, "network proxy listening");

        // Shared ELF patch cache — persists across connections so that
        // expensive ELF patching is amortized over the broker's lifetime.
        let elf_cache = litebox_broker::nine_p::server::Server::new_elf_cache();
        let extra_session_slots = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Accept connections, validating the LBNP handshake before entering the
        // proxy event loop.  Stray/slow clients are rejected quickly so they
        // cannot block the real runner from connecting.
        loop {
            let registry = build_local_services(&cli, Arc::clone(&elf_cache), &sandbox_policy);
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

        let server = litebox_broker::nine_p::server::Server::new(
            root.clone(),
            Arc::clone(&policy),
            cli.rewrite_syscalls,
        );
        server.serve(&mut stream);
        info!("9P client disconnected");
    }

    Ok(())
}
