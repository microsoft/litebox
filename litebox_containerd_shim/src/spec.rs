// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The parts of an OCI spec that the shim applies, and the few it refuses (see [`plan`]). The
//! network namespace is the broker's; other kernel isolation settings (other namespaces, cgroups
//! but the VM's [`Resources`], seccomp, AppArmor, SELinux, capabilities, rlimits, the umask) are
//! ignored, and so, until LiteBox supports them, are the user and a read-only root.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use litebox_guest_service_protocol::guest_service::Process;
use oci_spec::runtime::{LinuxNamespaceType, Spec};

use crate::{Result, invalid, unsupported};

/// Mount types that are dropped: `devpts`, which the broker serves in its `/dev`, and those LiteBox
/// does not have yet (a dropped `tmpfs` leaves the image's content, in the root's in-memory layer).
// TODO: mount `tmpfs`, `proc`, `sysfs`, `mqueue` and cgroups once LiteBox has them.
const IGNORED_MOUNTS: [&str; 7] = [
    "proc", "sysfs", "tmpfs", "devpts", "mqueue", "cgroup", "cgroup2",
];

/// Guest paths that the broker serves itself (`/dev`) or LiteBox does not have.
pub const SERVED_PATHS: [&str; 3] = ["/dev", "/proc", "/sys"];

const EGRESS_TCP: &str = "io.litebox.egress.tcp";
const EGRESS_UDP: &str = "io.litebox.egress.udp";
const EGRESS_ICMP_ECHO: &str = "io.litebox.egress.icmp-echo";
const INGRESS_TCP: &str = "io.litebox.ingress.tcp";
const INGRESS_UDP: &str = "io.litebox.ingress.udp";
/// `[HOST_IP:]HOST_PORT:GUEST_PORT,...`: TCP ports of the broker's network namespace, which is
/// the node's only without one of the container's own, that the broker holds and serves while the
/// guest listens on the guest ports. It binds them as it starts, maybe while hooks still set up a
/// new namespace: only 0.0.0.0 or a loopback HOST_IP is sure to exist then.
const PUBLISH_TCP: &str = "io.litebox.publish.tcp";
/// The same for guest UDP ports, served while a guest socket is bound to them.
const PUBLISH_UDP: &str = "io.litebox.publish.udp";

/// What the shim applies of a spec.
#[derive(Debug)]
pub struct Plan {
    /// Relative to the bundle unless absolute.
    pub root: PathBuf,
    pub process: Process,
    /// The user, which selects only `HOME` for now: every guest process runs as the guest user.
    pub uid: u32,
    pub binds: Vec<Bind>,
    pub egress: Egress,
    pub ingress: Ingress,
    /// Host ports that serve guest ports.
    pub publish: Vec<Publish>,
    pub network: Network,
    /// The spec's `net.*` sysctls, as paths under `/proc/sys`, for a network namespace of the
    /// container's own.
    pub sysctl: Vec<(String, String)>,
    pub resources: Resources,
}

/// The broker's network namespace, where it opens the guests' host sockets.
#[derive(Debug, PartialEq, Eq)]
pub enum Network {
    /// The daemon's: the spec has no network namespace.
    Daemon,
    /// The one at this path (CRI's pods, which CRI configured).
    Join(PathBuf),
    /// A new one, its loopback up, as runc creates it, for hooks to set up through the broker's
    /// pid.
    New,
}

/// A bind mount: a file is copied into the root archive, a directory is served by the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub source: PathBuf,
    /// Absolute, normalized, never `/`.
    pub destination: String,
    pub read_only: bool,
}

/// What the guests may reach outside the broker: the broker's `--allow-tcp-destination` and
/// `--allow-udp-destination` rules take `CIDR:PORT[-PORT]` (or the VM payload's `policy`), while its
/// `--allow-icmp-echo-destination` rules take a bare IPv4 CIDR. An allowed range reaches what the
/// broker's network namespace ([`Network`]) reaches: the guests' gateway, 10.0.2.1, is that
/// namespace's loopback: a pod's, shared by its containers, or in the daemon's namespace
/// ([`Network::Daemon`]), the host's. The VM's network, QEMU's, takes 10.0.2.0/24: of it, only the
/// gateway and QEMU's DNS forwarder, 10.0.2.3, are reachable.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Egress {
    pub tcp: Vec<Destination>,
    pub udp: Vec<Destination>,
    /// IPv4 networks allowed to receive ICMP echo requests (no ports).
    pub icmp_echo: Vec<Cidr>,
}

/// The networks whose clients published ports admit, as the broker's `--allow-tcp-source` and
/// `--allow-udp-source`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ingress {
    pub tcp: Vec<Cidr>,
    pub udp: Vec<Cidr>,
}

/// The spec's limits that the VM backend applies, as its memory and CPUs; the userland broker has
/// no cgroups.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Resources {
    /// `linux.resources.memory.limit`, in bytes, if positive.
    pub memory: Option<u64>,
    /// `linux.resources.cpu`'s quota over its period (Linux's default, 100 ms, if unset), rounded
    /// up, if both are positive.
    pub cpus: Option<u32>,
}

/// A canonical IPv4 network, `NETWORK/PREFIX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

impl FromStr for Cidr {
    type Err = &'static str;

    /// Parses as the broker does: no host bits may be set.
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (network, prefix) = value.split_once('/').ok_or("no `/` before the prefix")?;
        let network: Ipv4Addr = network.parse().map_err(|_| "invalid network")?;
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|prefix| *prefix <= 32)
            .ok_or("invalid prefix")?;
        if u32::from(network) & !u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0) != 0 {
            return Err("the network has host bits set");
        }
        Ok(Self { network, prefix })
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination {
    cidr: Cidr,
    ports: (u16, u16),
}

impl FromStr for Destination {
    type Err = &'static str;

    /// Parses as the broker does: a [`Cidr`], and an ordered range of nonzero ports.
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (cidr, ports) = value.rsplit_once(':').ok_or("no `:` before the ports")?;
        let cidr = cidr.parse()?;
        let (first, last) = ports.split_once('-').unwrap_or((ports, ports));
        let port = |port: &str| port.parse::<u16>().map_err(|_| "invalid port");
        let ports = (port(first)?, port(last)?);
        if ports.0 == 0 || ports.0 > ports.1 {
            return Err("the port range must be ordered and exclude 0");
        }
        Ok(Self { cidr, ports })
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.cidr, self.ports.0)?;
        if self.ports.1 != self.ports.0 {
            write!(f, "-{}", self.ports.1)?;
        }
        Ok(())
    }
}

/// A host port published to a guest port, as the broker's `--publish`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publish {
    pub host: SocketAddrV4,
    guest_port: u16,
    protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
}

impl Publish {
    /// Parses `[HOST_IP:]HOST_PORT:GUEST_PORT` as the broker does: the host IP is `0.0.0.0` by
    /// default, and ports are not 0.
    fn parse(value: &str, protocol: Protocol) -> std::result::Result<Self, &'static str> {
        let (host, guest) = value
            .rsplit_once(':')
            .ok_or("no `:` before the guest port")?;
        let (ip, host_port) = host.rsplit_once(':').unwrap_or(("0.0.0.0", host));
        let port = |port: &str| port.parse().ok().filter(|port| *port != 0);
        Ok(Self {
            host: SocketAddrV4::new(
                ip.parse().map_err(|_| "invalid host IP")?,
                port(host_port).ok_or("invalid host port")?,
            ),
            guest_port: port(guest).ok_or("invalid guest port")?,
            protocol,
        })
    }
}

impl std::fmt::Display for Publish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.guest_port)?;
        f.write_str(match self.protocol {
            Protocol::Tcp => "",
            Protocol::Udp => "/udp",
        })
    }
}

/// The comma-separated `form`s of the annotation `key`.
fn entries<T>(
    annotations: &HashMap<String, String>,
    key: &str,
    form: &str,
    parse: impl Fn(&str) -> std::result::Result<T, &'static str>,
) -> Result<Vec<T>> {
    let Some(value) = annotations.get(key).filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .enumerate()
        .map(|(index, entry)| {
            parse(entry).map_err(|reason| {
                invalid(format!(
                    "annotation {key}: entry {index} is not {form} ({reason})"
                ))
            })
        })
        .collect()
}

/// The egress that the annotations grant; unknown `io.litebox.*` annotations are refused.
fn egress(annotations: &HashMap<String, String>) -> Result<Egress> {
    if let Some(key) = annotations.keys().find(|key| {
        key.get(..11)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("io.litebox."))
            && !matches!(
                key.as_str(),
                EGRESS_TCP
                    | EGRESS_UDP
                    | EGRESS_ICMP_ECHO
                    | INGRESS_TCP
                    | INGRESS_UDP
                    | PUBLISH_TCP
                    | PUBLISH_UDP
            )
    }) {
        return Err(invalid(format!("unknown annotation {key:?}")));
    }
    Ok(Egress {
        tcp: entries(annotations, EGRESS_TCP, "CIDR:PORT[-PORT]", str::parse)?,
        udp: entries(annotations, EGRESS_UDP, "CIDR:PORT[-PORT]", str::parse)?,
        icmp_echo: entries(annotations, EGRESS_ICMP_ECHO, "CIDR", str::parse)?,
    })
}

/// The ingress that the annotations [`INGRESS_TCP`] and [`INGRESS_UDP`] grant.
fn ingress(annotations: &HashMap<String, String>) -> Result<Ingress> {
    Ok(Ingress {
        tcp: entries(annotations, INGRESS_TCP, "CIDR", str::parse)?,
        udp: entries(annotations, INGRESS_UDP, "CIDR", str::parse)?,
    })
}

/// The ports that the annotations [`PUBLISH_TCP`] and [`PUBLISH_UDP`] publish. As the broker, it
/// refuses an entry whose host endpoint overlaps an earlier one's (the same port, at the same or
/// the unspecified IP), or whose guest port an earlier one names.
fn published(annotations: &HashMap<String, String>) -> Result<Vec<Publish>> {
    let mut published = Vec::new();
    for (key, protocol) in [(PUBLISH_TCP, Protocol::Tcp), (PUBLISH_UDP, Protocol::Udp)] {
        let form = "[HOST_IP:]HOST_PORT:GUEST_PORT";
        let publish = entries(annotations, key, form, |entry| {
            Publish::parse(entry, protocol)
        })?;
        if let Some((index, _)) = publish.iter().enumerate().find(|(index, p)| {
            (publish[..*index].iter()).any(|q| {
                let any = q.host.ip().is_unspecified() || p.host.ip().is_unspecified();
                let ip = any || q.host.ip() == p.host.ip();
                (ip && q.host.port() == p.host.port()) || q.guest_port == p.guest_port
            })
        }) {
            return Err(invalid(format!(
                "annotation {key}: entry {index} overlaps an earlier host endpoint or guest port"
            )));
        }
        published.extend(publish);
    }
    Ok(published)
}

/// The resources of `spec` (see [`Resources`]).
/// Linux's CFS period, in microseconds, where a spec's quota has none.
const DEFAULT_CPU_PERIOD: u64 = 100_000;

fn resources(spec: &Spec) -> Resources {
    let Some(resources) = spec
        .linux()
        .as_ref()
        .and_then(|linux| linux.resources().as_ref())
    else {
        return Resources::default();
    };
    let memory = resources
        .memory()
        .as_ref()
        .and_then(oci_spec::runtime::LinuxMemory::limit)
        .and_then(|limit| u64::try_from(limit).ok())
        .filter(|limit| *limit > 0);
    let cpus = resources
        .cpu()
        .as_ref()
        .and_then(|cpu| {
            let quota = u64::try_from(cpu.quota()?).ok()?;
            Some((quota, cpu.period().unwrap_or(DEFAULT_CPU_PERIOD)))
        })
        .filter(|(quota, period)| *quota > 0 && *period > 0)
        .map(|(quota, period)| u32::try_from(quota.div_ceil(period)).unwrap_or(u32::MAX));
    Resources { memory, cpus }
}

/// The process that the guest service runs for `process`, with a terminal if `terminal`; and
/// the user it asks for.
pub fn process(process: &oci_spec::runtime::Process, terminal: bool) -> Result<(Process, u32)> {
    let args = process.args().clone().unwrap_or_default();
    if args.first().is_none_or(String::is_empty) {
        return Err(invalid("process.args must name a program"));
    }
    let cwd = process
        .cwd()
        .to_str()
        .filter(|cwd| cwd.starts_with('/'))
        .ok_or_else(|| invalid("process.cwd must be an absolute path"))?;
    let size = process.console_size();
    let guest = Process {
        args,
        env: process.env().clone().unwrap_or_default(),
        cwd: cwd.to_owned(),
        terminal,
        rows: size.map_or(0, |size| u32::try_from(size.height()).unwrap_or(u32::MAX)),
        columns: size.map_or(0, |size| u32::try_from(size.width()).unwrap_or(u32::MAX)),
        ..Default::default()
    };
    // TODO: run processes as this user once LiteBox supports `setuid`.
    Ok((guest, process.user().uid()))
}

/// Checks `spec`. Refused: `createContainer` and `startContainer` hooks, which runc runs in the
/// container's namespaces, and Kata Containers not at all; and malformed or unknown `io.litebox.*`
/// annotations. Not supported yet: mounts of other types. A network namespace without a path, or
/// with an empty one, is a new one, as runc takes it.
pub fn plan(spec: &Spec) -> Result<Plan> {
    let process = spec
        .process()
        .as_ref()
        .ok_or_else(|| invalid("the spec has no process"))?;
    let root = spec
        .root()
        .as_ref()
        .ok_or_else(|| invalid("the spec has no root"))?;
    if let Some(hooks) = spec.hooks()
        && [hooks.create_container(), hooks.start_container()]
            .iter()
            .any(|hooks| hooks.as_ref().is_some_and(|hooks| !hooks.is_empty()))
    {
        return Err(unsupported(
            "createContainer and startContainer hooks are not supported",
        ));
    }
    let namespaces = spec
        .linux()
        .as_ref()
        .and_then(|linux| linux.namespaces().as_ref());
    let network = namespaces
        .into_iter()
        .flatten()
        .find(|namespace| namespace.typ() == LinuxNamespaceType::Network)
        .map_or(Network::Daemon, |namespace| match namespace.path() {
            Some(path) if !path.as_os_str().is_empty() => Network::Join(path.clone()),
            _ => Network::New,
        });
    let mut binds = Vec::new();
    for mount in spec.mounts().iter().flatten() {
        let destination = normalize(mount.destination())?;
        let typ = mount.typ().as_deref().unwrap_or_default();
        let options = mount.options().as_deref().unwrap_or_default();
        let served = SERVED_PATHS
            .iter()
            .any(|served| Path::new(&destination).starts_with(served));
        if served || IGNORED_MOUNTS.contains(&typ) {
            continue;
        }
        if typ != "bind"
            && !options
                .iter()
                .any(|option| option == "bind" || option == "rbind")
        {
            // TODO: mount other types on the host and serve them as directory binds are served.
            return Err(unsupported(format!("{typ:?} mounts are not supported yet")));
        }
        let source = mount
            .source()
            .clone()
            .filter(|source| source.is_absolute())
            .ok_or_else(|| {
                invalid(format!(
                    "the bind at {destination} needs an absolute source"
                ))
            })?;
        // `rro` (recursively read-only, as runc takes it) makes it read-only whatever follows;
        // otherwise the last `ro` or `rw` decides.
        let read_only = options.iter().any(|o| o == "rro")
            || options
                .iter()
                .rev()
                .find(|o| *o == "ro" || *o == "rw")
                .is_some_and(|o| o == "ro");
        binds.push(Bind {
            source,
            destination,
            read_only,
        });
    }
    let (process, uid) = self::process(process, process.terminal().unwrap_or(false))?;
    let no_annotations = HashMap::new();
    let annotations = spec.annotations().as_ref().unwrap_or(&no_annotations);
    let sysctl = self::sysctl(spec, &network)?;
    Ok(Plan {
        root: root.path().clone(),
        process,
        uid,
        binds,
        egress: egress(annotations)?,
        ingress: ingress(annotations)?,
        publish: published(annotations)?,
        network,
        sysctl,
        resources: resources(spec),
    })
}

/// The spec's `net.*` sysctls as paths under `/proc/sys`, in order, which runc sets in a network
/// namespace of the container's own; in the daemon's they are ignored rather than set on the
/// host. The others do not apply. Set before the hooks, they cannot reach an interface a hook
/// creates.
fn sysctl(spec: &Spec, network: &Network) -> Result<Vec<(String, String)>> {
    let sysctl = spec
        .linux()
        .as_ref()
        .and_then(|linux| linux.sysctl().as_ref());
    let mut paths = Vec::new();
    for (key, value) in sysctl.into_iter().flatten() {
        // As sysctl(8) reads it: if `/` separates its first name, `.` is part of names.
        let slashed = key
            .find(['.', '/'])
            .is_some_and(|at| key.as_bytes()[at] == b'/');
        let swap = |c| match c {
            '.' if !slashed => '/',
            '/' if !slashed => '.',
            c => c,
        };
        let path: String = key.chars().map(swap).collect();
        let name = |part: &str| {
            part.bytes().any(|byte| byte != b'.')
                && (part.bytes()).all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
        };
        if !path.starts_with("net/") || *network == Network::Daemon {
            continue;
        }
        if !path.split('/').all(name) || value.contains('\0') {
            return Err(invalid(format!("invalid sysctl {key:?}")));
        }
        paths.push((path, value.clone()));
    }
    paths.sort();
    Ok(paths)
}

/// `path` as an absolute guest path without `.`; never `/`.
fn normalize(path: &Path) -> Result<String> {
    let refuse = || {
        invalid(format!(
            "mount destination {} must be below / without ..",
            path.display()
        ))
    };
    // Not `is_absolute`, which on Windows also wants a drive.
    if !path.has_root() {
        return Err(refuse());
    }
    let mut normalized = String::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                normalized.push('/');
                normalized.push_str(name.to_str().ok_or_else(refuse)?);
            }
            Component::ParentDir | Component::Prefix(_) => return Err(refuse()),
        }
    }
    if normalized.is_empty() {
        return Err(refuse());
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_annotations_are_the_brokers_lists() {
        let annotations = |k: &str, v: &str| HashMap::from([(k.to_owned(), v.to_owned())]);
        let tcp = egress(&annotations(EGRESS_TCP, "10.0.0.0/8:443,192.0.2.1/32:1-9"));
        let listed: Vec<String> = tcp.unwrap().tcp.iter().map(ToString::to_string).collect();
        assert_eq!(listed, ["10.0.0.0/8:443", "192.0.2.1/32:1-9"]);
        let echo =
            |value| egress(&annotations(EGRESS_ICMP_ECHO, value)).map(|policy| policy.icmp_echo);
        assert!(echo("192.0.2.17/32,198.51.100.0/24").is_ok_and(|rules| rules.len() == 2));
        assert!(echo("192.0.2.0/24:7").is_err());
        assert!(echo("192.0.2.1/24").is_err());
        assert!(egress(&annotations(EGRESS_UDP, "")).is_ok_and(|e| e == Egress::default()));
        let udp = |value| ingress(&annotations(INGRESS_UDP, value)).map(|ingress| ingress.udp);
        assert!(udp("10.0.2.1/32,0.0.0.0/0").is_ok_and(|udp| udp[1].to_string() == "0.0.0.0/0"));
        assert!(udp("10.0.0.1/8").is_err() && udp("10.0.0.0/8:80").is_err());
        let bad = "10.0.0.1/8:53 10.0.0.0/33:53 10.0.0.0/8:0 10.0.0.0/8:9-8 10.0.0.0:53 x";
        for bad in bad.split(' ') {
            assert!(egress(&annotations(EGRESS_UDP, bad)).is_err(), "{bad}");
        }
        assert!(egress(&annotations("io.litebox.Egress.tcp", "")).is_err());
        assert!(egress(&annotations("io.other", "")).is_ok());
        let publish = |key, value: &str| published(&annotations(key, value));
        let udp = publish(PUBLISH_UDP, "80:81").unwrap()[0];
        assert_eq!(udp.to_string(), "0.0.0.0:80:81/udp");
        for bad in ["80", "x:80:80", "80:1,127.0.0.1:80:2", "80:1,81:1"] {
            assert!(publish(PUBLISH_TCP, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resources_are_the_memory_limit_and_the_cpus() {
        let resources = |value: serde_json::Value| {
            let spec: Spec = serde_json::from_value(serde_json::json!({
                "ociVersion": "1.2.0",
                "linux": {"resources": value},
            }))
            .unwrap();
            resources(&spec)
        };
        let limited = serde_json::json!({
            "memory": {"limit": 1 << 30},
            "cpu": {"quota": 150_000, "period": 100_000, "cpus": "0-7"},
        });
        let expected = Resources {
            memory: Some(1 << 30),
            cpus: Some(2),
        };
        assert_eq!(resources(limited), expected);
        // Linux's default period.
        let quota_only = serde_json::json!({"cpu": {"quota": 200_000, "cpus": "0-3"}});
        assert_eq!(resources(quota_only).cpus, Some(2));
        for unlimited in [
            serde_json::json!({}),
            serde_json::json!({"memory": {"limit": -1}, "cpu": {"quota": -1, "period": 100_000}}),
            serde_json::json!({"cpu": {"quota": 200_000, "period": 0}}),
        ] {
            assert_eq!(resources(unlimited), Resources::default());
        }
    }

    #[test]
    fn mounts_are_binds_or_ignored() {
        let spec = |mounts: serde_json::Value| -> Spec {
            serde_json::from_value(serde_json::json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "process": {"args": ["sh"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
                "mounts": mounts,
            }))
            .unwrap()
        };
        let plan = plan(&spec(serde_json::json!([
            {"destination": "/proc", "type": "proc"},
            {"destination": "/run", "type": "tmpfs"},
            {"destination": "/dev/x", "type": "bind", "source": "/x"},
            {"destination": "/data/./x/", "type": "none", "source": "/x", "options": ["rbind", "ro"]},
        ])))
        .unwrap();
        let bind = Bind {
            source: "/x".into(),
            destination: "/data/x".to_owned(),
            read_only: true,
        };
        assert_eq!(plan.binds, [bind]);
        for (options, read_only) in [
            (serde_json::json!(["rbind", "rro"]), true),
            (serde_json::json!(["rro", "rw"]), true),
            (serde_json::json!(["rw", "ro"]), true),
            (serde_json::json!(["ro", "rw"]), false),
        ] {
            let mounts = serde_json::json!([
                {"destination": "/d", "type": "bind", "source": "/x", "options": options},
            ]);
            let binds = super::plan(&spec(mounts)).unwrap().binds;
            assert_eq!(binds[0].read_only, read_only, "{options}");
        }
        for bad in [
            serde_json::json!([{"destination": "/a/../b", "type": "bind", "source": "/x"}]),
            serde_json::json!([{"destination": "/a", "type": "bind", "source": "x"}]),
            serde_json::json!([{"destination": "/a", "type": "overlay", "source": "/x"}]),
        ] {
            assert!(super::plan(&spec(bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_network_namespace_is_the_daemon_s_a_joined_or_a_new_one() {
        let spec = |namespace: serde_json::Value, sysctl: serde_json::Value| -> Spec {
            serde_json::from_value(json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "process": {"args": ["sh"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
                "linux": {"namespaces": [namespace], "sysctl": sysctl},
            }))
            .unwrap()
        };
        let sysctl = json!({"net/core/x.y": "1", "net.ipv4.a/b": "2", "kernel.z": "3"});
        let join = Network::Join("/run/x".into());
        // Its own namespace gets the `net.*` ones.
        for (namespace, expected, count) in [
            (json!({"type": "pid"}), Network::Daemon, 0),
            (json!({"type": "network"}), Network::New, 2),
            (json!({"type": "network", "path": ""}), Network::New, 2),
            (json!({"type": "network", "path": "/run/x"}), join, 2),
        ] {
            let plan = plan(&spec(namespace, sysctl.clone())).unwrap();
            assert_eq!((plan.network, plan.sysctl.len()), (expected, count));
        }
        // As paths: a leading `/` keeps `.` in names.
        let joined = plan(&spec(json!({"type": "network", "path": "/x"}), sysctl)).unwrap();
        let paths = [("net/core/x.y", "1"), ("net/ipv4/a.b", "2")];
        let paths = paths.map(|(path, value)| (path.to_owned(), value.to_owned()));
        assert_eq!(joined.sysctl, paths);
        for bad in ["net.ipv4..x", "net/ipv4/../x", "net.ipv4.x y"] {
            assert!(plan(&spec(json!({"type": "network"}), json!({bad: "1"}))).is_err());
        }
    }
}
