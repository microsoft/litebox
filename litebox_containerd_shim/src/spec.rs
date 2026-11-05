// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The parts of an OCI spec that the shim applies, and the few it refuses (see [`plan`]). Kernel
//! isolation settings (other namespaces, cgroups, seccomp, AppArmor, SELinux, capabilities,
//! rlimits, the user, the umask, a read-only root) have no meaning in a broker and are ignored.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use litebox_guest_service_protocol::guest_service::Process;
#[cfg(target_os = "linux")]
use oci_spec::runtime::LinuxNamespaceType;
use oci_spec::runtime::Spec;

use crate::{Result, invalid, unsupported};

/// Mount types that LiteBox serves itself, or does without.
const IGNORED_MOUNTS: [&str; 7] = [
    "proc", "sysfs", "tmpfs", "devpts", "mqueue", "cgroup", "cgroup2",
];

/// Guest paths that the broker serves itself (`/dev`) or LiteBox does not have.
pub const SERVED_PATHS: [&str; 3] = ["/dev", "/proc", "/sys"];

const EGRESS_TCP: &str = "io.litebox.egress.tcp";
const EGRESS_UDP: &str = "io.litebox.egress.udp";

/// What the shim applies of a spec.
#[derive(Debug)]
pub struct Plan {
    /// Relative to the bundle unless absolute.
    pub root: PathBuf,
    pub process: Process,
    /// The user, which selects `HOME` only: every guest process runs as the guest user.
    pub uid: u32,
    pub binds: Vec<Bind>,
    pub egress: Egress,
}

/// A bind mount: a file is copied into the root archive, a directory is served by the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub source: PathBuf,
    /// Absolute, normalized, never `/`.
    pub destination: String,
    pub read_only: bool,
}

/// What the guests may reach outside the broker, as the broker's `CIDR:PORT[-PORT]` lists:
/// `--allow-tcp-destination` and `--allow-udp-destination`. An allowed range reaches what the
/// broker's host reaches, as the host: the broker's gateway, 10.0.2.1, is the host's loopback, and
/// cloud metadata services (169.254.169.254, Azure's 168.63.129.16) answer the host.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Egress {
    pub tcp: Vec<Destination>,
    pub udp: Vec<Destination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination {
    network: Ipv4Addr,
    prefix: u8,
    ports: (u16, u16),
}

impl FromStr for Destination {
    type Err = &'static str;

    /// Parses as the broker does: a canonical network, and an ordered range of nonzero ports.
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (cidr, ports) = value.rsplit_once(':').ok_or("no `:` before the ports")?;
        let (network, prefix) = cidr.split_once('/').ok_or("no `/` before the prefix")?;
        let network: Ipv4Addr = network.parse().map_err(|_| "invalid network")?;
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|prefix| *prefix <= 32)
            .ok_or("invalid prefix")?;
        if u32::from(network) & !u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0) != 0 {
            return Err("the network has host bits set");
        }
        let (first, last) = ports.split_once('-').unwrap_or((ports, ports));
        let port = |port: &str| port.parse::<u16>().map_err(|_| "invalid port");
        let ports = (port(first)?, port(last)?);
        if ports.0 == 0 || ports.0 > ports.1 {
            return Err("the port range must be ordered and exclude 0");
        }
        Ok(Self {
            network,
            prefix,
            ports,
        })
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}:{}", self.network, self.prefix, self.ports.0)?;
        if self.ports.1 != self.ports.0 {
            write!(f, "-{}", self.ports.1)?;
        }
        Ok(())
    }
}

/// The egress that the annotations grant; any other `io.litebox.*` annotation is refused.
fn egress(annotations: &HashMap<String, String>) -> Result<Egress> {
    if let Some(key) = annotations.keys().find(|key| {
        key.get(..11)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("io.litebox."))
            && *key != EGRESS_TCP
            && *key != EGRESS_UDP
    }) {
        return Err(invalid(format!("unknown annotation {key:?}")));
    }
    let destinations = |key: &str| -> Result<Vec<Destination>> {
        let Some(value) = annotations.get(key).filter(|value| !value.is_empty()) else {
            return Ok(Vec::new());
        };
        value
            .split(',')
            .enumerate()
            .map(|(index, entry)| {
                entry.parse().map_err(|reason| {
                    invalid(format!(
                        "annotation {key}: entry {index} is not CIDR:PORT[-PORT] ({reason})"
                    ))
                })
            })
            .collect()
    };
    Ok(Egress {
        tcp: destinations(EGRESS_TCP)?,
        udp: destinations(EGRESS_UDP)?,
    })
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
/// container's namespaces; a new network namespace (one
/// without a path), which whatever sets it up would set up through the broker's PID, the daemon's
/// network; mounts of other types; and malformed or unknown `io.litebox.*` annotations. A
/// namespace's path (CRI's pods, which CRI configured) is ignored. On macOS all Linux
/// namespace settings are ignored; there are no host Linux namespaces to create or join.
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
    #[cfg(target_os = "linux")]
    let namespaces = spec
        .linux()
        .as_ref()
        .and_then(|linux| linux.namespaces().as_ref());
    #[cfg(target_os = "linux")]
    for namespace in namespaces.into_iter().flatten() {
        // TODO: accept it once the broker gives each container a network of its own.
        if namespace.typ() == LinuxNamespaceType::Network && namespace.path().is_none() {
            return Err(unsupported(
                "a new network namespace is not supported: guests use the shim's network (`ctr \
                 run --net-host`, `docker run --network host`)",
            ));
        }
    }
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
            return Err(unsupported(format!("{typ:?} mounts are not supported")));
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
        let read_only = options
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
    Ok(Plan {
        root: root.path().clone(),
        process,
        uid,
        binds,
        egress: egress(spec.annotations().as_ref().unwrap_or(&HashMap::new()))?,
    })
}

/// `path` as an absolute guest path without `.`; never `/`.
fn normalize(path: &Path) -> Result<String> {
    let refuse = || {
        invalid(format!(
            "mount destination {} must be below / without ..",
            path.display()
        ))
    };
    if !path.is_absolute() {
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

    #[test]
    fn egress_annotations_are_the_brokers_lists() {
        let annotations =
            |key: &str, value: &str| HashMap::from([(key.to_owned(), value.to_owned())]);
        let tcp = egress(&annotations(
            EGRESS_TCP,
            "10.0.0.0/8:443,192.0.2.1/32:1-1024",
        ))
        .unwrap()
        .tcp;
        let listed: Vec<String> = tcp.iter().map(ToString::to_string).collect();
        assert_eq!(listed, ["10.0.0.0/8:443", "192.0.2.1/32:1-1024"]);
        assert_eq!(
            egress(&annotations(EGRESS_UDP, "")).unwrap(),
            Egress::default()
        );
        for bad in [
            "10.0.0.1/8:53",
            "10.0.0.0/33:53",
            "10.0.0.0/8:0",
            "10.0.0.0/8:9-8",
            "10.0.0.0:53",
            "x",
        ] {
            assert!(egress(&annotations(EGRESS_UDP, bad)).is_err(), "{bad}");
        }
        assert!(egress(&annotations("io.litebox.Egress.tcp", "")).is_err());
        assert!(egress(&annotations("io.other", "")).is_ok());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn linux_namespaces_need_no_host_namespaces_on_macos() {
        let spec: Spec = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": {"args": ["/bin/sh"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
            "linux": {"namespaces": [
                {"type": "network"}, {"type": "pid"}, {"type": "mount"},
                {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
            ]}
        }))
        .unwrap();
        assert!(plan(&spec).is_ok());
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
        for bad in [
            serde_json::json!([{"destination": "/a/../b", "type": "bind", "source": "/x"}]),
            serde_json::json!([{"destination": "/a", "type": "bind", "source": "x"}]),
            serde_json::json!([{"destination": "/a", "type": "overlay", "source": "/x"}]),
        ] {
            assert!(super::plan(&spec(bad.clone())).is_err(), "{bad}");
        }
    }
}
