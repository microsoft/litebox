// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Validation and translation of an OCI runtime spec into the supported LiteBox subset.
//!
//! Nothing here touches the host. Settings LiteBox cannot honor yet are rejected; host-kernel
//! settings that have no meaning for a broker-served container are ignored (see the README).

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use litebox_broker_protocol::terminal::WindowSize;
use oci_spec::runtime::{LinuxNamespaceType, Mount, Process, Spec};

use crate::error::{Error, Result};

/// `PATH` searched for the program when the process environment sets none.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// File mode creation mask of a process whose spec sets none, as runc uses.
const DEFAULT_UMASK: u32 = 0o022;

/// Mode of a tmpfs root whose options set none, as Linux uses.
const DEFAULT_TMPFS_MODE: u16 = 0o1777;

/// Guest paths that LiteBox serves itself (`/dev`) or does not have (`/proc`, `/sys`).
const SERVED_PATHS: [&str; 3] = ["/dev", "/proc", "/sys"];

/// Kernel file systems, which LiteBox does not provide anywhere.
const KERNEL_FS_TYPES: [&str; 6] = ["proc", "sysfs", "devpts", "mqueue", "cgroup", "cgroup2"];

/// A container process, in what the Linux runner's program startup expresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessSpec {
    /// The exact `argv`; `args[0]` also names the program.
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<String>,
    /// Absolute guest working directory.
    pub(crate) cwd: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) umask: u32,
    /// The initial size of the process's terminal, if it has one: zero, as Linux starts it,
    /// unless the spec sets `consoleSize`.
    pub(crate) terminal: Option<WindowSize>,
}

impl ProcessSpec {
    pub(crate) fn from_oci(process: &Process) -> Result<Self> {
        let terminal = process
            .terminal()
            .unwrap_or(false)
            .then(|| {
                let Some(size) = process.console_size() else {
                    return Ok(WindowSize::default());
                };
                window_size(size.height(), size.width())
                    .ok_or_else(|| Error::invalid("process.consoleSize is too large"))
            })
            .transpose()?;
        let args = process.args().clone().unwrap_or_default();
        if args.first().is_none_or(String::is_empty) {
            return Err(Error::invalid("process.args must name a program"));
        }
        let env = process.env().clone().unwrap_or_default();
        // Entries are named by index only: values may be secrets.
        for (field, values) in [("args", &args), ("env", &env)] {
            if let Some(index) = values.iter().position(|value| value.contains('\0')) {
                return Err(Error::invalid(format!(
                    "process.{field}[{index}] contains a NUL byte"
                )));
            }
        }
        let cwd = process
            .cwd()
            .to_str()
            .filter(|cwd| cwd.starts_with('/'))
            .ok_or_else(|| Error::invalid("process.cwd must be an absolute path"))?;
        let user = process.user();
        let umask = user.umask().unwrap_or(DEFAULT_UMASK);
        if umask > 0o777 {
            return Err(Error::invalid("process.user.umask must be at most 0777"));
        }
        Ok(Self {
            args,
            env,
            cwd: cwd.to_owned(),
            uid: user.uid(),
            gid: user.gid(),
            umask,
            terminal,
        })
    }

    /// The value of the first `PATH` entry, which a program lookup uses.
    pub(crate) fn search_path(&self) -> &str {
        self.env
            .iter()
            .find_map(|entry| entry.strip_prefix("PATH="))
            .unwrap_or(DEFAULT_PATH)
    }
}

/// What the broker serves to a container, and how the container's runners and hooks run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerPlan {
    /// The root file system, relative to the bundle unless absolute.
    pub(crate) root: PathBuf,
    pub(crate) root_read_only: bool,
    pub(crate) mounts: Vec<MountPlan>,
    pub(crate) network: Network,
    pub(crate) hooks: Hooks,
    /// The spec's `ociVersion` and `annotations`, which the hooks' OCI state reports.
    pub(crate) oci_version: String,
    pub(crate) annotations: HashMap<String, String>,
}

/// The network namespace of the container's runners, whose `/proc/<pid>/ns/net` container
/// managers configure. The guest's own network is always the broker's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Network {
    /// The daemon's own namespace: the spec has no `network` namespace.
    Daemon,
    /// A new namespace.
    New,
    /// The existing namespace at this path.
    Join(PathBuf),
}

/// The container's OCI hooks, which run on the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Hooks {
    /// `prestart`, `createRuntime` and `createContainer`, in the order they run at `Create`.
    pub(crate) create: Vec<Hook>,
    pub(crate) poststart: Vec<Hook>,
    pub(crate) poststop: Vec<Hook>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hook {
    /// The hook's kind and index, which name it in messages.
    pub(crate) name: String,
    /// Absolute host path.
    pub(crate) path: PathBuf,
    /// The exact `argv`, if any; `path` is `argv[0]` otherwise.
    pub(crate) args: Vec<String>,
    /// The exact environment, or none to inherit the daemon's, as runc does.
    pub(crate) env: Option<Vec<String>>,
    pub(crate) timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountPlan {
    /// Absolute normalized guest path, never `/`.
    pub(crate) destination: String,
    pub(crate) kind: MountKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MountKind {
    /// A host directory, served with the mounts below it, or a host file.
    Bind { source: PathBuf, read_only: bool },
    /// An in-memory file system whose root has `mode`.
    Tmpfs { mode: u16 },
}

impl ContainerPlan {
    /// Validates `spec`, returning the container plan and its init process.
    pub(crate) fn from_spec(spec: &Spec) -> Result<(Self, ProcessSpec)> {
        let process = spec
            .process()
            .as_ref()
            .ok_or_else(|| Error::invalid("the spec has no process"))?;
        let root = spec
            .root()
            .as_ref()
            .ok_or_else(|| Error::invalid("the spec has no root"))?;
        let network = spec
            .linux()
            .as_ref()
            .and_then(|linux| linux.namespaces().as_ref())
            .and_then(|namespaces| {
                namespaces
                    .iter()
                    .find(|namespace| namespace.typ() == LinuxNamespaceType::Network)
            })
            .map_or(Network::Daemon, |namespace| {
                namespace.path().clone().map_or(Network::New, Network::Join)
            });
        let mut mounts: Vec<MountPlan> = Vec::new();
        for mount in spec.mounts().iter().flatten() {
            if let Some(plan) = MountPlan::from_oci(mount)? {
                for earlier in &mounts {
                    // Linux would stack them, but the broker serves one file system per path.
                    if earlier.destination == plan.destination {
                        return Err(Error::unimplemented(format!(
                            "two mounts at {}, which is not supported",
                            plan.destination
                        )));
                    }
                    // Linux would cover the earlier mount, but the broker would keep serving it.
                    if earlier
                        .destination
                        .strip_prefix(&plan.destination)
                        .is_some_and(|rest| rest.starts_with('/'))
                    {
                        return Err(Error::unimplemented(format!(
                            "the mount at {} covers the earlier mount at {}, which is not \
                             supported",
                            plan.destination, earlier.destination
                        )));
                    }
                }
                mounts.push(plan);
            }
        }
        let plan = Self {
            root: root.path().clone(),
            root_read_only: root.readonly().unwrap_or(false),
            mounts,
            network,
            hooks: spec
                .hooks()
                .as_ref()
                .map(Hooks::from_oci)
                .transpose()?
                .unwrap_or_default(),
            oci_version: spec.version().clone(),
            annotations: spec.annotations().clone().unwrap_or_default(),
        };
        Ok((plan, ProcessSpec::from_oci(process)?))
    }
}

impl Hooks {
    fn from_oci(hooks: &oci_spec::runtime::Hooks) -> Result<Self> {
        // `startContainer` hooks run in the container, where only LiteBox guests run.
        if hooks
            .start_container()
            .as_ref()
            .is_some_and(|hooks| !hooks.is_empty())
        {
            return Err(Error::unimplemented(
                "startContainer hooks are not supported",
            ));
        }
        let translate = |kind: &str, hooks: &Option<Vec<oci_spec::runtime::Hook>>| {
            hooks
                .iter()
                .flatten()
                .enumerate()
                .map(|(index, hook)| Hook::from_oci(format!("{kind} hook {index}"), hook))
                .collect::<Result<Vec<_>>>()
        };
        let mut create = translate("prestart", hooks.prestart())?;
        create.extend(translate("createRuntime", hooks.create_runtime())?);
        create.extend(translate("createContainer", hooks.create_container())?);
        Ok(Self {
            create,
            poststart: translate("poststart", hooks.poststart())?,
            poststop: translate("poststop", hooks.poststop())?,
        })
    }
}

impl Hook {
    fn from_oci(name: String, hook: &oci_spec::runtime::Hook) -> Result<Self> {
        if !hook.path().is_absolute() {
            return Err(Error::invalid(format!("the {name} needs an absolute path")));
        }
        let timeout = hook
            .timeout()
            .map(|seconds| {
                u64::try_from(seconds)
                    .ok()
                    .filter(|seconds| *seconds > 0)
                    .map(Duration::from_secs)
                    .ok_or_else(|| {
                        Error::invalid(format!("the timeout of the {name} must be positive"))
                    })
            })
            .transpose()?;
        Ok(Self {
            path: hook.path().clone(),
            args: hook.args().clone().unwrap_or_default(),
            env: hook.env().clone(),
            timeout,
            name,
        })
    }
}

/// Whether `path` is or is beneath a guest path that LiteBox serves or does not have.
fn under_served_path(path: &str) -> bool {
    SERVED_PATHS.iter().any(|served| {
        path.strip_prefix(served)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// Normalizes an absolute guest path, rejecting `..` and the root itself.
fn normalize(path: &Path) -> Result<String> {
    let invalid = || {
        Error::invalid(format!(
            "mount destination {} must be an absolute path below / without ..",
            path.display()
        ))
    };
    if !path.is_absolute() {
        return Err(invalid());
    }
    let mut normalized = String::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                normalized.push('/');
                normalized.push_str(name.to_str().ok_or_else(invalid)?);
            }
            Component::ParentDir | Component::Prefix(_) => return Err(invalid()),
        }
    }
    if normalized.is_empty() {
        return Err(invalid());
    }
    Ok(normalized)
}

impl MountPlan {
    /// Translates `mount`, or returns `None` for one that LiteBox guests never see.
    fn from_oci(mount: &Mount) -> Result<Option<Self>> {
        let destination = normalize(mount.destination())?;
        let typ = mount.typ().as_deref().unwrap_or_default();
        let options = mount.options().as_deref().unwrap_or_default();
        let bind = typ == "bind" || options.iter().any(|o| o == "bind" || o == "rbind");
        if KERNEL_FS_TYPES.contains(&typ)
            || (under_served_path(&destination) && !(typ == "tmpfs" && destination == "/dev/shm"))
        {
            return Ok(None);
        }
        let unsupported = |option: &str| {
            Err(Error::unimplemented(format!(
                "option {option} of the mount at {destination} is not supported"
            )))
        };
        if bind {
            let source = mount
                .source()
                .clone()
                .filter(|source| source.is_absolute())
                .ok_or_else(|| {
                    Error::invalid(format!(
                        "the bind mount at {destination} needs an absolute source"
                    ))
                })?;
            let mut read_only = false;
            for option in options {
                match option.as_str() {
                    "ro" => read_only = true,
                    "rw" => read_only = false,
                    // Guests reach files only through the broker, which applies none of these.
                    "bind" | "rbind" | "nosuid" | "suid" | "nodev" | "dev" | "noexec" | "exec"
                    | "private" | "rprivate" | "shared" | "rshared" | "slave" | "rslave"
                    | "unbindable" | "runbindable" => {}
                    other => return unsupported(other),
                }
            }
            let kind = MountKind::Bind { source, read_only };
            return Ok(Some(Self { destination, kind }));
        }
        if typ != "tmpfs" {
            return Err(Error::unimplemented(format!(
                "{typ:?} mounts, as at {destination}, are not supported"
            )));
        }
        let mut mode = DEFAULT_TMPFS_MODE;
        for option in options {
            if let Some(value) = option.strip_prefix("mode=") {
                mode = u16::from_str_radix(value, 8)
                    .ok()
                    .filter(|mode| *mode <= 0o7777)
                    .ok_or_else(|| Error::invalid(format!("invalid {option} at {destination}")))?;
            } else if option == "ro" {
                // The in-memory file system cannot be made read-only.
                return unsupported(option);
            }
        }
        Ok(Some(Self {
            destination,
            kind: MountKind::Tmpfs { mode },
        }))
    }
}

/// The terminal size of `rows` and `columns`, unless Linux cannot represent it.
pub(crate) fn window_size(
    rows: impl TryInto<u16>,
    columns: impl TryInto<u16>,
) -> Option<WindowSize> {
    Some(WindowSize {
        rows: rows.try_into().ok()?,
        columns: columns.try_into().ok()?,
        ..WindowSize::default()
    })
}

/// Validates a `Kill` signal number.
pub(crate) fn kill_signal(signal: u32) -> Result<u32> {
    // SIGSTOP, SIGTSTP, SIGTTIN and SIGTTOU: LiteBox treats stopping as termination.
    if (19..=22).contains(&signal) {
        return Err(Error::unimplemented(format!(
            "signal {signal}: stopping processes is not supported"
        )));
    }
    if signal > 64 {
        return Err(Error::invalid(format!(
            "signal {signal} is not a Linux signal"
        )));
    }
    Ok(signal)
}

/// Parses an OCI spec or process from JSON, describing failures without quoting the input.
pub(crate) fn parse_json<T: serde::de::DeserializeOwned>(what: &str, json: &[u8]) -> Result<T> {
    serde_json::from_slice(json).map_err(|error| {
        Error::invalid(format!(
            "invalid {what}: {:?} error at line {} column {}",
            error.classify(),
            error.line(),
            error.column()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Kind;

    /// The spec `ctr run` generates for an image, trimmed to what matters here.
    fn ctr_default() -> serde_json::Value {
        serde_json::json!({
            "ociVersion": "1.2.1",
            "root": {"path": "rootfs"},
            "process": {
                "user": {"uid": 0, "gid": 0, "additionalGids": [0, 10]},
                "args": ["sh", "-c", "echo hi"],
                "env": ["PATH=/usr/local/bin:/usr/bin:/bin", "TERM=xterm"],
                "cwd": "/",
                "capabilities": {"bounding": ["CAP_CHOWN"]},
                "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
                "noNewPrivileges": true
            },
            "hostname": "lbx",
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
                {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
                {"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"]},
                {"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]},
                {"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue", "options": ["nosuid", "noexec", "nodev"]},
                {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]},
                {"destination": "/run", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}
            ],
            "linux": {
                "resources": {"devices": [{"allow": false, "access": "rwm"}]},
                "cgroupsPath": "/default/lbx",
                "namespaces": [{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}, {"type": "network"}],
                "maskedPaths": ["/proc/kcore"],
                "readonlyPaths": ["/proc/sys"]
            }
        })
    }

    fn translate(json: &serde_json::Value) -> Result<(ContainerPlan, ProcessSpec)> {
        ContainerPlan::from_spec(&serde_json::from_value(json.clone()).unwrap())
    }

    #[test]
    fn ctr_default_spec_translates() {
        let (plan, process) = translate(&ctr_default()).unwrap();
        assert_eq!(
            plan,
            ContainerPlan {
                root: "rootfs".into(),
                root_read_only: false,
                mounts: vec![
                    MountPlan {
                        destination: "/dev/shm".into(),
                        kind: MountKind::Tmpfs { mode: 0o1777 },
                    },
                    MountPlan {
                        destination: "/run".into(),
                        kind: MountKind::Tmpfs { mode: 0o755 },
                    },
                ],
                network: Network::New,
                hooks: Hooks::default(),
                oci_version: "1.2.1".into(),
                annotations: HashMap::new(),
            }
        );
        assert_eq!(
            process,
            ProcessSpec {
                args: vec!["sh".into(), "-c".into(), "echo hi".into()],
                env: vec![
                    "PATH=/usr/local/bin:/usr/bin:/bin".into(),
                    "TERM=xterm".into()
                ],
                cwd: "/".into(),
                uid: 0,
                gid: 0,
                umask: 0o022,
                terminal: None,
            }
        );
        assert_eq!(process.search_path(), "/usr/local/bin:/usr/bin:/bin");
    }

    #[test]
    fn console_sizes_linux_cannot_represent_are_rejected_for_terminals() {
        let mut json = ctr_default();
        json["process"]["consoleSize"] = serde_json::json!({"height": 24, "width": 65536});
        assert_eq!(translate(&json).unwrap().1.terminal, None);
        json["process"]["terminal"] = true.into();
        assert_eq!(translate(&json).unwrap_err().kind, Kind::InvalidArgument);
    }

    #[test]
    fn host_settings_without_meaning_for_the_guest_are_ignored() {
        let mut json = ctr_default();
        json["process"]["user"] =
            serde_json::json!({"uid": 1000, "gid": 2000, "additionalGids": [3]});
        json["linux"]["namespaces"] = serde_json::json!([
            {"type": "pid"},
            {"type": "user"},
            {"type": "network", "path": "/run/netns/x"},
        ]);
        json["linux"]["uidMappings"] =
            serde_json::json!([{"containerID": 0, "hostID": 100000, "size": 65536}]);
        let (plan, process) = translate(&json).unwrap();
        assert_eq!((process.uid, process.gid), (1000, 2000));
        assert_eq!(plan.mounts.len(), 2);
        assert_eq!(plan.network, Network::Join("/run/netns/x".into()));

        json["linux"]["namespaces"] = serde_json::json!([{"type": "pid"}]);
        assert_eq!(translate(&json).unwrap().0.network, Network::Daemon);
    }

    #[test]
    fn binds_translate_with_their_options() {
        let mut json = ctr_default();
        json["mounts"] = serde_json::json!([
            {"destination": "//data/./x/", "type": "none", "source": "/srv", "options": ["rbind", "rw", "rprivate"]},
            {"destination": "/etc/hosts.d", "type": "bind", "source": "/etc/h", "options": ["nosuid", "nodev", "noexec"]},
            {"destination": "/etc/hosts", "type": "bind", "source": "/h", "options": ["rbind", "ro", "rprivate"]},
            {"destination": "/ro-rw", "type": "bind", "source": "/s", "options": ["ro", "rw"]},
        ]);
        let (plan, _) = translate(&json).unwrap();
        let bind = |source: &str, read_only| MountKind::Bind {
            source: source.into(),
            read_only,
        };
        assert_eq!(
            plan.mounts,
            [
                MountPlan {
                    destination: "/data/x".into(),
                    kind: bind("/srv", false),
                },
                MountPlan {
                    destination: "/etc/hosts.d".into(),
                    kind: bind("/etc/h", false),
                },
                MountPlan {
                    destination: "/etc/hosts".into(),
                    kind: bind("/h", true),
                },
                MountPlan {
                    destination: "/ro-rw".into(),
                    kind: bind("/s", false),
                },
            ]
        );
        json["root"]["readonly"] = true.into();
        assert!(translate(&json).unwrap().0.root_read_only);
    }

    #[test]
    fn unsupported_settings_are_rejected_without_quoting_values() {
        let mut json = ctr_default();
        json["process"]["env"] = serde_json::json!(["TOKEN=secret\u{0}x"]);
        let error = translate(&json).unwrap_err();
        assert_eq!(error.message, "process.env[0] contains a NUL byte");

        let bind = |options: &[&str]| serde_json::json!([{"destination": "/d", "type": "bind", "source": "/s", "options": options}]);
        let cases: [(&str, serde_json::Value, Kind); 13] = [
            (
                "/process/args",
                serde_json::json!([]),
                Kind::InvalidArgument,
            ),
            ("/process/cwd", "relative".into(), Kind::InvalidArgument),
            (
                "/process/user",
                serde_json::json!({"uid": 0, "gid": 0, "umask": 0o1000}),
                Kind::InvalidArgument,
            ),
            (
                "/hooks",
                serde_json::json!({"startContainer": [{"path": "/s"}]}),
                Kind::Unimplemented,
            ),
            (
                "/hooks",
                serde_json::json!({"poststart": [{"path": "s"}]}),
                Kind::InvalidArgument,
            ),
            (
                "/hooks",
                serde_json::json!({"poststop": [{"path": "/s", "timeout": 0}]}),
                Kind::InvalidArgument,
            ),
            (
                "/mounts",
                serde_json::json!([{"destination": "/a/../etc", "type": "tmpfs"}]),
                Kind::InvalidArgument,
            ),
            (
                "/mounts",
                serde_json::json!([{"destination": "/", "type": "tmpfs"}]),
                Kind::InvalidArgument,
            ),
            (
                "/mounts",
                serde_json::json!([{"destination": "/d", "type": "bind", "source": "rel"}]),
                Kind::InvalidArgument,
            ),
            (
                "/mounts",
                serde_json::json!([{"destination": "/d", "type": "nfs", "source": "s:/x"}]),
                Kind::Unimplemented,
            ),
            ("/mounts", bind(&["rbind", "rro"]), Kind::Unimplemented),
            ("/mounts", bind(&["bind", "idmap"]), Kind::Unimplemented),
            (
                "/mounts",
                serde_json::json!([{"destination": "/t", "type": "tmpfs", "options": ["ro"]}]),
                Kind::Unimplemented,
            ),
        ];
        for (pointer, value, kind) in cases {
            let mut json = ctr_default();
            let mut field = &mut json;
            for key in pointer.split('/').skip(1) {
                field = &mut field[key];
            }
            *field = value.clone();
            assert_eq!(
                translate(&json).unwrap_err().kind,
                kind,
                "{pointer} = {value}"
            );
        }
    }

    #[test]
    fn mounts_may_not_cover_or_repeat_earlier_mounts() {
        let mount = |destination: &str, typ: &str, options: &[&str]| serde_json::json!({"destination": destination, "type": typ, "source": "/s", "options": options});
        let child = mount("/data/x", "bind", &["rbind"]);
        let translate_mounts = |mounts: &[&serde_json::Value]| {
            let mut json = ctr_default();
            json["mounts"] = serde_json::json!(mounts);
            translate(&json).map(|(plan, _)| plan.mounts.len())
        };
        for parent in [
            mount("/data", "bind", &["rbind"]),
            mount("/data", "tmpfs", &[]),
        ] {
            assert_eq!(
                translate_mounts(&[&child, &parent]).unwrap_err().kind,
                Kind::Unimplemented,
                "{parent}"
            );
            assert_eq!(translate_mounts(&[&parent, &child]), Ok(2), "{parent}");
        }
        let adjacent = mount("/data2/x", "bind", &["rbind"]);
        let data = mount("/data", "bind", &["rbind"]);
        assert_eq!(translate_mounts(&[&adjacent, &data]), Ok(2));
        let again = mount("/data/", "tmpfs", &[]);
        assert_eq!(
            translate_mounts(&[&data, &again]).unwrap_err().kind,
            Kind::Unimplemented
        );
    }

    #[test]
    fn json_errors_do_not_quote_the_input() {
        let json = br#"{"args": ["sh"], "env": "TOKEN=hunter2", "cwd": "/", "user": {"uid": 0, "gid": 0}}"#;
        let error = parse_json::<Process>("exec process spec", json).unwrap_err();
        assert!(
            error.message.starts_with("invalid exec process spec"),
            "{error}"
        );
        assert!(!error.message.contains("hunter2"), "{error}");
    }
}
