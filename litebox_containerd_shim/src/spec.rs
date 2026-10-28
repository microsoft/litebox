// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Validation and translation of an OCI runtime spec into the supported LiteBox subset.
//!
//! Nothing here touches the host. Settings LiteBox cannot honor yet are rejected; host-kernel
//! settings that have no meaning for a broker-served container are ignored (see the README).

use std::path::{Component, Path, PathBuf};

use oci_spec::runtime::{Mount, Process, Spec};

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
}

impl ProcessSpec {
    pub(crate) fn from_oci(process: &Process) -> Result<Self> {
        if process.terminal().unwrap_or(false) {
            return Err(Error::unimplemented("terminals are not supported"));
        }
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

/// What the broker serves to a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerPlan {
    /// The root file system, relative to the bundle unless absolute.
    pub(crate) root: PathBuf,
    pub(crate) mounts: Vec<MountPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountPlan {
    /// Absolute normalized guest path, never `/`.
    pub(crate) destination: String,
    pub(crate) kind: MountKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MountKind {
    /// A host directory, served with the mounts below it.
    Bind { source: PathBuf },
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
        if root.readonly().unwrap_or(false) {
            return Err(Error::unimplemented("read-only roots are not supported"));
        }
        // Hooks configure host namespaces (such as CNI networking), which the guest never uses.
        if spec.hooks().is_some() {
            log::info!("ignoring the spec's hooks");
        }
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
            mounts,
        };
        Ok((plan, ProcessSpec::from_oci(process)?))
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
            for option in options {
                match option.as_str() {
                    // Guests reach files only through the broker, which applies none of these.
                    "bind" | "rbind" | "rw" | "nosuid" | "suid" | "nodev" | "dev" | "noexec"
                    | "exec" | "private" | "rprivate" | "shared" | "rshared" | "slave"
                    | "rslave" | "unbindable" | "runbindable" => {}
                    // Includes `ro`: the broker writes with the daemon's access.
                    other => return unsupported(other),
                }
            }
            let kind = MountKind::Bind { source };
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
            }
        );
        assert_eq!(process.search_path(), "/usr/local/bin:/usr/bin:/bin");
    }

    #[test]
    fn host_settings_without_meaning_for_the_guest_are_ignored() {
        let mut json = ctr_default();
        json["process"]["user"] =
            serde_json::json!({"uid": 1000, "gid": 2000, "additionalGids": [3]});
        json["hooks"] = serde_json::json!({"createRuntime": [{"path": "/usr/bin/cni"}]});
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

        json["linux"]["namespaces"] = serde_json::json!([{"type": "pid"}]);
        translate(&json).unwrap();
    }

    #[test]
    fn binds_translate_with_their_options() {
        let mut json = ctr_default();
        json["mounts"] = serde_json::json!([
            {"destination": "//data/./x/", "type": "none", "source": "/srv", "options": ["rbind", "rw", "rprivate"]},
            {"destination": "/etc/hosts.d", "type": "bind", "source": "/etc/h", "options": ["nosuid", "nodev", "noexec"]},
        ]);
        let (plan, _) = translate(&json).unwrap();
        let bind = |source: &str| MountKind::Bind {
            source: source.into(),
        };
        assert_eq!(
            plan.mounts,
            [
                MountPlan {
                    destination: "/data/x".into(),
                    kind: bind("/srv"),
                },
                MountPlan {
                    destination: "/etc/hosts.d".into(),
                    kind: bind("/etc/h"),
                },
            ]
        );
    }

    #[test]
    fn unsupported_settings_are_rejected_without_quoting_values() {
        let mut json = ctr_default();
        json["process"]["env"] = serde_json::json!(["TOKEN=secret\u{0}x"]);
        let error = translate(&json).unwrap_err();
        assert_eq!(error.message, "process.env[0] contains a NUL byte");

        let bind = |options: &[&str]| serde_json::json!([{"destination": "/d", "type": "bind", "source": "/s", "options": options}]);
        let cases: [(&str, serde_json::Value, Kind); 12] = [
            ("/process/terminal", true.into(), Kind::Unimplemented),
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
            ("/root/readonly", true.into(), Kind::Unimplemented),
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
            ("/mounts", bind(&["rbind", "ro"]), Kind::Unimplemented),
            ("/mounts", bind(&["rbind", "rro"]), Kind::Unimplemented),
            ("/mounts", bind(&["bind", "idmap"]), Kind::Unimplemented),
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
