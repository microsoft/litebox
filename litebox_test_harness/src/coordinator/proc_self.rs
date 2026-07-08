// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Focused `/proc/self/*` correctness probes used by diagnostics-heavy consumers.

use super::TestOutcome;
use super::agents::AgentName;
use super::matrix::{EXEC, ExecArgs};
use super::registry::Registry;
use crate::protocol::Response;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

const PROC_SELF_CASES: &[&str] = &[
    "exe_points_to_guest_program",
    "fd_lists_guest_table",
    "fd_N_symlink_target_correct",
    "fd_N_chmod_reaches_real_file",
    "cmdline_is_guest_argv",
    "cwd_matches_guest_chdir",
    "status_pid_is_guest_pid",
    "maps_contains_guest_program",
    "auxv_is_guest_values",
    "comm_is_guest_progname",
];

pub(crate) fn register_proc_self_tests(reg: &mut Registry<'_>) {
    crate::register_leaf_subcommand!("proc-self", proc_self_leaf);

    for &case in PROC_SELF_CASES {
        reg.test("matrix", "proc_self", format!("PROC_SELF.{case}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    let self_exe = run.self_exe().to_string();
                    Box::pin(async move {
                        let resp = run
                            .typed_or_error(
                                &handle,
                                &EXEC,
                                ExecArgs {
                                    args: vec![
                                        self_exe,
                                        "proc-self".into(),
                                        case.into(),
                                        "argv sentinel with spaces".into(),
                                    ],
                                    timeout_secs: Some(15),
                                    stdin: None,
                                    background: false,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains(&format!("PROC_SELF_OK:{case}"))
                        );
                        TestOutcome::new(AgentName::Dpg1.name(), pass, format!("{resp:?}"))
                    })
                })
            });
    }
}

fn proc_self_leaf(args: &[String]) -> i32 {
    let Some(case) = args.get(2).map(String::as_str) else {
        eprintln!("PROC_SELF_ERR:missing case");
        return 2;
    };

    let result = match case {
        "exe_points_to_guest_program" => check_exe_points_to_guest_program(args),
        "fd_lists_guest_table" => check_fd_lists_guest_table(),
        "fd_N_symlink_target_correct" => check_fd_n_symlink_target_correct(),
        "fd_N_chmod_reaches_real_file" => check_fd_n_chmod_reaches_real_file(),
        "cmdline_is_guest_argv" => check_cmdline_is_guest_argv(args),
        "cwd_matches_guest_chdir" => check_cwd_matches_guest_chdir(),
        "status_pid_is_guest_pid" => check_status_pid_is_guest_pid(),
        "maps_contains_guest_program" => check_maps_contains_guest_program(args),
        "auxv_is_guest_values" => check_auxv_is_guest_values(),
        "comm_is_guest_progname" => check_comm_is_guest_progname(),
        other => Err(format!("unknown case {other}")),
    };

    match result {
        Ok(detail) => {
            println!("PROC_SELF_OK:{case}:{detail}");
            0
        }
        Err(detail) => {
            println!("PROC_SELF_ERR:{case}:{detail}");
            1
        }
    }
}

fn check_exe_points_to_guest_program(args: &[String]) -> Result<String, String> {
    let target = fs::read_link("/proc/self/exe").map_err(|e| format!("readlink exe: {e}"))?;
    let argv0 = args.first().ok_or_else(|| "missing argv0".to_string())?;
    let expected = canonicalize_existing(argv0)?;
    if target == expected {
        Ok(format!("target={}", target.display()))
    } else {
        Err(format!(
            "target={} expected={}",
            target.display(),
            expected.display()
        ))
    }
}

fn check_fd_lists_guest_table() -> Result<String, String> {
    let path = unique_shared_path("proc-self-fd-list");
    fs::write(&path, b"fd-list").map_err(|e| format!("write {}: {e}", path.display()))?;
    let file = File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let fd_name = file.as_raw_fd().to_string();
    let entries = fs::read_dir("/proc/self/fd")
        .map_err(|e| format!("read_dir /proc/self/fd: {e}"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read_dir entry: {e}"))?;

    let has_stdio = ["0", "1", "2"]
        .into_iter()
        .all(|name| entries.iter().any(|entry| entry == OsStr::new(name)));
    let has_open_file = entries.iter().any(|entry| entry == OsStr::new(&fd_name));
    if has_stdio && has_open_file {
        Ok(format!("fd={fd_name} entries={entries:?}"))
    } else {
        Err(format!(
            "fd={fd_name} has_stdio={has_stdio} has_open_file={has_open_file} entries={entries:?}"
        ))
    }
}

fn check_fd_n_symlink_target_correct() -> Result<String, String> {
    let path = unique_shared_path("proc-self-fd-target");
    fs::write(&path, b"fd-target").map_err(|e| format!("write {}: {e}", path.display()))?;
    let file = File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let fd = file.as_raw_fd();
    let target = fs::read_link(format!("/proc/self/fd/{fd}"))
        .map_err(|e| format!("readlink fd {fd}: {e}"))?;
    let expected = canonicalize_existing(&path)?;
    if target == expected {
        Ok(format!("fd={fd} target={}", target.display()))
    } else {
        Err(format!(
            "fd={fd} target={} expected={}",
            target.display(),
            expected.display()
        ))
    }
}

/// A chmod through `/proc/self/fd/N` must land on the file behind fd N.
///
/// This is exactly how musl's `fchmod(fd, mode)` is implemented and how GNU
/// `tar` sets permissions while extracting — so it is the minimal repro for the
/// VS Code Remote-SSH server tar-extraction failure under Litebox, where every
/// `fchmodat(AT_FDCWD, "/proc/self/fd/N", …)` mis-resolves broker-side (the
/// broker canonicalizes `/proc/self/fd/N` against *its own* fd table). Under an
/// allow-all policy it silently chmods the wrong file (the guest's file keeps
/// its old mode); under an enforcing policy it surfaces as `EPERM`.
///
/// Native: `chmod("/proc/self/fd/N", 0o755)` follows the magic symlink and the
/// real file becomes `0o755`.
fn check_fd_n_chmod_reaches_real_file() -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = unique_shared_path("proc-self-fd-chmod");
    fs::write(&path, b"chmod-target").map_err(|e| format!("write {}: {e}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("set initial mode {}: {e}", path.display()))?;
    let file = File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let fd = file.as_raw_fd();
    let proc_path = format!("/proc/self/fd/{fd}");
    fs::set_permissions(&proc_path, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod via {proc_path}: {e}"))?;
    let mode = fs::metadata(&path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode == 0o755 {
        Ok(format!("fd={fd} mode={mode:o}"))
    } else {
        Err(format!(
            "chmod via {proc_path} did not reach the file behind fd {fd}: mode={mode:o} expected=755"
        ))
    }
}

fn check_cmdline_is_guest_argv(args: &[String]) -> Result<String, String> {
    let bytes = fs::read("/proc/self/cmdline").map_err(|e| format!("read cmdline: {e}"))?;
    let parts = split_nul(&bytes);
    let expected = [
        "proc-self",
        "cmdline_is_guest_argv",
        "argv sentinel with spaces",
    ];
    let missing: Vec<&str> = expected
        .into_iter()
        .filter(|want| !parts.iter().any(|part| part == want))
        .collect();
    let argv0 = args.first().map_or("", String::as_str);
    if missing.is_empty()
        && parts
            .first()
            .is_some_and(|part| path_ends_with(part, argv0))
    {
        Ok(format!("parts={parts:?}"))
    } else {
        Err(format!(
            "argv0={argv0:?} missing={missing:?} parts={parts:?}"
        ))
    }
}

fn check_cwd_matches_guest_chdir() -> Result<String, String> {
    let dir = unique_shared_path("proc-self-cwd-dir");
    fs::create_dir_all(&dir).map_err(|e| format!("create_dir {}: {e}", dir.display()))?;
    std::env::set_current_dir(&dir).map_err(|e| format!("chdir {}: {e}", dir.display()))?;
    let target = fs::read_link("/proc/self/cwd").map_err(|e| format!("readlink cwd: {e}"))?;
    let expected = canonicalize_existing(&dir)?;
    if target == expected {
        Ok(format!("cwd={}", target.display()))
    } else {
        Err(format!(
            "target={} expected={}",
            target.display(),
            expected.display()
        ))
    }
}

fn check_status_pid_is_guest_pid() -> Result<String, String> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|e| format!("read status: {e}"))?;
    let pid = std::process::id();
    let status_pid = status
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .ok_or_else(|| format!("missing Pid line in {status:?}"))?
        .trim()
        .parse::<u32>()
        .map_err(|e| format!("parse Pid line: {e}"))?;
    if status_pid == pid {
        Ok(format!("pid={pid}"))
    } else {
        Err(format!("status_pid={status_pid} getpid={pid}"))
    }
}

fn check_maps_contains_guest_program(args: &[String]) -> Result<String, String> {
    let maps = fs::read_to_string("/proc/self/maps").map_err(|e| format!("read maps: {e}"))?;
    let exe = args.first().ok_or_else(|| "missing argv0".to_string())?;
    let exe_name = Path::new(exe)
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| format!("argv0 has no utf8 file name: {exe}"))?;
    if maps.lines().any(|line| line.contains(exe_name)) {
        Ok(format!("exe_name={exe_name}"))
    } else {
        let preview = maps.lines().take(5).collect::<Vec<_>>().join(" | ");
        Err(format!(
            "exe_name={exe_name} not found; maps_prefix={preview}"
        ))
    }
}

fn check_auxv_is_guest_values() -> Result<String, String> {
    let mut bytes = Vec::new();
    File::open("/proc/self/auxv")
        .map_err(|e| format!("open auxv: {e}"))?
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read auxv: {e}"))?;
    let auxv = parse_auxv(&bytes)?;
    let pagesz = auxv.get(&6).copied().ok_or_else(|| {
        format!(
            "missing AT_PAGESZ keys={:?}",
            auxv.keys().collect::<Vec<_>>()
        )
    })?;
    let phdr = auxv.get(&3).copied().unwrap_or(0);
    let phent = auxv.get(&4).copied().unwrap_or(0);
    let phnum = auxv.get(&5).copied().unwrap_or(0);
    if pagesz == 4096 && phdr != 0 && phent != 0 && phnum != 0 {
        Ok(format!(
            "pagesz={pagesz} phdr=0x{phdr:x} phent={phent} phnum={phnum}"
        ))
    } else {
        Err(format!(
            "pagesz={pagesz} phdr=0x{phdr:x} phent={phent} phnum={phnum}"
        ))
    }
}

fn check_comm_is_guest_progname() -> Result<String, String> {
    let comm = fs::read_to_string("/proc/self/comm")
        .map_err(|e| format!("read comm: {e}"))?
        .trim_end_matches('\n')
        .to_string();
    let exe = std::env::args()
        .next()
        .ok_or_else(|| "missing argv0".to_string())?;
    let name = Path::new(&exe)
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| format!("argv0 has no utf8 file name: {exe}"))?;
    let expected: String = name.chars().take(15).collect();
    if comm == expected {
        Ok(format!("comm={comm}"))
    } else {
        Err(format!("comm={comm:?} expected={expected:?}"))
    }
}

fn unique_shared_path(stem: &str) -> PathBuf {
    PathBuf::from(format!("/shared/{stem}-{}", std::process::id()))
}

fn canonicalize_existing(path: impl AsRef<Path>) -> Result<PathBuf, String> {
    path.as_ref()
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", path.as_ref().display()))
}

fn split_nul(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&byte| byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

fn path_ends_with(actual: &str, expected: &str) -> bool {
    actual == expected
        || Path::new(actual)
            .file_name()
            .is_some_and(|name| Path::new(expected).file_name() == Some(name))
}

fn parse_auxv(bytes: &[u8]) -> Result<BTreeMap<usize, usize>, String> {
    let word = std::mem::size_of::<usize>();
    let entry = word * 2;
    if bytes.len() % entry != 0 {
        return Err(format!(
            "auxv length {} is not multiple of {entry}",
            bytes.len()
        ));
    }

    let mut out = BTreeMap::new();
    for pair in bytes.chunks_exact(entry) {
        let key = native_usize(&pair[..word])?;
        let value = native_usize(&pair[word..])?;
        if key == 0 {
            break;
        }
        out.insert(key, value);
    }
    Ok(out)
}

fn native_usize(bytes: &[u8]) -> Result<usize, String> {
    let array: [u8; std::mem::size_of::<usize>()] = bytes
        .try_into()
        .map_err(|_| format!("bad usize byte count {}", bytes.len()))?;
    Ok(usize::from_ne_bytes(array))
}
