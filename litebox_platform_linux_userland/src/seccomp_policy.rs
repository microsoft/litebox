// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The host interface the runner keeps once [`LinuxUserland::enable_seccomp_filter`] is installed.
//!
//! Every host syscall that may still be made after the filter is installed is listed here, with
//! the reason it is needed. Anything not listed is denied. The table is the single source of
//! truth: the filter is built from it, and `seccomp_policy.<arch>.txt` next to this file is a
//! rendering of it that tests keep in sync, so that any change to the host interface shows up in
//! review as a short, readable diff.
//!
//! To update the rendering after changing the table, run the tests with
//! `LITEBOX_BLESS_SECCOMP_POLICY=1`.
//!
//! [`LinuxUserland::enable_seccomp_filter`]: crate::LinuxUserland::enable_seccomp_filter

use alloc::vec::Vec;

use litebox_common_linux::OFlags;

/// Width of a syscall argument comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArgWidth {
    /// Compare the low 32 bits of the argument.
    U32,
    /// Compare all 64 bits of the argument.
    U64,
}

/// A condition that a syscall argument must equal a fixed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArgEq {
    /// Zero-based index of the syscall argument.
    pub(crate) index: u8,
    pub(crate) width: ArgWidth,
    pub(crate) value: u64,
}

/// One syscall the filter admits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Grant {
    pub(crate) sysno: i64,
    /// The kernel's name for `sysno`; checked against the number by tests.
    pub(crate) name: &'static str,
    /// All conditions must hold. Empty means any arguments are admitted.
    pub(crate) conditions: &'static [ArgEq],
    /// Admitted only in debug builds.
    pub(crate) debug_only: bool,
    /// Why the runner still needs this syscall after the filter is installed.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "documentation, rendered by tests")
    )]
    pub(crate) reason: &'static str,
}

/// One syscall the filter admits only on descriptors supplied when it is installed.
///
/// The filter admits the syscall when argument 0 equals one of the descriptors and
/// `conditions` also hold.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PerFdGrant {
    pub(crate) sysno: i64,
    pub(crate) name: &'static str,
    /// Which descriptor list passed to `enable_seccomp_filter` scopes this grant.
    pub(crate) fds: FdList,
    pub(crate) conditions: &'static [ArgEq],
    /// Why the runner still needs this syscall after the filter is installed.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "documentation, rendered by tests")
    )]
    pub(crate) reason: &'static str,
}

/// The descriptor lists that `enable_seccomp_filter` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FdList {
    PositionalIo,
    Shutdown,
}

const fn grant(sysno: i64, name: &'static str, reason: &'static str) -> Grant {
    Grant {
        sysno,
        name,
        conditions: &[],
        debug_only: false,
        reason,
    }
}

/// Connected-socket calls only: no peer address (`dest_addr`/`src_addr`, `addrlen`).
const NO_PEER_ADDRESS: &[ArgEq] = &[
    ArgEq {
        index: 4,
        width: ArgWidth::U64,
        value: 0,
    },
    ArgEq {
        index: 5,
        width: ArgWidth::U64,
        value: 0,
    },
];

#[allow(
    clippy::cast_lossless,
    reason = "`From` is not usable in const context"
)]
const O_RDONLY: u64 = OFlags::RDONLY.bits() as u64;

#[allow(
    clippy::cast_sign_loss,
    reason = "SHUT_RDWR is a small non-negative constant"
)]
const SHUT_RDWR_VALUE: u64 = libc::SHUT_RDWR as u64;

// A mismatched syscall and flags index would admit arbitrary flags; see `OPEN_FLAGS_ARG`.
const OPEN_RDONLY: &[ArgEq] = &[ArgEq {
    index: crate::OPEN_FLAGS_ARG,
    width: ArgWidth::U32,
    value: O_RDONLY,
}];

const SHUT_RDWR: &[ArgEq] = &[ArgEq {
    index: 1,
    width: ArgWidth::U32,
    value: SHUT_RDWR_VALUE,
}];

/// Syscalls admitted regardless of the descriptors supplied at installation.
pub(crate) const GRANTS: &[Grant] = &[
    // Terminal and broker I/O
    grant(libc::SYS_read, "read", "terminal and broker I/O"),
    grant(libc::SYS_write, "write", "terminal and broker I/O"),
    // The AArch64 (asm-generic) syscall table has no `poll`; glibc implements `poll(3)` there
    // via `ppoll`.
    #[cfg(target_arch = "x86_64")]
    grant(libc::SYS_poll, "poll", "terminal and broker I/O"),
    #[cfg(target_arch = "aarch64")]
    grant(libc::SYS_ppoll, "ppoll", "terminal and broker I/O"),
    // Memory management
    grant(libc::SYS_mmap, "mmap", "memory management"),
    grant(libc::SYS_mprotect, "mprotect", "memory management"),
    grant(libc::SYS_munmap, "munmap", "memory management"),
    grant(libc::SYS_mremap, "mremap", "memory management"),
    // Signals
    grant(libc::SYS_rt_sigreturn, "rt_sigreturn", "signal handling"),
    grant(libc::SYS_sigaltstack, "sigaltstack", "signal handling"),
    grant(libc::SYS_tgkill, "tgkill", "signal handling"),
    grant(libc::SYS_timer_create, "timer_create", "signal handling"),
    grant(libc::SYS_timer_settime, "timer_settime", "signal handling"),
    grant(libc::SYS_timer_delete, "timer_delete", "signal handling"),
    // Called by [pthread_create](https://codebrowser.dev/glibc/glibc/nptl/pthread_create.c.html#83)
    // to set up the signal handler that supports setuid et al. (which we probably don't need, but
    // admit in debug builds to suppress the warnings about missing seccomp rules for it).
    Grant {
        debug_only: true,
        ..grant(
            libc::SYS_rt_sigaction,
            "rt_sigaction",
            "pthread_create setuid support; quiets debug warnings",
        )
    },
    // TODO: also called by `next_signal_handler`, but I'm not sure if it's really needed.
    grant(
        libc::SYS_rt_sigprocmask,
        "rt_sigprocmask",
        "signal handling",
    ),
    // Thread management
    grant(libc::SYS_exit, "exit", "thread management"),
    grant(libc::SYS_exit_group, "exit_group", "thread management"),
    grant(libc::SYS_clone3, "clone3", "thread management"),
    // Synchronization
    grant(libc::SYS_futex, "futex", "synchronization"),
    // Miscellaneous
    grant(libc::SYS_getrandom, "getrandom", "randomness"),
    // Required by std spawn
    grant(libc::SYS_rseq, "rseq", "std thread spawn"),
    grant(
        libc::SYS_set_robust_list,
        "set_robust_list",
        "std thread spawn",
    ),
    grant(
        libc::SYS_get_robust_list,
        "get_robust_list",
        "std thread spawn",
    ),
    grant(
        libc::SYS_sched_getaffinity,
        "sched_getaffinity",
        "std thread spawn",
    ),
    grant(libc::SYS_gettid, "gettid", "std thread spawn"),
    grant(libc::SYS_madvise, "madvise", "std thread spawn"),
    // Required by libc allocator
    grant(libc::SYS_brk, "brk", "libc allocator"),
    grant(libc::SYS_getpid, "getpid", "libc allocator"),
    // TODO: could be removed if we pre-open files (see `try_allocate_cow_pages`)
    Grant {
        conditions: OPEN_RDONLY,
        ..grant(
            crate::OPEN_SYSNO,
            crate::OPEN_NAME,
            "copy-on-write file regions (`try_allocate_cow_pages`)",
        )
    },
    // Connected UnixStream I/O may use sendto/recvfrom rather than raw read/write. Limit these
    // rules to connected-socket calls that do not name a peer address.
    Grant {
        conditions: NO_PEER_ADDRESS,
        ..grant(libc::SYS_sendto, "sendto", "connected UnixStream I/O")
    },
    Grant {
        conditions: NO_PEER_ADDRESS,
        ..grant(libc::SYS_recvfrom, "recvfrom", "connected UnixStream I/O")
    },
    grant(libc::SYS_close, "close", "closing descriptors"),
];

/// Syscalls admitted only on descriptors supplied at installation.
pub(crate) const PER_FD_GRANTS: &[PerFdGrant] = &[
    PerFdGrant {
        sysno: libc::SYS_pread64,
        name: "pread64",
        fds: FdList::PositionalIo,
        conditions: &[],
        reason: "broker shared memory (positional I/O)",
    },
    PerFdGrant {
        sysno: libc::SYS_pwrite64,
        name: "pwrite64",
        fds: FdList::PositionalIo,
        conditions: &[],
        reason: "broker shared memory (positional I/O)",
    },
    PerFdGrant {
        sysno: libc::SYS_shutdown,
        name: "shutdown",
        fds: FdList::Shutdown,
        conditions: SHUT_RDWR,
        reason: "association failure interrupts liveness waits",
    },
];

fn condition(c: &ArgEq) -> seccompiler::SeccompCondition {
    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition};
    let width = match c.width {
        ArgWidth::U32 => SeccompCmpArgLen::Dword,
        ArgWidth::U64 => SeccompCmpArgLen::Qword,
    };
    SeccompCondition::new(c.index, width, SeccompCmpOp::Eq, c.value).unwrap()
}

/// Builds the filter rules from the policy.
///
/// Per-descriptor grants are admitted only for the descriptors supplied, and are left out
/// entirely when their list is empty.
///
/// # Panics
///
/// Panics if a descriptor is negative, or if the policy lists a syscall twice.
pub(crate) fn rules(
    positional_io_fds: &[std::os::fd::RawFd],
    shutdown_fds: &[std::os::fd::RawFd],
) -> std::collections::BTreeMap<i64, Vec<seccompiler::SeccompRule>> {
    use seccompiler::SeccompRule;

    let mut rules = std::collections::BTreeMap::new();
    let mut add = |sysno: i64, name: &str, rule_list: Vec<SeccompRule>| {
        assert!(
            rules.insert(sysno, rule_list).is_none(),
            "seccomp policy lists {name} twice"
        );
    };
    for g in GRANTS {
        if g.debug_only && !cfg!(debug_assertions) {
            continue;
        }
        let rule_list = if g.conditions.is_empty() {
            Vec::new()
        } else {
            alloc::vec![SeccompRule::new(g.conditions.iter().map(condition).collect()).unwrap()]
        };
        add(g.sysno, g.name, rule_list);
    }
    for g in PER_FD_GRANTS {
        let fds = match g.fds {
            FdList::PositionalIo => positional_io_fds,
            FdList::Shutdown => shutdown_fds,
        };
        if fds.is_empty() {
            continue;
        }
        let rule_list = fds
            .iter()
            .map(|&fd| {
                let fd = ArgEq {
                    index: 0,
                    width: ArgWidth::U32,
                    value: u64::from(u32::try_from(fd).expect("descriptor must be valid")),
                };
                let conditions = core::iter::once(&fd)
                    .chain(g.conditions)
                    .map(condition)
                    .collect();
                SeccompRule::new(conditions).unwrap()
            })
            .collect();
        add(g.sysno, g.name, rule_list);
    }
    rules
}

#[cfg(test)]
/// Renders the policy for the current architecture as one line per syscall.
///
/// The rendering does not depend on the build profile: debug-only grants are marked as such.
pub(crate) fn render() -> alloc::string::String {
    use alloc::string::String;
    use core::fmt::Write as _;

    fn conditions(out: &mut String, conditions: &[ArgEq]) {
        for (i, c) in conditions.iter().enumerate() {
            if i > 0 {
                out.push_str(" && ");
            }
            let width = match c.width {
                ArgWidth::U32 => "u32",
                ArgWidth::U64 => "u64",
            };
            let _ = write!(out, "arg{}:{width} == {:#x}", c.index, c.value);
        }
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Host syscalls admitted after the seccomp filter is installed ({}).",
        std::env::consts::ARCH
    );
    let _ = writeln!(
        out,
        "# Generated from seccomp_policy.rs; everything not listed is denied."
    );
    let mut rows: Vec<(&str, String, &str)> = Vec::new();
    for g in GRANTS {
        let mut when = String::new();
        if g.conditions.is_empty() {
            when.push_str("any arguments");
        } else {
            conditions(&mut when, g.conditions);
        }
        if g.debug_only {
            when.push_str(" [debug builds only]");
        }
        rows.push((g.name, when, g.reason));
    }
    for g in PER_FD_GRANTS {
        let list = match g.fds {
            FdList::PositionalIo => "positional_io_fds",
            FdList::Shutdown => "shutdown_fds",
        };
        let mut when = alloc::format!("arg0:u32 in {list}");
        if !g.conditions.is_empty() {
            when.push_str(" && ");
            conditions(&mut when, g.conditions);
        }
        rows.push((g.name, when, g.reason));
    }
    let name_width = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    let when_width = rows.iter().map(|r| r.1.len()).max().unwrap_or(0);
    for (name, when, reason) in rows {
        let _ = writeln!(out, "{name:name_width$}  {when:when_width$}  {reason}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_sysnos() -> impl Iterator<Item = (i64, &'static str)> {
        GRANTS
            .iter()
            .map(|g| (g.sysno, g.name))
            .chain(PER_FD_GRANTS.iter().map(|g| (g.sysno, g.name)))
    }

    /// Rules are collected into a map keyed by syscall number, so a second entry for the same
    /// syscall would silently replace the first.
    #[test]
    fn no_syscall_is_listed_twice() {
        let mut seen = std::collections::BTreeMap::new();
        for (sysno, name) in all_sysnos() {
            if let Some(previous) = seen.insert(sysno, name) {
                panic!("syscall {sysno} is listed twice (as {previous} and {name})");
            }
        }
    }

    #[test]
    fn names_match_numbers() {
        for (sysno, name) in all_sysnos() {
            let actual = syscalls::Sysno::new(usize::try_from(sysno).unwrap())
                .unwrap_or_else(|| panic!("{name}: {sysno} is not a syscall on this architecture"));
            assert_eq!(
                actual.name(),
                name,
                "syscall {sysno} is listed under the wrong name"
            );
        }
    }

    #[test]
    fn every_grant_has_a_reason() {
        for g in GRANTS {
            assert!(!g.reason.trim().is_empty(), "{} has no reason", g.name);
        }
        for g in PER_FD_GRANTS {
            assert!(!g.reason.trim().is_empty(), "{} has no reason", g.name);
        }
    }

    #[test]
    fn conditions_name_real_arguments() {
        let conditions = GRANTS
            .iter()
            .flat_map(|g| g.conditions.iter().map(move |c| (g.name, c)))
            .chain(
                PER_FD_GRANTS
                    .iter()
                    .flat_map(|g| g.conditions.iter().map(move |c| (g.name, c))),
            );
        for (name, c) in conditions {
            assert!(c.index < 6, "{name}: syscalls take at most six arguments");
            if c.width == ArgWidth::U32 {
                assert!(
                    u32::try_from(c.value).is_ok(),
                    "{name}: {:#x} does not fit the 32-bit comparison",
                    c.value
                );
            }
        }
    }

    /// The checked-in rendering must match the table, so that any change to the host interface
    /// is visible in review as a diff to `seccomp_policy.<arch>.txt`.
    #[test]
    fn rendering_is_up_to_date() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(alloc::format!(
                "seccomp_policy.{}.txt",
                std::env::consts::ARCH
            ));
        let rendered = render();
        if std::env::var_os("LITEBOX_BLESS_SECCOMP_POLICY").is_some() {
            std::fs::write(&path, &rendered).unwrap();
            return;
        }
        let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            checked_in == rendered,
            "{} is out of date with seccomp_policy.rs.\n\
             Review the change, then rerun the tests with LITEBOX_BLESS_SECCOMP_POLICY=1.\n\
             --- checked in\n{checked_in}\n--- current\n{rendered}",
            path.display()
        );
    }
}
