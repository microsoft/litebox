// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Library interface for the litebox test harness.
//!
//! Re-exports modules shared between the binary (`main.rs`) and the
//! integration test (`tests/integration.rs`).

pub mod coordinator;
pub mod protocol;
pub mod test_registry;

// ─────────────────────────────────────────────────────────────────────
// Binary-type axis
// ─────────────────────────────────────────────────────────────────────
//
// litebox's behavior on `execve` depends on the kind of ELF binary
// being loaded. The current set of legs the harness covers:
//
//   PIE-glibc            ET_DYN, dynamic glibc, default `cargo build`
//   non-PIE-glibc        ET_EXEC, dynamic glibc, `-no-pie`
//   static-PIE-glibc     ET_DYN, glibc + `crt-static` (still uses ld.so
//                        for libnss); `--target x86_64-unknown-linux-gnu`
//   static-PIE-musl      ET_DYN, musl + `crt-static`, truly static, no
//                        ld.so; `--target x86_64-unknown-linux-musl`.
//                        This is the link mode of the actual VS Code
//                        Server CLI (`cli-alpine-x64`).
//   non-PIE-static-musl  ET_EXEC, musl + `crt-static`, truly static,
//                        fixed-addr; `-no-pie` plus the musl target.
//
// Each leg exercises a different combination of (linker, libc, PIE)
// and triggers a different code path through litebox's syscall shim
// and worker-migration logic. Tests that depend on per-leg behavior
// iterate over [`BinaryType::ALL`] and resolve the actual binary path
// via [`binary_path`].
//
// Strict-mode invariant: every leg MUST have its binary present at
// test time. The accessor functions panic on missing — there is no
// "skip this leg" path. Build all 5 binaries via the integration
// test setup (`tests/integration.rs::ensure_binaries_built`).

/// One leg of the binary-type axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryType {
    /// `ET_DYN`, dynamically linked, glibc. The default `cargo build`
    /// output.
    PieGlibc,
    /// `ET_EXEC`, dynamically linked, glibc. Built with
    /// `-C link-args=-no-pie`.
    NonPieGlibc,
    /// `ET_DYN`, glibc + `crt-static`. Position-independent but still
    /// loads ld.so for nss/dlopen. Built with
    /// `RUSTFLAGS="-C target-feature=+crt-static" --target
    /// x86_64-unknown-linux-gnu`.
    StaticPieGlibc,
    /// `ET_DYN`, musl + `crt-static`. Truly static — no ld.so. Built
    /// with `RUSTFLAGS="-C target-feature=+crt-static" --target
    /// x86_64-unknown-linux-musl`. Matches the actual VS Code Server
    /// CLI distribution.
    StaticPieMusl,
    /// `ET_EXEC`, musl + `crt-static`. Truly static, fixed-addr. Built
    /// with `RUSTFLAGS="-C link-args=-no-pie -C
    /// target-feature=+crt-static" --target x86_64-unknown-linux-musl`.
    NonPieStaticMusl,
}

impl BinaryType {
    /// All five legs of the binary-type axis. Tests iterating over
    /// this slice cover the full matrix.
    pub const ALL: &'static [BinaryType] = &[
        Self::PieGlibc,
        Self::NonPieGlibc,
        Self::StaticPieGlibc,
        Self::StaticPieMusl,
        Self::NonPieStaticMusl,
    ];

    /// Stable kebab-case label suitable for test IDs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::PieGlibc => "pie-glibc",
            Self::NonPieGlibc => "nonpie-glibc",
            Self::StaticPieGlibc => "static-pie-glibc",
            Self::StaticPieMusl => "static-pie-musl",
            Self::NonPieStaticMusl => "non-pie-static-musl",
        }
    }

    /// The Rust target triple this leg requires, or `None` for the
    /// default host target. The musl legs require
    /// `rustup target add x86_64-unknown-linux-musl`.
    #[must_use]
    pub fn target(self) -> Option<&'static str> {
        match self {
            Self::PieGlibc | Self::NonPieGlibc | Self::StaticPieGlibc => None,
            Self::StaticPieMusl | Self::NonPieStaticMusl => Some("x86_64-unknown-linux-musl"),
        }
    }
}

impl core::fmt::Display for BinaryType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

/// Return the path to the harness binary built in mode `bt`.
///
/// `self_exe` is the path of the currently-running test harness
/// binary (which is always [`BinaryType::PieGlibc`] under default
/// `cargo build`).
///
/// # Panics
///
/// Panics if the requested binary type isn't present at the expected
/// docker mount or as a sibling of `self_exe`. The panic message
/// points at the build flags needed to produce the missing binary.
/// Tests that exercise per-binary-type behavior require all legs as
/// hard dependencies — there is no skip semantics.
#[must_use]
pub fn binary_path(bt: BinaryType, self_exe: &str) -> String {
    match bt {
        BinaryType::PieGlibc => self_exe.to_string(),
        BinaryType::NonPieGlibc => nonpie_binary(),
        BinaryType::StaticPieGlibc => static_pie_glibc_binary(),
        BinaryType::StaticPieMusl => static_pie_musl_binary(),
        BinaryType::NonPieStaticMusl => non_pie_static_musl_binary(),
    }
}

/// Find the non-PIE test harness binary.
///
/// In Docker: bind-mounted at `/opt/nonpie/litebox_test_harness`.
/// Locally: sibling of current exe with `_nonpie` or `-nonpie` suffix.
#[must_use]
pub fn find_nonpie_binary() -> Option<String> {
    find_companion_binary("nonpie", &["nonpie"])
}

/// Like [`find_nonpie_binary`] but panics if the binary is missing.
///
/// Tests that exercise non-PIE code paths require the non-PIE binary
/// as a hard dependency; rather than degrade to a "FAIL: binary not
/// found" outcome, panic with a clear message so the harness logs
/// surface the missing dependency immediately.
///
/// Use [`find_nonpie_binary`] only in non-test infrastructure
/// (e.g., `coordinator::TestRunner::spawn_tree`) that legitimately
/// wants to skip work when the binary isn't mounted.
///
/// # Panics
/// Panics if neither the bind-mounted Docker path nor a sibling
/// `*_nonpie` / `*-nonpie` binary exists alongside the current exe.
#[must_use]
pub fn nonpie_binary() -> String {
    find_nonpie_binary().unwrap_or_else(|| {
        panic!(
            "non-PIE test harness binary not found. Required at \
             /opt/nonpie/litebox_test_harness (Docker) or as \
             *_nonpie / *-nonpie sibling of current exe. Build with \
             `cargo rustc -p litebox_test_harness --bin \
             litebox_test_harness --target-dir target/nonpie -- \
             -C link-args=-no-pie`."
        )
    })
}

/// Find the static-PIE-glibc test harness binary.
///
/// In Docker: bind-mounted at `/opt/static-pie-glibc/litebox_test_harness`.
/// Locally: sibling of current exe with `_static-pie-glibc` suffix.
#[must_use]
pub fn find_static_pie_glibc_binary() -> Option<String> {
    find_companion_binary("static-pie-glibc", &["static-pie-glibc"])
}

/// Panic-flavor accessor for the static-PIE-glibc binary.
///
/// # Panics
/// Panics with build instructions if the binary isn't present.
#[must_use]
pub fn static_pie_glibc_binary() -> String {
    find_static_pie_glibc_binary().unwrap_or_else(|| {
        panic!(
            "static-PIE-glibc test harness binary not found. \
             Required at /opt/static-pie-glibc/litebox_test_harness \
             (Docker) or as a sibling of current exe. Build with \
             `RUSTFLAGS=\"-C target-feature=+crt-static\" cargo \
             rustc -p litebox_test_harness --bin \
             litebox_test_harness --target-dir target/static-pie-glibc \
             --target x86_64-unknown-linux-gnu`."
        )
    })
}

/// Find the static-PIE-musl test harness binary.
///
/// In Docker: bind-mounted at `/opt/static-pie-musl/litebox_test_harness`.
/// Locally: sibling of current exe with `_static-pie-musl` suffix.
///
/// This binary matches the link mode of the actual VS Code Server
/// CLI (`cli-alpine-x64`): musl libc, statically linked, no ld.so.
#[must_use]
pub fn find_static_pie_musl_binary() -> Option<String> {
    find_companion_binary("static-pie-musl", &["static-pie-musl"])
}

/// Panic-flavor accessor for the static-PIE-musl binary.
///
/// # Panics
/// Panics with build instructions if the binary isn't present.
#[must_use]
pub fn static_pie_musl_binary() -> String {
    find_static_pie_musl_binary().unwrap_or_else(|| {
        panic!(
            "static-PIE-musl test harness binary not found. \
             Required at /opt/static-pie-musl/litebox_test_harness \
             (Docker) or as a sibling of current exe. Build with \
             `rustup target add x86_64-unknown-linux-musl && \
             RUSTFLAGS=\"-C target-feature=+crt-static\" cargo \
             rustc -p litebox_test_harness --bin \
             litebox_test_harness --target-dir target/static-pie-musl \
             --target x86_64-unknown-linux-musl`."
        )
    })
}

/// Find the non-PIE-static-musl test harness binary.
///
/// In Docker: bind-mounted at `/opt/non-pie-static-musl/litebox_test_harness`.
/// Locally: sibling of current exe with `_non-pie-static-musl` suffix.
#[must_use]
pub fn find_non_pie_static_musl_binary() -> Option<String> {
    find_companion_binary("non-pie-static-musl", &["non-pie-static-musl"])
}

/// Panic-flavor accessor for the non-PIE-static-musl binary.
///
/// # Panics
/// Panics with build instructions if the binary isn't present.
#[must_use]
pub fn non_pie_static_musl_binary() -> String {
    find_non_pie_static_musl_binary().unwrap_or_else(|| {
        panic!(
            "non-PIE-static-musl test harness binary not found. \
             Required at /opt/non-pie-static-musl/litebox_test_harness \
             (Docker) or as a sibling of current exe. Build with \
             `rustup target add x86_64-unknown-linux-musl && \
             RUSTFLAGS=\"-C link-args=-no-pie -C \
             target-feature=+crt-static -C relocation-model=static\" \
             cargo rustc -p litebox_test_harness --bin \
             litebox_test_harness --target-dir target/non-pie-static-musl \
             --target x86_64-unknown-linux-musl`."
        )
    })
}

/// Look for a companion harness binary at the conventional Docker
/// bind-mount path or as a sibling of the current executable.
///
/// `mount_dir` is the leaf component of the docker bind-mount root
/// (e.g. `"nonpie"` → `/opt/nonpie/litebox_test_harness`).
/// `sibling_suffixes` is the list of suffixes (without leading
/// underscore/dash) to try when looking for a sibling — e.g.
/// `&["nonpie"]` finds both `*_nonpie` and `*-nonpie`.
fn find_companion_binary(mount_dir: &str, sibling_suffixes: &[&str]) -> Option<String> {
    let docker_path = format!("/opt/{mount_dir}/litebox_test_harness");
    if std::path::Path::new(&docker_path).exists() {
        eprintln!("[harness] {mount_dir} binary: {docker_path}");
        return Some(docker_path);
    }
    if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent().unwrap_or(std::path::Path::new("."));
        let stem = exe
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        for suffix in sibling_suffixes {
            for sep in ["_", "-"] {
                let candidate = dir.join(format!("{stem}{sep}{suffix}"));
                if candidate.exists() {
                    let path = candidate.to_string_lossy().to_string();
                    eprintln!("[harness] {mount_dir} binary: {path}");
                    return Some(path);
                }
            }
        }
    }
    None
}
