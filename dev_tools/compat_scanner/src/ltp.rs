// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Linux Test Project (<https://github.com/linux-test-project/ltp>).
//!
//! LTP is GPL-licensed, so it is downloaded at a pinned release and built in the Cargo target
//! directory, never vendored.

use crate::exec::{InterruptHint, Outcome, parallel_map, run_logged, session_command};
use crate::litebox::{self, LiteBox};
use crate::report::{self, Counts, Report, RunResult, Status, TestRecord};
use crate::{CommonArgs, Workspace};
use anyhow::{Context as _, Result, bail};
use clap::Args;
use sha2::{Digest as _, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;
use xshell::{Shell, cmd};

/// The LTP release run: the latest at the time of pinning. Update all three together.
const TAG: &str = "20260930";
/// The commit `TAG` names, for reference.
const COMMIT: &str = "2279d708c817db657611a30c427c7d06c4360049";
/// The SHA-256 of the release's `ltp-full-<TAG>.tar.xz`, which, unlike a git checkout, comes
/// with `configure` generated, so building needs no autotools.
const TARBALL_SHA256: &str = "b9837481134fa6eabce91c2fba57d96695f81360468f83e11e6982584ad4d29d";

#[derive(Debug, Args)]
pub struct LtpArgs {
    /// LTP runtest file (from LTP's runtest/ directory) whose tests to run; may be repeated.
    ///
    /// Files other than syscalls and syscalls-ipc make the scanner build all of LTP.
    #[arg(long = "runtest", value_name = "NAME", default_value = "syscalls")]
    runtests: Vec<String>,
    /// Run only tests whose names match GLOB (`*` and `?` wildcards); may be repeated.
    #[arg(long = "filter", value_name = "GLOB")]
    filters: Vec<String>,
    #[command(flatten)]
    common: CommonArgs,
}

pub fn run(workspace: &Workspace, args: &LtpArgs) -> Result<()> {
    let common = &args.common;
    let jobs = common
        .jobs
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
    let ltp = Ltp::prepare(workspace, &args.runtests, jobs)?;
    let tests = ltp.tests(args)?;
    if tests.is_empty() {
        bail!("no tests match");
    }

    let litebox = LiteBox::build(workspace, common.release, !common.no_fork)?;
    let tar = ltp.dir.join(format!("rootfs-{}.tar", litebox.profile));
    litebox.package(&ltp.installed_files()?, &tar, jobs)?;

    let out_dir = out_dir(workspace, common.out_dir.as_deref())?;
    let _hint = InterruptHint::new(&format!(
        "Interrupted. Tests may still be running; stop them with: pkill -KILL -f '{}/'",
        ltp.dir.display()
    ))?;

    let litebox_target = Target::LiteBox {
        litebox: &litebox,
        tar: &tar,
    };
    let litebox_runs = parallel_map(jobs, "LiteBox", &tests, |test| {
        test.run(&out_dir, &litebox_target, &ltp)
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    let native_runs = if common.native {
        let mut runs = parallel_map(jobs, "Native", &tests, |test| {
            test.run(&out_dir, &Target::Native, &ltp)
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
        // LTP expects tests to run one at a time; on the host, concurrent tests can contend for
        // system-wide resources (e.g. System V IPC), so failures are retried alone.
        let failures: Vec<usize> = (0..runs.len())
            .filter(|&index| {
                matches!(
                    runs[index].status,
                    Status::Fail | Status::Broken | Status::Timeout | Status::Crash
                )
            })
            .collect();
        let reruns = parallel_map(1, "Native, retrying failures alone", &failures, |&index| {
            tests[index].run(&out_dir, &Target::Native, &ltp)
        });
        for (index, run) in failures.into_iter().zip(reruns) {
            runs[index] = run?;
        }
        runs
    } else {
        Vec::new()
    };
    let mut native_runs = native_runs.into_iter();

    let report = Report {
        suite: "LTP".into(),
        suite_version: format!("{TAG} ({COMMIT})"),
        litebox_commit: workspace.litebox_commit(),
        profile: litebox.profile.into(),
        allow_fork: !common.no_fork,
        tests: tests
            .into_iter()
            .zip(litebox_runs)
            .map(|(test, litebox)| TestRecord {
                name: test.name,
                command: test.argv,
                group: test.group,
                tags: test.tags,
                litebox,
                native: native_runs.next(),
            })
            .collect(),
    };
    report::write(&report, &out_dir, &litebox::host_syscall_names())
}

/// Creates the directory for a run's results: `requested`, which must not hold a run already, or
/// a new one.
fn out_dir(workspace: &Workspace, requested: Option<&Path>) -> Result<PathBuf> {
    let out_dir = if let Some(requested) = requested {
        if requested.join("results.json").exists() {
            bail!("{} already holds a run", requested.display());
        }
        fs::create_dir_all(requested)?;
        requested.to_path_buf()
    } else {
        let runs = workspace.scratch().join("runs");
        fs::create_dir_all(&runs)?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let mut attempt = 1;
        loop {
            let suffix = if attempt == 1 {
                String::new()
            } else {
                format!("-{attempt}")
            };
            let out_dir = runs.join(format!("ltp-{}{suffix}", now.as_secs()));
            match fs::create_dir(&out_dir) {
                Ok(()) => break out_dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => attempt += 1,
                Err(error) => return Err(error.into()),
            }
        }
    };
    fs::create_dir_all(out_dir.join("logs"))?;
    Ok(out_dir.canonicalize()?)
}

/// A fetched and built LTP.
struct Ltp {
    /// Everything for this release.
    dir: PathBuf,
    src: PathBuf,
    /// Where LTP is installed, at the same path on the host and in the guest.
    install: PathBuf,
    /// LTP's per-test metadata (`metadata/ltp.json`): the `tests` object.
    metadata: serde_json::Map<String, serde_json::Value>,
}

impl Ltp {
    /// Downloads, builds, and installs LTP for `runtests`, unless that was done before; for just
    /// the syscall runtest files, only the syscall tests.
    fn prepare(workspace: &Workspace, runtests: &[String], jobs: usize) -> Result<Self> {
        let dir = workspace.scratch().join(format!("ltp-{TAG}"));
        fs::create_dir_all(&dir)?;
        let src = dir.join("src");
        let install = dir.join("install");
        let log = dir.join("build.log");
        let sh = Shell::new()?;

        let tarball = dir.join(format!("ltp-full-{TAG}.tar.xz"));
        let sha256 = |path: &Path| -> Result<String> {
            Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
        };
        if !tarball.exists() || sha256(&tarball)? != TARBALL_SHA256 {
            let url = format!(
                "https://github.com/linux-test-project/ltp/releases/download/{TAG}/ltp-full-{TAG}.tar.xz"
            );
            let partial = dir.join("download.partial");
            eprintln!("Downloading {url}...");
            cmd!(
                sh,
                "curl --fail --location --silent --show-error --output {partial} {url}"
            )
            .run()?;
            let digest = sha256(&partial)?;
            if digest != TARBALL_SHA256 {
                bail!("{url} has SHA-256 {digest}, but {TARBALL_SHA256} was expected");
            }
            fs::rename(&partial, &tarball)?;
        }

        // Holds the tarball's digest, so that changing the pin rebuilds from scratch.
        let configured = src.join(".compat_scanner-configured");
        if fs::read_to_string(&configured).ok().as_deref() != Some(TARBALL_SHA256) {
            eprintln!(
                "Extracting and configuring LTP {TAG} (log: {})...",
                log.display()
            );
            let _ = fs::remove_dir_all(&src);
            fs::create_dir_all(&src)?;
            cmd!(sh, "tar -xJf {tarball} -C {src} --strip-components=1").run()?;
            sh.change_dir(&src);
            build_step(&log, cmd!(sh, "./configure --prefix={install}"), true)?;
            fs::write(&configured, TARBALL_SHA256)?;
        }

        for runtest in runtests {
            if !src.join("runtest").join(runtest).is_file() {
                bail!(
                    "LTP has no runtest file {runtest}; see {}",
                    src.join("runtest").display()
                );
            }
        }
        let only_syscalls = runtests
            .iter()
            .all(|runtest| runtest == "syscalls" || runtest == "syscalls-ipc");

        sh.change_dir(&src);
        let jobs = format!("-j{jobs}");
        let built_all = src.join(".compat_scanner-built-all");
        let built = if only_syscalls {
            src.join(".compat_scanner-built-syscalls")
        } else {
            built_all.clone()
        };
        if !built.exists() && !built_all.exists() {
            eprintln!("Building LTP {TAG} (log: {})...", log.display());
            if only_syscalls {
                build_step(&log, cmd!(sh, "make {jobs} -C lib"), true)?;
                build_step(
                    &log,
                    cmd!(sh, "make {jobs} -C testcases/kernel/syscalls"),
                    true,
                )?;
                build_step(
                    &log,
                    cmd!(sh, "make -C testcases/kernel/syscalls install"),
                    true,
                )?;
            } else {
                // Tests whose optional dependencies are missing fail to build; they are reported
                // as not run.
                build_step(&log, cmd!(sh, "make {jobs} -k"), false)?;
                build_step(&log, cmd!(sh, "make -k install"), false)?;
            }
            build_step(&log, cmd!(sh, "make -C metadata"), true)?;
            // The installed files changed, so their packages are out of date.
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.to_string_lossy().ends_with(".tar.key") {
                    fs::remove_file(path)?;
                }
            }
            fs::write(&built, "")?;
        }

        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(src.join("metadata/ltp.json"))?)
                .context("reading LTP's metadata/ltp.json")?;
        let metadata = metadata["tests"]
            .as_object()
            .context("LTP metadata has no tests object")?
            .clone();

        Ok(Self {
            dir,
            src,
            install,
            metadata,
        })
    }

    fn installed_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let mut dirs = vec![self.install.clone()];
        while let Some(dir) = dirs.pop() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    dirs.push(entry.path());
                } else if file_type.is_file() {
                    files.push(entry.path());
                }
            }
        }
        files.sort();
        Ok(files)
    }

    fn bin(&self) -> PathBuf {
        self.install.join("testcases/bin")
    }

    /// The tests the runtest files list that `args`' filters select, in order.
    fn tests(&self, args: &LtpArgs) -> Result<Vec<Test>> {
        let mut tests: Vec<Test> = Vec::new();
        for runtest in &args.runtests {
            let path = self.src.join("runtest").join(runtest);
            let contents = fs::read_to_string(&path)?;
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((name, command)) = line.split_once(char::is_whitespace) else {
                    continue;
                };
                if !(args.filters.is_empty()
                    || args.filters.iter().any(|filter| glob_match(filter, name)))
                    || tests.iter().any(|test| test.name == name)
                {
                    continue;
                }
                tests.push(self.test(name, command.trim(), args.common.timeout));
            }
        }
        Ok(tests)
    }

    fn test(&self, name: &str, command: &str, timeout: u64) -> Test {
        let mut argv: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        let program = argv[0].clone();
        let metadata = [program.as_str(), program.trim_end_matches("_64"), name]
            .iter()
            .find_map(|key| self.metadata.get(*key))
            .and_then(serde_json::Value::as_object);
        let not_run = if command.contains(['|', ';', '&', '<', '>', '$', '`', '"', '\'', '(', ')'])
        {
            Some("needs a shell to run its command line")
        } else {
            let path = self.bin().join(&program);
            argv[0] = path.to_string_lossy().into_owned();
            (!path.exists()).then_some("not built")
        };
        let group = metadata
            .and_then(|metadata| metadata.get("groups")?.as_array()?.first()?.as_str())
            .map_or_else(
                || {
                    name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '_')
                        .to_owned()
                },
                str::to_owned,
            );
        let seconds = |key: &str| {
            let value = metadata?.get(key)?;
            value.as_u64().or_else(|| value.as_str()?.parse().ok())
        };
        let unlimited = metadata
            .and_then(|metadata| metadata.get("timeout"))
            .is_some_and(|value| {
                value.as_i64().is_some_and(i64::is_negative)
                    || value.as_str() == Some("TST_UNLIMITED_TIMEOUT")
            });
        // LTP's own limit is 30 seconds plus the test's timeout, plus its runtime.
        let declared = seconds("timeout").unwrap_or(0)
            + seconds("runtime")
                .or_else(|| seconds("min_runtime"))
                .unwrap_or(0);
        let timeout = if unlimited {
            timeout.max(UNLIMITED_TIMEOUT)
        } else if declared > 0 {
            timeout.max(30 + declared + 60)
        } else {
            timeout
        };
        Test {
            name: name.to_owned(),
            script: is_script(Path::new(&argv[0])),
            argv,
            not_run,
            group,
            tags: metadata.map(tags).unwrap_or_default(),
            timeout: Duration::from_secs(timeout),
        }
    }
}

/// The scanner's limit, in seconds, for tests that LTP does not limit.
const UNLIMITED_TIMEOUT: u64 = 60 * 60;

fn is_script(program: &Path) -> bool {
    let mut magic = [0; 2];
    fs::File::open(program)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok()
        && magic == *b"#!"
}

/// Runs a build step, appending its output to `log`; fails if it fails and `must_succeed`.
fn build_step(log: &Path, command: xshell::Cmd<'_>, must_succeed: bool) -> Result<()> {
    let description = command.to_string();
    let output = command.quiet().ignore_status().output()?;
    let mut log_file = OpenOptions::new().create(true).append(true).open(log)?;
    writeln!(log_file, "$ {description}")?;
    log_file.write_all(&output.stdout)?;
    log_file.write_all(&output.stderr)?;
    if !output.status.success() {
        if must_succeed {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: Vec<_> = stderr.lines().rev().take(20).collect();
            bail!(
                "`{description}` failed ({}); see {}. It ended:\n{}",
                output.status,
                log.display(),
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
        }
        eprintln!(
            "warning: `{description}` failed ({}); see {}",
            output.status,
            log.display()
        );
    }
    Ok(())
}

/// The requirements in a test's metadata that commonly decide whether it can run, as LTP names
/// them.
fn tags(metadata: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    const KEYS: &[&str] = &[
        "needs_root",
        "needs_device",
        "format_device",
        "mount_device",
        "all_filesystems",
        "needs_kconfigs",
        "needs_checkpoints",
        "child_needs_reinit",
        "needs_cgroup_ctrls",
        "hugepages",
        "needs_hugetlbfs",
        "needs_cmds",
        "caps",
        "taint_check",
    ];
    KEYS.iter()
        .filter(|key| {
            metadata.get(**key).is_some_and(|value| {
                !matches!(
                    value,
                    serde_json::Value::Bool(false) | serde_json::Value::Null
                )
            })
        })
        .map(|key| (*key).to_owned())
        .collect()
}

/// Matches `text` against `pattern`, in which `*` matches any run of characters and `?` any one.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (pattern, text): (Vec<char>, Vec<char>) =
        (pattern.chars().collect(), text.chars().collect());
    let (mut p, mut t) = (0, 0);
    let mut backtrack = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            backtrack = Some((p, t));
            p += 1;
        } else if let Some((star, matched)) = backtrack {
            p = star + 1;
            t = matched + 1;
            backtrack = Some((star, matched + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

struct Test {
    name: String,
    /// The command, with the program as an absolute path.
    argv: Vec<String>,
    /// Why the test cannot be run, if it cannot.
    not_run: Option<&'static str>,
    /// Whether the program is a script, which needs an interpreter that LiteBox's root file
    /// system lacks.
    script: bool,
    group: String,
    tags: Vec<String>,
    timeout: Duration,
}

enum Target<'a> {
    LiteBox { litebox: &'a LiteBox, tar: &'a Path },
    Native,
}

impl Test {
    /// Runs the test on `target`; fails only if the scanner itself fails.
    fn run(&self, out_dir: &Path, target: &Target<'_>, ltp: &Ltp) -> Result<RunResult> {
        let under_litebox = matches!(target, Target::LiteBox { .. });
        if let Some(not_run) = self.not_run {
            return Ok(RunResult::not_run(not_run));
        }
        if self.script && under_litebox {
            return Ok(RunResult::not_run(
                "is a script, and LiteBox's root file system has no shell",
            ));
        }
        let mut env = vec![
            ("LTPROOT", ltp.install.to_string_lossy().into_owned()),
            (
                "PATH",
                format!("{}:/usr/sbin:/usr/bin:/sbin:/bin", ltp.bin().display()),
            ),
            ("LTP_COLORIZE_OUTPUT", "n".to_owned()),
            ("HOME", "/".to_owned()),
        ];
        let (suffix, temp, command) = match target {
            Target::LiteBox { litebox, tar } => {
                // The broker gives each run a fresh in-memory /tmp.
                env.push(("TMPDIR", "/tmp".to_owned()));
                ("litebox", None, litebox.command(tar, &env, &self.argv))
            }
            Target::Native => {
                let temp = out_dir.join("tmp").join(&self.name);
                let _ = fs::remove_dir_all(&temp);
                fs::create_dir_all(&temp)?;
                env.push(("TMPDIR", temp.to_string_lossy().into_owned()));
                let mut command = session_command(&self.argv[0]);
                command
                    .args(&self.argv[1..])
                    .env_clear()
                    .envs(env)
                    .current_dir(&temp);
                ("native", Some(temp), command)
            }
        };
        let log = PathBuf::from("logs").join(format!("{}.{suffix}.log", self.name));
        let outcome = run_logged(command, &out_dir.join(&log), self.timeout);
        if let Some(temp) = temp {
            let _ = fs::remove_dir_all(temp);
        }
        let mut result = classify(&outcome?, under_litebox);
        result.log = Some(log);
        Ok(result)
    }
}

/// The results an LTP test reported, from its output.
#[derive(Default)]
struct Reported<'a> {
    counts: Counts,
    first_fail: Option<&'a str>,
    first_broken: Option<&'a str>,
    first_skipped: Option<&'a str>,
    /// Whether LTP's own timeout killed the test.
    timed_out: bool,
}

fn reported(output: &str) -> Reported<'_> {
    let mut reported = Reported::default();
    for line in output.lines() {
        let Some((tag, message)) = result_line(line) else {
            continue;
        };
        let counts = &mut reported.counts;
        let (count, first) = match tag {
            "TPASS" => (&mut counts.pass, None),
            "TFAIL" => (&mut counts.fail, Some(&mut reported.first_fail)),
            "TBROK" => (&mut counts.broken, Some(&mut reported.first_broken)),
            "TCONF" => (&mut counts.skipped, Some(&mut reported.first_skipped)),
            _ => (&mut counts.warn, None),
        };
        *count += 1;
        if let Some(first) = first {
            first.get_or_insert(message);
        }
        if tag == "TBROK" && message.starts_with("Test killed! (timeout?)") {
            reported.timed_out = true;
        }
    }
    reported
}

/// Parses an LTP result line, returning its tag (e.g. `TPASS`) and message.
fn result_line(line: &str) -> Option<(&str, &str)> {
    const TAGS: [&str; 5] = ["TPASS", "TFAIL", "TBROK", "TCONF", "TWARN"];
    // The C API's "<file>:<line>: <tag>: <message>".
    if let Some((location, rest)) = line.split_once(": ")
        && let Some((file, number)) = location.rsplit_once(':')
        && !file.is_empty()
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
    {
        let (tag, message) = rest
            .split_once(": ")
            .unwrap_or((rest.trim_end_matches(':'), ""));
        return TAGS.contains(&tag).then_some((tag, message.trim()));
    }
    // The legacy C API's "<test> <number> <tag> : <message>", and the shell API's
    // "<test> <number> <tag>: <message>".
    let mut words = line.split_whitespace();
    let (_, number, tag) = (words.next()?, words.next()?, words.next()?);
    let tag = match tag.strip_suffix(':') {
        Some(tag) => tag,
        None if words.next() == Some(":") => tag,
        None => return None,
    };
    if number.parse::<u32>().is_err() || !TAGS.contains(&tag) {
        return None;
    }
    let after_tag = &line[line.find(tag)? + tag.len()..];
    Some((tag, after_tag.trim_start().strip_prefix(':')?.trim()))
}

fn classify(outcome: &Outcome, under_litebox: bool) -> RunResult {
    let (output, host_syscalls_blocked) = if under_litebox {
        litebox::strip_runner_warnings(&outcome.output)
    } else {
        (outcome.output.clone(), Vec::new())
    };
    let reported = reported(&output);
    let end = if under_litebox {
        litebox::guest_end(&output, outcome.code)
    } else {
        litebox::GuestEnd {
            code: outcome.code,
            ..litebox::GuestEnd::default()
        }
    };
    // Under the runner, a guest a signal killed exits 128 + the signal, but LTP's own exit codes
    // are combinations of bits below 64.
    let signal = outcome.signal.or_else(|| {
        end.code
            .filter(|&code| under_litebox && (129..=192).contains(&code))
            .map(|code| code - 128)
    });
    let killer = if under_litebox && outcome.signal.is_some() {
        "the broker was killed by"
    } else {
        "killed by"
    };
    // LiteBox failed to run the guest to its end: the runner died or could not start it.
    let litebox_error = end.error.as_deref().filter(|_| end.code.is_none());

    let (status, cause) = if outcome.timed_out {
        let cause = format!("timed out after {}s", outcome.duration.as_secs());
        (Status::Timeout, Some(cause))
    } else if reported.timed_out {
        (
            Status::Timeout,
            Some("timed out by LTP's own limit".to_owned()),
        )
    } else if let Some(panic) = &end.panic {
        (Status::Crash, Some(format!("LiteBox panicked: {panic}")))
    } else if let Some(signal) = signal {
        let cause = format!("{killer} {}", signal_name(signal));
        (Status::Crash, Some(cause))
    } else if let Some(error) = litebox_error {
        (Status::Crash, Some(normalize(error)))
    } else if let Some(message) = reported.first_fail {
        (Status::Fail, Some(normalize(message)))
    } else if let Some(message) = reported.first_broken {
        (Status::Broken, Some(normalize(message)))
    } else if reported.counts.pass > 0 {
        (Status::Pass, None)
    } else if let Some(message) = reported.first_skipped {
        (Status::Skipped, Some(normalize(message)))
    } else if end.code == Some(0) {
        // Some legacy-API tests report only failures, so LTP counts a clean exit as a pass.
        (Status::Pass, None)
    } else if let Some(error) = &end.error {
        // E.g. the runner could not load the guest, so it exited 1 itself.
        (Status::Crash, Some(normalize(error)))
    } else {
        // E.g. a legacy-API test that gave up before reporting, printing why.
        let code = end
            .code
            .map_or_else(|| "?".to_owned(), |code| code.to_string());
        // The broker's and runner's errors start with "Error: ".
        let last_words = output
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| !(line.is_empty() || under_litebox && line.starts_with("Error: ")));
        let cause = match last_words {
            Some(line) => format!(
                "exited {code} without reporting results: {}",
                normalize(line)
            ),
            None => format!("exited {code} without reporting results"),
        };
        (Status::Broken, Some(cause))
    };
    RunResult {
        status,
        cause,
        counts: reported.counts,
        exit_code: end.code,
        duration_ms: u64::try_from(outcome.duration.as_millis()).unwrap_or(u64::MAX),
        log: None,
        host_syscalls_blocked,
    }
}

fn signal_name(signal: i32) -> String {
    let name = match signal {
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        31 => "SIGSYS",
        _ => return format!("signal {signal}"),
    };
    name.to_owned()
}

/// Elides the run-specific parts of an LTP message, e.g. temporary paths, PIDs, and addresses, so
/// that tests failing alike share a cause.
fn normalize(message: &str) -> String {
    // Legacy-API messages may start with the reporting location, e.g. "tst_tmpdir.c:281: ".
    let mut message = message.trim();
    while let Some((location, rest)) = message.split_once(": ")
        && let Some((file, number)) = location.rsplit_once(':')
        && Path::new(file)
            .extension()
            .is_some_and(|extension| extension == "c" || extension == "h")
        && !file.contains(' ')
        && number.bytes().all(|b| b.is_ascii_digit())
    {
        message = rest;
    }
    // Legacy-API messages give errors as "errno=ENOSYS(38): Function not implemented" at their
    // end; the current API as "ENOSYS (38)".
    let unified;
    if let Some(start) = message.rfind("errno=E")
        && let Some((name, rest)) = message[start + "errno=".len()..].split_once('(')
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && let Some((number, rest)) = rest.split_once(')')
        && number.bytes().all(|b| b.is_ascii_digit())
        && (rest.is_empty() || rest.starts_with(": ") && !rest[2..].contains(':'))
    {
        unified = format!("{}{name} ({number})", &message[..start]);
        message = &unified;
    }

    let chars: Vec<char> = message.chars().collect();
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(message.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '/' && (i == 0 || !is_word(chars[i - 1])) {
            let end = chars[i..]
                .iter()
                .position(|&c| c.is_whitespace() || matches!(c, ',' | ')' | '\'' | '"'))
                .map_or(chars.len(), |len| i + len);
            let path: String = chars[i..end].iter().collect();
            out.push_str(if path.contains("/LTP_") {
                "<tmpdir>"
            } else {
                &path
            });
            i = end;
        } else if c == '0'
            && chars.get(i + 1) == Some(&'x')
            && chars.get(i + 2).is_some_and(char::is_ascii_hexdigit)
            && (i == 0 || !is_word(chars[i - 1]))
        {
            out.push_str("0x…");
            i += 2;
            while chars.get(i).is_some_and(char::is_ascii_hexdigit) {
                i += 1;
            }
        } else if c.is_ascii_digit() && (i == 0 || !is_word(chars[i - 1])) {
            let end = chars[i..]
                .iter()
                .position(|c| !c.is_ascii_digit())
                .map_or(chars.len(), |len| i + len);
            // Short numbers (errnos, sizes, counts) usually matter; long ones (PIDs, UIDs,
            // addresses, times) usually vary between runs.
            if end - i >= 4 && !chars.get(end).copied().is_some_and(is_word) {
                out.push('N');
            } else {
                out.extend(&chars[i..end]);
            }
            i = end;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}
