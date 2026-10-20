// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Results of a run, and the reports made from them.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    Broken,
    Skipped,
    Timeout,
    Crash,
    NotRun,
}

impl Status {
    const ALL: [Self; 7] = [
        Self::Pass,
        Self::Fail,
        Self::Broken,
        Self::Skipped,
        Self::Timeout,
        Self::Crash,
        Self::NotRun,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Broken => "broken",
            Self::Skipped => "skipped",
            Self::Timeout => "timeout",
            Self::Crash => "crash",
            Self::NotRun => "not_run",
        }
    }
}

/// How many results of each kind a test reported.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Counts {
    pub pass: u32,
    pub fail: u32,
    pub broken: u32,
    pub skipped: u32,
    pub warn: u32,
}

/// One test's run, natively or under LiteBox.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunResult {
    pub status: Status,
    /// Why it did not pass, normalized so that tests failing alike share it.
    pub cause: Option<String>,
    pub counts: Counts,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    /// The run's output, relative to the run's directory.
    pub log: Option<PathBuf>,
    /// Host syscalls that the runner's seccomp filter blocked (debug builds report them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_syscalls_blocked: Vec<u32>,
}

impl RunResult {
    pub fn not_run(cause: &str) -> Self {
        Self {
            status: Status::NotRun,
            cause: Some(cause.to_owned()),
            counts: Counts::default(),
            exit_code: None,
            duration_ms: 0,
            log: None,
            host_syscalls_blocked: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestRecord {
    pub name: String,
    pub command: Vec<String>,
    /// What the test exercises, e.g. the syscall.
    pub group: String,
    /// Requirements the suite declares for the test, e.g. `needs_root`.
    pub tags: Vec<String>,
    pub litebox: RunResult,
    pub native: Option<RunResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub suite: String,
    pub suite_version: String,
    pub litebox_commit: String,
    pub profile: String,
    pub allow_fork: bool,
    pub tests: Vec<TestRecord>,
}

/// Writes results.json and report.md into `out_dir`, report.html too if pandoc is installed, and
/// prints a summary.
pub fn write(report: &Report, out_dir: &Path, syscall_names: &BTreeMap<u32, String>) -> Result<()> {
    let json = out_dir.join("results.json");
    std::fs::write(&json, serde_json::to_string_pretty(report)?)?;
    let markdown = out_dir.join("report.md");
    std::fs::write(&markdown, render_markdown(report, syscall_names))?;
    print!("{}", render_summary(report));
    println!("\nReport:  {}", markdown.display());
    // The report is already written, so a failed rendering only warrants a warning.
    match render_html(&markdown) {
        Ok(Some(html)) => println!("         {}", html.display()),
        Ok(None) => eprintln!(
            "warning: pandoc is not installed; with it, report.md would also be rendered as \
             report.html"
        ),
        Err(error) => eprintln!("warning: could not render report.md as HTML: {error:#}"),
    }
    println!("Results: {}", json.display());
    println!("Logs:    {}", out_dir.join("logs").display());
    Ok(())
}

/// Renders `markdown` as a self-contained HTML file beside it, returning that file, or `None` if
/// pandoc is not installed.
fn render_html(markdown: &Path) -> Result<Option<PathBuf>> {
    const STYLE: &str = "<style>
  body { max-width: 75em; }
  table { font-size: 0.85em; }
  tbody tr:nth-child(odd) { background: #f6f6f6; }
  thead th { position: sticky; top: 0; background: #fff; }
  td { vertical-align: top; }
</style>
";
    let html = markdown.with_extension("html");
    let style = markdown.with_extension("style.html");
    std::fs::write(&style, STYLE)?;
    let output = Command::new("pandoc")
        .args(["--from=markdown", "--standalone"])
        // Pandoc gives a pipe table with a source line longer than this equal, fixed-width
        // columns; a huge value lets columns fit their contents.
        .arg("--columns=100000")
        // Makes the report's single top-level heading the page's title.
        .arg("--shift-heading-level-by=-1")
        .arg("--include-in-header")
        .arg(&style)
        .arg("--output")
        .arg(&html)
        .arg(markdown)
        .output();
    let _ = std::fs::remove_file(&style);
    let output = match output {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        output => output.context("running pandoc")?,
    };
    if !output.status.success() {
        bail!(
            "pandoc failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(Some(html))
}

/// How many of `runs` have each status.
fn tally<'a>(runs: impl Iterator<Item = &'a RunResult>) -> BTreeMap<Status, usize> {
    let mut tally: BTreeMap<_, _> = Status::ALL.iter().map(|&status| (status, 0)).collect();
    for run in runs {
        *tally.entry(run.status).or_default() += 1;
    }
    tally
}

fn tally_line(tally: &BTreeMap<Status, usize>) -> String {
    Status::ALL
        .iter()
        .map(|status| format!("{} {}", status.as_str(), tally[status]))
        .collect::<Vec<_>>()
        .join(", ")
}

fn percent(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "-".into();
    }
    #[allow(clippy::cast_precision_loss)]
    let percent = part as f64 * 100.0 / whole as f64;
    format!("{percent:.1}%")
}

/// Tests that did not pass under LiteBox for the same cause, most common first, among those whose
/// status `include` accepts.
fn causes(report: &Report, include: impl Fn(Status) -> bool) -> Vec<(&str, Status, Vec<&str>)> {
    let mut causes: BTreeMap<(&str, Status), Vec<&str>> = BTreeMap::new();
    for test in &report.tests {
        let run = &test.litebox;
        if include(run.status) {
            let cause = run.cause.as_deref().unwrap_or("(no cause reported)");
            causes
                .entry((cause, run.status))
                .or_default()
                .push(&test.name);
        }
    }
    let mut causes: Vec<_> = causes
        .into_iter()
        .map(|((cause, status), tests)| (cause, status, tests))
        .collect();
    causes.sort_by(|a, b| b.2.len().cmp(&a.2.len()).then_with(|| a.0.cmp(b.0)));
    causes
}

fn is_problem(status: Status) -> bool {
    !matches!(status, Status::Pass | Status::Skipped)
}

/// Sentences on how many tests LiteBox passes, of those run and of those that pass natively.
fn pass_rates(report: &Report) -> Vec<String> {
    let litebox = tally(report.tests.iter().map(|test| &test.litebox));
    let ran = report.tests.len() - litebox[&Status::NotRun];
    let passed = litebox[&Status::Pass];
    let mut sentences = vec![format!(
        "LiteBox passes {passed} of {ran} tests run ({}).",
        percent(passed, ran)
    )];
    if report.tests.iter().any(|test| test.native.is_some()) {
        let native_passes: Vec<_> = report
            .tests
            .iter()
            .filter(|test| {
                test.native
                    .as_ref()
                    .is_some_and(|run| run.status == Status::Pass)
            })
            .collect();
        let both = native_passes
            .iter()
            .filter(|test| test.litebox.status == Status::Pass)
            .count();
        sentences.push(format!(
            "LiteBox passes {both} of the {} tests that pass natively ({}).",
            native_passes.len(),
            percent(both, native_passes.len())
        ));
    }
    sentences
}

fn render_summary(report: &Report) -> String {
    let mut out = String::new();
    let litebox = tally(report.tests.iter().map(|test| &test.litebox));
    let _ = writeln!(
        out,
        "\n{} {} under LiteBox {} ({} build{}): {} tests",
        report.suite,
        report.suite_version,
        report.litebox_commit,
        report.profile,
        if report.allow_fork {
            ", fork allowed"
        } else {
            ""
        },
        report.tests.len()
    );
    let _ = writeln!(out, "  LiteBox: {}", tally_line(&litebox));
    if report.tests.iter().any(|test| test.native.is_some()) {
        let native = tally(report.tests.iter().filter_map(|test| test.native.as_ref()));
        let _ = writeln!(out, "  Native:  {}", tally_line(&native));
    }
    for sentence in pass_rates(report) {
        let _ = writeln!(out, "  {sentence}");
    }
    let causes = causes(report, is_problem);
    if !causes.is_empty() {
        let _ = writeln!(out, "\nMost common causes of failure under LiteBox:");
        for (cause, status, tests) in causes.iter().take(15) {
            let _ = writeln!(out, "  {:>5}  {:<8} {cause}", tests.len(), status.as_str());
        }
    }
    out
}

/// Makes `text` safe in a Markdown table cell, where e.g. `<tmpdir>` would read as an HTML tag.
fn cell(text: &str) -> String {
    text.replace('|', "\\|")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', " ")
}

fn examples(tests: &[&str]) -> String {
    const SHOWN: usize = 5;
    let mut examples = tests
        .iter()
        .take(SHOWN)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    if tests.len() > SHOWN {
        let _ = write!(examples, ", +{} more", tests.len() - SHOWN);
    }
    examples
}

/// Writes a table with `header` and `rows`, or "None." if there are no rows.
fn table(out: &mut String, header: &str, rows: Vec<String>) {
    if rows.is_empty() {
        out.push_str("None.\n");
        return;
    }
    let _ = writeln!(out, "{header}");
    for row in rows {
        let _ = writeln!(out, "{row}");
    }
}

fn render_markdown(report: &Report, syscall_names: &BTreeMap<u32, String>) -> String {
    let mut out = String::new();
    let has_native = report.tests.iter().any(|test| test.native.is_some());
    let _ = writeln!(out, "# LiteBox compatibility: {}\n", report.suite);
    let _ = writeln!(out, "| | |\n|---|---|");
    let _ = writeln!(out, "| Suite | {} {} |", report.suite, report.suite_version);
    let _ = writeln!(
        out,
        "| LiteBox | {} ({} build, process duplication {}) |",
        report.litebox_commit,
        report.profile,
        if report.allow_fork {
            "allowed"
        } else {
            "denied"
        }
    );
    let _ = writeln!(out, "| Tests | {} |\n", report.tests.len());

    let _ = writeln!(out, "## Totals\n");
    let litebox = tally(report.tests.iter().map(|test| &test.litebox));
    let native = tally(report.tests.iter().filter_map(|test| test.native.as_ref()));
    if has_native {
        let _ = writeln!(out, "| Status | LiteBox | Native |\n|---|---:|---:|");
    } else {
        let _ = writeln!(out, "| Status | LiteBox |\n|---|---:|");
    }
    for status in Status::ALL {
        let _ = write!(out, "| {} | {} |", status.as_str(), litebox[&status]);
        if has_native {
            let _ = write!(out, " {} |", native[&status]);
        }
        out.push('\n');
    }
    out.push('\n');
    for sentence in pass_rates(report) {
        let _ = writeln!(out, "{sentence}");
    }

    let _ = writeln!(
        out,
        "\n## Why tests do not pass under LiteBox\n\n\
         Causes are the first failure each test reported, with run-specific details such as \
         temporary paths and large numbers elided.\n"
    );
    let rows = causes(report, is_problem)
        .into_iter()
        .map(|(cause, status, tests)| {
            let (count, status) = (tests.len(), status.as_str());
            format!(
                "| {count} | {status} | {} | {} |",
                cell(cause),
                examples(&tests)
            )
        })
        .collect();
    table(
        &mut out,
        "| Tests | Status | Cause | Examples |\n|---:|---|---|---|",
        rows,
    );

    let _ = writeln!(out, "\n## Why tests are skipped under LiteBox\n");
    let rows = causes(report, |status| status == Status::Skipped)
        .into_iter()
        .map(|(cause, _, tests)| {
            format!(
                "| {} | {} | {} |",
                tests.len(),
                cell(cause),
                examples(&tests)
            )
        })
        .collect();
    table(
        &mut out,
        "| Tests | Reason | Examples |\n|---:|---|---|",
        rows,
    );

    if has_native {
        let _ = writeln!(out, "\n## Pass natively, but not under LiteBox\n");
        let rows = report
            .tests
            .iter()
            .filter(|test| {
                test.native
                    .as_ref()
                    .is_some_and(|run| run.status == Status::Pass)
                    && test.litebox.status != Status::Pass
            })
            .map(|test| {
                let run = &test.litebox;
                let cause = cell(run.cause.as_deref().unwrap_or(""));
                format!("| {} | {} | {cause} |", test.name, run.status.as_str())
            })
            .collect();
        table(&mut out, "| Test | LiteBox | Cause |\n|---|---|---|", rows);

        let _ = writeln!(out, "\n## Pass under LiteBox, but not natively\n");
        let rows = report
            .tests
            .iter()
            .filter(|test| test.litebox.status == Status::Pass)
            .filter_map(|test| Some((test, test.native.as_ref()?)))
            .filter(|(_, native)| native.status != Status::Pass)
            .map(|(test, native)| {
                let cause = cell(native.cause.as_deref().unwrap_or(""));
                format!("| {} | {} | {cause} |", test.name, native.status.as_str())
            })
            .collect();
        table(&mut out, "| Test | Native | Cause |\n|---|---|---|", rows);
    }

    let _ = writeln!(out, "\n## By group\n");
    let _ = write!(out, "| Group | Tests | Pass rate |");
    for status in Status::ALL {
        let _ = write!(out, " {} |", status.as_str());
    }
    let _ = write!(out, "\n|---|---:|---:|");
    for _ in Status::ALL {
        out.push_str("---:|");
    }
    out.push('\n');
    let mut groups: BTreeMap<&str, Vec<&RunResult>> = BTreeMap::new();
    for test in &report.tests {
        groups.entry(&test.group).or_default().push(&test.litebox);
    }
    for (group, runs) in groups {
        let tally = tally(runs.iter().copied());
        let ran = runs.len() - tally[&Status::NotRun];
        let _ = write!(
            out,
            "| {group} | {} | {} |",
            runs.len(),
            percent(tally[&Status::Pass], ran)
        );
        for status in Status::ALL {
            let _ = write!(out, " {} |", tally[&status]);
        }
        out.push('\n');
    }

    let mut blocked: BTreeMap<u32, usize> = BTreeMap::new();
    for test in &report.tests {
        for &number in &test.litebox.host_syscalls_blocked {
            *blocked.entry(number).or_default() += 1;
        }
    }
    if !blocked.is_empty() {
        let _ = writeln!(
            out,
            "\n## Host syscalls blocked in the runner\n\n\
             The runner's seccomp filter blocked these syscalls that LiteBox itself made on the \
             host (not the guest's syscalls); debug builds report them.\n"
        );
        let _ = writeln!(out, "| Syscall | Tests |\n|---|---:|");
        let mut blocked: Vec<_> = blocked.into_iter().collect();
        blocked.sort_by_key(|&(number, tests)| (std::cmp::Reverse(tests), number));
        for (number, tests) in blocked {
            let name = syscall_names.get(&number).map_or("?", String::as_str);
            let _ = writeln!(out, "| {name} ({number}) | {tests} |");
        }
    }

    let _ = writeln!(
        out,
        "\n## All tests\n\n<details>\n<summary>{} tests</summary>\n",
        report.tests.len()
    );
    if has_native {
        let _ = writeln!(
            out,
            "| Test | Group | LiteBox | Native | Cause under LiteBox | Tags |\n|---|---|---|---|---|---|"
        );
    } else {
        let _ = writeln!(
            out,
            "| Test | Group | LiteBox | Cause | Tags |\n|---|---|---|---|---|"
        );
    }
    for test in &report.tests {
        let _ = write!(
            out,
            "| {} | {} | {} |",
            test.name,
            test.group,
            test.litebox.status.as_str()
        );
        if has_native {
            let native = test.native.as_ref().map_or("", |run| run.status.as_str());
            let _ = write!(out, " {native} |");
        }
        let _ = writeln!(
            out,
            " {} | {} |",
            cell(test.litebox.cause.as_deref().unwrap_or("")),
            test.tags.join(", ")
        );
    }
    let _ = writeln!(out, "\n</details>");
    out
}

fn load(path: &Path) -> Result<Report> {
    let path = if path.is_dir() {
        path.join("results.json")
    } else {
        path.to_path_buf()
    };
    let json =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&json).with_context(|| format!("parsing {}", path.display()))
}

/// Prints how LiteBox's results changed from run `old` to run `new`.
pub fn compare(old: &Path, new: &Path) -> Result<()> {
    let old = load(old)?;
    let new = load(new)?;
    let mut out = String::new();
    let _ = writeln!(out, "# Comparison: {} runs\n", new.suite);
    let _ = writeln!(out, "| | Old | New |\n|---|---|---|");
    let _ = writeln!(
        out,
        "| Suite | {} | {} |",
        old.suite_version, new.suite_version
    );
    let _ = writeln!(
        out,
        "| LiteBox | {} | {} |",
        old.litebox_commit, new.litebox_commit
    );
    let _ = writeln!(out, "| Build | {} | {} |", old.profile, new.profile);
    let _ = writeln!(
        out,
        "| Process duplication | {} | {} |\n",
        old.allow_fork, new.allow_fork
    );

    let old_tally = tally(old.tests.iter().map(|test| &test.litebox));
    let new_tally = tally(new.tests.iter().map(|test| &test.litebox));
    let _ = writeln!(out, "| Status | Old | New | Change |\n|---|---:|---:|---:|");
    for status in Status::ALL {
        let (before, after) = (old_tally[&status], new_tally[&status]);
        #[allow(clippy::cast_possible_wrap)]
        let change = after as isize - before as isize;
        let _ = writeln!(
            out,
            "| {} | {before} | {after} | {change:+} |",
            status.as_str()
        );
    }

    let old_tests: BTreeMap<&str, &TestRecord> = old
        .tests
        .iter()
        .map(|test| (test.name.as_str(), test))
        .collect();
    let new_tests: BTreeMap<&str, &TestRecord> = new
        .tests
        .iter()
        .map(|test| (test.name.as_str(), test))
        .collect();
    let mut fixed = Vec::new();
    let mut regressed = Vec::new();
    let mut changed = Vec::new();
    for (name, after) in &new_tests {
        let Some(before) = old_tests.get(name) else {
            continue;
        };
        let (before, after) = (&before.litebox, &after.litebox);
        if before.status == after.status {
            continue;
        }
        let line = format!(
            "| {name} | {} | {} | {} |",
            before.status.as_str(),
            after.status.as_str(),
            cell(after.cause.as_deref().unwrap_or(""))
        );
        match (before.status == Status::Pass, after.status == Status::Pass) {
            (false, true) => fixed.push(line),
            (true, false) => regressed.push(line),
            _ => changed.push(line),
        }
    }
    for (title, lines) in [
        ("Newly passing", fixed),
        ("No longer passing", regressed),
        ("Other status changes", changed),
    ] {
        let _ = writeln!(out, "\n## {title} ({})\n", lines.len());
        table(
            &mut out,
            "| Test | Old | New | New cause |\n|---|---|---|---|",
            lines,
        );
    }
    let only_old = old_tests
        .keys()
        .filter(|name| !new_tests.contains_key(*name))
        .count();
    let only_new = new_tests
        .keys()
        .filter(|name| !old_tests.contains_key(*name))
        .count();
    if only_old > 0 || only_new > 0 {
        let _ = writeln!(
            out,
            "\nTests only in the old run: {only_old}; only in the new run: {only_new}."
        );
    }

    let count_causes = |report: &Report| {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for (cause, _, tests) in causes(report, is_problem) {
            *counts.entry(cause.to_owned()).or_default() += tests.len();
        }
        counts
    };
    let old_causes = count_causes(&old);
    let new_causes = count_causes(&new);
    let mut cause_changes: Vec<(&str, usize, usize)> = old_causes
        .keys()
        .chain(new_causes.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|cause| {
            let before = *old_causes.get(cause).unwrap_or(&0);
            let after = *new_causes.get(cause).unwrap_or(&0);
            (cause.as_str(), before, after)
        })
        .filter(|(_, before, after)| before != after)
        .collect();
    cause_changes
        .sort_by_key(|&(cause, before, after)| (std::cmp::Reverse(before.abs_diff(after)), cause));
    let _ = writeln!(
        out,
        "\n## Causes of failure that changed ({})\n",
        cause_changes.len()
    );
    let rows = cause_changes
        .into_iter()
        .map(|(cause, before, after)| format!("| {before} | {after} | {} |", cell(cause)))
        .collect();
    table(&mut out, "| Old | New | Cause |\n|---:|---:|---|", rows);
    print!("{out}");
    Ok(())
}
