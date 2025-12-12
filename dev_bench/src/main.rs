use anyhow::{Result, anyhow};
use clap::Parser;
use std::sync::atomic::Ordering::Relaxed;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};
use tracing::{debug, error, info, trace, warn};

static COMMAND_EXECUTION_IS_QUIET: AtomicBool = AtomicBool::new(true);

macro_rules! cmd {
    ($($tt:tt)*) => {{
        let mut cmd = xshell::cmd!($($tt)*);
        let quiet = COMMAND_EXECUTION_IS_QUIET.load(Relaxed);
        cmd.set_quiet(quiet);
        cmd.set_ignore_stdout(quiet);
        cmd.set_ignore_stderr(quiet);
        cmd
    }}
}

macro_rules! output {
    ($($tt:tt)*) => {{
        let mut cmd = cmd!($($tt)*);
        cmd.set_ignore_stdout(false);
        cmd.set_ignore_stderr(false);
        cmd.output()
    }}
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    /// Increase verbosity (pass multiple times to increase)
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Record the current run as RUN (overriding prior recording if it exists).
    ///
    /// If not specified, generates a new random name to record with.
    #[arg(long, value_name = "RUN", conflicts_with_all = &["compare"])]
    record: Option<String>,
    /// Limit to a specific benchmark that uniquely matches FILTER.
    ///
    /// If not specified, runs all benchmarks.  If multiple benchmarks match FILTER, an error is raised.
    #[arg(long, value_name = "FILTER")]
    filter: Option<String>,
    /// List available benchmarks and exit.
    #[arg(long, conflicts_with_all = &["record", "compare", "filter"])]
    list: bool,
    /// Compare prior runs RUN1 and RUN2.
    ///
    /// If specified, compares the two runs instead of performing a new run.
    #[arg(long, value_names = &["RUN1", "RUN2"], num_args = 2)]
    compare: Option<Vec<String>>,
    /// Number of iterations to run the benchmark.
    ///
    /// Runs the initialization stage only once per benchmark, but the main run is what is repeated
    /// this number of times.
    #[arg(short = 'n', long, default_value = "1")]
    iterations: std::num::NonZeroU32,
    /// Technique to summarize across multiple iterations.
    #[arg(long, default_value = "min", requires = "iterations")]
    summarization: Summarization,
}

// JB: We are not actually storing `n` or the type of summarization into the csv files, so
// comparisons across two CSVs that use different values for these might not be valid.
//
// FUTURE: Store more relevant info in the CSVs.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum Summarization {
    /// Minimum run time across executions
    Min,
    /// Mean run time across executions
    Mean,
}

impl Summarization {
    fn summarize(self, durations: &[Duration]) -> Duration {
        assert!(!durations.is_empty());
        match self {
            Summarization::Min => *durations.iter().min().unwrap(),
            Summarization::Mean => {
                durations.iter().sum::<Duration>() / u32::try_from(durations.len()).unwrap()
            }
        }
    }
}

fn main() -> Result<()> {
    let mut cli_args = CliArgs::parse();
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_max_level(match cli_args.verbose {
            0 => tracing::Level::INFO,
            1 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        })
        .init();
    if cli_args.verbose > 2 {
        warn!(
            verbosity = cli_args.verbose,
            "Too much verbosity, capping to TRACE (equivalent to -vv)"
        );
    }
    if cli_args.verbose > 0 {
        COMMAND_EXECUTION_IS_QUIET.store(false, Relaxed);
    }
    debug!(cli_args.verbose);

    if cli_args.list {
        list_benchmarks();
        return Ok(());
    }

    project_root()?;

    if let Some(runs) = cli_args.compare.as_ref() {
        assert_eq!(runs.len(), 2);
        return compare_runs(true, &runs[0], &runs[1], &cli_args);
    }

    let run_name = match cli_args.record.as_ref() {
        Some(name) => name.clone(),
        None => {
            petname::petname(2, "-").ok_or_else(|| anyhow!("Failed to generate random run name"))?
        }
    };
    info!(run_name, "Beginning run");
    cli_args.record = Some(run_name.clone());

    if let Some(filter) = cli_args.filter.as_deref() {
        let mut matches = BENCHMARKS
            .iter()
            .filter(|(name, _func)| name.contains(filter));
        let (name, func) = match (matches.next(), matches.next()) {
            (Some(m), None) => m,
            (Some(_), Some(_)) => {
                error!(filter, "Multiple benchmarks match filter");
                list_benchmarks();
                return Err(anyhow!("Multiple benchmarks match filter '{filter}'"));
            }
            (None, None) => {
                error!(filter, "No benchmarks match filter");
                list_benchmarks();
                return Err(anyhow!("No benchmarks match filter '{filter}'"));
            }
            (None, Some(_)) => unreachable!(),
        };
        info!(benchmark = %name, "Running filtered benchmark");
        run_benchmark(name, *func, &cli_args)?;
    } else {
        for (name, func) in BENCHMARKS {
            info!(benchmark = %name, "Running benchmark");
            run_benchmark(name, *func, &cli_args)?;
        }
    }

    info!(run_name, "Completed");

    // If a run called `main` exists, then we compare the current run against it; otherwise, we warn
    // the user that no automatic comparison was done.
    if run_name == "main" {
        info!("Current run is 'main'; not performing automatic comparison against itself");
    } else if let Ok(()) = compare_runs(false, "main", &run_name, &cli_args) {
        // Awesome!
    } else {
        warn!("No comparison was printed; to compare runs, use the --compare option");
        warn!("For automatic comparison against 'main', use `--record main` to create one");
    }

    Ok(())
}

fn list_benchmarks() {
    println!("Available benchmarks:");
    for (name, _func) in BENCHMARKS {
        println!(" - {name}");
    }
}

/// Finds and switches to the project root directory.
///
/// This is to make the rest of the reasoning easier.
fn project_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir().ok().unwrap();
    loop {
        if dir.join("target").is_dir() {
            std::env::set_current_dir(&dir)?;
            debug!(dir = %dir.display(), "Changed working directory to project root");
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(anyhow!("Could not find project root"));
        }
    }
}

const BENCH_DIR_BASE: &str = "target/dev_bench";

fn run_benchmark(name: &str, func: BenchFn, cli_args: &CliArgs) -> Result<()> {
    let sh = xshell::Shell::new()?;
    sh.create_dir(BENCH_DIR_BASE)?;
    sh.change_dir(BENCH_DIR_BASE);
    info!(benchmark = %name, "Initializing benchmark");
    let ctx = BenchCtx {
        sh: &sh,
        cli_args,
        project_root: &std::env::current_dir()?,
        is_init: true,
    };
    func(ctx.with_init(true))?;
    info!(benchmark = %name, iterations=cli_args.iterations, "Running benchmark");
    let duration = {
        let mut durations: Vec<Duration> = vec![];
        for _ in 0..cli_args.iterations.get() {
            let start = std::time::Instant::now();
            func(ctx.with_init(false))?;
            durations.push(start.elapsed());
        }
        cli_args.summarization.summarize(&durations)
    };
    info!(benchmark = %name, ?duration, "Completed benchmark");

    let run_csv = format!("runs/{}.csv", cli_args.record.as_ref().unwrap());
    let existing_data = sh.read_file(&run_csv).unwrap_or_default();
    let new_data = format!("{}{},{}\n", existing_data, name, duration.as_millis());
    sh.write_file(&run_csv, new_data)?;
    Ok(())
}

fn compare_runs(print_on_missing: bool, run1: &str, run2: &str, cli_args: &CliArgs) -> Result<()> {
    fn available_runs(sh: &xshell::Shell) -> Result<Vec<String>> {
        let mut files = sh.read_dir("runs")?.into_iter().collect::<Vec<PathBuf>>();
        files.sort_by_key(|file| {
            if let Ok(metadata) = file.metadata() {
                metadata.modified().ok()
            } else {
                None
            }
        });
        let runs = files
            .into_iter()
            .filter_map(|entry| {
                let file_name = entry.file_name()?;
                let file_name = file_name.to_str()?;
                #[allow(clippy::case_sensitive_file_extension_comparisons)]
                if file_name.ends_with(".csv") {
                    Some(file_name.trim_end_matches(".csv").to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(runs)
    }

    let sh = xshell::Shell::new()?;
    sh.change_dir(BENCH_DIR_BASE);

    let Ok(run1_csv) = sh.read_file(format!("runs/{run1}.csv")) else {
        warn!(run1, "Could not find run");
        let available = available_runs(&sh)?;
        if print_on_missing {
            eprintln!("Available runs (oldest to newest):");
            for run in available {
                eprintln!(" - {run}");
            }
        }
        return Err(anyhow!("Run '{run1}' not found"));
    };
    let Ok(run2_csv) = sh.read_file(format!("runs/{run2}.csv")) else {
        warn!(run2, "Could not find run");
        let available = available_runs(&sh)?;
        if print_on_missing {
            eprintln!("Available runs (oldest to newest):");
            for run in available {
                eprintln!(" - {run}");
            }
        }
        return Err(anyhow!("Run '{run2}' not found"));
    };

    #[allow(clippy::items_after_statements, clippy::ref_option)]
    fn f<'a>(csv: &'a str, filter: &Option<String>) -> BTreeMap<&'a str, Duration> {
        csv.lines()
            .filter(|line| filter.as_ref().is_none_or(|f| line.contains(f)))
            .map(|line| line.split_once(',').unwrap())
            .map(|(name, time_str)| (name, Duration::from_millis(time_str.parse().unwrap())))
            .collect()
    }

    let r1 = f(&run1_csv, &cli_args.filter);
    let r2 = f(&run2_csv, &cli_args.filter);

    let all_benches: BTreeSet<&str> = r1.keys().chain(r2.keys()).copied().collect();

    info!(run1, run2, "Comparing runs");
    let bench_width = all_benches
        .iter()
        .map(|b| b.len())
        .max()
        .unwrap_or(9)
        .max(9);
    let run1_header = format!("{run1} (ms)");
    let run2_header = format!("{run2} (ms)");
    let max_time1_width = r1
        .values()
        .map(|d| d.as_millis().to_string().len())
        .max()
        .unwrap_or(0);
    let max_time2_width = r2
        .values()
        .map(|d| d.as_millis().to_string().len())
        .max()
        .unwrap_or(0);
    let run1_width = run1_header.len().max(max_time1_width);
    let run2_width = run2_header.len().max(max_time2_width);
    let diff_width = 9;
    println!(
        "| {:<bench_width$} | {:>run1_width$} | {:>run2_width$} | {:>diff_width$} |",
        "Benchmark", run1_header, run2_header, "Diff (ms)"
    );
    println!(
        "|:{:-<bench_width$}-|-{:-<run1_width$}:|-{:-<run2_width$}:|-{:-<diff_width$}:|",
        "", "", "", ""
    );

    let mut total_counted = 0i128;
    let mut diff_total = 0i128;

    for bench in all_benches {
        match (r1.get(bench), r2.get(bench)) {
            (Some(t1), Some(t2)) => {
                let abs_diff = i128::try_from(t2.abs_diff(*t1).as_millis()).unwrap();
                let diff = if t1 > t2 { -abs_diff } else { abs_diff };
                println!(
                    "| {:<bench_width$} | {:>run1_width$} | {:>run2_width$} | {:>diff_width$} |",
                    bench,
                    t1.as_millis(),
                    t2.as_millis(),
                    diff
                );
                diff_total += diff;
                total_counted += 1;
            }
            (Some(t1), None) => {
                warn!(benchmark = %bench, time1 = ?t1, "Only present in run 1");
            }
            (None, Some(t2)) => {
                warn!(benchmark = %bench, time2 = ?t2, "Only present in run 2");
            }
            (None, None) => unreachable!(),
        }
    }

    #[allow(clippy::cast_precision_loss)]
    let avg_diff = diff_total as f64 / total_counted as f64;
    let reaction = match diff_total.cmp(&0) {
        std::cmp::Ordering::Less => "🚀 run 2 is faster than run 1",
        std::cmp::Ordering::Equal => "⚖️ perfectly balanced",
        std::cmp::Ordering::Greater => "🐌 run 2 is slower than run 1",
    };

    info!(total_counted, avg_diff, %reaction, "Summarized change");

    Ok(())
}

#[derive(Clone)]
struct BenchCtx<'a> {
    /// The shell is in a working directory shared across benchmark runs, so if the benchmark needs a
    /// temporary directory, it should create its own.
    sh: &'a xshell::Shell,
    #[expect(dead_code, reason = "unused for now")]
    cli_args: &'a CliArgs,
    project_root: &'a Path,
    is_init: bool,
}

impl BenchCtx<'_> {
    fn with_init(&self, is_init: bool) -> Self {
        Self {
            is_init,
            ..self.clone()
        }
    }
}

/// Type alias for benchmark functions.
type BenchFn = fn(BenchCtx<'_>) -> Result<()>;

macro_rules! benchtable {
    ($($func_name:ident),* $(,)?) => {
        &[ $( (stringify!($func_name), $func_name), )* ]
    };
}

/// All available benchmarks
const BENCHMARKS: &[(&str, BenchFn)] = benchtable![
    //
    rewriter_hello_static,
    run_rewritten_hello_static,
    rewriter_node,
    run_rewritten_node,
    //
];

fn rewriter_hello_static(ctx: BenchCtx) -> Result<()> {
    let BenchCtx {
        sh,
        cli_args: _,
        project_root,
        is_init,
    } = ctx;
    if is_init {
        cmd!(sh, "gcc -o hello_static {project_root}/litebox_runner_linux_userland/tests/hello.c -static -m64").run()?;
        cmd!(sh, "cargo build -p litebox_syscall_rewriter --release").run()?;
    } else {
        cmd!(sh, "{project_root}/target/release/litebox_syscall_rewriter hello_static -o hello_static_rewritten").run()?;
    }
    Ok(())
}

fn run_rewritten_hello_static(ctx: BenchCtx<'_>) -> Result<()> {
    let BenchCtx {
        sh,
        cli_args: _,
        project_root,
        is_init,
    } = ctx;
    if is_init {
        rewriter_hello_static(ctx.with_init(true))?;
        rewriter_hello_static(ctx.with_init(false))?;
        cmd!(sh, "cargo build -p litebox_runner_linux_userland --release").run()?;
    } else {
        cmd!(
            sh,
            "{project_root}/target/release/litebox_runner_linux_userland --unstable --interception-backend rewriter hello_static_rewritten"
        ).run()?;
    }
    Ok(())
}

// XXX: This is not ideal, because it means that we have differing tests/benchmarks depending on
// different machines. Ideally we'd switch this out to a more deterministic approach.
fn locate_command(sh: &xshell::Shell, command: &str) -> Result<PathBuf> {
    let r = output!(sh, "which {command}")?.stdout;
    let r = PathBuf::from(String::from_utf8_lossy(&r).trim());
    Ok(r)
}

/// Find all dependencies for `command` via `ldd`
fn find_dependencies(sh: &xshell::Shell, command: &str) -> Result<Vec<PathBuf>> {
    let executable = locate_command(sh, command)?;
    let output = output!(sh, "ldd {executable}")?;
    let dependencies = String::from_utf8_lossy(&output.stdout);
    trace!("Dependencies:\n{dependencies}");
    let mut paths = Vec::new();
    for line in dependencies.lines().filter(|l| !l.trim().is_empty()) {
        if let Some(idx) = line.find("=>") {
            // Format: "libc.so.6 => /lib/.../libc.so.6 (0x...)"
            let right = line[idx + 2..].trim();
            // Skip "not found"
            if right.starts_with("not found") {
                warn!(line, "dependency not found");
                continue;
            }
            // Extract token before whitespace or '('
            if let Some(token) = right.split_whitespace().next()
                && token.starts_with('/')
            {
                paths.push(token.to_string());
            } else {
                warn!(line, "unexpected ldd output line format");
            }
        } else {
            // Format: "/lib64/ld-linux-x86-64.so.2 (0x...)" or "linux-vdso.so.1 (0x...)"
            if let Some(token) = line.split_whitespace().next()
                && token.starts_with('/')
            {
                paths.push(token.to_string());
            }
        }
    }
    let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    for p in &paths {
        if !p.exists() {
            warn!(path = %p.display(), "Resolved dependency path does not exist");
        }
    }
    trace!("Resolved dependency paths: {paths:?}");
    Ok(paths)
}

fn rewriter_node(ctx: BenchCtx) -> Result<()> {
    let BenchCtx {
        sh,
        cli_args: _,
        project_root,
        is_init,
    } = ctx;
    let node = locate_command(sh, "node")?;
    if is_init {
        cmd!(sh, "cargo build -p litebox_syscall_rewriter --release").run()?;
    } else {
        cmd!(
            sh,
            "{project_root}/target/release/litebox_syscall_rewriter {node} -o node_rewritten"
        )
        .run()?;
    }
    Ok(())
}

fn run_rewritten_node(ctx: BenchCtx<'_>) -> Result<()> {
    let BenchCtx {
        sh,
        cli_args: _,
        project_root,
        is_init,
    } = ctx;
    let tar_file = sh.current_dir().join("node_rootfs.tar");
    let release_mode = true;
    if is_init {
        const HELLO_WORLD_JS: &str = r"
            const content = 'Hello World!';
            console.log(content);
        ";
        rewriter_node(ctx.with_init(true))?;
        rewriter_node(ctx.with_init(false))?;

        let tar_base_dir = sh.current_dir().join("node_tar_base");
        sh.write_file(tar_base_dir.join("hello_world.js"), HELLO_WORLD_JS)?;
        let libs = find_dependencies(sh, "node")?;
        sh.create_dir(&tar_base_dir)?;
        for lib in libs {
            let dest_path = tar_base_dir
                .join(lib.strip_prefix("/").unwrap_or_else(|_| {
                    panic!("Library path '{}' is not absolute", lib.display())
                }));
            if let Some(parent) = dest_path.parent() {
                sh.create_dir(parent)?;
            }
            cmd!(
                sh,
                "{project_root}/target/release/litebox_syscall_rewriter {lib} -o {dest_path}"
            )
            .run()?;
        }

        sh.remove_path(&tar_file)?;
        // ustar allows longer file names
        cmd!(sh, "tar --format=ustar -C {tar_base_dir} -cvf {tar_file} .").run()?;
        let release = release_mode.then_some("--release");
        cmd!(
            sh,
            "cargo build -p litebox_runner_linux_userland {release...}"
        )
        .run()?;
    } else {
        let mode = if release_mode { "release" } else { "debug" };
        cmd!(
            sh,
            "{project_root}/target/{mode}/litebox_runner_linux_userland --unstable --interception-backend rewriter --env HOME=/ --initial-files {tar_file} node_rewritten hello_world.js"
        ).run()?;
    }
    Ok(())
}
