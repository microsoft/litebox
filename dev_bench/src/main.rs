use anyhow::{Result, anyhow};
use clap::Parser;
use std::sync::atomic::Ordering::Relaxed;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};
#[expect(unused_imports, reason = "some of these are unused for now")]
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
        println!("Available benchmarks:");
        for (name, _func) in BENCHMARKS {
            println!(" - {}", name);
        }
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
            (Some(matched), None) => matched,
            (Some(_), Some(_)) => {
                return Err(anyhow!("Multiple benchmarks match filter '{}'", filter));
            }
            (None, None) => {
                return Err(anyhow!("No benchmarks match filter '{}'", filter));
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
    } else if let Ok(_) = compare_runs(false, "main", &run_name, &cli_args) {
        // Awesome!
    } else {
        warn!("No comparison was printed; to compare runs, use the --compare option");
        warn!("For automatic comparison against 'main', use `--record main` to create one");
    }

    Ok(())
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
    func(BenchCtx {
        sh: &sh,
        cli_args,
        project_root: &std::env::current_dir()?,
        is_init: true,
    })?;
    info!(benchmark = %name, "Running benchmark");
    let start = std::time::Instant::now();
    func(BenchCtx {
        sh: &sh,
        cli_args,
        project_root: &std::env::current_dir()?,
        is_init: false,
    })?;
    let duration = start.elapsed();
    info!(benchmark = %name, ?duration, "Completed benchmark");

    let run_csv = format!("runs/{}.csv", cli_args.record.as_ref().unwrap());
    let existing_data = sh.read_file(&run_csv).unwrap_or_default();
    let new_data = format!("{}{},{}\n", existing_data, name, duration.as_millis());
    sh.write_file(&run_csv, new_data)?;
    Ok(())
}

fn compare_runs(print_on_missing: bool, run1: &str, run2: &str, cli_args: &CliArgs) -> Result<()> {
    let sh = xshell::Shell::new()?;
    sh.change_dir(BENCH_DIR_BASE);

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
                if file_name.ends_with(".csv") {
                    Some(file_name.trim_end_matches(".csv").to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(runs)
    }

    let Ok(run1_csv) = sh.read_file(format!("runs/{}.csv", run1)) else {
        warn!(run1, "Could not find run");
        let available = available_runs(&sh)?;
        if print_on_missing {
            eprintln!("Available runs (oldest to newest):");
            for run in available {
                eprintln!(" - {}", run);
            }
        }
        return Err(anyhow!("Run '{}' not found", run1));
    };
    let Ok(run2_csv) = sh.read_file(format!("runs/{}.csv", run2)) else {
        warn!(run2, "Could not find run");
        let available = available_runs(&sh)?;
        if print_on_missing {
            eprintln!("Available runs (oldest to newest):");
            for run in available {
                eprintln!(" - {}", run);
            }
        }
        return Err(anyhow!("Run '{}' not found", run2));
    };

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
    println!("| Benchmark                      | {run1:>22} (ms) | {run2:>22} (ms) | Diff (ms) |");
    println!(
        "|:-------------------------------|----------------------------:|----------------------------:|----------:|"
    );

    let mut total_counted = 0i128;
    let mut diff_total = 0i128;

    for bench in all_benches {
        match (r1.get(bench), r2.get(bench)) {
            (Some(t1), Some(t2)) => {
                let abs_diff = t2.abs_diff(*t1).as_millis() as i128;
                let diff = if t1 > t2 { -abs_diff } else { abs_diff };
                println!(
                    "| {:<30} | {:>27} | {:>27} | {:>9} |",
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

    let avg_diff = diff_total as f64 / total_counted as f64;
    let reaction = if diff_total < 0 {
        "🚀 run 2 is faster than run 1"
    } else if diff_total > 0 {
        "🐌 run 2 is slower than run 1"
    } else {
        "⚖️ perfectly balanced"
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
        cmd!(sh, "gcc -o hello_static {project_root}/litebox_runner_linux_userland/tests/hello.c -static -m64").run()?;
        cmd!(sh, "cargo build -p litebox_runner_linux_userland --release").run()?;
        cmd!(sh, "cargo run -p litebox_syscall_rewriter --release -- hello_static -o hello_static_rewritten").run()?;
    } else {
        cmd!(
            sh,
            "{project_root}/target/release/litebox_runner_linux_userland --unstable --interception-backend rewriter hello_static_rewritten"
        ).run()?;
    }
    Ok(())
}
