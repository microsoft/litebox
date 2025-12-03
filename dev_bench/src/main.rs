#![expect(unused_imports)]

use anyhow::{Result, anyhow};
use clap::Parser;
use fs_err as fs;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::Duration,
};
use tracing::{debug, error, info, trace, warn};

macro_rules! cmd {
    ($($tt:tt)*) => {
        xshell::cmd!($($tt)*).quiet()
    }
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
        return compare_runs(&runs[0], &runs[1], &cli_args);
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
    sh.change_dir(BENCH_DIR_BASE);
    info!(benchmark = %name, "Initializing benchmark");
    func(true, &sh, cli_args)?;
    info!(benchmark = %name, "Running benchmark");
    let start = std::time::Instant::now();
    func(false, &sh, cli_args)?;
    let duration = start.elapsed();
    info!(benchmark = %name, ?duration, "Completed benchmark");

    let run_csv = format!("runs/{}.csv", cli_args.record.as_ref().unwrap());
    let existing_data = sh.read_file(&run_csv).unwrap_or_default();
    let new_data = format!("{}{},{}\n", existing_data, name, duration.as_millis());
    sh.write_file(&run_csv, new_data)?;
    Ok(())
}

fn compare_runs(run1: &str, run2: &str, cli_args: &CliArgs) -> Result<()> {
    let sh = xshell::Shell::new()?;
    sh.change_dir(BENCH_DIR_BASE);

    fn available_runs(sh: &xshell::Shell) -> Result<Vec<String>> {
        Ok(sh
            .read_dir("runs")?
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
            .collect::<Vec<_>>())
    }

    let Ok(run1_csv) = sh.read_file(format!("runs/{}.csv", run1)) else {
        error!(run1, "Could not find run");
        let available = available_runs(&sh)?;
        eprintln!("Available runs:");
        for run in available {
            eprintln!(" - {}", run);
        }
        return Err(anyhow!("Run '{}' not found", run1));
    };
    let Ok(run2_csv) = sh.read_file(format!("runs/{}.csv", run2)) else {
        error!(run2, "Could not find run");
        let available = available_runs(&sh)?;
        eprintln!("Available runs:");
        for run in available {
            eprintln!(" - {}", run);
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
    println!("| Benchmark            | {run1:>20} (ms) | {run2:>20} (ms) | Diff (ms) |");
    println!(
        "|:---------------------|--------------------------:|--------------------------:|----------:|"
    );
    for bench in all_benches {
        match (r1.get(bench), r2.get(bench)) {
            (Some(t1), Some(t2)) => {
                let abs_diff = t2.abs_diff(*t1).as_millis();
                let neg = if t1 < t2 { "-" } else { "" };
                let diff = format!("{neg}{abs_diff}");
                println!(
                    "| {:<20} | {:>25} | {:>25} | {:>9} |",
                    bench,
                    t1.as_millis(),
                    t2.as_millis(),
                    diff
                );
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

    Ok(())
}

/// Type alias for benchmark functions.
///
/// Args: (is_init: bool, sh: &xshell::Shell, cli_args: &CliArgs)
///
/// The shell is in a working directory shared across benchmark runs, so if the benchmark needs a
/// temporary directory, it should create its own.
type BenchFn = fn(bool, &xshell::Shell, &CliArgs) -> Result<()>;

macro_rules! benchtable {
    ($($func_name:ident),* $(,)?) => {
        &[ $( (stringify!($func_name), $func_name), )* ]
    };
}

/// All available benchmarks
const BENCHMARKS: &[(&str, BenchFn)] = benchtable![
    //
    example_benchmark,
    //
];

fn example_benchmark(is_init: bool, sh: &xshell::Shell, cli_args: &CliArgs) -> Result<()> {
    if is_init {
        cmd!(sh, "sleep 1").run()?;
    } else {
        cmd!(sh, "sleep 2").run()?;
    }
    Ok(())
}
