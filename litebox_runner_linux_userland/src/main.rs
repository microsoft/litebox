use clap::Parser as _;
use litebox_runner_linux_userland::CliArgs;

fn main() -> anyhow::Result<()> {
    litebox_runner_linux_userland::run(CliArgs::parse())
}
