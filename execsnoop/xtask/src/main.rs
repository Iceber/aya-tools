mod build_ebpf;
mod run;

use std::process::exit;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    Run(run::Options),
}
fn main() {
    let opts = Options::parse();

    use Command::*;
    if let Err(e) = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        Run(opts) => run::run(opts),
    } {
        eprintln!("{e:#}");
        exit(1);
    };
}
