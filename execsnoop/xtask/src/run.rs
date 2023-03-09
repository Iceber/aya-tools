use std::process::Command;

use anyhow::Context as _;

use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,

    #[clap(long)]
    pub release: bool,

    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,

    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

fn build(opts: &Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");

    assert!(status.success());
    Ok(())
}

pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;
    build(&opts).context("Error while building userspace application")?;

    let profile = if opts.release { "release" } else { "debug" };
    let bin_path = format!("target/{profile}/execsnoop");

    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .status()
        .expect("failed to run the command");
    if !status.success() {
        anyhow::bail!("Failed to run `{}`", args.join(" "));
    }
    Ok(())
}
