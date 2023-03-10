use aya::programs::KProbe;
use aya::{include_bytes_aligned, maps::HashMap, Bpf};
use aya_log::BpfLogger;
use log::{info, warn};
use std::net::Ipv4Addr;
use tcptop_common::IPV4KEY;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tcptop"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tcptop"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut KProbe = bpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_sendmsg", 0)?;

    let program: &mut KProbe = bpf.program_mut("do_ret_tcp_sendmsg").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_sendmsg", 0)?;

    let program: &mut KProbe = bpf.program_mut("tcp_sendpage").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_sendpage", 0)?;

    let program: &mut KProbe = bpf.program_mut("do_ret_tcp_sendpage").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_sendpage", 0)?;

    let mut ipv2_send_bytes: HashMap<_, IPV4KEY, u64> =
        bpf.take_map("IPV4_SEND_BYTES").unwrap().try_into()?;

    tokio::spawn(async move {
        loop {
            let mut v = ipv2_send_bytes
                .iter()
                .map(|v| v.unwrap())
                .collect::<Vec<(IPV4KEY, u64)>>();
            v.sort_by(|a, b| b.1.cmp(&a.1));

            print!("\x1b[2J");
            print!("\x1b[H");
            println!(
                "{:16} {:7} {:20} {:20} {}",
                "PCOMM", "PID", "SOURCE", "DEST", "SIZE"
            );
            for (k, v) in v {
                println!(
                    "{:<16} {:<7} {:<20} {:<20} {}",
                    String::from_utf8_lossy(&k.name).trim_end_matches("\0"),
                    k.pid,
                    format!("{}:{}", Ipv4Addr::from(k.saddr), k.lport,),
                    format!("{}:{}", Ipv4Addr::from(k.daddr), k.dport,),
                    v
                );

                let _ = ipv2_send_bytes.remove(&k);
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
