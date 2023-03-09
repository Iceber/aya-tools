use bytes::BytesMut;
use dashmap::DashMap;
use log::{info, warn};
use std::sync::Arc;

use aya::{
    include_bytes_aligned, maps::AsyncPerfEventArray, programs::KProbe, util::online_cpus,
    BpfLoader,
};
use aya_log::BpfLogger;
use common::{Data, EventType};
use tokio::signal;

// TODO(Iceber): Add Options

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // set by options
    let max_args: u64 = 20;

    #[cfg(debug_assertions)]
    let mut bpf =
        BpfLoader::new()
            .set_global("MAX_ARGS", &max_args)
            .load(include_bytes_aligned!(
                "../target/bpfel-unknown-none/debug/execsnoop"
            ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf =
        BpfLoader::new()
            .set_global("MAX_ARGS", &max_args)
            .load(include_bytes_aligned!(
                "../target/bpfel-unknown-none/release/execsnoop"
            ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {e}")
    };

    let mut events: AsyncPerfEventArray<_> = bpf.take_map("EVENTS").unwrap().try_into()?;

    let program: &mut KProbe = bpf.program_mut("execsnoop").unwrap().try_into()?;
    program.load()?;
    program.attach("__x64_sys_execve", 0)?;

    let program: &mut KProbe = bpf.program_mut("do_ret_sys_execve").unwrap().try_into()?;
    program.load()?;
    program.attach("__x64_sys_execve", 0)?;

    println!(
        "{:16} {:7} {:7} {:3} {}",
        "PCOMM", "PID", "PPIC", "RET", "ARGS"
    );

    let rc_argv: Arc<DashMap<u32, String>> = Arc::new(DashMap::new());

    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    for cpu_id in cpus {
        let argv = Arc::clone(&rc_argv);
        let mut buf = events.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const Data;
                    let data = unsafe { ptr.read_unaligned() };

                    match data.event_type {
                        EventType::EventArg => match argv.get_mut(&data.pid) {
                            Some(mut value) => {
                                value.push_str(&String::from_utf8_lossy(&data.argv[..data.arglen]));
                                value.push_str(" "); // TODO(Iceber): Use join
                            }
                            None => {
                                let mut value = String::new();
                                value.push_str(&String::from_utf8_lossy(&data.argv[..data.arglen]));
                                value.push_str(" "); // TODO(Iceber): Use join
                                argv.insert(data.pid, value);
                            }
                        },
                        EventType::EventRet => match argv.remove(&data.pid) {
                            Some((_, value)) => {
                                println!(
                                    "{:<16} {:<7} {:<7} {:<3} {}",
                                    String::from_utf8_lossy(&data.comm).trim_end_matches("\0"),
                                    data.ppid,
                                    data.pid,
                                    data.retval,
                                    value,
                                );
                            }
                            None => (),
                        },
                    }
                }
            }
        });
    }

    //    info!("Waiting for Ctrl-C...");

    signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c event");

    info!("Exiting...");
    Ok(())
}
