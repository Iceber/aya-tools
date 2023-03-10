#![no_std]
#![no_main]

use aya_bpf::{
    cty::c_uint,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerCpuHashMap},
    programs::ProbeContext,
};
use aya_log_ebpf::info;

use tcptop_common::IPV4KEY;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::{sock, sock_common};

#[map]
static mut IPV4_SEND_BYTES: HashMap<IPV4KEY, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static mut IPV4_RECV_BYTES: HashMap<IPV4KEY, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static mut SOCKET_STORE: HashMap<u32, *const sock> = HashMap::with_max_entries(10240, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

fn send_entry(socket: *const sock) -> Result<u32, u32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    unsafe {
        SOCKET_STORE
            .insert(&tgid, &socket, 0)
            .map_err(|e| e as u32)?;
    }
    Ok(0)
}

#[kprobe(name = "tcp_sendmsg")]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let sock: *const sock = ctx.arg(0).ok_or(1u32)?;
    send_entry(sock)
}

#[kprobe(name = "tcp_sendpage")]
pub fn tcp_sendpage(ctx: ProbeContext) -> u32 {
    match try_tcp_sendpage(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendpage(ctx: ProbeContext) -> Result<u32, u32> {
    let sock: *const sock = ctx.arg(0).ok_or(1u32)?;
    send_entry(sock)
}

/*
#[kprobe(name = "tcp_cleanup_rbuf")]
pub fn tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    match try_tcp_cleanup_rbuf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
*/

unsafe fn send_stat(ctx: &ProbeContext, size: u64) -> Result<u32, u32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let sock = SOCKET_STORE.get(&tgid).ok_or(1u32)?;

    let sk_common = bpf_probe_read_kernel(&(*(*sock)).__sk_common).map_err(|_| 1u32)?;
    match sk_common.skc_family {
        AF_INET => {
            let pid = pid;
            let name = bpf_get_current_comm().map_err(|_| 1u32)?;
            let saddr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let daddr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            let lport =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num });
            let dport =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });

            let key = IPV4KEY {
                pid,
                name,
                saddr,
                daddr,
                lport,
                dport,
            };

            match IPV4_SEND_BYTES.get_ptr_mut(&key) {
                Some(value) => (*value) += size,
                None => {
                    match IPV4_SEND_BYTES.insert(&key, &size, 0) {
                        Ok(_) => (),
                        Err(e) => info!(ctx, "insert failed: {}", e),
                    };
                }
            }
        }
        AF_INET6 => {
            let addr = sk_common.skc_v6_rcv_saddr;
            let daddr = sk_common.skc_v6_daddr;
        }
        _ => {}
    }
    Ok(0)
}

#[kretprobe(name = "do_ret_tcp_sendmsg")]
pub fn do_ret_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_do_ret_tcp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_ret_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let size: u32 = ctx.ret().ok_or(1u32)?;
    if size > 0 {
        return unsafe { send_stat(&ctx, size as u64) };
    }
    Ok(0)
}

#[kretprobe(name = "do_ret_tcp_sendpage")]
pub fn do_ret_tcp_sendpage(ctx: ProbeContext) -> u32 {
    match try_do_ret_tcp_sendpage(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_ret_tcp_sendpage(ctx: ProbeContext) -> Result<u32, u32> {
    let size: u32 = ctx.ret().ok_or(1u32)?;
    if size > 0 {
        return unsafe { send_stat(&ctx, size as u64) };
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
