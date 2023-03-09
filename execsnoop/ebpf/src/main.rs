#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, kretprobe, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::ProbeContext,
    PtRegs,
};

//use aya_log_ebpf::debug;

use common::{Data, EventType, ARG_SIZE};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::task_struct;

#[no_mangle]
static MAX_ARGS: usize = 20;

#[no_mangle]
static UID: i64 = -1;

#[no_mangle]
static PPID: u32 = 0;

#[map]
static mut EVENTS: PerfEventArray<Data> = PerfEventArray::new(0);

#[map]
static mut SCRATCH: PerCpuArray<Data> = PerCpuArray::with_max_entries(1, 0);

#[kprobe(name = "execsnoop")]
pub fn execsnoop(ctx: ProbeContext) -> u32 {
    match unsafe { try_execsnoop(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1, // TODO(Iceber): add error log to userspace
    }
}

unsafe fn try_execsnoop(ctx: ProbeContext) -> Result<u32, u32> {
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);

    let fp: *const u8 = regs.arg(0).ok_or(1u32)?;
    let argsp: *const usize = regs.arg(1).ok_or(1u32)?;

    let data = SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    (*data).pid = bpf_get_current_pid_tgid() as u32;
    (*data).uid = bpf_get_current_uid_gid() as u32;
    (*data).comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    (*data).event_type = EventType::EventArg;

    let task = bpf_get_current_task() as *const task_struct;
    let parent = bpf_probe_read_kernel(&(*task).real_parent).map_err(|_| 1u32)?;
    (*data).ppid = bpf_probe_read_kernel(&(*parent).tgid).map_err(|_| 1u32)? as u32;

    let mut buf = [0; ARG_SIZE];

    // TODO(Iceber): Add *submit_data* function
    // TODO(Iceber): Use *bpf_probe_read_user_str* to replace *bpf_probe_read_user_str_bytes* and remove `buf`
    let arg = bpf_probe_read_user_str_bytes(fp, &mut buf).map_err(|_| 1u32)?;
    (*data).arglen = arg.len();
    (*data).argv[..arg.len()].copy_from_slice(arg);

    EVENTS.output(&ctx, &(*data), 0);

    for i in 1..core::ptr::read_volatile(&MAX_ARGS) {
        let p = bpf_probe_read_user(argsp.add(i) as *const usize).unwrap_or_default() as *const u8;
        if p.is_null() {
            return Ok(0);
        };

        // TODO(Iceber): Add *submit_data* function
        // TODO(Iceber): Use *bpf_probe_read_user_str* to replace *bpf_probe_read_user_str_bytes* and remove `buf`
        let arg = bpf_probe_read_user_str_bytes(p, &mut buf).map_err(|_| 1u32)?;
        (*data).arglen = arg.len();
        (*data).argv[..arg.len()].copy_from_slice(arg);

        EVENTS.output(&ctx, &(*data), 0);
    }

    (*data).arglen = 3;
    (*data).argv[..3].copy_from_slice("...".as_bytes());

    EVENTS.output(&ctx, &(*data), 0);
    Ok(0)
}

#[kretprobe(name = "do_ret_sys_execve")]
pub fn do_ret_sys_execve(ctx: ProbeContext) -> u32 {
    match unsafe { try_ret_sys_execve(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1, // TODO(Iceber): add error log to userspace
    }
}
unsafe fn try_ret_sys_execve(ctx: ProbeContext) -> Result<u32, u32> {
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);

    let data = SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    (*data).pid = bpf_get_current_pid_tgid() as u32;
    (*data).uid = bpf_get_current_uid_gid() as u32;
    (*data).comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    (*data).event_type = EventType::EventRet;

    let task = bpf_get_current_task() as *const task_struct;
    let parent = bpf_probe_read_kernel(&(*task).real_parent).map_err(|_| 1u32)?;
    (*data).ppid = bpf_probe_read_kernel(&(*parent).tgid).map_err(|_| 1u32)? as u32;

    match regs.ret::<*const i32>() {
        None => (),
        Some(p) => match bpf_probe_read(p) {
            Err(_) => (),
            Ok(i) => (*data).retval = i,
        },
    }

    EVENTS.output(&ctx, &(*data), 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
