#![no_std]

pub const ARG_SIZE: usize = 128;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Data {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub event_type: EventType,
    pub argv: [u8; ARG_SIZE],
    pub arglen: usize,
    pub retval: i32,
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum EventType {
    EventArg = 1,
    EventRet,
}
