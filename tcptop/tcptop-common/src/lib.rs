#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IPV4KEY {
    pub pid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub name: [u8; 16],
    pub lport: u16,
    pub dport: u16,
}

#[cfg(feature = "user")]
mod user {
    use super::*;

    unsafe impl aya::Pod for IPV4KEY {}
}
