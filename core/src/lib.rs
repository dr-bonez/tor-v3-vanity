#![no_std]
#![cfg_attr(
    any(target_arch = "nvptx", target_arch = "nvptx64"),
    feature(abi_ptx, stdsimd)
)]

use rustacuda_core::DevicePointer;
use rustacuda_derive::DeviceCopy;

#[cfg(any(target_arch = "nvptx", target_arch = "nvptx64"))]
mod kernel;

#[derive(DeviceCopy, Clone)]
#[repr(C)]
pub struct KernelParams {
    pub seed: DevicePointer<u8>,
    pub byte_prefixes: DevicePointer<BytePrefix>,
    pub byte_prefixes_len: usize,
}

#[derive(DeviceCopy, Clone)]
#[repr(C)]
pub struct BytePrefix {
    pub byte_prefix: DevicePointer<u8>,
    pub byte_prefix_len: usize,
    pub last_byte_idx: usize,
    pub last_byte_mask: u8,
    pub out: DevicePointer<u8>,
    pub success: DevicePointer<bool>,
}
impl BytePrefix {
    pub fn matches(&self, data: &[u8]) -> bool {
        let slice =
            unsafe { core::slice::from_raw_parts(self.byte_prefix.as_raw(), self.byte_prefix_len) };
        data.starts_with(&slice[..self.last_byte_idx])
            && data[self.last_byte_idx] & self.last_byte_mask == slice[self.last_byte_idx]
    }
}
