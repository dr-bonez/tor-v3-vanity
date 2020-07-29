#![no_std]
#![cfg_attr(
    any(target_arch = "nvptx", target_arch = "nvptx64"),
    feature(abi_ptx, stdsimd)
)]

use rustacuda_derive::DeviceCopy;
use rustacuda_core::DevicePointer;

#[cfg(any(target_arch = "nvptx", target_arch = "nvptx64"))]
mod kernel;

#[derive(DeviceCopy, Clone)]
#[repr(C)]
pub struct KernelParams {
    pub seed: DevicePointer<u8>,
    pub byte_prefix: DevicePointer<u8>,
    pub byte_prefix_len: usize,
    pub last_byte_idx: usize,
    pub last_byte_mask: u8,
    pub out: DevicePointer<u8>,
    pub success: DevicePointer<bool>,
}