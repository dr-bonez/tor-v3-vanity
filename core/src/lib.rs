#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    any(target_arch = "nvptx", target_arch = "nvptx64"),
    feature(abi_ptx, stdsimd)
)]

use rustacuda_core::DevicePointer;
use rustacuda_derive::DeviceCopy;

pub mod ed25519;

#[cfg(any(target_arch = "nvptx", target_arch = "nvptx64"))]
mod kernel;

/// Keys checked per batch inversion: each candidate costs ~11 field multiplications plus
/// 1/BATCH of an inversion (~265 multiplications).
pub const BATCH: usize = 64;
/// Batches per kernel launch.
pub const ROUNDS: usize = 64;
pub const KEYS_PER_LAUNCH: usize = BATCH * ROUNDS;
/// Thread `t` starts at scalar `base + t * 2^STRIDE_SHIFT` and steps by 8, so threads never
/// overlap for 2^40 steps each.
pub const STRIDE_SHIFT: u32 = 43;

/// Secret scalar searched by `thread` after `step` increments.
pub fn thread_scalar(base: &[u8; 32], thread: u64, step: u64) -> [u8; 32] {
    let offset = ((thread as u128) << STRIDE_SHIFT) + 8 * step as u128;
    ed25519::add_scalar(base, offset as u64, (offset >> 64) as u64)
}

/// A prefix of the encoded public key, as little-endian words.
#[derive(DeviceCopy, Clone, Copy)]
#[repr(C)]
pub struct Prefix {
    pub value: [u32; 8],
    pub mask: [u32; 8],
}
impl Prefix {
    #[inline(always)]
    pub fn matches(&self, words: &[u32; 8]) -> bool {
        for i in 0..8 {
            if words[i] & self.mask[i] != self.value[i] {
                return false;
            }
        }
        true
    }
}

#[derive(DeviceCopy, Clone, Copy)]
#[repr(C)]
pub struct Found {
    pub thread: u32,
    /// Index of the candidate within the launch, `< KEYS_PER_LAUNCH`.
    pub iter: u32,
}

#[derive(DeviceCopy, Clone)]
#[repr(C)]
pub struct KernelParams {
    pub base_scalar: [u8; 32],
    /// 8 * B, the point added between candidates (scalars step by 8 to stay clamped).
    pub step: ed25519::GePrecomp,
    /// Current point of every thread, persisted across launches.
    pub points: DevicePointer<ed25519::GeP3>,
    pub prefixes: DevicePointer<Prefix>,
    pub prefixes_len: usize,
    pub found_count: DevicePointer<u32>,
    pub found: DevicePointer<Found>,
    pub found_cap: u32,
}
