use super::KernelParams;
use byteorder::{ByteOrder, LittleEndian};

#[inline]
fn add_u256(base: &[u8; 32], mut offset: u64) -> [u8; 32] {
    let mut res = [0; 32];
    for i in 0..4 {
        let start = i * 8;
        let end = (i + 1) * 8;
        let base = LittleEndian::read_u64(&base[start..end]);
        let (total, overflow) = base.overflowing_add(offset);
        LittleEndian::write_u64(&mut res[start..end], total);
        if overflow {
            offset = 1;
        } else {
            offset = 0;
        }
    }
    res
}

#[no_mangle]
pub extern "ptx-kernel" fn render(params_ptr: *mut KernelParams) {
    use core::arch::nvptx::*;
    use core::convert::TryInto;

    let params = unsafe { &mut *params_ptr };
    let x = unsafe { _block_dim_x() * _block_idx_x() + _thread_idx_x() } as u64;

    let seed = unsafe { core::slice::from_raw_parts(params.seed.as_raw(), 32) }
        .try_into()
        .unwrap();
    let cur_seed = add_u256(seed, x);
    let s = ed25519_compact::Seed::new(cur_seed);
    let kp = ed25519_compact::KeyPair::from_seed(s);

    let byte_prefixes =
        unsafe { core::slice::from_raw_parts_mut(params.byte_prefixes.as_raw_mut(), params.byte_prefixes_len) };
    for byte_prefix in byte_prefixes {
        if byte_prefix.matches(&*kp.pk) {
            let out = unsafe { core::slice::from_raw_parts_mut(byte_prefix.out.as_raw_mut(), 32) };
            out.clone_from_slice(&cur_seed);
            let success = unsafe { &mut *byte_prefix.success.as_raw_mut() };
            *success = true;
        }
    }
}

#[panic_handler]
fn panic(_: &::core::panic::PanicInfo) -> ! {
    use core::arch::nvptx::*;

    unsafe { trap() }
}
