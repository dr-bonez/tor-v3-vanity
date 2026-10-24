use super::ed25519::{invert, mul, to_words, Fe, GeP3, FE_ZERO};
use super::{thread_scalar, Found, KernelParams, BATCH, ROUNDS};
use core::sync::atomic::{AtomicU32, Ordering};

#[inline(always)]
fn thread_id() -> usize {
    use core::arch::nvptx::*;
    unsafe { (_block_dim_x() * _block_idx_x() + _thread_idx_x()) as usize }
}

/// Computes every thread's starting point once. Slow (a full scalar multiplication), but it
/// only runs at startup.
#[no_mangle]
pub unsafe extern "ptx-kernel" fn init(params_ptr: *mut KernelParams) {
    let params = &mut *params_ptr;
    let t = thread_id();
    let scalar = thread_scalar(&params.base_scalar, t as u64, 0);
    *params.points.as_raw_mut().add(t) = GeP3::base().scalarmult(&scalar);
}

/// Checks `KEYS_PER_LAUNCH` consecutive keys per thread. Each key is the previous point plus
/// 8B (one mixed addition), and the affine y coordinates of a batch share a single inversion.
#[no_mangle]
pub unsafe extern "ptx-kernel" fn render(params_ptr: *mut KernelParams) {
    let params = &mut *params_ptr;
    let t = thread_id();
    let point_ptr = params.points.as_raw_mut().add(t);
    let mut p = *point_ptr;
    let step = params.step;
    let prefixes = core::slice::from_raw_parts(params.prefixes.as_raw(), params.prefixes_len);

    for round in 0..ROUNDS {
        let mut ys = [FE_ZERO; BATCH];
        let mut zs = [FE_ZERO; BATCH];
        // prods[i] = z_0 * ... * z_i
        let mut prods = [FE_ZERO; BATCH];
        let mut acc = p.z;
        for i in 0..BATCH {
            ys[i] = p.y;
            zs[i] = p.z;
            if i > 0 {
                acc = mul(&acc, &p.z);
            }
            prods[i] = acc;
            p = p.add_precomp(&step);
        }

        let mut inv = invert(&acc);
        for i in (0..BATCH).rev() {
            let zinv: Fe = if i > 0 {
                let zinv = mul(&inv, &prods[i - 1]);
                inv = mul(&inv, &zs[i]);
                zinv
            } else {
                inv
            };
            let words = to_words(&mul(&ys[i], &zinv));
            for prefix in prefixes {
                if prefix.matches(&words) {
                    let count = &*(params.found_count.as_raw_mut() as *const AtomicU32);
                    let idx = count.fetch_add(1, Ordering::Relaxed);
                    if idx < params.found_cap {
                        *params.found.as_raw_mut().add(idx as usize) = Found {
                            thread: t as u32,
                            iter: (round * BATCH + i) as u32,
                        };
                    }
                }
            }
        }
    }

    *point_ptr = p;
}

#[panic_handler]
fn panic(_: &::core::panic::PanicInfo) -> ! {
    use core::arch::nvptx::*;

    unsafe { trap() }
}
