//! Minimal ed25519 arithmetic for incremental key search.
//!
//! Field elements use the ref10 radix-2^25.5 representation (10 signed 32-bit limbs), so every
//! limb product is a single 32x32->64 multiply, which GPUs execute natively. The mul/sq bodies
//! are generated and fully unrolled to keep everything in registers.

use rustacuda_derive::DeviceCopy;

#[derive(DeviceCopy, Clone, Copy)]
#[repr(C)]
pub struct Fe(pub [i32; 10]);

/// Extended twisted Edwards coordinates: x = X/Z, y = Y/Z, xy = T/Z.
#[derive(DeviceCopy, Clone, Copy)]
#[repr(C)]
pub struct GeP3 {
    pub x: Fe,
    pub y: Fe,
    pub z: Fe,
    pub t: Fe,
}

/// Affine point in "Niels" form, for mixed addition.
#[derive(DeviceCopy, Clone, Copy)]
#[repr(C)]
pub struct GePrecomp {
    pub yplusx: Fe,
    pub yminusx: Fe,
    pub xy2d: Fe,
}

struct GeCached {
    yplusx: Fe,
    yminusx: Fe,
    z: Fe,
    t2d: Fe,
}

pub const FE_ZERO: Fe = Fe([0; 10]);
pub const FE_ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

const BASE_X: [u8; 32] = [
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
    0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
];
const BASE_Y: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

#[inline(always)]
fn load3(s: &[u8]) -> i64 {
    s[0] as i64 | (s[1] as i64) << 8 | (s[2] as i64) << 16
}

#[inline(always)]
fn load4(s: &[u8]) -> i64 {
    load3(s) | (s[3] as i64) << 24
}

#[inline(always)]
fn carry(h: [i64; 10]) -> Fe {
    let [mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7, mut h8, mut h9] = h;
    let mut c;
    c = (h0 + (1 << 25)) >> 26; h1 += c; h0 -= c << 26;
    c = (h4 + (1 << 25)) >> 26; h5 += c; h4 -= c << 26;
    c = (h1 + (1 << 24)) >> 25; h2 += c; h1 -= c << 25;
    c = (h5 + (1 << 24)) >> 25; h6 += c; h5 -= c << 25;
    c = (h2 + (1 << 25)) >> 26; h3 += c; h2 -= c << 26;
    c = (h6 + (1 << 25)) >> 26; h7 += c; h6 -= c << 26;
    c = (h3 + (1 << 24)) >> 25; h4 += c; h3 -= c << 25;
    c = (h7 + (1 << 24)) >> 25; h8 += c; h7 -= c << 25;
    c = (h4 + (1 << 25)) >> 26; h5 += c; h4 -= c << 26;
    c = (h8 + (1 << 25)) >> 26; h9 += c; h8 -= c << 26;
    c = (h9 + (1 << 24)) >> 25; h0 += c * 19; h9 -= c << 25;
    c = (h0 + (1 << 25)) >> 26; h1 += c; h0 -= c << 26;
    Fe([
        h0 as i32, h1 as i32, h2 as i32, h3 as i32, h4 as i32,
        h5 as i32, h6 as i32, h7 as i32, h8 as i32, h9 as i32,
    ])
}

#[inline(always)]
pub fn add(f: &Fe, g: &Fe) -> Fe {
    let mut h = [0; 10];
    for i in 0..10 {
        h[i] = f.0[i] + g.0[i];
    }
    Fe(h)
}

#[inline(always)]
pub fn sub(f: &Fe, g: &Fe) -> Fe {
    let mut h = [0; 10];
    for i in 0..10 {
        h[i] = f.0[i] - g.0[i];
    }
    Fe(h)
}

pub fn from_bytes(s: &[u8; 32]) -> Fe {
    carry_bytes([
        load4(&s[0..]),
        load3(&s[4..]) << 6,
        load3(&s[7..]) << 5,
        load3(&s[10..]) << 3,
        load3(&s[13..]) << 2,
        load4(&s[16..]),
        load3(&s[20..]) << 7,
        load3(&s[23..]) << 5,
        load3(&s[26..]) << 4,
        (load3(&s[29..]) & 8388607) << 2,
    ])
}

fn carry_bytes(h: [i64; 10]) -> Fe {
    let [mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7, mut h8, mut h9] = h;
    let mut c;
    c = (h9 + (1 << 24)) >> 25; h0 += c * 19; h9 -= c << 25;
    c = (h1 + (1 << 24)) >> 25; h2 += c; h1 -= c << 25;
    c = (h3 + (1 << 24)) >> 25; h4 += c; h3 -= c << 25;
    c = (h5 + (1 << 24)) >> 25; h6 += c; h5 -= c << 25;
    c = (h7 + (1 << 24)) >> 25; h8 += c; h7 -= c << 25;
    c = (h0 + (1 << 25)) >> 26; h1 += c; h0 -= c << 26;
    c = (h2 + (1 << 25)) >> 26; h3 += c; h2 -= c << 26;
    c = (h4 + (1 << 25)) >> 26; h5 += c; h4 -= c << 26;
    c = (h6 + (1 << 25)) >> 26; h7 += c; h6 -= c << 26;
    c = (h8 + (1 << 25)) >> 26; h9 += c; h8 -= c << 26;
    Fe([
        h0 as i32, h1 as i32, h2 as i32, h3 as i32, h4 as i32,
        h5 as i32, h6 as i32, h7 as i32, h8 as i32, h9 as i32,
    ])
}

/// Canonical little-endian encoding as eight 32-bit words.
#[inline(always)]
pub fn to_words(f: &Fe) -> [u32; 8] {
    let [mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7, mut h8, mut h9] = f.0;
    let mut q = (19 * h9 + (1 << 24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    q = (h9 + q) >> 25;
    h0 += 19 * q;
    let mut c;
    c = h0 >> 26; h1 += c; h0 -= c << 26;
    c = h1 >> 25; h2 += c; h1 -= c << 25;
    c = h2 >> 26; h3 += c; h2 -= c << 26;
    c = h3 >> 25; h4 += c; h3 -= c << 25;
    c = h4 >> 26; h5 += c; h4 -= c << 26;
    c = h5 >> 25; h6 += c; h5 -= c << 25;
    c = h6 >> 26; h7 += c; h6 -= c << 26;
    c = h7 >> 25; h8 += c; h7 -= c << 25;
    c = h8 >> 26; h9 += c; h8 -= c << 26;
    c = h9 >> 25; h9 -= c << 25;
    let [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9] = [
        h0 as u32, h1 as u32, h2 as u32, h3 as u32, h4 as u32,
        h5 as u32, h6 as u32, h7 as u32, h8 as u32, h9 as u32,
    ];
    [
        h0 | h1 << 26,
        h1 >> 6 | h2 << 19,
        h2 >> 13 | h3 << 13,
        h3 >> 19 | h4 << 6,
        h5 | h6 << 25,
        h6 >> 7 | h7 << 19,
        h7 >> 13 | h8 << 12,
        h8 >> 20 | h9 << 6,
    ]
}

pub fn to_bytes(f: &Fe) -> [u8; 32] {
    let mut s = [0; 32];
    for (i, w) in to_words(f).iter().enumerate() {
        for j in 0..4 {
            s[4 * i + j] = (w >> (8 * j)) as u8;
        }
    }
    s
}

#[inline(always)]
fn sq_n(f: &Fe, n: usize) -> Fe {
    let mut r = sq(f);
    for _ in 1..n {
        r = sq(&r);
    }
    r
}

/// z^(p-2), the ref10 addition chain.
#[inline(always)]
pub fn invert(z: &Fe) -> Fe {
    let t0 = sq(z);
    let t1 = sq_n(&t0, 2);
    let t1 = mul(z, &t1);
    let t0 = mul(&t0, &t1);
    let t2 = sq(&t0);
    let t1 = mul(&t1, &t2);
    let t2 = sq_n(&t1, 5);
    let t1 = mul(&t2, &t1);
    let t2 = sq_n(&t1, 10);
    let t2 = mul(&t2, &t1);
    let t3 = sq_n(&t2, 20);
    let t2 = mul(&t3, &t2);
    let t2 = sq_n(&t2, 10);
    let t1 = mul(&t2, &t1);
    let t2 = sq_n(&t1, 50);
    let t2 = mul(&t2, &t1);
    let t3 = sq_n(&t2, 100);
    let t2 = mul(&t3, &t2);
    let t2 = sq_n(&t2, 50);
    let t1 = mul(&t2, &t1);
    let t1 = sq_n(&t1, 5);
    mul(&t1, &t0)
}

/// d = -121665/121666
fn curve_d() -> Fe {
    let num = sub(&FE_ZERO, &Fe([121665, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    mul(&num, &invert(&Fe([121666, 0, 0, 0, 0, 0, 0, 0, 0, 0])))
}

impl GeP3 {
    pub fn identity() -> GeP3 {
        GeP3 {
            x: FE_ZERO,
            y: FE_ONE,
            z: FE_ONE,
            t: FE_ZERO,
        }
    }

    pub fn base() -> GeP3 {
        let x = from_bytes(&BASE_X);
        let y = from_bytes(&BASE_Y);
        GeP3 {
            x,
            y,
            z: FE_ONE,
            t: mul(&x, &y),
        }
    }

    fn to_cached(&self, d2: &Fe) -> GeCached {
        GeCached {
            yplusx: add(&self.y, &self.x),
            yminusx: sub(&self.y, &self.x),
            z: self.z,
            t2d: mul(&self.t, d2),
        }
    }

    /// Unified extended addition (also valid for doubling, ed25519's formula is complete).
    fn add_cached(&self, q: &GeCached) -> GeP3 {
        let a = mul(&add(&self.y, &self.x), &q.yplusx);
        let b = mul(&sub(&self.y, &self.x), &q.yminusx);
        let c = mul(&q.t2d, &self.t);
        let zz = mul(&self.z, &q.z);
        let d = add(&zz, &zz);
        p1p1_to_p3(&sub(&a, &b), &add(&a, &b), &add(&d, &c), &sub(&d, &c))
    }

    /// Mixed addition with an affine point: 7 multiplications.
    #[inline(always)]
    pub fn add_precomp(&self, q: &GePrecomp) -> GeP3 {
        let a = mul(&add(&self.y, &self.x), &q.yplusx);
        let b = mul(&sub(&self.y, &self.x), &q.yminusx);
        let c = mul(&q.xy2d, &self.t);
        let d = add(&self.z, &self.z);
        p1p1_to_p3(&sub(&a, &b), &add(&a, &b), &add(&d, &c), &sub(&d, &c))
    }

    /// Variable-time scalar multiplication (the scalar is never secret on the search device:
    /// it's derived from a random base the host knows anyway).
    pub fn scalarmult(&self, scalar: &[u8; 32]) -> GeP3 {
        let d = curve_d();
        let d2 = add(&d, &d);
        let q = self.to_cached(&d2);
        let mut r = GeP3::identity();
        for i in (0..256).rev() {
            r = r.add_cached(&r.to_cached(&d2));
            if (scalar[i >> 3] >> (i & 7)) & 1 == 1 {
                r = r.add_cached(&q);
            }
        }
        r
    }

    pub fn to_precomp(&self) -> GePrecomp {
        let d = curve_d();
        let d2 = add(&d, &d);
        let zinv = invert(&self.z);
        let x = mul(&self.x, &zinv);
        let y = mul(&self.y, &zinv);
        GePrecomp {
            yplusx: add(&y, &x),
            yminusx: sub(&y, &x),
            xy2d: mul(&mul(&x, &y), &d2),
        }
    }

    /// Standard 32-byte point encoding: y with the sign of x in the top bit.
    pub fn to_bytes(&self) -> [u8; 32] {
        let zinv = invert(&self.z);
        let x = mul(&self.x, &zinv);
        let y = mul(&self.y, &zinv);
        let mut s = to_bytes(&y);
        s[31] ^= (to_bytes(&x)[0] & 1) << 7;
        s
    }
}

#[inline(always)]
fn p1p1_to_p3(e: &Fe, h: &Fe, g: &Fe, f: &Fe) -> GeP3 {
    GeP3 {
        x: mul(e, f),
        y: mul(h, g),
        z: mul(g, f),
        t: mul(e, h),
    }
}

/// Adds `lo + hi * 2^64` to a little-endian 256-bit number.
pub fn add_scalar(base: &[u8; 32], lo: u64, hi: u64) -> [u8; 32] {
    let mut res = [0; 32];
    let mut carry = 0u64;
    for i in 0..4 {
        let mut limb = 0u64;
        for j in 0..8 {
            limb |= (base[8 * i + j] as u64) << (8 * j);
        }
        let add = match i {
            0 => lo,
            1 => hi,
            _ => 0,
        };
        let (s1, o1) = limb.overflowing_add(add);
        let (s2, o2) = s1.overflowing_add(carry);
        carry = (o1 | o2) as u64;
        for j in 0..8 {
            res[8 * i + j] = (s2 >> (8 * j)) as u8;
        }
    }
    res
}

#[inline(always)]
pub fn mul(f: &Fe, g: &Fe) -> Fe {
    let [f0, f1, f2, f3, f4, f5, f6, f7, f8, f9] = f.0;
    let [g0, g1, g2, g3, g4, g5, g6, g7, g8, g9] = g.0;
    let g1_19 = 19 * g1;
    let g2_19 = 19 * g2;
    let g3_19 = 19 * g3;
    let g4_19 = 19 * g4;
    let g5_19 = 19 * g5;
    let g6_19 = 19 * g6;
    let g7_19 = 19 * g7;
    let g8_19 = 19 * g8;
    let g9_19 = 19 * g9;
    let f1_2 = 2 * f1;
    let f3_2 = 2 * f3;
    let f5_2 = 2 * f5;
    let f7_2 = 2 * f7;
    let f9_2 = 2 * f9;
    carry([
        (f0 as i64) * (g0 as i64) + (f1_2 as i64) * (g9_19 as i64) + (f2 as i64) * (g8_19 as i64) + (f3_2 as i64) * (g7_19 as i64) + (f4 as i64) * (g6_19 as i64) + (f5_2 as i64) * (g5_19 as i64) + (f6 as i64) * (g4_19 as i64) + (f7_2 as i64) * (g3_19 as i64) + (f8 as i64) * (g2_19 as i64) + (f9_2 as i64) * (g1_19 as i64),
        (f0 as i64) * (g1 as i64) + (f1 as i64) * (g0 as i64) + (f2 as i64) * (g9_19 as i64) + (f3 as i64) * (g8_19 as i64) + (f4 as i64) * (g7_19 as i64) + (f5 as i64) * (g6_19 as i64) + (f6 as i64) * (g5_19 as i64) + (f7 as i64) * (g4_19 as i64) + (f8 as i64) * (g3_19 as i64) + (f9 as i64) * (g2_19 as i64),
        (f0 as i64) * (g2 as i64) + (f1_2 as i64) * (g1 as i64) + (f2 as i64) * (g0 as i64) + (f3_2 as i64) * (g9_19 as i64) + (f4 as i64) * (g8_19 as i64) + (f5_2 as i64) * (g7_19 as i64) + (f6 as i64) * (g6_19 as i64) + (f7_2 as i64) * (g5_19 as i64) + (f8 as i64) * (g4_19 as i64) + (f9_2 as i64) * (g3_19 as i64),
        (f0 as i64) * (g3 as i64) + (f1 as i64) * (g2 as i64) + (f2 as i64) * (g1 as i64) + (f3 as i64) * (g0 as i64) + (f4 as i64) * (g9_19 as i64) + (f5 as i64) * (g8_19 as i64) + (f6 as i64) * (g7_19 as i64) + (f7 as i64) * (g6_19 as i64) + (f8 as i64) * (g5_19 as i64) + (f9 as i64) * (g4_19 as i64),
        (f0 as i64) * (g4 as i64) + (f1_2 as i64) * (g3 as i64) + (f2 as i64) * (g2 as i64) + (f3_2 as i64) * (g1 as i64) + (f4 as i64) * (g0 as i64) + (f5_2 as i64) * (g9_19 as i64) + (f6 as i64) * (g8_19 as i64) + (f7_2 as i64) * (g7_19 as i64) + (f8 as i64) * (g6_19 as i64) + (f9_2 as i64) * (g5_19 as i64),
        (f0 as i64) * (g5 as i64) + (f1 as i64) * (g4 as i64) + (f2 as i64) * (g3 as i64) + (f3 as i64) * (g2 as i64) + (f4 as i64) * (g1 as i64) + (f5 as i64) * (g0 as i64) + (f6 as i64) * (g9_19 as i64) + (f7 as i64) * (g8_19 as i64) + (f8 as i64) * (g7_19 as i64) + (f9 as i64) * (g6_19 as i64),
        (f0 as i64) * (g6 as i64) + (f1_2 as i64) * (g5 as i64) + (f2 as i64) * (g4 as i64) + (f3_2 as i64) * (g3 as i64) + (f4 as i64) * (g2 as i64) + (f5_2 as i64) * (g1 as i64) + (f6 as i64) * (g0 as i64) + (f7_2 as i64) * (g9_19 as i64) + (f8 as i64) * (g8_19 as i64) + (f9_2 as i64) * (g7_19 as i64),
        (f0 as i64) * (g7 as i64) + (f1 as i64) * (g6 as i64) + (f2 as i64) * (g5 as i64) + (f3 as i64) * (g4 as i64) + (f4 as i64) * (g3 as i64) + (f5 as i64) * (g2 as i64) + (f6 as i64) * (g1 as i64) + (f7 as i64) * (g0 as i64) + (f8 as i64) * (g9_19 as i64) + (f9 as i64) * (g8_19 as i64),
        (f0 as i64) * (g8 as i64) + (f1_2 as i64) * (g7 as i64) + (f2 as i64) * (g6 as i64) + (f3_2 as i64) * (g5 as i64) + (f4 as i64) * (g4 as i64) + (f5_2 as i64) * (g3 as i64) + (f6 as i64) * (g2 as i64) + (f7_2 as i64) * (g1 as i64) + (f8 as i64) * (g0 as i64) + (f9_2 as i64) * (g9_19 as i64),
        (f0 as i64) * (g9 as i64) + (f1 as i64) * (g8 as i64) + (f2 as i64) * (g7 as i64) + (f3 as i64) * (g6 as i64) + (f4 as i64) * (g5 as i64) + (f5 as i64) * (g4 as i64) + (f6 as i64) * (g3 as i64) + (f7 as i64) * (g2 as i64) + (f8 as i64) * (g1 as i64) + (f9 as i64) * (g0 as i64),
    ])
}

#[inline(always)]
pub fn sq(f: &Fe) -> Fe {
    let [f0, f1, f2, f3, f4, f5, f6, f7, f8, f9] = f.0;
    let f0_2 = 2 * f0;
    let f1_2 = 2 * f1;
    let f1_4 = 4 * f1;
    let f2_2 = 2 * f2;
    let f3_2 = 2 * f3;
    let f3_4 = 4 * f3;
    let f4_2 = 2 * f4;
    let f5_2 = 2 * f5;
    let f5_4 = 4 * f5;
    let f5_19 = 19 * f5;
    let f6_2 = 2 * f6;
    let f6_19 = 19 * f6;
    let f7_2 = 2 * f7;
    let f7_4 = 4 * f7;
    let f7_19 = 19 * f7;
    let f8_2 = 2 * f8;
    let f8_19 = 19 * f8;
    let f9_2 = 2 * f9;
    let f9_19 = 19 * f9;
    carry([
        (f0 as i64) * (f0 as i64) + (f1_4 as i64) * (f9_19 as i64) + (f2_2 as i64) * (f8_19 as i64) + (f3_4 as i64) * (f7_19 as i64) + (f4_2 as i64) * (f6_19 as i64) + (f5_2 as i64) * (f5_19 as i64),
        (f0_2 as i64) * (f1 as i64) + (f2_2 as i64) * (f9_19 as i64) + (f3_2 as i64) * (f8_19 as i64) + (f4_2 as i64) * (f7_19 as i64) + (f5_2 as i64) * (f6_19 as i64),
        (f0_2 as i64) * (f2 as i64) + (f1_2 as i64) * (f1 as i64) + (f3_4 as i64) * (f9_19 as i64) + (f4_2 as i64) * (f8_19 as i64) + (f5_4 as i64) * (f7_19 as i64) + (f6 as i64) * (f6_19 as i64),
        (f0_2 as i64) * (f3 as i64) + (f1_2 as i64) * (f2 as i64) + (f4_2 as i64) * (f9_19 as i64) + (f5_2 as i64) * (f8_19 as i64) + (f6_2 as i64) * (f7_19 as i64),
        (f0_2 as i64) * (f4 as i64) + (f1_4 as i64) * (f3 as i64) + (f2 as i64) * (f2 as i64) + (f5_4 as i64) * (f9_19 as i64) + (f6_2 as i64) * (f8_19 as i64) + (f7_2 as i64) * (f7_19 as i64),
        (f0_2 as i64) * (f5 as i64) + (f1_2 as i64) * (f4 as i64) + (f2_2 as i64) * (f3 as i64) + (f6_2 as i64) * (f9_19 as i64) + (f7_2 as i64) * (f8_19 as i64),
        (f0_2 as i64) * (f6 as i64) + (f1_4 as i64) * (f5 as i64) + (f2_2 as i64) * (f4 as i64) + (f3_2 as i64) * (f3 as i64) + (f7_4 as i64) * (f9_19 as i64) + (f8 as i64) * (f8_19 as i64),
        (f0_2 as i64) * (f7 as i64) + (f1_2 as i64) * (f6 as i64) + (f2_2 as i64) * (f5 as i64) + (f3_2 as i64) * (f4 as i64) + (f8_2 as i64) * (f9_19 as i64),
        (f0_2 as i64) * (f8 as i64) + (f1_4 as i64) * (f7 as i64) + (f2_2 as i64) * (f6 as i64) + (f3_4 as i64) * (f5 as i64) + (f4 as i64) * (f4 as i64) + (f9_2 as i64) * (f9_19 as i64),
        (f0_2 as i64) * (f9 as i64) + (f1_2 as i64) * (f8 as i64) + (f2_2 as i64) * (f7 as i64) + (f3_2 as i64) * (f6 as i64) + (f4_2 as i64) * (f5 as i64),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use rand::RngCore;

    fn random_clamped() -> [u8; 32] {
        let mut s = [0; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s[0] &= 248;
        s[31] = (s[31] & 31) | 64;
        s
    }

    fn reference(s: &[u8; 32]) -> [u8; 32] {
        (&Scalar::from_bits(*s) * &ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes()
    }

    #[test]
    fn field_roundtrip_and_invert() {
        for _ in 0..100 {
            let mut b = [0; 32];
            rand::thread_rng().fill_bytes(&mut b);
            b[31] &= 127;
            let f = from_bytes(&b);
            let one = mul(&f, &invert(&f));
            assert_eq!(to_bytes(&one), to_bytes(&FE_ONE));
            // values >= p must come out reduced
            if b < [0xff; 32] {
                let f2 = mul(&f, &FE_ONE);
                assert_eq!(to_bytes(&f2), to_bytes(&f));
            }
        }
        let mut p = [0xff; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_eq!(to_bytes(&from_bytes(&p)), [0; 32]);
    }

    #[test]
    fn scalarmult_matches_dalek() {
        for _ in 0..50 {
            let s = random_clamped();
            assert_eq!(GeP3::base().scalarmult(&s).to_bytes(), reference(&s));
        }
    }

    #[test]
    fn stepping_matches_dalek() {
        let mut eight = [0; 32];
        eight[0] = 8;
        let step = GeP3::base().scalarmult(&eight).to_precomp();
        let base = random_clamped();
        let mut p = GeP3::base().scalarmult(&base);
        for k in 0..300u64 {
            let s = add_scalar(&base, 8 * k, 0);
            assert_eq!(p.to_bytes(), reference(&s), "step {}", k);
            // y-only encoding, as the kernel compares it
            let zinv = invert(&p.z);
            let y = to_bytes(&mul(&p.y, &zinv));
            assert_eq!(y[..31], reference(&s)[..31]);
            p = p.add_precomp(&step);
        }
    }
}
