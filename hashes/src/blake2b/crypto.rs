// SPDX-License-Identifier: CC0-1.0
//
// BLAKE2b compression function, per RFC 7693.

#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]

use super::HashEngine;

/// `BLAKE2b` initialization vector, identical to the SHA-512 IV (RFC 7693 section 2.6).
#[rustfmt::skip]
pub(super) const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// Message word permutation schedule (RFC 7693 section 2.7).
#[rustfmt::skip]
const SIGMA: [[usize; 16]; 12] = [
    [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
    [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
    [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4],
    [ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8],
    [ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13],
    [ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9],
    [12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11],
    [13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10],
    [ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5],
    [10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0],
    [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
    [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
];

/// The G mixing function (RFC 7693 section 3.1).
#[inline]
#[rustfmt::skip]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

impl HashEngine {
    /// Compresses the buffered block into the state (RFC 7693 section 3.2).
    ///
    /// `last` sets the final-block flag `f0`. `self.t` must already account for this block.
    #[rustfmt::skip]
    pub(super) fn compress(&mut self, last: bool) {
        let mut m = [0u64; 16];
        for (word, chunk) in m.iter_mut().zip(self.buffer.chunks_exact(8)) {
            // The chunk is exactly 8 bytes, so the conversion cannot fail.
            *word = u64::from_le_bytes(chunk.try_into().expect("8 byte chunk"));
        }

        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);

        // BLAKE2b permits a 128 bit counter; the high half only matters past 2^64 bytes of
        // input, which is unreachable here, so v[13] stays at its IV value.
        v[12] ^= self.t;
        if last {
            v[14] = !v[14];
        }

        for s in &SIGMA {
            g(&mut v, 0, 4,  8, 12, m[s[0]],  m[s[1]]);
            g(&mut v, 1, 5,  9, 13, m[s[2]],  m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}
