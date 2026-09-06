// SPDX-License-Identifier: CC0-1.0

//! BLAKE2b-256.
//!
//! BLAKE2b as specified in [RFC 7693], with a 32 byte digest and no key. This is the hash function
//! used to compute the block id of an extended (164 byte) block header, so it lives here rather
//! than in `bitcoin_hashes`: that keeps the fork to a single patched crate for downstream users.
//!
//! [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693

#![allow(clippy::unreadable_literal)]

use core::cmp;

/// Length of the digest, in bytes.
pub const OUTPUT_SIZE: usize = 32;

/// Length of the compression block, in bytes.
pub const BLOCK_SIZE: usize = 128;

/// Engine computing the BLAKE2b-256 hash function.
#[derive(Clone, Debug)]
pub struct Blake2b256 {
    h: [u64; 8],
    buffer: [u8; BLOCK_SIZE],
    /// Bytes currently held in `buffer`. Ranges over `0..=BLOCK_SIZE`; a full buffer is retained
    /// rather than compressed, because it may turn out to be the final block.
    buffered: usize,
    /// The BLAKE2b byte counter: bytes compressed so far, including the block being compressed.
    t: u64,
}

impl Default for Blake2b256 {
    fn default() -> Self { Self::new() }
}

impl Blake2b256 {
    /// Constructs a new engine.
    pub const fn new() -> Self {
        let mut h = IV;
        // Parameter block, per RFC 7693 section 2.5: digest length, key length (0), fanout (1)
        // and depth (1), with every other parameter zero.
        h[0] ^= 0x0101_0000 ^ (OUTPUT_SIZE as u64);
        Blake2b256 { h, buffer: [0; BLOCK_SIZE], buffered: 0, t: 0 }
    }

    /// Adds data to the engine.
    pub fn input(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.buffered == BLOCK_SIZE {
                // We now know this block is not the last one, so it is safe to compress.
                self.t += BLOCK_SIZE as u64;
                self.compress(false);
                self.buffered = 0;
            }
            let take = cmp::min(BLOCK_SIZE - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
        }
    }

    /// Finalizes the engine, producing the digest.
    pub fn finalize(mut self) -> [u8; OUTPUT_SIZE] {
        // Unlike the SHA family, BLAKE2b has no padding byte: the final block is zero filled and
        // compressed with the "last block" flag set. A full buffer is therefore never compressed
        // eagerly by `input`, so there is always exactly one block left to process here.
        let buf_idx = self.buffered;
        self.buffer[buf_idx..].fill(0);
        self.t += buf_idx as u64;
        self.compress(true);

        let mut out = [0u8; OUTPUT_SIZE];
        for (word, chunk) in self.h.iter().take(OUTPUT_SIZE / 8).zip(out.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// BLAKE2b initialization vector, identical to the SHA-512 IV (RFC 7693 section 2.6).
#[rustfmt::skip]
const IV: [u64; 8] = [
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

impl Blake2b256 {
    /// Compresses the buffered block into the state (RFC 7693 section 3.2).
    ///
    /// `last` sets the final-block flag `f0`. `self.t` must already account for this block.
    #[rustfmt::skip]
    fn compress(&mut self, last: bool) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::String;

    /// One-shot hash, for the tests. The header pipeline feeds the engine incrementally.
    fn hash(data: &[u8]) -> [u8; OUTPUT_SIZE] {
        let mut engine = Blake2b256::new();
        engine.input(data);
        engine.finalize()
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut s = String::new();
        for b in bytes {
            write!(s, "{:02x}", b).expect("writing to a String cannot fail");
        }
        s
    }

    #[test]
    fn known_answers() {
        // Vectors computed with the reference BLAKE2b implementation (digest length 32, no key).
        let tests = [
            ("", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"),
            ("abc", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
            (
                "The quick brown fox jumps over the lazy dog",
                "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9",
            ),
        ];

        for (input, want) in tests {
            assert_eq!(hex(&hash(input.as_bytes())), want, "one shot {:?}", input);

            // Byte at a time, to exercise the deferred compression of a full buffer.
            let mut engine = Blake2b256::new();
            for byte in input.as_bytes() {
                engine.input(&[*byte]);
            }
            assert_eq!(hex(&engine.finalize()), want, "streamed {:?}", input);
        }
    }

    #[test]
    fn block_boundaries() {
        use crate::prelude::Vec;

        // A BLAKE2b block is 128 bytes and the final block must be compressed with the last-block
        // flag set, so an input that is an exact multiple of the block size is the case an eager
        // implementation gets wrong.
        let tests = [
            (127usize, "59e2f1aba240f20aa591016f5ef429990bc9c2131dcd0d30f0ffd75ed18f317d"),
            (128, "ae2aa48507885c4c950fb809b2076f959cde9f8ea6da260d9a3587df33dac450"),
            (129, "2f64744a6de0d2c0b56e64cf6e29a5aaa255010d415d51c75ccc82f73dccd865"),
            (255, "177ec7b22a982dd81ec80e0f8fd488bb347952a0876fed488191b6dede62df81"),
            (256, "eae4d3a7627549b383179dc18049964f91a6fed14c9f3fb26705eda3eeda5558"),
            (384, "9c8b40a56181f5f5ea06d1a1a48da5b7842717c921300d22b41475571842c1d1"),
        ];

        for (len, want) in tests {
            let input: Vec<u8> = core::iter::repeat(b'a').take(len).collect();
            assert_eq!(hex(&hash(&input)), want, "one shot, len {}", len);

            // Every split point must agree with the one-shot result.
            for split in [1, len / 3, len / 2, len - 1] {
                let mut engine = Blake2b256::new();
                engine.input(&input[..split]);
                engine.input(&input[split..]);
                assert_eq!(hex(&engine.finalize()), want, "split {} of len {}", split, len);
            }
        }
    }
}
