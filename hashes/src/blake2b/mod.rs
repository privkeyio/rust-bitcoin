// SPDX-License-Identifier: CC0-1.0

//! `BLAKE2b`-256 implementation.
//!
//! `BLAKE2b` as specified in [RFC 7693], with a 32 byte digest and no key. This is the hash
//! function used to compute the block id of an extended (164 byte) block header.
//!
//! [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693

#![allow(clippy::unreadable_literal)]

mod crypto;
#[cfg(test)]
mod tests;

crate::internal_macros::general_hash_type! {
    /// Output of the `BLAKE2b`-256 hash function.
    pub struct Hash([u8; 32]);

    const DISPLAY_BACKWARD: bool = false;
}

/// Length of the digest, in bytes.
pub const OUTPUT_SIZE: usize = 32;

pub(crate) const BLOCK_SIZE: usize = 128;

impl Hash {
    /// Finalizes a hash engine to produce a hash.
    #[cfg(not(hashes_fuzz))]
    pub fn from_engine(mut e: HashEngine) -> Self {
        // Unlike the SHA family, BLAKE2b has no padding byte: the final block is zero filled and
        // compressed with the "last block" flag set. A full buffer is therefore never compressed
        // eagerly by `input`, so there is always exactly one block left to process here.
        let buf_idx = e.buffered;
        e.buffer[buf_idx..].fill(0);
        e.t += buf_idx as u64;
        e.compress(true);

        let mut out = [0u8; OUTPUT_SIZE];
        for (word, chunk) in e.h.iter().take(OUTPUT_SIZE / 8).zip(out.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Self(out)
    }

    /// Finalizes a hash engine to produce a hash.
    #[cfg(hashes_fuzz)]
    pub fn from_engine(e: HashEngine) -> Self {
        let mut hash = [0u8; OUTPUT_SIZE];
        hash.copy_from_slice(&e.buffer[..OUTPUT_SIZE]);
        hash[0] ^= 0xfe; // Make this distinct from the other engines.
        Self(hash)
    }
}

/// Engine to compute the `BLAKE2b`-256 hash function.
#[derive(Debug, Clone)]
pub struct HashEngine {
    h: [u64; 8],
    bytes_hashed: u64,
    buffer: [u8; BLOCK_SIZE],
    /// Bytes currently held in `buffer`. Ranges over `0..=BLOCK_SIZE`; a full buffer is retained
    /// rather than compressed, because it may turn out to be the final block.
    buffered: usize,
    /// The `BLAKE2b` byte counter: bytes compressed so far, including the block being compressed.
    t: u64,
}

impl HashEngine {
    /// Constructs a new `BLAKE2b`-256 hash engine.
    pub const fn new() -> Self {
        let mut h = crypto::IV;
        // Parameter block, per RFC 7693 section 2.5: digest length, key length (0), fanout (1)
        // and depth (1), with every other parameter zero.
        h[0] ^= 0x0101_0000 ^ (OUTPUT_SIZE as u64);
        Self { h, bytes_hashed: 0, buffer: [0; BLOCK_SIZE], buffered: 0, t: 0 }
    }
}

impl Default for HashEngine {
    fn default() -> Self { Self::new() }
}

impl crate::HashEngine for HashEngine {
    type Hash = Hash;
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    fn n_bytes_hashed(&self) -> u64 { self.bytes_hashed }

    fn input(&mut self, mut data: &[u8]) {
        self.bytes_hashed += data.len() as u64;

        while !data.is_empty() {
            if self.buffered == BLOCK_SIZE {
                // We now know this block is not the last one, so it is safe to compress.
                self.t += BLOCK_SIZE as u64;
                self.compress(false);
                self.buffered = 0;
            }
            let take = core::cmp::min(BLOCK_SIZE - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
        }
    }

    fn finalize(self) -> Self::Hash { Hash::from_engine(self) }
}
