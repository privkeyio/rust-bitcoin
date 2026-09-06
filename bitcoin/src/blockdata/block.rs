// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use actual_arbitrary::{self as arbitrary, Arbitrary, Unstructured};
use hashes::{sha256d, Hash, HashEngine};
use io::{Read, Write};

use super::Weight;
use crate::blockdata::script;
use crate::blockdata::transaction::{Transaction, Txid, Wtxid};
use crate::consensus::{encode, Decodable, Encodable, Params};
use crate::internal_macros::{impl_consensus_encoding, impl_hashencode};
use crate::pow::{CompactTarget, Target, Work};
use crate::prelude::*;
use crate::{merkle_tree, VarInt};

// Consists of OP_RETURN, OP_PUSHBYTES_36, and four "witness header" bytes.
const WITNESS_COMMITMENT_MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

hashes::hash_newtype! {
    /// A bitcoin block hash.
    pub struct BlockHash(sha256d::Hash);
    /// A hash of the Merkle tree branch or root for transactions.
    pub struct TxMerkleNode(sha256d::Hash);
    /// A hash corresponding to the Merkle tree root for witness data.
    pub struct WitnessMerkleNode(sha256d::Hash);
    /// A hash corresponding to the witness structure commitment in the coinbase transaction.
    pub struct WitnessCommitment(sha256d::Hash);
}
impl_hashencode!(BlockHash);
impl_hashencode!(TxMerkleNode);
impl_hashencode!(WitnessMerkleNode);

impl From<Txid> for TxMerkleNode {
    fn from(txid: Txid) -> Self { Self::from_byte_array(txid.to_byte_array()) }
}

impl From<Wtxid> for WitnessMerkleNode {
    fn from(wtxid: Wtxid) -> Self { Self::from_byte_array(wtxid.to_byte_array()) }
}

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] committing to all transactions in the block.
///
/// [merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// ### Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
    /// The extra fields carried by an extended header, if this is one.
    ///
    /// `None` for the historical 80 byte form. See [`HeaderV2`].
    pub v2: Option<HeaderV2>,
}

/// The extra fields carried by an extended (164 byte) block header.
///
/// After the BLAKE2b proof-of-work hardfork a header may carry 84 bytes beyond the historical 80.
/// The extended form is announced by bit 31 of the header's version word, so a header is
/// self-describing and nothing keys off the block height. Below the activation height headers stay
/// 80 bytes and byte identical to what they always were.
///
/// The blob fields are held in wire (little endian) byte order, the same way [`BlockHash`] holds
/// its bytes.
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct HeaderV2 {
    /// Second nonce, ground directly by the mining hardware.
    pub nonce2: u32,
    /// Third nonce, ground directly by the mining hardware.
    pub nonce3: u32,
    /// Stratum v1 extranonce.
    pub extranonce: [u8; 16],
    /// Amount added to the time on the wire to obtain [`Header::time`].
    ///
    /// Only applied when [`HeaderV2::USE_TIME_OFFSET`] is set in [`HeaderV2::flags`], but the
    /// field is always present on the wire and always committed to by the block hash.
    pub time_offset: u32,
    /// Number of transactions in the block.
    pub txcount: u16,
    /// Header flags. The low two bits select the ASIC layout profile used by the block hash.
    pub flags: u8,
    /// Number of leading bits of the XOR mask to clear.
    pub xor_key_mask_clear_bits: u8,
    /// Proof-of-work XOR key.
    pub xor_key: [u8; 16],
    /// Height of this block.
    pub height: i32,
    /// Right hand side of the merge-mining hook.
    pub mm_rhs: [u8; 32],
}

impl HeaderV2 {
    /// Bit in [`HeaderV2::flags`] that makes [`HeaderV2::time_offset`] apply to the wire time.
    pub const USE_TIME_OFFSET: u8 = 4;

    /// Bits of [`HeaderV2::flags`] reserved for a future hardfork.
    ///
    /// These serve the same purpose for a future format change that version bit 31 served for
    /// this one, so a header that sets either of them must be rejected rather than hashed with
    /// today's algorithm. See [`Header::validate_form`].
    pub const RESERVED_FLAGS: u8 = 0xc0;

    /// The number of bytes an extended header adds to [`Header::SIZE`].
    // (nonce2, nonce3, extranonce, time_offset, txcount, flags, xor_key_mask_clear_bits, xor_key,
    // height, mm_rhs)
    pub const EXTRA_SIZE: usize = 4 + 4 + 16 + 4 + 2 + 1 + 1 + 16 + 4 + 32; // 84

    /// Returns the ASIC layout profile, which selects how the second BLAKE2b input is laid out.
    pub const fn asic_profile(&self) -> u8 { self.flags & 3 }

    fn to_extra_bytes(self) -> [u8; Self::EXTRA_SIZE] {
        let mut out = [0u8; Self::EXTRA_SIZE];
        out[0..4].copy_from_slice(&self.nonce2.to_le_bytes());
        out[4..8].copy_from_slice(&self.nonce3.to_le_bytes());
        out[8..24].copy_from_slice(&self.extranonce);
        out[24..28].copy_from_slice(&self.time_offset.to_le_bytes());
        out[28..30].copy_from_slice(&self.txcount.to_le_bytes());
        out[30] = self.flags;
        out[31] = self.xor_key_mask_clear_bits;
        out[32..48].copy_from_slice(&self.xor_key);
        out[48..52].copy_from_slice(&self.height.to_le_bytes());
        out[52..84].copy_from_slice(&self.mm_rhs);
        out
    }

    fn from_extra_bytes(buf: &[u8; Self::EXTRA_SIZE]) -> Self {
        // Every slice below is a fixed sub-range of a fixed size array, so no conversion can fail.
        HeaderV2 {
            nonce2: u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes")),
            nonce3: u32::from_le_bytes(buf[4..8].try_into().expect("4 bytes")),
            extranonce: buf[8..24].try_into().expect("16 bytes"),
            time_offset: u32::from_le_bytes(buf[24..28].try_into().expect("4 bytes")),
            txcount: u16::from_le_bytes(buf[28..30].try_into().expect("2 bytes")),
            flags: buf[30],
            xor_key_mask_clear_bits: buf[31],
            xor_key: buf[32..48].try_into().expect("16 bytes"),
            height: i32::from_le_bytes(buf[48..52].try_into().expect("4 bytes")),
            mm_rhs: buf[52..84].try_into().expect("32 bytes"),
        }
    }
}

impl Encodable for Header {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.complete_version().consensus_encode(w)?;
        len += self.prev_blockhash.consensus_encode(w)?;
        len += self.merkle_root.consensus_encode(w)?;
        len += self.time_on_wire().consensus_encode(w)?;
        len += self.bits.consensus_encode(w)?;
        len += self.nonce.consensus_encode(w)?;
        if let Some(v2) = self.v2 {
            let extra = v2.to_extra_bytes();
            w.write_all(&extra)?;
            len += extra.len();
        }
        Ok(len)
    }
}

impl Decodable for Header {
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Header, encode::Error> {
        // The wire form is self-describing: bit 31 of the version word says whether the extended
        // fields follow, so the length is only known after the first four bytes.
        let complete_version = u32::consensus_decode_from_finite_reader(r)?;
        let prev_blockhash = BlockHash::consensus_decode_from_finite_reader(r)?;
        let merkle_root = TxMerkleNode::consensus_decode_from_finite_reader(r)?;
        let wire_time = u32::consensus_decode_from_finite_reader(r)?;
        let bits = CompactTarget::consensus_decode_from_finite_reader(r)?;
        let nonce = u32::consensus_decode_from_finite_reader(r)?;

        let v2 = if complete_version & Header::V2_VERSION_FLAG != 0 {
            let mut extra = [0u8; HeaderV2::EXTRA_SIZE];
            r.read_exact(&mut extra)?;
            Some(HeaderV2::from_extra_bytes(&extra))
        } else {
            None
        };

        // Past the hardfork bit 31 announces the header form rather than belonging to the
        // version, and `Version::from_consensus` masks it off.
        // The cast reinterprets the bits; `Version` is signed only for historical reasons.
        let version = Version::from_consensus(complete_version as i32);

        // `time` on the wire is the effective time less the offset, when the offset is in use.
        let time = match v2 {
            Some(v2) if v2.flags & HeaderV2::USE_TIME_OFFSET != 0 =>
                wire_time.wrapping_add(v2.time_offset),
            _ => wire_time,
        };

        Ok(Header { version, prev_blockhash, merkle_root, time, bits, nonce, v2 })
    }

    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Header, encode::Error> {
        let mut r = r.take(encode::MAX_VEC_SIZE as u64);
        Self::consensus_decode_from_finite_reader(&mut r)
    }
}

impl Header {
    /// The number of bytes that the block header contributes to the size of a block.
    // Serialized length of fields (version, prev_blockhash, merkle_root, time, bits, nonce)
    pub const SIZE: usize = 4 + 32 + 32 + 4 + 4 + 4; // 80

    /// The number of bytes that an extended block header contributes to the size of a block.
    pub const V2_SIZE: usize = Self::SIZE + HeaderV2::EXTRA_SIZE; // 164

    /// Bit of the version word that announces the extended header form.
    pub const V2_VERSION_FLAG: u32 = 0x8000_0000;

    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        match self.v2 {
            None => {
                let mut engine = BlockHash::engine();
                self.consensus_encode(&mut engine).expect("engines don't error");
                BlockHash::from_engine(engine)
            }
            Some(ref v2) => self.block_hash_v2(v2),
        }
    }

    /// Returns the serialized size of this header, in bytes.
    ///
    /// Either [`Header::SIZE`] or [`Header::V2_SIZE`].
    pub const fn size(&self) -> usize {
        match self.v2 {
            None => Self::SIZE,
            Some(_) => Self::V2_SIZE,
        }
    }

    /// Returns the version word as it appears on the wire.
    ///
    /// This is [`Header::version`] with [`Header::V2_VERSION_FLAG`] set if and only if this is an
    /// extended header. `Version` never carries bit 31 itself.
    pub const fn complete_version(&self) -> u32 {
        // The cast reinterprets the bits; `Version` is signed only for historical reasons.
        let base = self.version.0 as u32 & !Self::V2_VERSION_FLAG;
        match self.v2 {
            None => base,
            Some(_) => base | Self::V2_VERSION_FLAG,
        }
    }

    /// Returns the timestamp as it appears on the wire.
    ///
    /// [`Header::time`] holds the effective block time. An extended header may carry part of it in
    /// [`HeaderV2::time_offset`] instead, in which case the wire form holds the difference.
    pub const fn time_on_wire(&self) -> u32 {
        match self.v2 {
            Some(v2) if v2.flags & HeaderV2::USE_TIME_OFFSET != 0 =>
                self.time.wrapping_sub(v2.time_offset),
            _ => self.time,
        }
    }

    /// Computes the BLAKE2b block id of an extended header.
    ///
    /// Follows Bitcoin Knots' `CBlockHeader::GetHash` for the extended form: a chain of BIP-340
    /// style tagged SHA256 hashes feeding two BLAKE2b passes, the second laid out according to the
    /// ASIC profile in the header flags, then masked and byte reversed.
    fn block_hash_v2(&self, v2: &HeaderV2) -> BlockHash {
        use hashes::{sha256, Hash as _, HashEngine as _};

        use crate::crypto::blake2b::Blake2b256;

        /// BIP-340 style tagged hash engine, seeded with `sha256(tag)` twice.
        fn tagged(tag: &[u8]) -> sha256::HashEngine {
            let tag_hash = sha256::Hash::hash(tag);
            let mut engine = sha256::Hash::engine();
            engine.input(tag_hash.as_byte_array());
            engine.input(tag_hash.as_byte_array());
            engine
        }

        const ZEROS: [u8; 16] = [0; 16];

        // The pooling miner only learns the XOR key once it finds a block, so the header commits
        // to the key's hash rather than the key.
        let mut engine = tagged(b"Bitcoin block hash PoW XOR key");
        engine.input(&v2.xor_key);
        let xor_key_hash = sha256::Hash::from_engine(engine);

        let mut xor_key_mask = [0u8; 32];
        if v2.xor_key != ZEROS {
            let mut engine = tagged(b"Bitcoin block hash PoW XOR mask");
            engine.input(&v2.xor_key);
            xor_key_mask = sha256::Hash::from_engine(engine).to_byte_array();
            // `xor_key_mask_clear_bits` is a `u8`, so this is at most 31 and stays in bounds.
            let clear_bytes = usize::from(v2.xor_key_mask_clear_bits / 8);
            xor_key_mask[..clear_bytes].fill(0);
            xor_key_mask[clear_bytes] &= 0xff_u8 >> (v2.xor_key_mask_clear_bits % 8);
        }

        let mut prev_blockhash = self.prev_blockhash.to_byte_array();
        prev_blockhash.reverse();

        let mut engine = tagged(b"Bitcoin prevblock header, hashed");
        engine.input(&prev_blockhash);
        let mut prev_blockhash_hidden = sha256::Hash::from_engine(engine).to_byte_array();

        // These fields are invisible to the mining machine, so the hasher cannot brick itself at
        // some future block version, time or difficulty.
        let mut h1 = tagged(b"Bitcoin block header 1");
        h1.input(&self.complete_version().to_le_bytes());
        h1.input(&prev_blockhash);
        h1.input(&v2.height.to_le_bytes());
        h1.input(&self.merkle_root.to_byte_array());
        h1.input(&self.time_on_wire().to_le_bytes());
        h1.input(&[0]); // Reserved for an extended 40 bit time.
        h1.input(&self.bits.to_consensus().to_le_bytes());
        h1.input(&u32::from(v2.txcount).to_le_bytes());
        h1.input(&[v2.flags, v2.xor_key_mask_clear_bits]);
        h1.input(xor_key_hash.as_byte_array());

        let mut h2 = tagged(b"Merge-mining hook");
        h2.input(sha256::Hash::from_engine(h1).as_byte_array());
        h2.input(&ZEROS);
        h2.input(&ZEROS);
        h2.input(&v2.mm_rhs);
        let h2_hash = sha256::Hash::from_engine(h2).to_byte_array();

        // These fields get sent to mining machines over Stratum v1.
        let mut engine = Blake2b256::new();
        engine.input(&0_u32.to_le_bytes()); // Sv1 "coinb1", less the implied first byte.
        engine.input(&h2_hash);
        engine.input(&v2.extranonce);
        let hash = engine.finalize();

        // Presumably the actual mining ASIC hardware sees these.
        //
        // Profiles 0, 2 and 3 end with the same five fields. Profile 1 deliberately swaps
        // `nonce3` and `time_offset`, so it is written out separately below.
        let tail = |engine: &mut Blake2b256| {
            engine.input(&self.nonce.to_le_bytes());
            engine.input(&v2.nonce2.to_le_bytes());
            engine.input(&v2.time_offset.to_le_bytes());
            engine.input(&v2.nonce3.to_le_bytes());
            engine.input(&hash);
        };

        let mut engine = Blake2b256::new();
        match v2.asic_profile() {
            profile @ (2 | 3) => {
                if profile == 3 {
                    engine.input(&ZEROS);
                    engine.input(&ZEROS);
                }
                engine.input(&ZEROS);
                engine.input(&ZEROS);
                engine.input(&ZEROS);
                engine.input(&h2_hash);
                tail(&mut engine);
            }
            0 => {
                prev_blockhash_hidden[..6].fill(0);
                engine.input(&prev_blockhash_hidden);
                tail(&mut engine);
            }
            // The profile is `flags & 3`, so 1 is the only value left.
            _ => {
                engine.input(&self.nonce.to_le_bytes());
                engine.input(&v2.nonce2.to_le_bytes());
                engine.input(&v2.nonce3.to_le_bytes());
                engine.input(&v2.time_offset.to_le_bytes());
                engine.input(&hash);
                engine.input(&h2_hash);
            }
        }
        let hash = engine.finalize();

        // Knots writes the masked digest into the block id back to front. That is exactly the
        // order `BlockHash` stores its bytes in, so the displayed id reads the digest forwards.
        let mut out = [0u8; 32];
        for (i, byte) in hash.iter().enumerate() {
            out[31 - i] = byte ^ xor_key_mask[i];
        }
        BlockHash::from_byte_array(out)
    }

    /// Checks the rules the BLAKE2b hardfork places on the header form.
    ///
    /// Implements the part of Bitcoin Knots' `CheckBlockHeader` that needs nothing but the header
    /// itself: an extended header may not claim a height below the activation, and the top two
    /// flag bits are reserved for a future hardfork.
    ///
    /// This is what a header syncing client can check on its own. The remaining rules compare the
    /// header against the height the block actually sits at, so they need chain context; see
    /// [`Header::validate_form_at_height`].
    ///
    /// # Errors
    ///
    /// [`InvalidHeaderFormError`] if the header breaks either rule.
    pub fn validate_form(&self, params: impl AsRef<Params>) -> Result<(), InvalidHeaderFormError> {
        let params = params.as_ref();
        let v2 = match self.v2 {
            Some(v2) => v2,
            None => return Ok(()),
        };

        // if (!consensusParams.IsBlake2bHeight(block.m_height)) -> bad-version-sha256d
        let activation =
            params.blake2b_height.ok_or(InvalidHeaderFormError::ExtendedHeaderNotScheduled)?;
        if v2.height < 0 || v2.height.unsigned_abs() < activation {
            return Err(InvalidHeaderFormError::ExtendedHeaderTooEarly);
        }

        // if (block.m_flags & 0xc0) -> bad-flags-highbits
        if v2.flags & HeaderV2::RESERVED_FLAGS != 0 {
            return Err(InvalidHeaderFormError::ReservedFlags);
        }

        Ok(())
    }

    /// Checks the header form against the height the block actually sits at.
    ///
    /// Implements Knots' `bad-header-height` and `bad-version-blake2b` on top of
    /// [`Header::validate_form`]: an extended header must agree with its real height, and from
    /// the activation height on a legacy header is no longer accepted.
    ///
    /// `height` must come from the chain, not from the header, since agreeing with itself is
    /// exactly what this checks.
    ///
    /// # Errors
    ///
    /// [`InvalidHeaderFormError`] if the header breaks any of the rules.
    pub fn validate_form_at_height(
        &self,
        height: u32,
        params: impl AsRef<Params>,
    ) -> Result<(), InvalidHeaderFormError> {
        let params = params.as_ref();
        self.validate_form(params)?;

        match self.v2 {
            // if (block.m_height != height) -> bad-header-height
            Some(v2) =>
                if v2.height < 0 || v2.height.unsigned_abs() != height {
                    return Err(InvalidHeaderFormError::HeightMismatch);
                },
            // if (consensusParams.IsBlake2bHeight(height)) -> bad-version-blake2b
            None =>
                if params.blake2b_height.map_or(false, |a| height >= a) {
                    return Err(InvalidHeaderFormError::LegacyHeaderTooLate);
                },
        }

        Ok(())
    }

    /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
    pub fn target(&self) -> Target { self.bits.into() }

    /// Computes the popular "difficulty" measure for mining.
    ///
    /// Difficulty represents how difficult the current target makes it to find a block, relative to
    /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
    pub fn difficulty(&self, params: impl AsRef<Params>) -> u128 {
        self.target().difficulty(params)
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    pub fn difficulty_float(&self) -> f64 { self.target().difficulty_float() }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError> {
        let target = self.target();
        if target != required_target {
            return Err(ValidationError::BadTarget);
        }
        let block_hash = self.block_hash();
        if target.is_met_by(block_hash) {
            Ok(block_hash)
        } else {
            Err(ValidationError::BadProofOfWork)
        }
    }

    /// Returns the total work of the block.
    pub fn work(&self) -> Work { self.target().to_work() }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("block_hash", &self.block_hash())
            .field("version", &self.version)
            .field("prev_blockhash", &self.prev_blockhash)
            .field("merkle_root", &self.merkle_root)
            .field("time", &self.time)
            .field("bits", &self.bits)
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// An error validating the form of a block header against the BLAKE2b hardfork rules.
///
/// See [`Header::validate_form`] and [`Header::validate_form_at_height`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidHeaderFormError {
    /// An extended header appeared on a network where the hardfork is not scheduled.
    ExtendedHeaderNotScheduled,
    /// An extended header claims a height below the activation height.
    ExtendedHeaderTooEarly,
    /// A legacy header appeared at or after the activation height.
    LegacyHeaderTooLate,
    /// The height in an extended header does not match the height of the block.
    HeightMismatch,
    /// The header sets flag bits reserved for a future hardfork.
    ReservedFlags,
}

impl fmt::Display for InvalidHeaderFormError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::ExtendedHeaderNotScheduled =>
                write!(f, "extended block header on a network without the BLAKE2b hardfork"),
            Self::ExtendedHeaderTooEarly =>
                write!(f, "extended block header below the BLAKE2b activation height"),
            Self::LegacyHeaderTooLate =>
                write!(f, "legacy block header at or after the BLAKE2b activation height"),
            Self::HeightMismatch =>
                write!(f, "height in the block header does not match the height of the block"),
            Self::ReservedFlags =>
                write!(f, "block header sets flag bits reserved for a future hardfork"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidHeaderFormError {}

/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if version bits is
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// ### Relevant BIPs
///
/// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-34 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-9 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-9 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Creates a [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    #[inline]
    ///
    /// Bit 31 is masked off: past the BLAKE2b hardfork it announces the extended header form
    /// rather than belonging to the version, so `from_consensus(i32::MIN)` is zero.
    pub const fn from_consensus(v: i32) -> Self {
        // The casts reinterpret the bits; `Version` is signed only for historical reasons.
        Version((v as u32 & !Header::V2_VERSION_FLAG) as i32)
    }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn to_consensus(self) -> i32 { self.0 }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-9 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(&self, bit: u8) -> bool {
        // Only bits [0, 28] inclusive are used for signalling.
        if bit > 28 {
            return false;
        }

        // To signal using version bits, the first three bits must be `001`.
        if (self.0 as u32) & !Self::VERSION_BITS_MASK != Self::USE_VERSION_BITS {
            return false;
        }

        // The bit is set if signalling a soft fork.
        (self.0 as u32 & Self::VERSION_BITS_MASK) & (1 << bit) > 0
    }
}

impl Default for Version {
    fn default() -> Version { Self::NO_SOFT_FORK_SIGNALLING }
}

impl Encodable for Version {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version)
    }
}

/// Bitcoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// ### Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>,
}

impl_consensus_encoding!(Block, header, txdata);

impl Block {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }

    /// Checks if merkle root of header matches merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    pub fn check_witness_commitment(&self) -> bool {
        if self.txdata.is_empty() {
            return false;
        }

        let coinbase = &self.txdata[0];
        if !coinbase.is_coinbase() {
            return false;
        }

        // Commitment is in the last output that starts with magic bytes.
        if let Some(pos) = coinbase.output.iter().rposition(|o| {
            o.script_pubkey.len() >= 38
                && o.script_pubkey.as_bytes()[0..6] == WITNESS_COMMITMENT_MAGIC
        }) {
            let commitment = WitnessCommitment::from_slice(
                &coinbase.output[pos].script_pubkey.as_bytes()[6..38],
            )
            .unwrap();
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some(witness_root) = self.witness_root() {
                    return commitment
                        == Self::compute_witness_commitment(&witness_root, witness_vec[0]);
                }
            }
            return false;
        }

        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.txdata.iter().all(|t| t.input.iter().all(|i| i.witness.is_empty())) {
            return true;
        }

        false
    }

    /// Computes the transaction merkle root.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.compute_txid().to_raw_hash());
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Computes the witness commitment for the block's transaction list.
    pub fn compute_witness_commitment(
        witness_root: &WitnessMerkleNode,
        witness_reserved_value: &[u8],
    ) -> WitnessCommitment {
        let mut encoder = WitnessCommitment::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_engine(encoder)
    }

    /// Computes the merkle root of transactions hashed for witness.
    pub fn witness_root(&self) -> Option<WitnessMerkleNode> {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::all_zeros().to_raw_hash()
            } else {
                t.compute_wtxid().to_raw_hash()
            }
        });
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Returns the weight of the block.
    ///
    /// > Block weight is defined as Base size * 3 + Total size.
    pub fn weight(&self) -> Weight {
        // This is the exact definition of a weight unit, as defined by BIP-141 (quote above).
        let wu = self.base_size() * 3 + self.total_size();
        Weight::from_wu_usize(wu)
    }

    /// Returns the base block size.
    ///
    /// > Base size is the block size in bytes with the original transaction serialization without
    /// > any witness-related data, as seen by a non-upgraded node.
    fn base_size(&self) -> usize {
        // An extended header is longer, so the size cannot be assumed.
        let mut size = self.header.size();

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.base_size()).sum::<usize>();

        size
    }

    /// Returns the total block size.
    ///
    /// > Total size is the block size in bytes with transactions serialized as described in BIP144,
    /// > including base data and witness data.
    pub fn total_size(&self) -> usize {
        // An extended header is longer, so the size cannot be assumed.
        let mut size = self.header.size();

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.total_size()).sum::<usize>();

        size
    }

    /// Returns the coinbase transaction, if one is present.
    pub fn coinbase(&self) -> Option<&Transaction> { self.txdata.first() }

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).

        if self.header.version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase().ok_or(Bip34Error::NotPresent)?;
        let input = cb.input.first().ok_or(Bip34Error::NotPresent)?;
        let push = input.script_sig.instructions_minimal().next().ok_or(Bip34Error::NotPresent)?;
        match push.map_err(|_| Bip34Error::NotPresent)? {
            script::Instruction::PushBytes(b) => {
                // Check that the number is encoded in the minimal way.
                let h = script::read_scriptint(b.as_bytes())
                    .map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    Ok(h as u64)
                }
            }
            _ => Err(Bip34Error::NotPresent),
        }
    }
}

impl From<Header> for BlockHash {
    fn from(header: Header) -> BlockHash { header.block_hash() }
}

impl From<&Header> for BlockHash {
    fn from(header: &Header) -> BlockHash { header.block_hash() }
}

impl From<Block> for BlockHash {
    fn from(block: Block) -> BlockHash { block.block_hash() }
}

impl From<&Block> for BlockHash {
    fn from(block: &Block) -> BlockHash { block.block_hash() }
}

/// An error when looking up a BIP34 block height.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip34Error {
    /// The block does not support BIP34 yet.
    Unsupported,
    /// No push was present where the BIP34 push was expected.
    NotPresent,
    /// The BIP34 push was larger than 8 bytes.
    UnexpectedPush(Vec<u8>),
    /// The BIP34 push was negative.
    NegativeHeight,
}

impl From<Infallible> for Bip34Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Bip34Error::*;

        match *self {
            Unsupported => write!(f, "block doesn't support BIP34"),
            NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            UnexpectedPush(ref p) => {
                write!(f, "unexpected byte push of > 8 bytes: {:?}", p)
            }
            NegativeHeight => write!(f, "negative BIP34 height"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Bip34Error::*;

        match *self {
            Unsupported | NotPresent | UnexpectedPush(_) | NegativeHeight => None,
        }
    }
}

/// A block validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The header hash is not below the target.
    BadProofOfWork,
    /// The `target` field of a block header did not match the expected difficulty.
    BadTarget,
}

impl From<Infallible> for ValidationError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ValidationError::*;

        match *self {
            BadProofOfWork => f.write_str("block target correct but not attained"),
            BadTarget => f.write_str("block target incorrect"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::ValidationError::*;

        match *self {
            BadProofOfWork | BadTarget => None,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Block {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Block { header: Header::arbitrary(u)?, txdata: Vec::<Transaction>::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BlockHash {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(BlockHash::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Header {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Header {
            version: Version::arbitrary(u)?,
            prev_blockhash: BlockHash::from_byte_array(u.arbitrary()?),
            merkle_root: TxMerkleNode::from_byte_array(u.arbitrary()?),
            time: u.arbitrary()?,
            bits: CompactTarget::from_consensus(u.arbitrary()?),
            nonce: u.arbitrary()?,
            v2: None,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Version {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Equally weight known versions and arbitrary versions
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => Ok(Version::ONE),
            1 => Ok(Version::TWO),
            2 => Ok(Version::NO_SOFT_FORK_SIGNALLING),
            _ => Ok(Version::from_consensus(u.arbitrary()?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::{test_hex_unwrap as hex, FromHex};

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::Network;

    #[test]
    fn test_coinbase_and_bip34() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();

        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(block.coinbase().unwrap().compute_txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // block with 9-byte bip34 push
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d09a08601112233445566000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();

        let push = Vec::<u8>::from_hex("a08601112233445566").unwrap();
        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::UnexpectedPush(push)));
    }

    #[test]
    fn block_test() {
        let params = Params::new(Network::Bitcoin);
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        let some_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000");
        let merkle = hex!("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c");
        let work = Work::from(0x100010001_u128);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(1));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1231965655);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(486604799));
        assert_eq!(real_decode.header.nonce, 2067413810);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(&params), 1);
        assert_eq!(real_decode.header.difficulty_float(), 1.0);

        assert_eq!(real_decode.total_size(), some_block.len());
        assert_eq!(real_decode.base_size(), some_block.len());
        assert_eq!(
            real_decode.weight(),
            Weight::from_non_witness_data_size(some_block.len() as u64)
        );

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[test]
    fn segwit_block_test() {
        let params = Params::new(Network::Testnet);
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000");
        let merkle = hex!("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e");
        let work = Work::from(0x257c3becdacc64_u64);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(Version::USE_VERSION_BITS as i32)); // VERSIONBITS but no bits set
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(real_decode.header.time, 1472004949);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(0x1a06d450));
        assert_eq!(real_decode.header.nonce, 1879759182);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(&params), 2456598);
        assert_eq!(real_decode.header.difficulty_float(), 2456598.4399242126);

        assert_eq!(real_decode.total_size(), segwit_block.len());
        assert_eq!(real_decode.base_size(), 4283);
        assert_eq!(real_decode.weight(), Weight::from_wu(17168));

        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), segwit_block);
    }

    #[test]
    fn block_version_test() {
        let block = hex!("ffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(2147483647));

        // Past the BLAKE2b hardfork bit 31 of the version word announces the extended header
        // form, so this 80 byte input is now a truncated 164 byte header rather than a block
        // whose version happens to be negative.
        let header2 = hex!("00000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assert!(deserialize::<Header>(&header2).is_err());
    }

    fn v2_header(height: i32, flags: u8) -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 0,
            v2: Some(HeaderV2 {
                nonce2: 0,
                nonce3: 0,
                extranonce: [0; 16],
                time_offset: 0,
                txcount: 1,
                flags,
                xor_key_mask_clear_bits: 0,
                xor_key: [0; 16],
                height,
                mm_rhs: [0; 32],
            }),
        }
    }

    #[test]
    fn validate_form_enforces_the_activation_height() {
        let params = &Params::MAINNET;
        assert_eq!(params.blake2b_height, Some(961_640));
        assert_eq!(params.blake2b_target_shift, 22);

        // Knots' bad-version-sha256d: an extended header may not claim a height below activation.
        assert_eq!(v2_header(961_640, 0).validate_form(params), Ok(()));
        assert_eq!(v2_header(961_641, 0).validate_form(params), Ok(()));
        for height in [961_639, 0, -1, i32::MIN] {
            assert_eq!(
                v2_header(height, 0).validate_form(params),
                Err(InvalidHeaderFormError::ExtendedHeaderTooEarly),
                "height {}",
                height
            );
        }

        // Knots' bad-flags-highbits.
        for flags in [0x40, 0x80, 0xc0] {
            assert_eq!(
                v2_header(961_640, flags).validate_form(params),
                Err(InvalidHeaderFormError::ReservedFlags),
                "flags {:#04x}",
                flags
            );
        }

        // Where the fork is not scheduled, an extended header has no valid height at all.
        assert_eq!(
            v2_header(961_640, 0).validate_form(&Params::SIGNET),
            Err(InvalidHeaderFormError::ExtendedHeaderNotScheduled)
        );

        // A legacy header is unaffected on every network.
        let v1 = Header { v2: None, ..v2_header(0, 0) };
        assert_eq!(v1.validate_form(params), Ok(()));
        assert_eq!(v1.validate_form(&Params::SIGNET), Ok(()));
    }

    #[test]
    fn validate_form_at_height_enforces_the_flag_day() {
        let params = &Params::MAINNET;

        // Knots' bad-header-height: the header must agree with where the block sits.
        assert_eq!(v2_header(961_640, 0).validate_form_at_height(961_640, params), Ok(()));
        assert_eq!(
            v2_header(961_641, 0).validate_form_at_height(961_640, params),
            Err(InvalidHeaderFormError::HeightMismatch)
        );

        // Knots' bad-version-blake2b: a legacy header is refused from the activation height on.
        let v1 = Header { v2: None, ..v2_header(0, 0) };
        assert_eq!(v1.validate_form_at_height(961_639, params), Ok(()));
        for height in [961_640, 1_000_000] {
            assert_eq!(
                v1.validate_form_at_height(height, params),
                Err(InvalidHeaderFormError::LegacyHeaderTooLate),
                "height {}",
                height
            );
        }

        // And a legacy header stays valid at any height where the fork is unscheduled.
        assert_eq!(v1.validate_form_at_height(961_640, &Params::SIGNET), Ok(()));
    }

    #[test]
    fn extended_header_counts_toward_block_size_and_weight() {
        // The extended header is 84 bytes longer, and those bytes are base data, so they count
        // four times over in the weight.
        let segwit = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();
        let v1: Block = deserialize(&segwit).unwrap();

        let mut v2 = v1.clone();
        v2.header.v2 = Some(HeaderV2 { txcount: 0, ..v2_header(840_000, 0).v2.unwrap() });

        assert_eq!(v2.total_size(), v1.total_size() + HeaderV2::EXTRA_SIZE);
        assert_eq!(v2.weight().to_wu(), v1.weight().to_wu() + 4 * HeaderV2::EXTRA_SIZE as u64);
        assert_eq!(serialize(&v2).len(), segwit.len() + HeaderV2::EXTRA_SIZE);
        assert_eq!(serialize(&v2).len(), v2.total_size());
    }

    #[test]
    fn version_never_carries_the_extended_header_flag() {
        // Bit 31 announces the header form, so it is not part of the version and no `Version` may
        // hold it. Otherwise a v1 header built with such a version would serialize with the bit
        // cleared and hash differently from the value it was constructed with.
        assert_eq!(Version::from_consensus(i32::MIN), Version(0));
        assert_eq!(Version::from_consensus(-1).to_consensus(), 0x7fff_ffff);
        assert_eq!(Version::from_consensus(0x7fff_ffff).to_consensus(), 0x7fff_ffff);
        assert_eq!(Version::from_consensus(2).to_consensus(), 2);
    }

    #[test]
    fn header_encoding_round_trips_for_every_version() {
        // The encoder masks bit 31, so the round trip is only total because `Version` cannot
        // hold it.
        for raw in [0, 1, 2, 0x2000_0000, 0x7fff_ffff, -1, i32::MIN, i32::MIN + 1] {
            let header = Header {
                version: Version::from_consensus(raw),
                prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0x77; 32]),
                time: 2,
                bits: CompactTarget::from_consensus(3),
                nonce: 4,
                v2: None,
            };
            let bytes = serialize(&header);
            assert_eq!(bytes.len(), Header::SIZE, "raw {}", raw);
            assert_eq!(deserialize::<Header>(&bytes).unwrap(), header, "raw {}", raw);
        }
    }

    #[test]
    fn validate_pow_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");
        let some_header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(
            some_header.validate_pow(some_header.target()).unwrap(),
            some_header.block_hash()
        );

        // test with zero target
        match some_header.validate_pow(Target::ZERO) {
            Err(ValidationError::BadTarget) => (),
            _ => panic!("unexpected result from validate_pow"),
        }

        // test with modified header
        let mut invalid_header: Header = some_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_pow(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn compact_roundrtip_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");

        let header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");

        assert_eq!(header.bits, header.target().to_compact_lossy());
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ 1 << i) as i32;
            let version = Version(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version(0x20000000 ^ 1 << 1);
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }

    #[test]
    fn block_rejects_empty_coinbase_witness_commitment() {
        let mut script = Vec::from(WITNESS_COMMITMENT_MAGIC);
        script.extend_from_slice(&[0; 32]);

        let coinbase = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            input: vec![crate::TxIn::default()],
            output: vec![crate::TxOut {
                value: crate::Amount::ZERO,
                script_pubkey: crate::ScriptBuf::from_bytes(script),
            }],
        };

        let header = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
            v2: None,
        };

        let mut block = Block { header, txdata: vec![coinbase] };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(block.check_merkle_root());
        // BIP-141 requires the witness reserved value, so the commitment is invalid.
        assert!(!block.check_witness_commitment());
    }
}

#[cfg(bench)]
mod benches {
    use io::sink;
    use test::{black_box, Bencher};

    use super::Block;
    use crate::consensus::{deserialize, Decodable, Encodable};

    #[bench]
    pub fn bench_stream_reader(bh: &mut Bencher) {
        let big_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        assert_eq!(big_block.len(), 1_381_836);
        let big_block = black_box(big_block);

        bh.iter(|| {
            let mut reader = &big_block[..];
            let block = Block::consensus_decode(&mut reader).unwrap();
            black_box(&block);
        });
    }

    #[bench]
    pub fn bench_block_serialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        let mut data = Vec::with_capacity(raw_block.len());

        bh.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut sink());
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        bh.iter(|| {
            let block: Block = deserialize(&raw_block[..]).unwrap();
            black_box(&block);
        });
    }
}
