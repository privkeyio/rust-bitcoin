// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!
//! # Examples
//!
//! ```rust
//! # #[cfg(feature = "alloc")]
//! # fn example() -> Result<(), bitcoin_primitives::block::InvalidBlockError> {
//! use bitcoin_primitives::block::{self, Block, Header, InvalidBlockError, Version};
//! use bitcoin_primitives::{
//!     absolute, transaction, Amount, BlockHash, BlockTime, CompactTarget, OutPoint,
//!     ScriptPubKeyBuf, ScriptSigBuf, Sequence, Transaction, TxIn, TxOut, Witness,
//! };
//!
//! let coinbase = Transaction {
//!     version: transaction::Version::ONE,
//!     lock_time: absolute::LockTime::ZERO,
//!     inputs: vec![TxIn {
//!         previous_output: OutPoint::COINBASE_PREVOUT,
//!         script_sig: ScriptSigBuf::from_bytes(vec![0x51, 0x52]),
//!         sequence: Sequence::MAX,
//!         witness: Witness::new(),
//!     }],
//!     outputs: vec![TxOut {
//!         amount: Amount::from_sat_u32(50_000),
//!         script_pubkey: ScriptPubKeyBuf::new(),
//!     }],
//! };
//! assert!(coinbase.is_coinbase());
//!
//! let transactions = vec![coinbase];
//! let merkle_root =
//!     block::compute_merkle_root(&transactions).ok_or(InvalidBlockError::NoTransactions)?;
//!
//! let header = Header {
//!     version: Version::TWO,
//!     prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
//!     merkle_root,
//!     time: BlockTime::from_u32(1_231_006_505),
//!     bits: CompactTarget::from_consensus(0x1d00_ffff),
//!     nonce: 2_083_236_893,
//!     v2: None,
//! };
//! assert_eq!(Header::SIZE, 80);
//!
//! // Decoding gives a `Block<Unchecked>`. `validate` must be called to get a `Block<Checked>`.
//! let block = Block::new_unchecked(header, transactions);
//! assert!(block.check_merkle_root());
//!
//! let block_hash = block.block_hash();
//! let block = block.validate()?;
//!
//! // The content accessors exist only on the checked type.
//! assert_eq!(block.transactions().len(), 1);
//! assert_eq!(block.block_hash(), block_hash);
//! assert_eq!(block.header().merkle_root, merkle_root);
//! # Ok(())
//! # }
//! # #[cfg(feature = "alloc")]
//! # example().unwrap();
//! ```

#[cfg(feature = "alloc")]
use core::borrow::Borrow;
use core::fmt;
#[cfg(feature = "alloc")]
use core::marker::PhantomData;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ArrayDecoder, Decoder6};
#[cfg(feature = "alloc")]
use encoding::{Decoder2, Encoder2, PrefixedSliceEncoder, VecDecoder};
use hashes::{blake2b, sha256, sha256d, HashEngine as _};

#[cfg(feature = "hex")]
use crate::hex_codec::HexPrimitive;
#[cfg(feature = "alloc")]
use crate::merkle_tree::WitnessMerkleNode;
use crate::merkle_tree::{TxMerkleNode, TxMerkleNodeDecoder};
use crate::pow::CompactTargetDecoder;
#[cfg(feature = "alloc")]
use crate::prelude::Vec;
use crate::time::BlockTimeDecoder;
use crate::{BlockTime, CompactTarget};
#[cfg(feature = "alloc")]
use crate::{Transaction, Wtxid};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use units::block::{BlockHeight, BlockHeightDecoder, BlockHeightEncoder, BlockHeightInterval, BlockMtp, BlockMtpInterval};

#[rustfmt::skip]                // Keep public re-exports separate.
#[cfg(feature = "alloc")]
#[doc(no_inline)]
pub use self::error::{BlockDecoderError, InvalidBlockError};
#[doc(no_inline)]
pub use self::error::{
    BlockHashDecoderError, BlockHeightDecoderError, HeaderDecoderError,
    TooBigForRelativeHeightError, VersionDecoderError,
};
#[doc(inline)]
pub use crate::hash_types::{BlockHash, BlockHashDecoder, BlockHashEncoder, WitnessCommitment};

// Consists of OP_RETURN, OP_PUSHBYTES_36, and four "witness header" bytes.
#[cfg(feature = "alloc")]
const WITNESS_COMMITMENT_MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Marker for whether or not a block has been validated.
///
/// We define valid as:
///
/// * The Merkle root of the header matches Merkle root of the transaction list.
/// * The witness commitment in coinbase matches the transaction list.
///
/// See `bitcoin::block::BlockUncheckedExt::validate()`.
#[cfg(feature = "alloc")]
pub trait Validation: sealed::Validation + Sync + Send + Sized + Unpin {
    /// Indicates whether this [`Validation`] is [`Checked`] or not.
    const IS_CHECKED: bool;
}

/// Bitcoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// # Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct Block<V = Unchecked>
where
    V: Validation,
{
    /// The block header
    header: Header,
    /// List of transactions contained in the block
    transactions: Vec<Transaction>,
    /// Cached witness root if it's been computed.
    witness_root: Option<WitnessMerkleNode>,
    /// Validation marker.
    _marker: PhantomData<V>,
}

#[cfg(feature = "alloc")]
impl Block<Unchecked> {
    /// Constructs a new [`Block`] without doing any validation.
    #[inline]
    pub fn new_unchecked(header: Header, transactions: Vec<Transaction>) -> Self {
        Self { header, transactions, witness_root: None, _marker: PhantomData::<Unchecked> }
    }

    /// Ignores block validation logic and just assumes you know what you are doing.
    ///
    /// You should only use this function if you trust the block i.e., it comes from a trusted node.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_primitives::block::{Block, Header, Version};
    /// # use bitcoin_primitives::merkle_tree::TxMerkleNode;
    /// # use bitcoin_primitives::{
    /// #     absolute, transaction, Amount, BlockHash, BlockTime, CompactTarget, OutPoint,
    /// #     ScriptPubKeyBuf, ScriptSigBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    /// # };
    /// # let coinbase = Transaction {
    /// #     version: transaction::Version::ONE,
    /// #     lock_time: absolute::LockTime::ZERO,
    /// #     inputs: vec![TxIn {
    /// #         previous_output: OutPoint::COINBASE_PREVOUT,
    /// #         script_sig: ScriptSigBuf::from_bytes(vec![0x51, 0x52]),
    /// #         sequence: Sequence::MAX,
    /// #         witness: Witness::new(),
    /// #     }],
    /// #     outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
    /// # };
    /// # let header = Header {
    /// #     version: Version::TWO,
    /// #     prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
    /// #     merkle_root: TxMerkleNode::from_byte_array([0xff; 32]),
    /// #     time: BlockTime::from_u32(1_231_006_505),
    /// #     bits: CompactTarget::from_consensus(0x1d00_ffff),
    /// #     nonce: 0,
    /// #     v2: None,
    /// # };
    /// // This header's Merkle root does not match the transaction list.
    /// let block = Block::new_unchecked(header, vec![coinbase]);
    /// assert!(!block.check_merkle_root());
    ///
    /// // `validate` would have rejected this block.
    /// assert_eq!(block.assume_checked(None).cached_witness_root(), None);
    /// ```
    ///
    /// [`validate`]: Self::validate
    /// [`cached_witness_root`]: Block<Checked>::cached_witness_root
    #[must_use]
    #[inline]
    pub fn assume_checked(self, witness_root: Option<WitnessMerkleNode>) -> Block<Checked> {
        Block {
            header: self.header,
            transactions: self.transactions,
            witness_root,
            _marker: PhantomData::<Checked>,
        }
    }

    /// Decomposes block into its constituent parts.
    #[inline]
    pub fn into_parts(self) -> (Header, Vec<Transaction>) { (self.header, self.transactions) }

    /// Returns the constituent parts of the block by reference.
    #[inline]
    pub fn as_parts(&self) -> (&Header, &[Transaction]) { (&self.header, &self.transactions) }

    /// Validates (or checks) a block.
    ///
    /// We define valid as:
    ///
    /// * The Merkle root of the header matches Merkle root of the transaction list.
    /// * The witness commitment in coinbase matches the transaction list.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The block has no transactions.
    /// * The first transaction is not a coinbase transaction.
    /// * The Merkle root of the header does not match the Merkle root of the transaction list.
    /// * The witness commitment in the coinbase does not match the transaction list.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_primitives::block::{self, Block, Header, InvalidBlockError, Version};
    /// # use bitcoin_primitives::merkle_tree::TxMerkleNode;
    /// # use bitcoin_primitives::{
    /// #     absolute, transaction, Amount, BlockHash, BlockTime, CompactTarget, OutPoint,
    /// #     ScriptPubKeyBuf, ScriptSigBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    /// # };
    /// # let coinbase = Transaction {
    /// #     version: transaction::Version::ONE,
    /// #     lock_time: absolute::LockTime::ZERO,
    /// #     inputs: vec![TxIn {
    /// #         previous_output: OutPoint::COINBASE_PREVOUT,
    /// #         script_sig: ScriptSigBuf::from_bytes(vec![0x51, 0x52]),
    /// #         sequence: Sequence::MAX,
    /// #         witness: Witness::new(),
    /// #     }],
    /// #     outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
    /// # };
    /// # fn header_with(merkle_root: TxMerkleNode) -> Header {
    /// #     Header {
    /// #         version: Version::TWO,
    /// #         prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
    /// #         merkle_root,
    /// #         time: BlockTime::from_u32(1_231_006_505),
    /// #         bits: CompactTarget::from_consensus(0x1d00_ffff),
    /// #         nonce: 0,
    /// #         v2: None,
    /// #     }
    /// # }
    /// let transactions = vec![coinbase];
    /// let root = block::compute_merkle_root(&transactions).unwrap();
    ///
    /// let block = Block::new_unchecked(header_with(root), transactions.clone());
    /// assert_eq!(block.validate()?.transactions().len(), 1);
    ///
    /// // A header committing to a different transaction list is rejected.
    /// let wrong_root = header_with(TxMerkleNode::from_byte_array([0xff; 32]));
    /// let block = Block::new_unchecked(wrong_root, transactions);
    /// assert_eq!(block.validate().unwrap_err(), InvalidBlockError::InvalidMerkleRoot);
    /// # Ok::<_, InvalidBlockError>(())
    /// ```
    ///
    /// [`assume_checked`]: Self::assume_checked
    /// [`cached_witness_root`]: Block<Checked>::cached_witness_root
    pub fn validate(self) -> Result<Block<Checked>, InvalidBlockError> {
        if self.transactions.is_empty() {
            return Err(InvalidBlockError::NoTransactions);
        }

        if !self.transactions[0].is_coinbase() {
            return Err(InvalidBlockError::InvalidCoinbase);
        }

        if !self.check_merkle_root() {
            return Err(InvalidBlockError::InvalidMerkleRoot);
        }

        match self.check_witness_commitment() {
            (false, _) => Err(InvalidBlockError::InvalidWitnessCommitment),
            (true, witness_root) => {
                let block = Self::new_unchecked(self.header, self.transactions);
                Ok(block.assume_checked(witness_root))
            }
        }
    }

    /// Checks if Merkle root of header matches Merkle root of the transaction list.
    #[inline]
    pub fn check_merkle_root(&self) -> bool {
        match compute_merkle_root(&self.transactions) {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Computes the witness commitment for a list of transactions.
    pub fn compute_witness_commitment(
        &self,
        witness_reserved_value: &[u8],
    ) -> Option<(WitnessMerkleNode, WitnessCommitment)> {
        compute_witness_root(&self.transactions).map(|witness_root| {
            let mut encoder = sha256d::Hash::engine();
            hashes::encode_to_engine(&witness_root, &mut encoder);
            encoder.input(witness_reserved_value);
            let witness_commitment = WitnessCommitment::from_byte_array(
                sha256d::Hash::from_engine(encoder).to_byte_array(),
            );
            (witness_root, witness_commitment)
        })
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    ///
    /// # Returns
    ///
    /// Returns the witness Merkle root if it was computed. This can then be passed into
    /// [`assume_checked`] to save re-calculating it.
    ///
    /// [`assume_checked`]: Block<Unchecked>::assume_checked
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_primitives::block::{self, Block, Header, Version};
    /// # use bitcoin_primitives::{
    /// #     absolute, transaction, Amount, BlockHash, BlockTime, CompactTarget, OutPoint,
    /// #     ScriptPubKeyBuf, ScriptSigBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    /// # };
    /// # let coinbase = Transaction {
    /// #     version: transaction::Version::ONE,
    /// #     lock_time: absolute::LockTime::ZERO,
    /// #     inputs: vec![TxIn {
    /// #         previous_output: OutPoint::COINBASE_PREVOUT,
    /// #         script_sig: ScriptSigBuf::from_bytes(vec![0x51, 0x52]),
    /// #         sequence: Sequence::MAX,
    /// #         witness: Witness::new(),
    /// #     }],
    /// #     outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
    /// # };
    /// # let merkle_root = block::compute_merkle_root(&[coinbase.clone()]).expect("one transaction");
    /// # let header = Header {
    /// #     version: Version::TWO,
    /// #     prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
    /// #     merkle_root,
    /// #     time: BlockTime::from_u32(1_231_006_505),
    /// #     bits: CompactTarget::from_consensus(0x1d00_ffff),
    /// #     nonce: 0,
    /// #     v2: None,
    /// # };
    /// // This block's only transaction has an empty witness.
    /// let block = Block::new_unchecked(header, vec![coinbase]);
    ///
    /// let (is_valid, witness_root) = block.check_witness_commitment();
    /// assert!(is_valid);
    /// assert_eq!(witness_root, None);
    ///
    /// assert_eq!(block.assume_checked(witness_root).cached_witness_root(), None);
    /// ```
    pub fn check_witness_commitment(&self) -> (bool, Option<WitnessMerkleNode>) {
        if self.transactions.is_empty() {
            return (false, None);
        }

        if self.transactions[0].is_coinbase() {
            let coinbase = &self.transactions[0];
            if let Some(commitment) = witness_commitment_from_coinbase(coinbase) {
                // Witness reserved value is in coinbase input witness.
                let witness_vec: Vec<_> = coinbase.inputs[0].witness.iter().collect();
                if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                    if let Some((witness_root, witness_commitment)) =
                        self.compute_witness_commitment(witness_vec[0])
                    {
                        if commitment == witness_commitment {
                            return (true, Some(witness_root));
                        }
                    }
                }

                return (false, None);
            }
        }

        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.transactions.iter().all(|t| t.inputs.iter().all(|i| i.witness.is_empty())) {
            return (true, None);
        }

        (false, None)
    }
}

#[cfg(feature = "alloc")]
impl Block<Checked> {
    /// Gets a reference to the block header.
    #[inline]
    pub fn header(&self) -> &Header { &self.header }

    /// Gets a reference to the block's list of transactions.
    #[inline]
    pub fn transactions(&self) -> &[Transaction] { &self.transactions }

    /// Returns the cached witness root if one is present.
    ///
    /// It is assumed that a block will have the witness root calculated and cached as part of the
    /// validation process.
    #[inline]
    pub fn cached_witness_root(&self) -> Option<WitnessMerkleNode> { self.witness_root }
}

#[cfg(feature = "alloc")]
impl<V: Validation> Block<V> {
    /// Returns the block hash.
    #[inline]
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }
}

#[cfg(feature = "alloc")]
impl<V: Validation> PartialEq for Block<V> {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.transactions == other.transactions
    }
}

#[cfg(feature = "alloc")]
impl<V: Validation> Eq for Block<V> {}

#[cfg(feature = "alloc")]
impl From<Block> for BlockHash {
    #[inline]
    fn from(block: Block) -> Self { block.block_hash() }
}

#[cfg(feature = "alloc")]
impl From<&Block> for BlockHash {
    #[inline]
    fn from(block: &Block) -> Self { block.block_hash() }
}

/// Marker that the block's merkle root has been successfully validated.
///
/// # Examples
///
/// ```rust
/// use bitcoin_primitives::block::{Block, Checked};
///
/// fn count_transactions(block: &Block<Checked>) -> usize { block.transactions().len() }
/// ```
///
/// The same function does not compile against an unchecked block:
///
/// ```compile_fail
/// use bitcoin_primitives::block::{Block, Unchecked};
///
/// fn count_transactions(block: &Block<Unchecked>) -> usize { block.transactions().len() }
/// ```
///
/// [`validate`]: Block<Unchecked>::validate
/// [`assume_checked`]: Block<Unchecked>::assume_checked
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg(feature = "alloc")]
pub enum Checked {}

#[cfg(feature = "alloc")]
impl Validation for Checked {
    const IS_CHECKED: bool = true;
}

/// Marker that the block's merkle root has not been validated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg(feature = "alloc")]
pub enum Unchecked {}

#[cfg(feature = "alloc")]
impl Validation for Unchecked {
    const IS_CHECKED: bool = false;
}

#[cfg(feature = "alloc")]
mod sealed {
    /// Seals the block validation marker traits.
    pub trait Validation {}
    impl Validation for super::Checked {}
    impl Validation for super::Unchecked {}
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl core::str::FromStr for Block<Unchecked>
where
    Self: encoding::Decode,
{
    type Err = encoding::FromHexError<BlockDecoderError>;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> { encoding::decode_from_hex(s) }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl<V: Validation> fmt::Display for Block<V>
where
    Self: encoding::Encode,
{
    #[allow(clippy::use_self)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&HexPrimitive(self), f)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl<V: Validation> fmt::LowerHex for Block<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&HexPrimitive(self), f)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl<V: Validation> fmt::UpperHex for Block<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&HexPrimitive(self), f)
    }
}

#[cfg(feature = "alloc")]
impl<V> encoding::Encode for Block<V>
where
    V: Validation,
{
    type Encoder<'e>
        = BlockEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        BlockEncoder::new(Encoder2::new(
            self.header.encoder(),
            PrefixedSliceEncoder::new(&self.transactions),
        ))
    }
}

#[cfg(feature = "alloc")]
impl encoding::Decode for Block<Unchecked> {
    type Decoder = BlockDecoder;
}

#[cfg(feature = "alloc")]
encoding::encoder_newtype! {
    /// The encoder for the [`Block`] type.
    #[derive(Debug, Clone)]
    pub struct BlockEncoder<'e>(
        Encoder2<HeaderEncoder, PrefixedSliceEncoder<'e, Transaction>>
    );
}

#[cfg(feature = "alloc")]
type BlockInnerDecoder = Decoder2<HeaderDecoder, VecDecoder<Transaction>>;

#[cfg(feature = "alloc")]
crate::decoder_newtype! {
    /// The decoder for the [`Block`] type.
    ///
    /// This decoder can only produce a [`Block<Unchecked>`].
    #[derive(Debug, Clone)]
    pub struct BlockDecoder(BlockInnerDecoder);

    /// Constructs a new [`Block`] decoder.
    pub const fn new() -> Self { Self(Decoder2::new(HeaderDecoder::new(), VecDecoder::new())) }

    fn end(result: Result<(Header, Vec<Transaction>), <BlockInnerDecoder as encoding::Decoder>::Error>) -> Result<Block, BlockDecoderError> {
        let (header, transactions) = result.map_err(BlockDecoderError)?;
        Ok(Self::Output::new_unchecked(header, transactions))
    }
}

/// Computes the Merkle root for a list of transactions.
///
/// Returns [`None`] if the iterator was empty, or if the transaction list contains
/// consecutive duplicates which would trigger CVE 2012-2459. Blocks with duplicate
/// transactions will always be invalid, so there is no harm in us refusing to
/// compute their merkle roots.
///
/// Unless you are certain your transaction list is nonempty and has no duplicates,
/// you should not unwrap the [`Option`] returned by this method!
#[cfg(feature = "alloc")]
pub fn compute_merkle_root<T>(transactions: T) -> Option<TxMerkleNode>
where
    T: IntoIterator,
    T::Item: Borrow<Transaction>,
{
    let hashes = transactions.into_iter().map(|t| t.borrow().compute_txid());
    TxMerkleNode::calculate_root(hashes)
}

/// Computes the Merkle root of transactions hashed for witness.
///
/// Returns [`None`] if the iterator was empty, or if the transaction list contains
/// consecutive duplicates which would trigger CVE 2012-2459. Blocks with duplicate
/// transactions will always be invalid, so there is no harm in us refusing to
/// compute their merkle roots.
///
/// Unless you are certain your transaction list is nonempty and has no duplicates,
/// you should not unwrap the [`Option`] returned by this method!
#[cfg(feature = "alloc")]
pub fn compute_witness_root<T>(transactions: T) -> Option<WitnessMerkleNode>
where
    T: IntoIterator,
    T::Item: Borrow<Transaction>,
{
    let hashes = transactions.into_iter().enumerate().map(|(i, t)| {
        if i == 0 {
            // Replace the first hash with zeroes.
            Wtxid::COINBASE
        } else {
            t.borrow().compute_wtxid()
        }
    });
    WitnessMerkleNode::calculate_root(hashes)
}

#[cfg(feature = "alloc")]
fn witness_commitment_from_coinbase(coinbase: &Transaction) -> Option<WitnessCommitment> {
    if !coinbase.is_coinbase() {
        return None;
    }

    // Commitment is in the last output that starts with magic bytes.
    if let Some(pos) = coinbase.outputs.iter().rposition(|o| {
        o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == WITNESS_COMMITMENT_MAGIC
    }) {
        let bytes =
            <[u8; 32]>::try_from(&coinbase.outputs[pos].script_pubkey.as_bytes()[6..38]).unwrap();
        Some(WitnessCommitment::from_byte_array(bytes))
    } else {
        None
    }
}

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [Merkle tree] committing to all transactions in the block.
///
/// [Merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// # Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the Merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: BlockTime,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
    /// The extra fields carried by an extended header, if this is one.
    ///
    /// `None` for the historical 80 byte form. See [`HeaderV2`].
    pub v2: Option<HeaderV2>,
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
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_primitives::block::{Header, Version};
    /// use bitcoin_primitives::merkle_tree::TxMerkleNode;
    /// use bitcoin_primitives::{BlockHash, BlockTime, CompactTarget};
    ///
    /// let mut header = Header {
    ///     version: Version::TWO,
    ///     prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
    ///     merkle_root: TxMerkleNode::from_byte_array([0xab; 32]),
    ///     time: BlockTime::from_u32(1_231_006_505),
    ///     bits: CompactTarget::from_consensus(0x1d00_ffff),
    ///     nonce: 0,
    ///     v2: None,
    /// };
    /// let block_hash = header.block_hash();
    ///
    /// header.nonce += 1;
    /// assert_ne!(header.block_hash(), block_hash);
    /// ```
    #[inline]
    pub fn block_hash(&self) -> BlockHash {
        match self.v2 {
            None => {
                let hash = hashes::encode_to_hash::<_, sha256d::HashEngine>(self);
                BlockHash::from_byte_array(hash.to_byte_array())
            }
            Some(ref v2) => self.block_hash_v2(v2),
        }
    }

    /// Returns the serialized size of this header, in bytes.
    ///
    /// Either [`Header::SIZE`] or [`Header::V2_SIZE`].
    #[inline]
    pub const fn size(&self) -> usize {
        match self.v2 {
            None => Self::SIZE,
            Some(_) => Self::V2_SIZE,
        }
    }

    /// Returns the version word as it appears on the wire.
    ///
    /// This is [`Header::version`] with [`Header::V2_VERSION_FLAG`] set if and only if this is an
    /// extended header. A version bit 31 set in [`Header::version`] itself is masked off, because
    /// past the hardfork that bit no longer belongs to the version.
    #[inline]
    pub const fn complete_version(&self) -> u32 {
        // The cast reinterprets the bits; `Version` is signed only for historical reasons.
        let base = self.version.to_consensus() as u32 & !Self::V2_VERSION_FLAG;
        match self.v2 {
            None => base,
            Some(_) => base | Self::V2_VERSION_FLAG,
        }
    }

    /// Returns the timestamp as it appears on the wire.
    ///
    /// [`Header::time`] holds the effective block time. An extended header may carry part of it in
    /// [`HeaderV2::time_offset`] instead, in which case the wire form holds the difference.
    #[inline]
    pub const fn time_on_wire(&self) -> u32 {
        match self.v2 {
            Some(v2) if v2.flags & HeaderV2::USE_TIME_OFFSET != 0 =>
                self.time.to_u32().wrapping_sub(v2.time_offset),
            _ => self.time.to_u32(),
        }
    }

    /// Serializes the header, returning the buffer and the number of bytes used.
    fn wire_bytes(&self) -> ([u8; Self::V2_SIZE], usize) {
        let mut out = [0u8; Self::V2_SIZE];
        out[0..4].copy_from_slice(&self.complete_version().to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_blockhash.to_byte_array());
        out[36..68].copy_from_slice(&self.merkle_root.to_byte_array());
        out[68..72].copy_from_slice(&self.time_on_wire().to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_consensus_u32().to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        match self.v2 {
            None => (out, Self::SIZE),
            Some(ref v2) => {
                v2.write_extra(
                    <&mut [u8; HeaderV2::EXTRA_SIZE]>::try_from(&mut out[Self::SIZE..])
                        .expect("EXTRA_SIZE bytes"),
                );
                (out, Self::V2_SIZE)
            }
        }
    }

    /// Computes the `BLAKE2b` block id of an extended header.
    ///
    /// Follows Bitcoin Knots' `CBlockHeader::GetHash` for the extended form: a chain of BIP-340
    /// style tagged SHA256 hashes feeding two `BLAKE2b` passes, the second laid out according to the
    /// ASIC profile in the header flags, then masked and byte reversed.
    fn block_hash_v2(&self, v2: &HeaderV2) -> BlockHash {
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
        let xor_key_hash = engine.finalize();

        let mut xor_key_mask = [0u8; 32];
        if v2.xor_key != ZEROS {
            let mut engine = tagged(b"Bitcoin block hash PoW XOR mask");
            engine.input(&v2.xor_key);
            xor_key_mask = engine.finalize().to_byte_array();
            // `xor_key_mask_clear_bits` is a `u8`, so this is at most 31 and stays in bounds.
            let clear_bytes = usize::from(v2.xor_key_mask_clear_bits / 8);
            xor_key_mask[..clear_bytes].fill(0);
            xor_key_mask[clear_bytes] &= 0xff_u8 >> (v2.xor_key_mask_clear_bits % 8);
        }

        let mut prev_blockhash = self.prev_blockhash.to_byte_array();
        prev_blockhash.reverse();

        let mut engine = tagged(b"Bitcoin prevblock header, hashed");
        engine.input(&prev_blockhash);
        let mut prev_blockhash_hidden = engine.finalize().to_byte_array();

        // These fields are invisible to the mining machine, so the hasher cannot brick itself at
        // some future block version, time or difficulty.
        let mut h1 = tagged(b"Bitcoin block header 1");
        h1.input(&self.complete_version().to_le_bytes());
        h1.input(&prev_blockhash);
        h1.input(&v2.height.to_le_bytes());
        h1.input(&self.merkle_root.to_byte_array());
        h1.input(&self.time_on_wire().to_le_bytes());
        h1.input(&[0]); // Reserved for an extended 40 bit time.
        h1.input(&self.bits.to_consensus_u32().to_le_bytes());
        h1.input(&u32::from(v2.txcount).to_le_bytes());
        h1.input(&[v2.flags, v2.xor_key_mask_clear_bits]);
        h1.input(xor_key_hash.as_byte_array());

        let mut h2 = tagged(b"Merge-mining hook");
        h2.input(h1.finalize().as_byte_array());
        h2.input(&ZEROS);
        h2.input(&ZEROS);
        h2.input(&v2.mm_rhs);
        let h2_hash = h2.finalize().to_byte_array();

        // These fields get sent to mining machines over Stratum v1.
        let mut engine = blake2b::Hash::engine();
        engine.input(&0_u32.to_le_bytes()); // Sv1 "coinb1", less the implied first byte.
        engine.input(&h2_hash);
        engine.input(&v2.extranonce);
        let hash = engine.finalize().to_byte_array();

        // Presumably the actual mining ASIC hardware sees these.
        let mut engine = blake2b::Hash::engine();
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
                engine.input(&self.nonce.to_le_bytes());
                engine.input(&v2.nonce2.to_le_bytes());
                engine.input(&v2.time_offset.to_le_bytes());
                engine.input(&v2.nonce3.to_le_bytes());
                engine.input(&hash);
            }
            0 => {
                prev_blockhash_hidden[..6].fill(0);
                engine.input(&prev_blockhash_hidden);
                engine.input(&self.nonce.to_le_bytes());
                engine.input(&v2.nonce2.to_le_bytes());
                engine.input(&v2.time_offset.to_le_bytes());
                engine.input(&v2.nonce3.to_le_bytes());
                engine.input(&hash);
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
        let hash = engine.finalize().to_byte_array();

        // Knots writes the masked digest into the block id back to front. That is exactly the
        // order `BlockHash` stores its bytes in, so the displayed id reads the digest forwards.
        let mut out = [0u8; 32];
        for (i, byte) in hash.iter().enumerate() {
            out[31 - i] = byte ^ xor_key_mask[i];
        }
        BlockHash::from_byte_array(out)
    }
}

#[cfg(feature = "hex")]
impl core::str::FromStr for Header {
    type Err = encoding::FromHexError<HeaderDecoderError>;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> { encoding::decode_from_hex(s) }
}

#[cfg(feature = "hex")]
impl fmt::Display for Header {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&HexPrimitive(self), f)
    }
}

#[cfg(feature = "hex")]
impl fmt::LowerHex for Header {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&HexPrimitive(self), f)
    }
}

#[cfg(feature = "hex")]
impl fmt::UpperHex for Header {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&HexPrimitive(self), f)
    }
}

impl fmt::Debug for Header {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("block_hash", &self.block_hash())
            .field("version", &self.version)
            .field("prev_blockhash", &self.prev_blockhash)
            .field("merkle_root", &self.merkle_root)
            .field("time", &self.time)
            .field("bits", &self.bits)
            .field("nonce", &self.nonce)
            .field("v2", &self.v2)
            .finish()
    }
}

impl encoding::Encode for Header {
    type Encoder<'e> = HeaderEncoder;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        let (buf, len) = self.wire_bytes();
        HeaderEncoder { buf, len }
    }
}

impl encoding::Decode for Header {
    type Decoder = HeaderDecoder;
}

/// The encoder for the [`Header`] type.
///
/// A header is either [`Header::SIZE`] or [`Header::V2_SIZE`] bytes, so unlike the other fixed
/// width primitives this encoder carries its own buffer rather than composing field encoders.
#[derive(Debug, Clone)]
pub struct HeaderEncoder {
    buf: [u8; Header::V2_SIZE],
    len: usize,
}

impl encoding::Encoder for HeaderEncoder {
    #[inline]
    fn current_chunk(&self) -> &[u8] { &self.buf[..self.len] }

    #[inline]
    fn advance(&mut self) -> encoding::EncoderStatus { encoding::EncoderStatus::Finished }
}

impl encoding::ExactSizeEncoder for HeaderEncoder {
    #[inline]
    fn len(&self) -> usize { self.len }
}

type HeaderInnerDecoder = Decoder6<
    VersionDecoder,
    BlockHashDecoder,
    TxMerkleNodeDecoder,
    BlockTimeDecoder,
    CompactTargetDecoder,
    ArrayDecoder<4>, // Nonce
>;

/// The decoder for the [`Header`] type.
///
/// The wire form is self-describing: bit 31 of the version word says whether 80 or
/// [`Header::V2_SIZE`] bytes follow, so the length is only known after the first four bytes.
#[derive(Debug, Clone)]
pub struct HeaderDecoder {
    buf: [u8; Header::V2_SIZE],
    filled: usize,
    /// Total bytes this header needs. `None` until the version word has been read.
    needed: Option<usize>,
}

impl HeaderDecoder {
    /// Constructs a new [`Header`] decoder.
    #[inline]
    pub const fn new() -> Self { Self { buf: [0; Header::V2_SIZE], filled: 0, needed: None } }

    /// Copies up to `needed - filled` bytes out of `bytes`, advancing it past what it consumed.
    fn take(&mut self, needed: usize, bytes: &mut &[u8]) {
        let take = core::cmp::min(needed - self.filled, bytes.len());
        self.buf[self.filled..self.filled + take].copy_from_slice(&bytes[..take]);
        self.filled += take;
        *bytes = &bytes[take..];
    }

    #[inline]
    fn from_inner(e: <HeaderInnerDecoder as encoding::Decoder>::Error) -> HeaderDecoderError {
        match e {
            encoding::Decoder6Error::First(e) => HeaderDecoderError::Version(e),
            encoding::Decoder6Error::Second(e) => HeaderDecoderError::PrevBlockhash(e),
            encoding::Decoder6Error::Third(e) => HeaderDecoderError::MerkleRoot(e),
            encoding::Decoder6Error::Fourth(e) => HeaderDecoderError::Time(e),
            encoding::Decoder6Error::Fifth(e) => HeaderDecoderError::Bits(e),
            encoding::Decoder6Error::Sixth(e) => HeaderDecoderError::Nonce(e),
        }
    }
}

impl Default for HeaderDecoder {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for HeaderDecoder {
    type Output = Header;
    type Error = HeaderDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        // The version word decides the length, so it has to be read before anything else.
        if self.needed.is_none() {
            self.take(4, bytes);
            if self.filled < 4 {
                return Ok(encoding::DecoderStatus::NeedsMore);
            }
            let version = u32::from_le_bytes(self.buf[..4].try_into().expect("4 bytes"));
            self.needed = Some(if version & Header::V2_VERSION_FLAG != 0 {
                Header::V2_SIZE
            } else {
                Header::SIZE
            });
        }

        let needed = self.needed.expect("set just above");
        self.take(needed, bytes);
        if self.filled < needed {
            Ok(encoding::DecoderStatus::NeedsMore)
        } else {
            Ok(encoding::DecoderStatus::Ready)
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        // Replay the base 80 bytes through the field decoders so that a truncated header reports
        // the field it was truncated in, exactly as it did before extended headers existed.
        let mut inner = HeaderInnerDecoder::new(
            VersionDecoder::new(),
            BlockHashDecoder::new(),
            TxMerkleNodeDecoder::new(),
            BlockTimeDecoder::new(),
            CompactTargetDecoder::new(),
            ArrayDecoder::new(),
        );
        let mut base = &self.buf[..core::cmp::min(self.filled, Header::SIZE)];
        let _ = inner.push_bytes(&mut base).map_err(Self::from_inner)?;
        let (version, prev_blockhash, merkle_root, time, bits, nonce) =
            inner.end().map_err(Self::from_inner)?;
        let nonce = u32::from_le_bytes(nonce);

        // Past the hardfork bit 31 announces the header form rather than belonging to the version.
        // The cast reinterprets the bits; `Version` is signed only for historical reasons.
        let version = Version::from_consensus(
            (version.to_consensus() as u32 & !Header::V2_VERSION_FLAG) as i32,
        );

        let v2 = if self.needed == Some(Header::V2_SIZE) {
            let mut tail = ArrayDecoder::<{ HeaderV2::EXTRA_SIZE }>::new();
            let mut extra = &self.buf[Header::SIZE..self.filled];
            let _ = tail.push_bytes(&mut extra).map_err(HeaderDecoderError::V2Fields)?;
            Some(HeaderV2::read_extra(&tail.end().map_err(HeaderDecoderError::V2Fields)?))
        } else {
            None
        };

        let mut header = Header { version, prev_blockhash, merkle_root, time, bits, nonce, v2 };
        // `time` on the wire is the effective time less the offset, when the offset is in use.
        if let Some(v2) = header.v2 {
            if v2.flags & HeaderV2::USE_TIME_OFFSET != 0 {
                header.time = BlockTime::from_u32(time.to_u32().wrapping_add(v2.time_offset));
            }
        }
        Ok(header)
    }

    #[inline]
    fn read_limit(&self) -> usize { self.needed.unwrap_or(4) - self.filled }
}

impl From<Header> for BlockHash {
    #[inline]
    fn from(header: Header) -> Self { header.block_hash() }
}

impl From<&Header> for BlockHash {
    #[inline]
    fn from(header: &Header) -> Self { header.block_hash() }
}

/// The extra fields carried by an extended (164 byte) block header.
///
/// After the `BLAKE2b` proof-of-work hardfork a header may carry 84 bytes beyond the historical 80.
/// The extended form is announced by bit 31 of the header's version word, so a header is
/// self-describing and nothing keys off the block height. Below the activation height headers stay
/// 80 bytes and byte identical to what they always were.
///
/// The blob fields are held in wire (little endian) byte order, the same way [`BlockHash`] holds
/// its bytes.
///
/// # Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoinknots/bitcoin/blob/v29.4.1.knots20260508/src/primitives/block.h)
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
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

    /// The number of bytes an extended header adds to [`Header::SIZE`].
    // (nonce2, nonce3, extranonce, time_offset, txcount, flags, xor_key_mask_clear_bits, xor_key,
    // height, mm_rhs)
    pub const EXTRA_SIZE: usize = 4 + 4 + 16 + 4 + 2 + 1 + 1 + 16 + 4 + 32; // 84

    /// Returns the ASIC layout profile, which selects how the second `BLAKE2b` input is laid out.
    #[inline]
    pub const fn asic_profile(&self) -> u8 { self.flags & 3 }

    fn write_extra(&self, out: &mut [u8; Self::EXTRA_SIZE]) {
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
    }

    fn read_extra(buf: &[u8; Self::EXTRA_SIZE]) -> Self {
        // Every slice below is a fixed sub-range of a fixed size array, so no conversion can fail.
        Self {
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

/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if the version bits are
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// # Relevant BIPs
///
/// * [BIP-0009 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP-0034 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-0034 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-0009 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-0009 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Constructs a new [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    #[inline]
    pub const fn from_consensus(v: i32) -> Self { Self(v) }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    #[inline]
    pub const fn to_consensus(self) -> i32 { self.0 }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-0009 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(self, bit: u8) -> bool {
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

impl fmt::Display for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl fmt::LowerHex for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

impl fmt::UpperHex for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

impl fmt::Octal for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Octal::fmt(&self.0, f) }
}

impl fmt::Binary for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Binary::fmt(&self.0, f) }
}

impl Default for Version {
    #[inline]
    fn default() -> Self { Self::NO_SOFT_FORK_SIGNALLING }
}

impl encoding::Encode for Version {
    type Encoder<'e> = VersionEncoder<'e>;
    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        VersionEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus().to_le_bytes(),
        ))
    }
}

impl encoding::Decode for Version {
    type Decoder = VersionDecoder;
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`Version`] type.
    #[derive(Debug, Clone)]
    pub struct VersionEncoder<'e>(encoding::ArrayEncoder<4>);
}

crate::decoder_newtype! {
    /// The decoder for the [`Version`] type.
    #[derive(Debug, Clone)]
    pub struct VersionDecoder(encoding::ArrayDecoder<4>);

    /// Constructs a new [`Version`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }

    fn end(result: Result<[u8; 4], encoding::UnexpectedEofError>) -> Result<Version, VersionDecoderError> {
        let value = result.map_err(VersionDecoderError)?;
        let n = i32::from_le_bytes(value);
        Ok(Version::from_consensus(n))
    }
}

/// Error types for Bitcoin blocks.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    use crate::merkle_tree::TxMerkleNodeDecoderError;
    use crate::pow::CompactTargetDecoderError;
    use crate::time::BlockTimeDecoderError;

    #[rustfmt::skip]                // Keep public re-exports separate.
    #[doc(no_inline)]
    pub use units::block::{BlockHeightDecoderError, TooBigForRelativeHeightError};
    #[doc(inline)]
    pub use crate::hash_types::BlockHashDecoderError;

    /// An error consensus decoding a [`Block`].
    ///
    /// [`Block`]: super::Block
    #[cfg(feature = "alloc")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BlockDecoderError(pub(super) <super::BlockInnerDecoder as encoding::Decoder>::Error);

    #[cfg(feature = "alloc")]
    impl From<Infallible> for BlockDecoderError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    #[cfg(feature = "alloc")]
    impl fmt::Display for BlockDecoderError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "block decoder error"; self.0)
        }
    }

    #[cfg(feature = "alloc")]
    #[cfg(feature = "std")]
    impl std::error::Error for BlockDecoderError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// Invalid block error.
    #[cfg(feature = "alloc")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum InvalidBlockError {
        /// Header Merkle root does not match the calculated Merkle root.
        InvalidMerkleRoot,
        /// The witness commitment in coinbase transaction does not match the calculated `witness_root`.
        InvalidWitnessCommitment,
        /// Block has no transactions (missing coinbase).
        NoTransactions,
        /// The first transaction is not a valid coinbase transaction.
        InvalidCoinbase,
    }

    #[cfg(feature = "alloc")]
    impl From<Infallible> for InvalidBlockError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    #[cfg(feature = "alloc")]
    impl fmt::Display for InvalidBlockError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::InvalidMerkleRoot =>
                    write!(f, "header Merkle root does not match the calculated Merkle root"),
                Self::InvalidWitnessCommitment => write!(f, "the witness commitment in coinbase transaction does not match the calculated witness_root"),
                Self::NoTransactions => write!(f, "block has no transactions (missing coinbase)"),
                Self::InvalidCoinbase =>
                    write!(f, "the first transaction is not a valid coinbase transaction"),
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[cfg(feature = "std")]
    impl std::error::Error for InvalidBlockError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::InvalidMerkleRoot => None,
                Self::InvalidWitnessCommitment => None,
                Self::NoTransactions => None,
                Self::InvalidCoinbase => None,
            }
        }
    }

    /// An error consensus decoding a [`Header`].
    ///
    /// [`Header`]: super::Header
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum HeaderDecoderError {
        /// Error while decoding the `version`.
        Version(VersionDecoderError),
        /// Error while decoding the `prev_blockhash`.
        PrevBlockhash(BlockHashDecoderError),
        /// Error while decoding the `merkle_root`.
        MerkleRoot(TxMerkleNodeDecoderError),
        /// Error while decoding the `time`.
        Time(BlockTimeDecoderError),
        /// Error while decoding the `bits`.
        Bits(CompactTargetDecoderError),
        /// Error while decoding the `nonce`.
        Nonce(encoding::UnexpectedEofError),
        /// Error while decoding the extended header fields.
        V2Fields(encoding::UnexpectedEofError),
    }

    impl From<Infallible> for HeaderDecoderError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for HeaderDecoderError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Self::Version(ref e) => write_err!(f, "header decoder error"; e),
                Self::PrevBlockhash(ref e) => write_err!(f, "header decoder error"; e),
                Self::MerkleRoot(ref e) => write_err!(f, "header decoder error"; e),
                Self::Time(ref e) => write_err!(f, "header decoder error"; e),
                Self::Bits(ref e) => write_err!(f, "header decoder error"; e),
                Self::Nonce(ref e) => write_err!(f, "header decoder error"; e),
                Self::V2Fields(ref e) => write_err!(f, "header decoder error"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for HeaderDecoderError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match *self {
                Self::Version(ref e) => Some(e),
                Self::PrevBlockhash(ref e) => Some(e),
                Self::MerkleRoot(ref e) => Some(e),
                Self::Time(ref e) => Some(e),
                Self::Bits(ref e) => Some(e),
                Self::Nonce(ref e) => Some(e),
                Self::V2Fields(ref e) => Some(e),
            }
        }
    }

    /// An error consensus decoding a [`Version`].
    ///
    /// [`Version`]: super::Version
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VersionDecoderError(pub(super) encoding::UnexpectedEofError);

    impl From<Infallible> for VersionDecoderError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for VersionDecoderError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "version decoder error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for VersionDecoderError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for Block {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let header = Header::arbitrary(u)?;
        let transactions = Vec::<Transaction>::arbitrary(u)?;
        Ok(Self::new_unchecked(header, transactions))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Header {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: Version::arbitrary(u)?,
            prev_blockhash: BlockHash::from_byte_array(u.arbitrary()?),
            merkle_root: TxMerkleNode::from_byte_array(u.arbitrary()?),
            time: u.arbitrary()?,
            bits: CompactTarget::from_consensus(u.arbitrary()?),
            nonce: u.arbitrary()?,
            v2: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for HeaderV2 {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            nonce2: u.arbitrary()?,
            nonce3: u.arbitrary()?,
            extranonce: u.arbitrary()?,
            time_offset: u.arbitrary()?,
            txcount: u.arbitrary()?,
            flags: u.arbitrary()?,
            xor_key_mask_clear_bits: u.arbitrary()?,
            xor_key: u.arbitrary()?,
            height: u.arbitrary()?,
            mm_rhs: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Version {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Equally weight known versions and arbitrary versions
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => Ok(Self::ONE),
            1 => Ok(Self::TWO),
            2 => Ok(Self::NO_SOFT_FORK_SIGNALLING),
            _ => Ok(Self::from_consensus(u.arbitrary()?)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;
    #[cfg(feature = "alloc")]
    use alloc::{format, vec};
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    use core::str::FromStr as _;

    #[cfg(feature = "alloc")]
    use encoding::Decode as _;
    use encoding::{check_encode, Decoder as _};
    #[cfg(feature = "hex")]
    use hex::hex;
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

    use super::*;

    fn dummy_header() -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0x77; 32]),
            time: BlockTime::from(2),
            bits: CompactTarget::from_consensus(3),
            nonce: 4,
            v2: None,
        }
    }

    #[test]
    fn version_is_not_signalling_with_invalid_bit() {
        let arbitrary_version = Version::from_consensus(1_234_567_890);
        // The max bit number to signal is 28.
        assert!(!Version::is_signalling_soft_fork(arbitrary_version, 29));
    }

    #[test]
    fn version_is_not_signalling_when_use_version_bit_not_set() {
        let version = Version::from_consensus(0b0100_0000_0000_0000_0000_0000_0000_0000);
        // Top three bits must be 001 to signal.
        assert!(!Version::is_signalling_soft_fork(version, 1));
    }

    #[test]
    fn version_is_signalling() {
        let version = Version::from_consensus(0b0010_0000_0000_0000_0000_0000_0000_0010);
        assert!(Version::is_signalling_soft_fork(version, 1));
        let version = Version::from_consensus(0b0011_0000_0000_0000_0000_0000_0000_0000);
        assert!(Version::is_signalling_soft_fork(version, 28));
    }

    #[test]
    fn version_is_not_signalling() {
        let version = Version::from_consensus(0b0010_0000_0000_0000_0000_0000_0000_0010);
        assert!(!Version::is_signalling_soft_fork(version, 0));
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x2000_0000u32 ^ (1 << i)) as i32;
            let version = Version::from_consensus(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version::from_consensus(0x2000_0000 ^ (1 << 1));
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }

    #[test]
    fn version_to_consensus() {
        let version = Version::from_consensus(1_234_567_890);
        assert_eq!(version.to_consensus(), 1_234_567_890);
    }

    #[test]
    fn version_default() {
        let version = Version::default();
        assert_eq!(version.to_consensus(), Version::NO_SOFT_FORK_SIGNALLING.to_consensus());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn version_display() {
        let version = Version(75);
        assert_eq!(format!("{}", version), "75");
        assert_eq!(format!("{:x}", version), "4b");
        assert_eq!(format!("{:#x}", version), "0x4b");
        assert_eq!(format!("{:X}", version), "4B");
        assert_eq!(format!("{:#X}", version), "0x4B");
        assert_eq!(format!("{:o}", version), "113");
        assert_eq!(format!("{:#o}", version), "0o113");
        assert_eq!(format!("{:b}", version), "1001011");
        assert_eq!(format!("{:#b}", version), "0b1001011");
    }

    // Check that the size of the header consensus serialization matches the const SIZE value
    #[test]
    fn header_size() {
        let header = dummy_header();

        // Calculate the size of the block header in bytes from the sum of the serialized lengths
        // its fields: version, prev_blockhash, merkle_root, time, bits, nonce.
        let header_size = header.version.to_consensus().to_le_bytes().len()
            + header.prev_blockhash.as_byte_array().len()
            + header.merkle_root.as_byte_array().len()
            + header.time.to_u32().to_le_bytes().len()
            + header.bits.to_consensus_u32().to_le_bytes().len()
            + header.nonce.to_le_bytes().len();

        assert_eq!(header_size, Header::SIZE);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_new_unchecked() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions.clone());
        assert_eq!(block.header, header);
        assert_eq!(block.transactions, transactions);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_assume_checked() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions.clone());
        let witness_root = Some(WitnessMerkleNode::from_byte_array([0x88; 32]));
        let checked_block = block.assume_checked(witness_root);
        assert_eq!(checked_block.header(), &header);
        assert_eq!(checked_block.transactions(), &transactions);
        assert_eq!(checked_block.cached_witness_root(), witness_root);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_into_parts() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions.clone());
        let (block_header, block_transactions) = block.into_parts();
        assert_eq!(block_header, header);
        assert_eq!(block_transactions, transactions);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_as_parts() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions.clone());
        let (block_header, block_transactions) = block.as_parts();
        assert_eq!(block_header, &header);
        assert_eq!(block_transactions, &transactions);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_cached_witness_root() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions);
        let witness_root = Some(WitnessMerkleNode::from_byte_array([0x88; 32]));
        let checked_block = block.assume_checked(witness_root);
        assert_eq!(checked_block.cached_witness_root(), witness_root);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_validation_no_transactions() {
        let header = dummy_header();
        let transactions = Vec::new(); // Empty transactions

        let block = Block::new_unchecked(header, transactions);
        let err = block.validate().unwrap_err();
        assert_eq!(err, InvalidBlockError::NoTransactions);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_validation_invalid_coinbase() {
        let header = dummy_header();

        // Create a non-coinbase transaction (has a real previous output, not all zeros)
        let non_coinbase_tx = Transaction {
            version: crate::transaction::Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn {
                previous_output: crate::OutPoint {
                    txid: crate::Txid::from_byte_array([1; 32]), // Not all zeros
                    vout: 0,
                },
                script_sig: crate::ScriptSigBuf::new(),
                sequence: units::Sequence::ENABLE_LOCKTIME_AND_RBF,
                witness: crate::Witness::new(),
            }],
            outputs: vec![crate::TxOut {
                amount: units::Amount::ONE_BTC,
                script_pubkey: crate::ScriptPubKeyBuf::new(),
            }],
        };

        let transactions = vec![non_coinbase_tx];
        let block = Block::new_unchecked(header, transactions);

        let err = block.validate().unwrap_err();
        assert_eq!(err, InvalidBlockError::InvalidCoinbase);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_decoder_read_limit() {
        let mut coinbase_in = crate::TxIn::EMPTY_COINBASE;
        coinbase_in.script_sig = crate::ScriptSigBuf::from_bytes(vec![0u8; 2]);

        let block = Block::new_unchecked(
            dummy_header(),
            vec![Transaction {
                version: crate::transaction::Version::ONE,
                lock_time: crate::absolute::LockTime::ZERO,
                inputs: vec![coinbase_in],
                outputs: vec![crate::TxOut {
                    amount: units::Amount::MIN,
                    script_pubkey: crate::ScriptPubKeyBuf::new(),
                }],
            }],
        );

        let bytes = encoding::encode_to_vec(&block);
        let mut view = bytes.as_slice();

        let mut decoder = Block::decoder();
        assert!(decoder.read_limit() > 0);
        let status = decoder.push_bytes(&mut view).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
        assert_eq!(decoder.end().unwrap(), block);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_decoder_new() {
        let decoder = BlockDecoder::new();
        assert!(decoder.read_limit() > 0);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_decoder_default() {
        let decoder = BlockDecoder::default();
        assert!(decoder.read_limit() > 0);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn header_decoder_read_limit() {
        let header = dummy_header();
        let bytes = encoding::encode_to_vec(&header);
        let mut view = bytes.as_slice();

        let mut decoder = Header::decoder();
        assert!(decoder.read_limit() > 0);
        let status = decoder.push_bytes(&mut view).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
        assert_eq!(decoder.end().unwrap(), header);
    }

    #[test]
    fn header_decoder_new() {
        let decoder = HeaderDecoder::new();
        assert!(decoder.read_limit() > 0);
    }

    #[test]
    fn header_decoder_default() {
        let decoder = HeaderDecoder::default();
        assert!(decoder.read_limit() > 0);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_check_witness_commitment_optional() {
        // Valid block with optional witness commitment
        let mut header = dummy_header();
        header.merkle_root = TxMerkleNode::from_byte_array([0u8; 32]);
        let coinbase = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![],
        };

        let transactions = vec![coinbase];
        let block = Block::new_unchecked(header, transactions);

        let result = block.check_witness_commitment();
        assert_eq!(result, (true, None));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_rejects_empty_coinbase_witness_commitment() {
        let mut script = Vec::from(WITNESS_COMMITMENT_MAGIC);
        script.extend_from_slice(&[0; 32]);

        let coinbase = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::ZERO,
                script_pubkey: crate::script::ScriptBuf::from_bytes(script),
            }],
        };

        let transactions = vec![coinbase];
        let mut header = dummy_header();
        header.merkle_root = compute_merkle_root(&transactions).unwrap();

        let block = Block::new_unchecked(header, transactions);
        assert_eq!(block.check_witness_commitment(), (false, None));
        assert!(matches!(block.validate(), Err(InvalidBlockError::InvalidWitnessCommitment)));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_block_hash() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions);
        assert_eq!(block.block_hash(), header.block_hash());
    }

    #[test]
    fn block_hash_from_header() {
        let header = dummy_header();
        let block_hash = header.block_hash();
        assert_eq!(block_hash, BlockHash::from(header));
    }

    #[test]
    fn block_hash_from_header_ref() {
        let header = dummy_header();
        let block_hash: BlockHash = BlockHash::from(&header);
        assert_eq!(block_hash, header.block_hash());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_hash_from_block() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions);
        let block_hash: BlockHash = BlockHash::from(block);
        assert_eq!(block_hash, header.block_hash());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_hash_from_block_ref() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions);
        let block_hash: BlockHash = BlockHash::from(&block);
        assert_eq!(block_hash, header.block_hash());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn header_debug() {
        let header = dummy_header();
        let expected = format!(
            "Header {{ block_hash: {:?}, version: {:?}, prev_blockhash: {:?}, merkle_root: {:?}, time: {:?}, bits: {:?}, nonce: {:?}, v2: {:?} }}",
            header.block_hash(),
            header.version,
            header.prev_blockhash,
            header.merkle_root,
            header.time,
            header.bits,
            header.nonce,
            header.v2
        );
        assert_eq!(format!("{:?}", header), expected);
    }

    #[test]
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    fn header_display() {
        let seconds: u32 = 1_653_195_600; // Arbitrary timestamp: May 22nd, 5am UTC.

        let header = Header {
            version: Version::TWO,
            prev_blockhash: BlockHash::from_byte_array([0xab; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0xcd; 32]),
            time: BlockTime::from(seconds),
            bits: CompactTarget::from_consensus(0xbeef),
            nonce: 0xcafe,
            v2: None,
        };

        let want = concat!(
            "02000000",                                                         // version
            "abababababababababababababababababababababababababababababababab", // prev_blockhash
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", // merkle_root
            "50c38962",                                                         // time
            "efbe0000",                                                         // bits
            "feca0000",                                                         // nonce
        );
        assert_eq!(want.len(), 160);
        assert_eq!(format!("{}", header), want);

        // Check how formatting options are handled.
        let want = format!("{:.20}", want);
        let got = format!("{:.20}", header);
        assert_eq!(got, want);

        let want = format!("{:.0}", want);
        let got = format!("{:.0}", header);
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    fn header_hex() {
        let header = dummy_header();

        let lower_hex = concat!(
            "01000000",                                                         // version
            "9999999999999999999999999999999999999999999999999999999999999999", // prev_blockhash
            "7777777777777777777777777777777777777777777777777777777777777777", // merkle_root
            "02000000",                                                         // time
            "03000000",                                                         // bits
            "04000000",                                                         // nonce
        );

        // All of these should yield a lowercase hex
        assert_eq!(lower_hex, format!("{:x}", header));
        assert_eq!(lower_hex, format!("{}", header));

        // And these should yield uppercase hex
        let upper_hex = lower_hex.to_ascii_uppercase();
        assert_eq!(upper_hex, format!("{:X}", header));

        // Check padding (right, left, center, custom char)
        assert_eq!(format!("{:>164}", lower_hex), format!("{:>164x}", header));
        assert_eq!(format!("{:<164}", lower_hex), format!("{:<164x}", header));
        assert_eq!(format!("{:^164}", lower_hex), format!("{:^164x}", header));
        assert_eq!(format!("{:_>164}", lower_hex), format!("{:_>164x}", header));

        // Alt forms
        let lower_hex_alt = format!("0x{}", lower_hex);
        assert_eq!(lower_hex_alt, format!("{:#x}", header));
        assert_eq!(format!("0X{}", upper_hex), format!("{:#X}", header));

        // Alternate + padding
        assert_eq!(format!("{:>166}", lower_hex_alt), format!("{:>#166x}", header));
        assert_eq!(format!("{:<166}", lower_hex_alt), format!("{:<#166x}", header));
        assert_eq!(format!("{:^166}", lower_hex_alt), format!("{:^#166x}", header));

        // Alt + truncate
        assert_eq!(format!("{:>.20}", lower_hex_alt), format!("{:>#.20x}", header));
        assert_eq!(format!("{:<.20}", lower_hex_alt), format!("{:<#.20x}", header));
        assert_eq!(format!("{:^.20}", lower_hex_alt), format!("{:^#.20x}", header));
    }

    #[test]
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    fn header_from_hex_str_round_trip() {
        // Create a header and convert it to a hex string
        let header = dummy_header();

        let lower_hex_header = format!("{:x}", header);
        let upper_hex_header = format!("{:X}", header);

        // Parse the hex strings back into headers
        let parsed_lower = Header::from_str(&lower_hex_header).unwrap();
        let parsed_upper = Header::from_str(&upper_hex_header).unwrap();

        // The parsed header should match the originals
        assert_eq!(header, parsed_lower);
        assert_eq!(header, parsed_upper);
    }

    #[cfg(feature = "alloc")]
    fn dummy_block() -> Block {
        let header = Header {
            version: Version::ONE,
            #[rustfmt::skip]
            prev_blockhash: BlockHash::from_byte_array([
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
            ]),
            #[rustfmt::skip]
            merkle_root: TxMerkleNode::from_byte_array([
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
            ]),
            time: BlockTime::from(1_742_979_600), // 26 Mar 2025 9:00 UTC
            bits: CompactTarget::from_consensus(12_345_678),
            nonce: 1024,
            v2: None,
        };

        let block: u32 = 741_521;
        let transactions = vec![Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: units::absolute::LockTime::from_height(block).unwrap(),
            inputs: vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint::COINBASE_PREVOUT,
                // Coinbase scriptSig must be 2-100 bytes
                script_sig: crate::script::ScriptSigBuf::from_bytes(vec![0x51, 0x51]),
                sequence: crate::sequence::Sequence::MAX,
                witness: crate::witness::Witness::new(),
            }],
            outputs: vec![crate::transaction::TxOut {
                amount: units::Amount::ONE_SAT,
                script_pubkey: crate::script::ScriptPubKeyBuf::new(),
            }],
        }];
        Block::new_unchecked(header, transactions)
    }

    #[test]
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    fn block_hex() {
        let header = dummy_header();
        let transactions = vec![Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::locktime::absolute::LockTime::ZERO,
            inputs: vec![],
            outputs: vec![],
        }];
        let block = Block::new_unchecked(header, transactions);

        // Transaction with no inputs uses segwit serialization:
        // version (4) + marker (1) + flag (1) + input_count (1) + output_count (1) + lock_time (4)
        let want = "010000009999999999999999999999999999999999999999999999999999999999999999777777777777777777777777777777777777777777777777777777777777777702000000030000000400000001010000000001000000000000";

        assert_eq!(format!("{}", block), want);
        assert_eq!(format!("{:x}", block), want);
        assert_eq!(format!("0x{want}"), format!("{:#x}", block));
        assert_eq!(format!("0X{}", want.to_ascii_uppercase()), format!("{:#X}", block));
        assert_eq!(format!("{:>166}", format!("0x{want}")), format!("{:>#166x}", block));
        assert_eq!(format!("{:.20}", want), format!("{:.20x}", block));

        // Note this is pointless because the hex does not have letters in it, only numbers.
        let want =
            want.chars().map(|chr| chr.to_ascii_uppercase()).collect::<alloc::string::String>();
        assert_eq!(want, format!("{:X}", block));
    }

    #[test]
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    fn block_from_hex_str_round_trip() {
        let block = dummy_block();

        let lower_hex_block = format!("{:x}", block);
        let upper_hex_block = format!("{:X}", block);

        let parsed_lower = Block::from_str(&lower_hex_block).unwrap();
        let parsed_upper = Block::from_str(&upper_hex_block).unwrap();

        assert_eq!(parsed_lower, block);
        assert_eq!(parsed_upper, block);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_decode() {
        let original = dummy_block();

        let encoded = encoding::encode_to_vec(&original);
        let decoded: Block = encoding::decode_from_slice(encoded.as_slice()).unwrap();

        assert_eq!(decoded, original);
    }

    // Test vector provided by tm0 in issue #5023
    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn merkle_tree_hash_collision() {
        // https://learnmeabitcoin.com/explorer/block/00000000000008a662b4a95a46e4c54cb04852525ac0ef67d1bcac85238416d4
        // this block has 7 transactions
        const BLOCK_128461_HEX: &str = "01000000166208c96de305f2a304130a1b53727abf8fb77e8a3cfe2a831e000000000000d4fd086755b4d46221362a09a4228bed60d729d22362b87803ff44b72c138ec04a8ce94d2194261af9551f720701000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08042194261a026005ffffffff018076242a01000000434104390e51c3d66d5ee10327395872e33bc232e9e1660225c9f88fa594fdcdcd785d86b1152fb380a63cdf57d8cf2345a55878412a6864656b158704e0b734b3fd9dac000000000100000001f591edc180a889b21a45b6bd5b5e0017d4137dae9695703107ac1e6e878c9f02000000008b483045022100e066df28b29bf18bfcd8da11ea576a6f502f59e7b1d37e2e849ee4648008962b022023be840ec01ffa6860b5577bf0b8546541f40c287eb57b8b421a1396c7aea583014104add16286f51f68cee1b436d0c29a41a59fa8bd224eb6bec34b073512303c70fc3d630cb4952416ef02340c56bee2eef294659b4023ea8a3d90a297bdb54321f9ffffffff02508470b5000000001976a91472579bbeaeca0802fde07ce88f946b64da63989388ac40aeeb02000000001976a914d2a7410246b5ece345aa821af89bff0b6fa3bcaa88ac0000000001000000016197cb143d4cef51389076fdee3f62c294b65bc9aff217a6c71b9dd987e22754000000008c493046022100bf174e942e4619f4e470b5d8b1c0c8ded9e2f7a6616c073c5ab05cc9d699ede3022100a642fa9d0bcc89523635f9468e4813a120b233a249678de0ebf7ba398a4205f6014104122979c0ac1c3af2aa84b4c1d6a9b3b6fa491827f1a2ba37c4b58bdecd644438da715497a44b16aedbadbd18cf9765cdb36851284f643ed743c4365798dd314affffffff02c0404384000000001976a91443cd8fbad7421a53f9e899a2c9761259705d465b88acc0f4f50e000000001976a9142f6c963506b0a2c93a09a92171957e9e7e11a7a388ac00000000010000000228a11f953c26d558a8299ad9dc61279d7abc9a4059820b614bf403c05e471c481d0000008b48304502205baff189016e6fee8e0faa9eebdc8f150d2d3815007719ceccabd995607bb0b0022100f4cc49ef0b29561e976bf6f6f7ae135f665b8dd38a67634bb6bbe74c0da9c1f7014104dd5920aedc3f79ace9c8061f3724812f5b218ea81d175dd990071175874d6c79025f9db516ab23975e510645aabc4ee699cc5c24358a403d15a7736a504399f8ffffffff191b06773a7cec0bb30539f185edbf1d139f9756071c6ae395c1c29f3e2484f6010000008c493046022100c7123436476f923cd8dacbe132f5128b529baa194c9aedc570402d8d2d7902ac02210094e6974695265d96d5859ab493df00c90b62a84dcc33a05753aea23b38c249670141041d878bc5438ff439490e71d059e6b687e511336c0aa53e0d129663c91db71cfe20008891f1e4780bf1139ec9c9e81bfd2e3ea9009608a78d96a5a3a5bf7812baffffffff0200093d00000000001976a914fd0d4c3d0963db8358bd01ba6f386d4c5ef2e30288ac0084d717000000001976a914dcb1e8e699eb9f07a1ddfd5d764aa74359ddd93088ac00000000010000000118e2286c42643e6146669b0f5ee35454fe256aac2b1401dbeefd941f2e6d2074000000008b483045022100edec1c5078fed29d808282d62f167eb3f0ea6a6655f3869c12eca9c63d8463c2022031a3ae430be137932059b4a3e3fb7f1e1f2a05065dbc47c3142972de45c76daa01410423162e5ac10ec46c4a142fea3197cc66e614b9f28f014882ebc8271c4ab6022e474ccdc246445dd2479f9de217e8aaf4d770da15aff1078d329c02e0f4de8d77ffffffff02b00ac165000000001976a914f543a7f0dfcd621a05c646810ba94da791ed14c488ac80de8002000000001976a9144763f6309b3aca0bff49ed6365ffbd791b1afc5d88ac0000000001000000014e3632994e6cbcae4122bf9e8de242aa1d7c13bf6d045392fa69fa92353f13cf000000008c493046022100c6879938322e9945dae2404a2b104b534df7fdab5927a30a57a12418d619c3b8022100c53331f402010cbdc8297d7a827154e42263fc2f6cef6e56b85bbc061d5e30810141047e717e70b8c5e928bc2c482662dbe9007113f7a5fb0360da1d2f193add960fed97ab3163e85c02b127829d694ab4a796326918d4f639d0b19345f7558406667dffffffff0270c8b165000000001976a9146c908731300d5c0a4215ba3bb3041b4f313d14f688ac40420f00000000001976a91457b01e2a6bf178a10a0e36cd3e301a41ac58b68b88ac000000000100000001a2e94f26db15d7098104a3616b650cc7490eca961a23111c12c3d94f593ab3bc000000008c493046022100b355076f2c956d7565d44fdf589ebdbdff70abcd806c71845b47d31c3579cbc00221008352a03c5276ba481ae92a2327307ad1ce9b234be7386c105fb914ceb9c63341014104872ee8390f11c8ac309df772362614ff7c99f98e1fd68888c5e8765d630c93ae86fcd33922b17f5da490ea14a9f9002ef4e7fb11166ba399f9794296ca02e401ffffffff02f07d5460000000001976a914ff1da11fbd50b9906e78c694169c19902d2ee20388ac804a5d05000000001976a91444d5774b8277c59a07ed9dce1225e2d24a3faab188ac00000000";
        let bytes = hex::decode_to_array::<1948>(BLOCK_128461_HEX).unwrap();
        let valid_block: Block<Unchecked> = encoding::decode_from_slice(&bytes).unwrap();
        let (header, mut transactions) = valid_block.clone().into_parts();
        transactions.push(transactions[6].clone());
        let forged_block = Block::new_unchecked(header, transactions);

        assert!(valid_block.validate().is_ok());
        assert!(forged_block.validate().is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn witness_commitment_from_coinbase_simple() {
        // Add witness commitment to the coinbase
        let mut pubkey_bytes = [0; 38];
        pubkey_bytes[0..6].copy_from_slice(&WITNESS_COMMITMENT_MAGIC);
        let witness_commitment =
            WitnessCommitment::from_byte_array(pubkey_bytes[6..38].try_into().unwrap());
        let commitment_script = crate::script::ScriptBuf::from_bytes(pubkey_bytes.to_vec());

        // Create a coinbase transaction with witness commitment
        let tx = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: commitment_script,
            }],
        };

        // Test if the witness commitment is extracted properly
        let extracted = witness_commitment_from_coinbase(&tx);
        assert_eq!(extracted, Some(witness_commitment));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn witness_commitment_from_non_coinbase_returns_none() {
        let tx = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn {
                previous_output: crate::OutPoint {
                    txid: crate::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: crate::ScriptSigBuf::new(),
                sequence: units::Sequence::ENABLE_LOCKTIME_AND_RBF,
                witness: crate::Witness::new(),
            }],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::ScriptPubKeyBuf::new(),
            }],
        };

        assert!(witness_commitment_from_coinbase(&tx).is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_check_witness_commitment_empty_script_pubkey() {
        let mut txin = crate::TxIn::EMPTY_COINBASE;
        let push = [11_u8];
        txin.witness.push(push);

        let tx = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![txin],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                // Empty scriptbuf means there is no witness commitment due to no magic bytes.
                script_pubkey: crate::script::ScriptBuf::new(),
            }],
        };

        let block = Block::new_unchecked(dummy_header(), vec![tx]);
        let result = block.check_witness_commitment();
        assert_eq!(result, (false, None)); // (false, None) since there's no valid witness commitment
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_check_witness_commitment_non_coinbase() {
        let tx = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn {
                previous_output: crate::OutPoint {
                    txid: crate::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: crate::ScriptSigBuf::new(),
                sequence: units::Sequence::ENABLE_LOCKTIME_AND_RBF,
                witness: crate::Witness::from_slice(&[&[11_u8; 32][..]]),
            }],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::ScriptPubKeyBuf::new(),
            }],
        };

        let block = Block::new_unchecked(dummy_header(), vec![tx]);
        assert_eq!(block.check_witness_commitment(), (false, None));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_check_witness_commitment_no_transactions() {
        // Test case of block with no transactions
        let empty_block = Block::new_unchecked(dummy_header(), vec![]);
        let result = empty_block.check_witness_commitment();
        assert_eq!(result, (false, None));
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn block_check_witness_commitment_with_witness() {
        let mut txin = crate::TxIn::EMPTY_COINBASE;
        // Single witness item of 32 bytes.
        let witness_bytes: [u8; 32] = [11u8; 32];
        txin.witness.push(witness_bytes);

        // pubkey bytes must match the magic bytes followed by the hash of the witness bytes.
        let script_pubkey_bytes = hex::decode_to_array::<38>(
            "6a24aa21a9ed3cde9e0b9f4ad8f9d0fd66d6b9326cd68597c04fa22ab64b8e455f08d2e31ceb",
        )
        .unwrap();
        let tx1 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![txin],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::from_bytes(script_pubkey_bytes.to_vec()),
            }],
        };

        let tx2 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::new(),
            }],
        };

        let block = Block::new_unchecked(dummy_header(), vec![tx1, tx2]);
        let result = block.check_witness_commitment();

        let exp_bytes = hex::decode_to_array::<32>(
            "fb848679079938b249a12f14b72d56aeb116df79254e17cdf72b46523bcb49db",
        )
        .unwrap();
        let expected = WitnessMerkleNode::from_byte_array(exp_bytes);
        assert_eq!(result, (true, Some(expected)));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_eq() {
        let coinbase = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::new(),
            }],
        };

        let header = dummy_header();
        let other_header = Header { nonce: header.nonce + 1, ..header };

        assert_eq!(
            Block::new_unchecked(header, vec![coinbase.clone()]),
            Block::new_unchecked(header, vec![coinbase.clone()]),
        );

        assert_ne!(
            Block::new_unchecked(header, vec![coinbase.clone()]),
            Block::new_unchecked(other_header, vec![coinbase.clone()]),
        );

        assert_ne!(
            Block::new_unchecked(header, vec![coinbase.clone()]),
            Block::new_unchecked(header, vec![coinbase.clone(), coinbase]),
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn checked_block_eq_ignores_cached_witness_root() {
        let mut txin = crate::TxIn::EMPTY_COINBASE;
        txin.witness.push([11u8; 32]);

        let script_pubkey_bytes = hex::decode_to_array::<38>(
            "6a24aa21a9ed3cde9e0b9f4ad8f9d0fd66d6b9326cd68597c04fa22ab64b8e455f08d2e31ceb",
        )
        .unwrap();
        let tx1 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![txin],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::from_bytes(script_pubkey_bytes.to_vec()),
            }],
        };
        let tx2 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::new(),
            }],
        };

        let transactions = vec![tx1, tx2];
        let mut header = dummy_header();
        header.merkle_root = compute_merkle_root(&transactions).unwrap();
        let block = Block::new_unchecked(header, transactions);

        let validated = block.clone().validate().unwrap();
        assert!(validated.cached_witness_root().is_some());
        let assumed = block.assume_checked(None);
        assert!(assumed.cached_witness_root().is_none());

        assert_eq!(validated.header(), assumed.header());
        assert_eq!(validated.transactions(), assumed.transactions());
        assert_eq!(encoding::encode_to_vec(&validated), encoding::encode_to_vec(&assumed));
        assert_eq!(validated, assumed);
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn block_check_witness_commitment_invalid_witness() {
        let mut txin = crate::TxIn::EMPTY_COINBASE;
        let witness_bytes: [u8; 32] = [11u8; 32];
        // First witness item is 32 bytes, but there are two witness elements.
        txin.witness.push(witness_bytes);
        txin.witness.push([12u8]);

        let script_pubkey_bytes = hex::decode_to_array::<38>(
            "6a24aa21a9ed3cde9e0b9f4ad8f9d0fd66d6b9326cd68597c04fa22ab64b8e455f08d2e31ceb",
        )
        .unwrap();
        let tx1 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![txin],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::from_bytes(script_pubkey_bytes.to_vec()),
            }],
        };

        let tx2 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::new(),
            }],
        };

        let mut header = dummy_header();
        let transactions = vec![tx1, tx2];
        header.merkle_root = compute_merkle_root(&transactions).unwrap();

        let block = Block::new_unchecked(header, transactions);
        assert_eq!(block.check_witness_commitment(), (false, None));
        assert!(matches!(block.validate(), Err(InvalidBlockError::InvalidWitnessCommitment)));
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn block_check_witness_commitment_invalid_commitment() {
        let mut txin = crate::TxIn::EMPTY_COINBASE;
        txin.witness.push([11u8; 32]);

        let mut script_pubkey_bytes = hex::decode_to_array::<38>(
            "6a24aa21a9ed3cde9e0b9f4ad8f9d0fd66d6b9326cd68597c04fa22ab64b8e455f08d2e31ceb",
        )
        .unwrap();
        script_pubkey_bytes[37] ^= 1;

        let tx1 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![txin],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::from_bytes(script_pubkey_bytes.to_vec()),
            }],
        };

        let tx2 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::new(),
            }],
        };

        let block = Block::new_unchecked(dummy_header(), vec![tx1, tx2]);
        assert_eq!(block.check_witness_commitment(), (false, None));
    }

    #[test]
    fn version_encoder_emits_consensus_bytes() {
        let version = Version::from_consensus(123_456_789);

        check_encode(&version, &version.to_consensus().to_le_bytes());
    }

    #[test]
    fn version_decoder_end_and_read_limit() {
        let mut decoder = VersionDecoder::new();
        let bytes_arr = Version::TWO.to_consensus().to_le_bytes();
        let mut bytes = bytes_arr.as_slice();

        assert!(decoder.read_limit() > 0);

        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert!(bytes.is_empty());

        assert_eq!(decoder.read_limit(), 0);
        let decoded = decoder.end().unwrap();
        assert_eq!(decoded, Version::TWO);
    }

    #[test]
    fn version_decoder_default_roundtrip() {
        let version = Version::from_consensus(123_456_789);
        let mut decoder = VersionDecoder::default();
        let consensus = version.to_consensus().to_le_bytes();
        let mut bytes = consensus.as_slice();
        decoder.push_bytes(&mut bytes).unwrap();

        assert_eq!(decoder.end().unwrap(), version);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn version_decodable_decoder() {
        let decoder = Version::decoder();
        assert!(decoder.read_limit() > 0);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_decoder_error() {
        fn is_first(err: &BlockDecoderError) -> bool {
            match err.0 {
                encoding::Decoder2Error::First(_) => true,
                encoding::Decoder2Error::Second(_) => false,
            }
        }

        fn is_second(err: &BlockDecoderError) -> bool {
            match err.0 {
                encoding::Decoder2Error::First(_) => false,
                encoding::Decoder2Error::Second(_) => true,
            }
        }

        let err_first = Block::decoder().end().unwrap_err();
        assert!(is_first(&err_first));
        assert!(!is_second(&err_first));
        assert!(!err_first.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(std::error::Error::source(&err_first).is_some());

        // Provide a complete header and a vec length prefix (1 tx) but omit any tx bytes.
        // This forces the inner VecDecoder to error when finalizing.
        let mut bytes = encoding::encode_to_vec(&dummy_header());
        bytes.push(1u8);
        let mut view = bytes.as_slice();

        let mut decoder = Block::decoder();
        assert!(decoder.push_bytes(&mut view).unwrap().needs_more());
        assert!(view.is_empty());

        let err_second = decoder.end().unwrap_err();
        assert!(is_second(&err_second));
        assert!(!is_first(&err_second));
        assert!(!err_second.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(std::error::Error::source(&err_second).is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn header_decoder_error() {
        let header_bytes = encoding::encode_to_vec(&dummy_header());
        // Number of bytes in the encoding up to the start of each field.
        let lengths = [0usize, 4, 36, 68, 72, 76];

        for &len in &lengths {
            let mut decoder = Header::decoder();
            let mut slice = header_bytes[..len].as_ref();
            decoder.push_bytes(&mut slice).unwrap();
            let err = decoder.end().unwrap_err();
            match len {
                0 => assert!(matches!(err, HeaderDecoderError::Version(_))),
                4 => assert!(matches!(err, HeaderDecoderError::PrevBlockhash(_))),
                36 => assert!(matches!(err, HeaderDecoderError::MerkleRoot(_))),
                68 => assert!(matches!(err, HeaderDecoderError::Time(_))),
                72 => assert!(matches!(err, HeaderDecoderError::Bits(_))),
                76 => assert!(matches!(err, HeaderDecoderError::Nonce(_))),
                _ => unreachable!(),
            }
            assert!(!err.to_string().is_empty());
            #[cfg(feature = "std")]
            assert!(std::error::Error::source(&err).is_some());
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn invalid_block_error() {
        #[cfg(feature = "std")]
        use std::error::Error as _;

        let variants = [
            InvalidBlockError::InvalidMerkleRoot,
            InvalidBlockError::InvalidWitnessCommitment,
            InvalidBlockError::NoTransactions,
            InvalidBlockError::InvalidCoinbase,
        ];

        for variant in variants {
            assert!(!variant.to_string().is_empty());
            #[cfg(feature = "std")]
            assert!(variant.source().is_none());
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn version_decoder_error() {
        let err = VersionDecoder::new().end().unwrap_err();
        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn parse_block_error() {
        let err = Block::from_str("00").unwrap_err();
        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn parse_header_error() {
        let err = Header::from_str("00").unwrap_err();
        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(std::error::Error::source(&err).is_some());
    }

    /// A type that has a `Block` field and a `Header` field.
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    #[cfg(feature = "serde")]
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Adt {
        #[serde(with = "encoding::serde_as_consensus")]
        header: Header,
        #[serde(with = "encoding::serde_as_consensus")]
        block: Block,
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    #[cfg(feature = "serde")]
    fn can_serde_as_consensus_json() {
        let orig = Adt { header: dummy_header(), block: dummy_block() };

        let json = serde_json::to_string(&orig).expect("failed to serialize");

        let want = "{\"header\":\"0100000099999999999999999999999999999999999999999999999999999999999999997777777777777777777777777777777777777777777777777777777777777777020000000300000004000000\",\"block\":\"01000000dcbadcbadcbadcbadcbadcbadcbadcbadcbadcbadcbadcbadcbadcbadcbadcbaabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd10c2e3674e61bc00000400000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff025151ffffffff0101000000000000000091500b00\"}";
        assert_eq!(json, want);

        let roundtrip: Adt = serde_json::from_str(&json).expect("failed to deserialize");
        assert_eq!(roundtrip, orig);
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    #[cfg(feature = "serde")]
    fn can_serde_as_consensus_extended_header() {
        // Wallets persist headers through `serde_as_consensus`, so the extended form has to
        // survive that round trip too. `profile_0_time_offset` from Bitcoin Knots'
        // `src/test/data/block_header_v2.json` at tag v29.4.1.knots20260508.
        const WIRE: &str = "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003001c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab";

        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct Wrapper {
            #[serde(with = "encoding::serde_as_consensus")]
            header: Header,
        }

        let orig = Wrapper { header: WIRE.parse().expect("valid extended header") };
        assert!(orig.header.v2.is_some());

        let json = serde_json::to_string(&orig).expect("failed to serialize");
        assert_eq!(json, alloc::format!("{{\"header\":\"{}\"}}", WIRE));
        let roundtrip: Wrapper = serde_json::from_str(&json).expect("failed to deserialize");
        assert_eq!(roundtrip, orig);

        let bytes = bincode::serialize(&orig).expect("failed to serialize");
        let roundtrip: Wrapper = bincode::deserialize(&bytes).expect("failed to deserialize");
        assert_eq!(roundtrip, orig);
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    #[cfg(feature = "serde")]
    fn can_serde_as_consensus_bincode() {
        let orig = Adt { header: dummy_header(), block: dummy_block() };

        // Bincode is non-human-readable, so it should use bytes
        let bytes = bincode::serialize(&orig).expect("failed to serialize");

        let roundtrip: Adt = bincode::deserialize(&bytes).expect("failed to deserialize");
        assert_eq!(roundtrip, orig);
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn block_version() {
        let block = hex!("ffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode: Result<Block<Unchecked>, _> = encoding::decode_from_slice(&block);
        assert!(decode.is_ok());

        let real_decode = decode.unwrap().assume_checked(None);
        assert_eq!(real_decode.header().version, Version::from_consensus(2_147_483_647));

        // Past the BLAKE2b hardfork bit 31 of the version word announces the extended header
        // form, so this 80 byte input is now a truncated 164 byte header rather than a block
        // whose version happens to be negative.
        let header2 = hex!("00000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assert!(encoding::decode_from_slice::<Header>(&header2).is_err());
    }
}
