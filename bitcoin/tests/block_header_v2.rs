// SPDX-License-Identifier: CC0-1.0

//! Extended (164 byte) block header vectors.
//!
//! `data/block_header_v2.json` is lifted verbatim from Bitcoin Knots' `src/test/data` at tag
//! `v29.4.1.knots20260508`, the release that schedules the BLAKE2b proof-of-work hardfork. It
//! covers all four ASIC layout profiles, a zero and a non-zero XOR key, and the boundary value of
//! the XOR mask clear-bit count.

use bitcoin::block::{Header, HeaderV2, Version};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};

const VECTORS: &str = include_str!("data/block_header_v2.json");

/// Randomized vectors, generated against an independent transcription of Knots'
/// `CBlockHeader::GetHash` that reproduces every intermediate value in `VECTORS`.
const DIFFERENTIAL: &str = include_str!("data/block_header_v2_differential.json");

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd length hex: {}", s);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}

/// Bitcoin renders hashes and blobs back to front, so a display string is the wire bytes reversed.
fn unhex_display<const N: usize>(s: &str) -> [u8; N] {
    let mut bytes = unhex(s);
    assert_eq!(bytes.len(), N, "wrong length for {}", s);
    bytes.reverse();
    bytes.try_into().expect("length checked above")
}

fn u32_field(v: &serde_json::Value, name: &str) -> u32 {
    u32::try_from(v[name].as_u64().unwrap_or_else(|| panic!("{} missing", name)))
        .unwrap_or_else(|_| panic!("{} out of range", name))
}

#[test]
fn knots_vectors() {
    let json: serde_json::Value = serde_json::from_str(VECTORS).expect("valid JSON");
    let headers = json["headers"].as_array().expect("headers array");
    assert_eq!(headers.len(), 5);

    for vector in headers {
        let name = vector["name"].as_str().expect("name");
        let f = &vector["fields"];

        let want = Header {
            version: Version::from_consensus(
                i32::try_from(f["nVersion"].as_i64().expect("nVersion")).expect("in range"),
            ),
            prev_blockhash: BlockHash::from_byte_array(unhex_display(
                f["hashPrevBlock"].as_str().expect("hashPrevBlock"),
            )),
            merkle_root: TxMerkleNode::from_byte_array(unhex_display(
                f["hashMerkleRoot"].as_str().expect("hashMerkleRoot"),
            )),
            time: u32_field(f, "nTime"),
            bits: CompactTarget::from_consensus(u32_field(f, "nBits")),
            nonce: u32_field(f, "nNonce"),
            v2: Some(HeaderV2 {
                nonce2: u32_field(f, "m_nonce2"),
                nonce3: u32_field(f, "m_nonce3"),
                extranonce: unhex_display(f["m_extranonce"].as_str().expect("m_extranonce")),
                time_offset: u32_field(f, "m_time_offset"),
                txcount: u16::try_from(u32_field(f, "m_txcount")).expect("in range"),
                flags: u8::try_from(u32_field(f, "m_flags")).expect("in range"),
                xor_key_mask_clear_bits: u8::try_from(u32_field(f, "m_xor_key_mask_clear_bits"))
                    .expect("in range"),
                xor_key: unhex_display(f["m_xor_key"].as_str().expect("m_xor_key")),
                height: i32::try_from(f["m_height"].as_i64().expect("m_height")).expect("in range"),
                mm_rhs: unhex_display(f["m_mm_rhs"].as_str().expect("m_mm_rhs")),
            }),
        };

        let wire = unhex(vector["serialized"].as_str().expect("serialized"));
        assert_eq!(wire.len(), Header::V2_SIZE, "{}", name);

        // Decoding the wire form must reproduce every field, including the effective `time`,
        // which the wire carries split between the timestamp and `time_offset`.
        let got: Header = deserialize(&wire).unwrap_or_else(|e| panic!("{}: {}", name, e));
        assert_eq!(got, want, "{}", name);
        assert_eq!(got.size(), Header::V2_SIZE, "{}", name);
        assert_eq!(
            got.complete_version(),
            Header::V2_VERSION_FLAG | u32_field(f, "nVersion"),
            "{}",
            name
        );

        // The BLAKE2b block id.
        assert_eq!(
            got.block_hash().to_string(),
            vector["block_hash"].as_str().expect("block_hash"),
            "{}",
            name
        );

        // And it round-trips byte for byte.
        assert_eq!(serialize(&got), wire, "{}", name);
    }
}

#[test]
fn differential_vectors() {
    let json: serde_json::Value = serde_json::from_str(DIFFERENTIAL).expect("valid JSON");
    let vectors = json["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 160);

    for (i, vector) in vectors.iter().enumerate() {
        let wire = unhex(vector["serialized"].as_str().expect("serialized"));
        let header: Header = deserialize(&wire).expect("decodes");
        assert_eq!(
            header.block_hash().to_string(),
            vector["block_hash"].as_str().expect("block_hash"),
            "vector {}",
            i
        );
        assert_eq!(serialize(&header), wire, "vector {}", i);
    }
}

#[test]
fn v1_header_unchanged() {
    // Mainnet block 100,000. A legacy header must decode, hash and re-serialize exactly as before.
    let wire = unhex(
        "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b5710",
    );
    assert_eq!(wire.len(), Header::SIZE);

    let header: Header = deserialize(&wire).expect("decodes");
    assert_eq!(header.v2, None);
    assert_eq!(header.size(), Header::SIZE);
    assert_eq!(header.version, Version::ONE);
    assert_eq!(header.complete_version(), 1);
    assert_eq!(header.time_on_wire(), header.time);
    assert_eq!(
        header.block_hash().to_string(),
        "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
    );
    assert_eq!(serialize(&header), wire);
}

#[test]
fn truncated_extended_header_is_an_error() {
    let json: serde_json::Value = serde_json::from_str(VECTORS).expect("valid JSON");
    let wire = unhex(json["headers"][0]["serialized"].as_str().expect("serialized"));

    // Anything short of the full 164 bytes must fail rather than being read as an 80 byte header.
    for len in [0, 1, 3, 4, 79, 80, 81, 163] {
        assert!(deserialize::<Header>(&wire[..len]).is_err(), "{} bytes decoded as a header", len);
    }
    assert!(deserialize::<Header>(&wire).is_ok());
}
