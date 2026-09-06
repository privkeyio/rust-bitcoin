
// SPDX-License-Identifier: CC0-1.0

//! A `headers` message may mix legacy and extended block headers.
//!
//! Past the `BLAKE2b` proof-of-work hardfork the entries in a `headers` message are no longer a
//! fixed width, so a peer can send 80 and 164 byte headers in the same message and a reader has
//! to take the length from each header's own version word.

// `bitcoin_p2p_messages::message` is gated on `std`, so this test cannot build without it.
#![cfg(feature = "std")]

use bitcoin_p2p_messages::message::{HeadersMessage, NetworkHeader};
use hex::hex;
use primitives::block::Header;

/// Mainnet block 100,000.
const V1: [u8; 80] = hex!(
    "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b5710"
);

/// `profile_0_time_offset` from Bitcoin Knots' `src/test/data/block_header_v2.json` at tag
/// `v29.4.1.knots20260508`.
const V2: [u8; 164] = hex!(
    "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003001c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab"
);

#[test]
fn headers_message_mixes_header_widths() {
    // The wire form: a compact size count, then each header followed by its zero transaction count.
    let mut wire = vec![4u8];
    for header in [&V1[..], &V2[..], &V2[..], &V1[..]] {
        wire.extend_from_slice(header);
        wire.push(0);
    }

    let message: HeadersMessage = encoding::decode_from_slice(&wire).expect("decodes");
    assert_eq!(message.0.len(), 4);

    let v1: Header = encoding::decode_from_slice(&V1[..]).expect("v1 decodes");
    let v2: Header = encoding::decode_from_slice(&V2[..]).expect("v2 decodes");
    assert_eq!(v1.v2, None);
    assert!(v2.v2.is_some());

    let want = [v1, v2, v2, v1];
    for (got, want) in message.0.iter().zip(want) {
        assert_eq!(got.header, want);
        assert_eq!(got.length, 0);
    }

    // The block ids come out of the two different algorithms.
    assert_eq!(
        message.0[0].header.block_hash().to_string(),
        "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
    );
    assert_eq!(
        message.0[1].header.block_hash().to_string(),
        "4b495dcf05d70a49785b799b22284fbcd9dd1209237c53c87e4674b15587d704"
    );

    // And the message round-trips byte for byte.
    let message = HeadersMessage(want.iter().copied().map(NetworkHeader::from_header).collect());
    assert_eq!(encoding::encode_to_vec(&message), wire);
}

#[test]
fn truncated_extended_header_in_a_headers_message_is_rejected() {
    // A peer that claims an extended header but sends only 80 bytes of it must be an error, not a
    // legacy header followed by garbage.
    let mut wire = vec![1u8];
    wire.extend_from_slice(&V2[..80]);
    wire.push(0);

    assert!(encoding::decode_from_slice::<HeadersMessage>(&wire).is_err());
}
