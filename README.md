# rust-bitcoin with BLAKE2b proof of work

This is an unofficial fork of [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) that follows the BLAKE2b proof-of-work hardfork of Bitcoin. It is not affiliated with the rust-bitcoin project. Upstream tracks Bitcoin Core consensus and has not adopted the fork, so use upstream instead if that is what you want.

> **Not reviewed by upstream.** It holds no keys and no funds, but wallets trust it for chain data, so a bug in header parsing or the block id means they follow the wrong chain. Everything below the divider is upstream's documentation and describes rust-bitcoin rather than this fork.

## What differs from upstream

- **The extended block header.** `Header` gains an optional `HeaderV2` carrying the 84 bytes an extended header adds to the historical 80. A header announces its own form through bit 31 of the version word, so no activation height is compiled in and nothing keys off the block height.
- **BLAKE2b block ids.** `Header::block_hash()` dispatches: SHA256d for the legacy form, and for the extended form the tagged-hash pipeline and two BLAKE2b passes that Bitcoin Knots uses, laid out by the ASIC profile in the header flags. BLAKE2b-256 lives in `bitcoin_hashes::blake2b`, which this line can do because `bitcoin` depends on the workspace copy.
- **A self-describing codec.** The header length is only known after the version word, so `HeaderEncoder` and `HeaderDecoder` are hand written rather than composed from fixed width field codecs. A truncated header still reports the field it was truncated in.
- **Bit 31 is no longer part of the version.** `Version::from_consensus` masks it off, by every construction path including `Deserialize`, so a header cannot be built that serializes as something other than the value it was made from.
- **Size and weight read the header's real length,** and `Params` gains the activation height and the one-off target shift applied at it.
- **Header form validation.** `Header::validate_form` and `validate_form_at_height` carry the four rules Knots enforces, so a header syncing client can apply them without building a `Block`.

## Branches

| Branch | Base | Use |
| --- | --- | --- |
| `master` | upstream `master` | The 0.33 line. This branch. For when the ecosystem moves off 0.32. |
| `0.32.xx` | upstream `0.32.xx` | The 0.32 line. This is what bdk, bdk_wallet and electrum-client pin, so it is the one in use today. |

The two lines are separate: 0.33 replaced the consensus encoding traits with a push-based codec, so the header work is implemented differently on each and neither merges into the other.

Releases are tagged so a dependent can pin an immutable rev: a moving branch would let consensus code change under a fresh clone.

## Activation

| Network | Height |
| --- | --- |
| mainnet | 961,640 |
| testnet4 | 150,308 |

Listed for reference. Parsing keys off the header itself rather than a height, so it needs no updating if these change. `Params` carries them for the rules that genuinely need chain context.

## Verification

The extended header and its block id are checked against Bitcoin Knots' own test data at tag `v29.4.1.knots20260508`, covering all four ASIC layout profiles, and against 25,000 randomized headers generated from an independent transcription of Knots' `CBlockHeader::GetHash`. The decoder is fuzzed. Both lines produce identical block ids for the same vectors.

---

<div align="center">
  <h1>Rust Bitcoin</h1>

  <img alt="Rust Bitcoin logo by Hunter Trujillo, see license and source files under /logo" src="./logo/rust-bitcoin.png" width="300" />

  <p>Library with support for de/serialization, parsing and executing on data-structures
    and network messages related to Bitcoin.
  </p>

  <p>
    <a href="https://crates.io/crates/bitcoin"><img alt="Crate Info" src="https://img.shields.io/crates/v/bitcoin.svg"/></a>
    <a href="https://github.com/rust-bitcoin/rust-bitcoin/blob/master/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://docs.rs/bitcoin"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-bitcoin-green"/></a>
    <a href="https://blog.rust-lang.org/2023/11/16/Rust-1.74.0/"><img alt="Rustc Version 1.74.0+" src="https://img.shields.io/badge/rustc-1.74.0%2B-lightgrey.svg"/></a>
    <a href="https://gnusha.org/bitcoin-rust/"><img alt="Chat on IRC" src="https://img.shields.io/badge/irc-%23bitcoin--rust%20on%20libera.chat-blue"></a>
  </p>
</div>

Supports (or should support)

* De/serialization of Bitcoin protocol network messages
* De/serialization of blocks and transactions
* Script de/serialization
* Private keys and address creation, de/serialization and validation (including full BIP-0032 support)

For JSONRPC interaction with Bitcoin Core, it is recommended to use
[corepc-client](https://crates.io/crates/corepc-client).

It is recommended to always use [cargo-crev](https://github.com/crev-dev/cargo-crev) to verify the
trustworthiness of each of your dependencies, including this one.

## Known limitations

### Consensus

This library **must not** be used for consensus code (i.e. fully validating blockchain data). It
technically supports doing this, but doing so is very ill-advised because there are many deviations,
known and unknown, between this library and the Bitcoin Core reference implementation. In a
consensus based cryptocurrency, such as Bitcoin, it is critical that all parties are using the same
rules to validate data, and this library is simply unable to implement the same rules as Core.

Given the complexity of both C++ and Rust, it is unlikely that this will ever be fixed, and there
are no plans to do so. Of course, patches to fix specific consensus incompatibilities are welcome.

### Support for 16-bit pointer sizes

16-bit pointer sizes are not supported, and we can't promise they will be. If you care about them
please let us know, so we can know how large the interest is and possibly decide to support them.

### Semver compliance

We try hard to maintain strict semver compliance with our releases. This codebase includes some
public functions marked unstable (e.g., `pub fn foo__unstable()`). These functions do not adhere to
semver rules; use them at your own discretion.


## Documentation

Currently can be found on [docs.rs/bitcoin](https://docs.rs/bitcoin/). Patches to add usage examples
and to expand on existing docs would be extremely appreciated.

## Contributing

Contributions are generally welcome. If you intend to make larger changes please discuss them in an
issue before PRing them to avoid duplicate work and architectural mismatches. If you have any
questions or ideas you want to discuss, please join us in
[#bitcoin-rust](https://web.libera.chat/?channel=#bitcoin-rust) on
[libera.chat](https://libera.chat).

For more information, please see [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features on **Rust 1.74.0**.

Use `Cargo-minimal.lock` to build the MSRV by copying to `Cargo.lock` and building.

## No-std support

The `std` cargo feature is enabled by default. To build this project without the Rust standard
library, use the `--no-default-features` flag or set `default-features = false` in your dependency
declaration when adding it to your project.

For embedded device examples, see [`bitcoin/embedded`](https://github.com/rust-bitcoin/rust-bitcoin/tree/master/bitcoin/embedded)
or [`hashes/embedded`](https://github.com/rust-bitcoin/rust-bitcoin/tree/master/hashes/embedded).

## External dependencies

We integrate with a few external libraries, most notably `serde`. These
are available via feature flags. To ensure compatibility and MSRV stability, we
provide two lock files as a means of inspecting compatible versions:
`Cargo-minimal.lock` containing minimal versions of dependencies and
`Cargo-recent.lock` containing recent versions of dependencies tested in our CI.

We do not provide any guarantees about the content of these lock files outside
of "our CI didn't fail with these versions". Specifically, we do not guarantee
that the committed hashes are free from malware. It is your responsibility to
review them.

## Policy on Altcoins/Altchains

Since the altcoin landscape includes projects which [frequently appear and disappear, and are poorly
designed anyway](https://download.wpsoftware.net/bitcoin/alts.pdf) we do not support any altcoins.
Supporting Bitcoin properly is already difficult enough, and we do not want to increase the
maintenance burden and decrease API stability by adding support for other coins.

Our code is public domain so by all means fork it and go wild :)


## Release Notes

Release notes are done per crate, see:

- [`base58ck`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/base58/CHANGELOG.md)
- [`bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/CHANGELOG.md)
- [`bitcoin-addresses`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/addresses/CHANGELOG.md)
- [`bitcoin-bip158`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bip158/CHANGELOG.md)
- [`bitcoin-consensus-encoding`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/consensus_encoding/CHANGELOG.md)
- [`bitcoin-crypto`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/crypto/CHANGELOG.md)
- [`bitcoin-internals`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/internals/CHANGELOG.md)
- [`bitcoin-io`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/io/CHANGELOG.md)
- [`bitcoin-key-expression`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/key_expression/CHANGELOG.md)
- [`bitcoin-network-kind`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/network/CHANGELOG.md)
- [`bitcoin-p2p-messages`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/p2p/CHANGELOG.md)
- [`bitcoin-primitives`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/primitives/CHANGELOG.md)
- [`bitcoin-taproot-primitives`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/taproot_primitives/CHANGELOG.md)
- [`bitcoin-units`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/units/CHANGELOG.md)
- [`bitcoin_hashes`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/hashes/CHANGELOG.md)
- [`chacha20-poly1305`](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/chacha20_poly1305/CHANGELOG.md)


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
