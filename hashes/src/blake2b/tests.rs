#[test]
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
fn test() {
    use alloc::string::ToString;

    use crate::{blake2b, HashEngine};

    struct Test {
        input: &'static str,
        output_str: &'static str,
    }

    // Vectors computed with the reference BLAKE2b implementation (digest length 32, no key).
    let tests = [
        Test {
            input: "",
            output_str: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        },
        Test {
            input: "abc",
            output_str: "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
        },
        Test {
            input: "The quick brown fox jumps over the lazy dog",
            output_str: "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9",
        },
    ];

    for test in tests {
        let hash = blake2b::Hash::hash(test.input.as_bytes());
        assert_eq!(hash.to_string(), test.output_str);

        // Byte at a time, to exercise the deferred compression of a full buffer.
        let mut engine = blake2b::Hash::engine();
        for byte in test.input.as_bytes() {
            engine.input(&[*byte]);
        }
        assert_eq!(engine.finalize(), hash);
    }
}

#[test]
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
fn block_boundaries() {
    use alloc::string::ToString;
    use alloc::vec;

    use crate::{blake2b, HashEngine};

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
        let input = vec![b'a'; len];
        assert_eq!(blake2b::Hash::hash(&input).to_string(), want, "one shot, len {}", len);

        // Every possible split point must agree with the one-shot result.
        for split in [1, len / 3, len / 2, len - 1] {
            let mut engine = blake2b::Hash::engine();
            engine.input(&input[..split]);
            engine.input(&input[split..]);
            assert_eq!(engine.finalize().to_string(), want, "split {} of len {}", split, len);
        }

        assert_eq!(blake2b::Hash::hash(&input).as_byte_array().len(), blake2b::OUTPUT_SIZE);
    }
}

#[test]
fn n_bytes_hashed() {
    use crate::{blake2b, HashEngine};

    let mut engine = blake2b::HashEngine::new();
    assert_eq!(engine.n_bytes_hashed(), 0);
    engine.input(&[0u8; 200]);
    assert_eq!(engine.n_bytes_hashed(), 200);
    engine.input(&[0u8; 56]);
    assert_eq!(engine.n_bytes_hashed(), 256);
}
