// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use dusk_bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use sha2::Sha256;

// This backend forwards the upstream dusk types directly. The stable
// backend-portable contract lives in `crate::bls12_381`; any extra inherent
// methods reachable here should be treated as dusk-specific surface.
pub use dusk_bls12_381::{
    BlsScalar, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, GENERATOR, Gt,
    MillerLoopResult, ROOT_OF_UNITY, TWO_ADACITY,
};

#[cfg(feature = "rkyv-impl")]
pub use dusk_bls12_381::{
    ArchivedBlsScalar, ArchivedG1Affine, ArchivedG2Affine, ArchivedG2Prepared, ArchivedGt,
    ArchivedMillerLoopResult, BlsScalarResolver, G1AffineResolver, G2AffineResolver,
    G2PreparedResolver, GtResolver, MillerLoopResultResolver,
};

/// Scalar field element type for this backend.
pub type Scalar = BlsScalar;

#[must_use]
#[inline]
pub fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    Scalar::hash_to_scalar(bytes)
}

#[must_use]
#[inline]
pub fn hash_to_g1(message: &[u8], dst: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, dst)
}

#[must_use]
#[inline]
pub fn hash_to_g2(message: &[u8], dst: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, dst)
}

#[must_use]
#[inline]
pub fn scalar_from_wide(bytes: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_wide(bytes)
}

#[must_use]
#[inline]
pub fn msm_variable_base(points: &[G1Affine], scalars: &[Scalar]) -> G1Projective {
    dusk_bls12_381::multiscalar_mul::msm_variable_base(points, scalars)
}

#[must_use]
#[inline]
pub fn multi_miller_loop_result(terms: &[(&G1Affine, &G2Prepared)]) -> Gt {
    dusk_bls12_381::multi_miller_loop(terms).final_exponentiation()
}

#[must_use]
#[inline]
pub fn pairing_product_is_identity(terms: &[(&G1Affine, &G2Affine)]) -> bool {
    let prepared: Vec<_> = terms
        .iter()
        .map(|(g1, g2)| (**g1, G2Prepared::from(**g2)))
        .collect();
    let refs: Vec<_> = prepared.iter().map(|(g1, g2p)| (g1, g2p)).collect();

    dusk_bls12_381::multi_miller_loop(&refs).final_exponentiation()
        == dusk_bls12_381::Gt::identity()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_bytes::Serializable;

    const G1_RO_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const G2_RO_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);

        let mut out = [0u8; N];
        for (byte, digits) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            *byte = (hex_nibble(digits[0]) << 4) | hex_nibble(digits[1]);
        }
        out
    }

    fn hex_nibble(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    #[test]
    fn g1_generator_serialization_roundtrip() {
        let g = G1Affine::generator();
        let bytes = g.to_bytes();
        let decoded = G1Affine::from_bytes(&bytes).expect("generator should roundtrip");
        assert_eq!(g, decoded);
    }

    #[test]
    fn g2_generator_serialization_roundtrip() {
        let g = G2Affine::generator();
        let bytes = g.to_bytes();
        let decoded = G2Affine::from_bytes(&bytes).expect("generator should roundtrip");
        assert_eq!(g, decoded);
    }

    #[test]
    fn hash_to_scalar_deterministic() {
        let a = hash_to_scalar(b"test-input");
        let b = hash_to_scalar(b"test-input");
        assert_eq!(a, b);
        // Different input gives different output.
        let c = hash_to_scalar(b"other-input");
        assert_ne!(a, c);
    }

    #[test]
    fn hash_to_g1_matches_rfc9380_vectors() {
        for (message, expected_uncompressed) in [
            (
                b"" as &[u8],
                concat!(
                    "052926add2207b76ca4fa57a8734416c8dc95e24501772c8142787",
                    "00eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
                    "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c6",
                    "7e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
                ),
            ),
            (
                b"abc" as &[u8],
                concat!(
                    "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a794",
                    "3388a49a3aee664ba5379a7655d3c68900be2f6903",
                    "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67",
                    "af215533311f0b8dfaaa154fa6b88176c229f2885d",
                ),
            ),
        ] {
            let affine = G1Affine::from(hash_to_g1(message, G1_RO_DST));
            assert_eq!(affine.to_uncompressed(), decode_hex(expected_uncompressed));
        }
    }

    #[test]
    fn hash_to_g2_matches_rfc9380_vectors() {
        for (message, expected_uncompressed) in [
            (
                b"" as &[u8],
                concat!(
                    "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab",
                    "379ba13dff5bf5dd71b72418717047f5b0f37da03d",
                    "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d693352",
                    "66f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
                    "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259d",
                    "dc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
                    "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11",
                    "062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
                ),
            ),
            (
                b"abc" as &[u8],
                concat!(
                    "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9",
                    "eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
                    "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a21",
                    "0245129dbec7780ccc7954725f4168aff2787776e6",
                    "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e",
                    "9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
                    "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea0",
                    "5c4cfe244aeb197642555a0645fb87bf7466b2ba48",
                ),
            ),
        ] {
            let affine = G2Affine::from(hash_to_g2(message, G2_RO_DST));
            assert_eq!(affine.to_uncompressed(), decode_hex(expected_uncompressed));
        }
    }

    #[test]
    fn scalar_from_wide_nonzero() {
        let mut wide = [0u8; 64];
        wide[0] = 1;
        let s = scalar_from_wide(&wide);
        assert_ne!(s, Scalar::zero());
    }

    #[test]
    fn msm_single_point() {
        let g = G1Affine::generator();
        let two = Scalar::from(2u64);
        let result = msm_variable_base(&[g], &[two]);
        let expected = G1Projective::from(g) + G1Projective::from(g);
        assert_eq!(G1Affine::from(result), G1Affine::from(expected));
    }

    #[test]
    fn msm_empty_is_identity() {
        let result = msm_variable_base(&[], &[]);
        assert_eq!(G1Affine::from(result), G1Affine::identity());
    }

    #[test]
    fn pairing_empty_is_identity() {
        assert!(pairing_product_is_identity(&[]));
    }

    #[test]
    fn pairing_generator_with_negation_is_identity() {
        let g1 = G1Affine::generator();
        let g1_neg = -g1;
        let g2 = G2Affine::generator();
        assert!(pairing_product_is_identity(&[(&g1, &g2), (&g1_neg, &g2)]));
    }
}
