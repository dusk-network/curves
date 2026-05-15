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
