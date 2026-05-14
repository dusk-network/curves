// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! blst-backed BLS12-381 backend for the `bls-backend-blst` feature.
//!
//! When this backend is selected, the curve types (`G1Affine`, `G2Affine`,
//! `G1Projective`, `G2Projective`) are native blst wrappers.  The scalar
//! type (`Scalar` / `BlsScalar`) is still the dusk scalar because it already
//! provides all required trait impls (`ff::Field`, `Serializable`, etc.) and
//! the scalar field arithmetic does not benefit from the blst C library.

// ── dusk re-exports (non-curve items) ────────────────────────────────────────
//
// BlsScalar and scalar-field constants are re-exported verbatim from the dusk
// crate.  They have no blst counterpart and downstream code depends on their
// rich trait surface (ff::Field, Serializable, etc.).

pub use dusk_bls12_381::{BlsScalar, GENERATOR, ROOT_OF_UNITY, TWO_ADACITY};

#[cfg(feature = "rkyv-impl")]
pub use dusk_bls12_381::{ArchivedBlsScalar, BlsScalarResolver};

/// Scalar type for this backend — same as `BlsScalar`.
pub type Scalar = dusk_bls12_381::BlsScalar;

// ── Internal byte helpers ────────────────────────────────────────────────────
//
// Shared by G1 and G2 raw-encoding logic.  Private here; accessible to child
// modules via `super::write_raw_limbs` / `super::read_raw_limbs`.

fn write_raw_limbs<'a, I>(out: &mut [u8], limbs: I)
where
    I: IntoIterator<Item = &'a u64>,
{
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
}

fn read_raw_limbs<'a, I>(bytes: &[u8], limbs: I)
where
    I: IntoIterator<Item = &'a mut u64>,
{
    let mut word = [0u8; 8];
    for (chunk, limb) in bytes.chunks_exact(8).zip(limbs) {
        word.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(word);
    }
}

// ── Encoding repr newtypes ───────────────────────────────────────────────────
//
// `GroupEncoding::Repr` requires `Default`, but `[u8; 48]` and `[u8; 96]`
// do not implement `Default` on stable Rust.  Thin newtypes solve this.

/// Compressed (48-byte) encoding of a G1 point.
#[derive(Copy, Clone)]
pub struct G1Compressed(pub [u8; 48]);

impl Default for G1Compressed {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

impl AsRef<[u8]> for G1Compressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G1Compressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Uncompressed (96-byte) encoding of a G1 point.
#[derive(Copy, Clone)]
pub struct G1Uncompressed(pub [u8; 96]);

impl Default for G1Uncompressed {
    fn default() -> Self {
        Self([0u8; 96])
    }
}

impl AsRef<[u8]> for G1Uncompressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G1Uncompressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Compressed (96-byte) encoding of a G2 point.
#[derive(Copy, Clone)]
pub struct G2Compressed(pub [u8; 96]);

impl Default for G2Compressed {
    fn default() -> Self {
        Self([0u8; 96])
    }
}

impl AsRef<[u8]> for G2Compressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G2Compressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Uncompressed (192-byte) encoding of a G2 point.
#[derive(Copy, Clone)]
pub struct G2Uncompressed(pub [u8; 192]);

impl Default for G2Uncompressed {
    fn default() -> Self {
        Self([0u8; 192])
    }
}

impl AsRef<[u8]> for G2Uncompressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G2Uncompressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// ── Shared reference-operator macro ─────────────────────────────────────────
//
// Generates `impl Trait<Rhs> for &Lhs` and `impl Trait<&Rhs> for &Lhs` by
// delegating to the by-value impl.

macro_rules! impl_ref_binops {
    ($trait:ident, $fn:ident, $lhs:ty, $rhs:ty, $out:ty) => {
        impl $trait<$rhs> for &$lhs {
            type Output = $out;

            fn $fn(self, rhs: $rhs) -> Self::Output {
                (*self).$fn(rhs)
            }
        }

        impl $trait<&$rhs> for &$lhs {
            type Output = $out;

            fn $fn(self, rhs: &$rhs) -> Self::Output {
                (*self).$fn(*rhs)
            }
        }
    };
}

// ── Submodules ───────────────────────────────────────────────────────────────

mod g1;
mod g2;
mod pairings;
#[cfg(all(test, feature = "rkyv-impl"))]
mod rkyv_tests;

#[cfg(feature = "rkyv-impl")]
pub use g1::{ArchivedG1Affine, G1AffineResolver, InvalidG1Affine};
pub use g1::{G1Affine, G1Projective, msm_variable_base};
#[cfg(feature = "rkyv-impl")]
pub use g2::{ArchivedG2Affine, G2AffineResolver, InvalidG2Affine};
pub use g2::{G2Affine, G2Projective};
#[cfg(feature = "rkyv-impl")]
pub use pairings::{
    ArchivedG2Prepared, ArchivedGt, ArchivedMillerLoopResult, G2PreparedResolver, GtResolver,
    InvalidG2Prepared, InvalidGt, InvalidMillerLoopResult, MillerLoopResultResolver,
};
pub use pairings::{
    G2Prepared, Gt, MillerLoopResult, multi_miller_loop_result, pairing_product_is_identity,
};

// ── Module-level scalar functions ────────────────────────────────────────────
//
// These delegate to the dusk scalar implementation and are backend-independent.

/// Hash arbitrary bytes to a BLS scalar.
#[must_use]
#[inline]
/// NOTE: internal function comes from the dusk backend, not blst
pub fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    Scalar::hash_to_scalar(bytes)
}

/// Reduce a wide little-endian integer modulo the scalar field order.
#[must_use]
#[inline]
/// NOTE: internal function comes from the dusk backend, not blst
pub fn scalar_from_wide(bytes: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_wide(bytes)
}

// ── Cross-module tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use dusk_bls12_381 as dusk_reference;

    fn fixed_wide_bytes() -> [u8; 64] {
        let mut bytes = [0u8; 64];
        for (byte_index, byte) in bytes.iter_mut().enumerate() {
            *byte = (byte_index as u8).wrapping_mul(17).wrapping_add(3);
        }
        bytes
    }

    fn assert_g1_interchanges_with_dusk(
        blst_affine: G1Affine,
        dusk_affine: dusk_reference::G1Affine,
    ) {
        let blst_compressed = blst_affine.to_compressed();
        let dusk_compressed = dusk_affine.to_compressed();
        let blst_uncompressed = blst_affine.to_uncompressed();
        let dusk_uncompressed = dusk_affine.to_uncompressed();

        assert_eq!(blst_compressed, dusk_compressed);
        assert_eq!(blst_uncompressed, dusk_uncompressed);
        assert_eq!(blst_affine.to_raw_bytes(), dusk_affine.to_raw_bytes());

        assert_eq!(
            G1Affine::from_compressed(&dusk_compressed).unwrap(),
            blst_affine
        );
        assert_eq!(
            G1Affine::from_uncompressed(&dusk_uncompressed).unwrap(),
            blst_affine
        );
        assert_eq!(
            dusk_reference::G1Affine::from_compressed(&blst_compressed).unwrap(),
            dusk_affine
        );
        assert_eq!(
            dusk_reference::G1Affine::from_uncompressed(&blst_uncompressed).unwrap(),
            dusk_affine
        );
    }

    fn assert_g2_interchanges_with_dusk(
        blst_affine: G2Affine,
        dusk_affine: dusk_reference::G2Affine,
    ) {
        let blst_compressed = blst_affine.to_compressed();
        let dusk_compressed = dusk_affine.to_compressed();
        let blst_uncompressed = blst_affine.to_uncompressed();
        let dusk_uncompressed = dusk_affine.to_uncompressed();

        assert_eq!(blst_compressed, dusk_compressed);
        assert_eq!(blst_uncompressed, dusk_uncompressed);
        assert_eq!(blst_affine.to_raw_bytes(), dusk_affine.to_raw_bytes());

        assert_eq!(
            G2Affine::from_compressed(&dusk_compressed).unwrap(),
            blst_affine
        );
        assert_eq!(
            G2Affine::from_uncompressed(&dusk_uncompressed).unwrap(),
            blst_affine
        );
        assert_eq!(
            dusk_reference::G2Affine::from_compressed(&blst_compressed).unwrap(),
            dusk_affine
        );
        assert_eq!(
            dusk_reference::G2Affine::from_uncompressed(&blst_uncompressed).unwrap(),
            dusk_affine
        );
    }

    fn dusk_pairing_product_is_identity(
        terms: &[(&dusk_reference::G1Affine, &dusk_reference::G2Affine)],
    ) -> bool {
        let prepared_terms: Vec<_> = terms
            .iter()
            .map(|(g1_affine, g2_affine)| {
                (**g1_affine, dusk_reference::G2Prepared::from(**g2_affine))
            })
            .collect();
        let refs: Vec<_> = prepared_terms
            .iter()
            .map(|(g1_affine, g2_prepared)| (g1_affine, g2_prepared))
            .collect();

        dusk_reference::multi_miller_loop(&refs).final_exponentiation()
            == dusk_reference::Gt::identity()
    }

    #[test]
    fn affine_validation_methods_match_expectations() {
        assert!(bool::from(G1Affine::generator().is_on_curve()));
        assert!(bool::from(G1Affine::generator().is_torsion_free()));
        assert!(bool::from(G2Affine::generator().is_on_curve()));
        assert!(bool::from(G2Affine::generator().is_torsion_free()));
    }

    #[test]
    fn scalar_helpers_match_dusk_backend() {
        for input in [
            b"" as &[u8],
            b"backend parity",
            b"dusk-curves blst wrapper interchange",
        ] {
            assert_eq!(
                hash_to_scalar(input),
                dusk_reference::BlsScalar::hash_to_scalar(input)
            );
        }

        let zero_wide = [0u8; 64];
        let patterned_wide = fixed_wide_bytes();
        for wide in [zero_wide, patterned_wide] {
            assert_eq!(
                scalar_from_wide(&wide),
                dusk_reference::BlsScalar::from_bytes_wide(&wide)
            );
        }
    }

    #[test]
    fn g1_computations_interchange_with_dusk_backend() {
        let scalar = scalar_from_wide(&fixed_wide_bytes());
        let blst_generator = G1Projective::generator();
        let dusk_generator = dusk_reference::G1Projective::generator();

        for (blst_affine, dusk_affine) in [
            (G1Affine::identity(), dusk_reference::G1Affine::identity()),
            (G1Affine::generator(), dusk_reference::G1Affine::generator()),
            (
                G1Affine::from(blst_generator + blst_generator),
                dusk_reference::G1Affine::from(dusk_generator + dusk_generator),
            ),
            (
                G1Affine::from(blst_generator * BlsScalar::from(7u64)),
                dusk_reference::G1Affine::from(dusk_generator * BlsScalar::from(7u64)),
            ),
            (
                G1Affine::from((blst_generator * scalar) - blst_generator),
                dusk_reference::G1Affine::from((dusk_generator * scalar) - dusk_generator),
            ),
            (
                G1Affine::from(-blst_generator),
                dusk_reference::G1Affine::from(-dusk_generator),
            ),
        ] {
            assert_g1_interchanges_with_dusk(blst_affine, dusk_affine);
        }
    }

    #[test]
    fn g2_computations_interchange_with_dusk_backend() {
        let scalar = scalar_from_wide(&fixed_wide_bytes());
        let blst_generator = G2Projective::generator();
        let dusk_generator = dusk_reference::G2Projective::generator();

        for (blst_affine, dusk_affine) in [
            (G2Affine::identity(), dusk_reference::G2Affine::identity()),
            (G2Affine::generator(), dusk_reference::G2Affine::generator()),
            (
                G2Affine::from(blst_generator + blst_generator),
                dusk_reference::G2Affine::from(dusk_generator + dusk_generator),
            ),
            (
                G2Affine::from(blst_generator * BlsScalar::from(7u64)),
                dusk_reference::G2Affine::from(dusk_generator * BlsScalar::from(7u64)),
            ),
            (
                G2Affine::from((blst_generator * scalar) - blst_generator),
                dusk_reference::G2Affine::from((dusk_generator * scalar) - dusk_generator),
            ),
            (
                G2Affine::from(-blst_generator),
                dusk_reference::G2Affine::from(-dusk_generator),
            ),
        ] {
            assert_g2_interchanges_with_dusk(blst_affine, dusk_affine);
        }
    }

    #[test]
    fn msm_matches_dusk_backend() {
        let scalar = scalar_from_wide(&fixed_wide_bytes());
        let blst_generator = G1Projective::generator();
        let dusk_generator = dusk_reference::G1Projective::generator();
        let blst_points = [
            G1Affine::generator(),
            G1Affine::from(blst_generator + blst_generator),
            G1Affine::from(blst_generator * BlsScalar::from(9u64)),
            G1Affine::from(-blst_generator),
        ];
        let dusk_points = [
            dusk_reference::G1Affine::generator(),
            dusk_reference::G1Affine::from(dusk_generator + dusk_generator),
            dusk_reference::G1Affine::from(dusk_generator * BlsScalar::from(9u64)),
            dusk_reference::G1Affine::from(-dusk_generator),
        ];
        let scalars = [
            BlsScalar::one(),
            BlsScalar::from(3u64),
            scalar,
            -&BlsScalar::one(),
        ];

        assert_g1_interchanges_with_dusk(
            G1Affine::from(msm_variable_base(&blst_points, &scalars)),
            dusk_reference::G1Affine::from(dusk_reference::multiscalar_mul::msm_variable_base(
                &dusk_points,
                &scalars,
            )),
        );
        assert_g1_interchanges_with_dusk(
            G1Affine::from(msm_variable_base(&blst_points[..3], &scalars[..2])),
            dusk_reference::G1Affine::from(dusk_reference::multiscalar_mul::msm_variable_base(
                &dusk_points[..3],
                &scalars[..2],
            )),
        );
        assert_g1_interchanges_with_dusk(
            G1Affine::from(msm_variable_base(&blst_points[..2], &scalars[..3])),
            dusk_reference::G1Affine::from(dusk_reference::multiscalar_mul::msm_variable_base(
                &dusk_points[..2],
                &scalars[..3],
            )),
        );
    }

    #[test]
    fn pairing_identity_checks_match_dusk_backend() {
        let scalar = BlsScalar::from(11u64);
        let blst_g1 = G1Affine::generator();
        let blst_neg_g1 = -blst_g1;
        let blst_g1_scaled = G1Affine::from(G1Projective::generator() * scalar);
        let blst_g2 = G2Affine::generator();
        let blst_g2_scaled = G2Affine::from(G2Projective::generator() * scalar);
        let blst_neg_g2_scaled = -blst_g2_scaled;

        let dusk_g1 = dusk_reference::G1Affine::generator();
        let dusk_neg_g1 = -dusk_g1;
        let dusk_g1_scaled =
            dusk_reference::G1Affine::from(dusk_reference::G1Projective::generator() * scalar);
        let dusk_g2 = dusk_reference::G2Affine::generator();
        let dusk_g2_scaled =
            dusk_reference::G2Affine::from(dusk_reference::G2Projective::generator() * scalar);
        let dusk_neg_g2_scaled = -dusk_g2_scaled;

        assert_eq!(
            pairing_product_is_identity(&[]),
            dusk_pairing_product_is_identity(&[])
        );
        assert_eq!(
            pairing_product_is_identity(&[(&blst_g1, &blst_g2)]),
            dusk_pairing_product_is_identity(&[(&dusk_g1, &dusk_g2)])
        );
        assert_eq!(
            pairing_product_is_identity(&[(&blst_g1, &blst_g2), (&blst_neg_g1, &blst_g2)]),
            dusk_pairing_product_is_identity(&[(&dusk_g1, &dusk_g2), (&dusk_neg_g1, &dusk_g2)])
        );
        assert_eq!(
            pairing_product_is_identity(&[
                (&blst_g1_scaled, &blst_g2),
                (&blst_g1, &blst_neg_g2_scaled),
            ]),
            dusk_pairing_product_is_identity(&[
                (&dusk_g1_scaled, &dusk_g2),
                (&dusk_g1, &dusk_neg_g2_scaled),
            ])
        );

        let blst_prepared =
            G2Prepared::from(G2Affine::from_compressed(&dusk_g2.to_compressed()).unwrap());
        assert_ne!(
            multi_miller_loop_result(&[(&blst_g1, &blst_prepared)]),
            Gt::identity()
        );
        assert_ne!(
            dusk_reference::multi_miller_loop(&[(
                &dusk_g1,
                &dusk_reference::G2Prepared::from(dusk_g2)
            )])
            .final_exponentiation(),
            dusk_reference::Gt::identity()
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrips_blst_types() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        let g1_json = serde_json::to_string(&g1).unwrap();
        let g2_json = serde_json::to_string(&g2).unwrap();

        let g1_back: G1Affine = serde_json::from_str(&g1_json).unwrap();
        let g2_back: G2Affine = serde_json::from_str(&g2_json).unwrap();

        assert_eq!(g1, g1_back);
        assert_eq!(g2, g2_back);
    }
}
