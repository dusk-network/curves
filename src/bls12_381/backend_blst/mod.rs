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
pub use pairings::{G2Prepared, Gt, multi_miller_loop_result, pairing_product_is_identity};

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

    #[cfg(feature = "rkyv-impl")]
    #[derive(Debug)]
    struct RkyvTestDeserializer;

    #[cfg(feature = "rkyv-impl")]
    #[derive(Debug, PartialEq, Eq)]
    enum RkyvTestDeserializeError {
        G1Affine,
        G2Affine,
        G2Prepared,
        Gt,
        MillerLoopResult,
    }

    #[cfg(feature = "rkyv-impl")]
    impl rkyv::Fallible for RkyvTestDeserializer {
        type Error = RkyvTestDeserializeError;
    }

    #[cfg(feature = "rkyv-impl")]
    impl From<InvalidG1Affine> for RkyvTestDeserializeError {
        fn from(_: InvalidG1Affine) -> Self {
            Self::G1Affine
        }
    }

    #[cfg(feature = "rkyv-impl")]
    impl From<InvalidG2Affine> for RkyvTestDeserializeError {
        fn from(_: InvalidG2Affine) -> Self {
            Self::G2Affine
        }
    }

    #[cfg(feature = "rkyv-impl")]
    impl From<InvalidG2Prepared> for RkyvTestDeserializeError {
        fn from(_: InvalidG2Prepared) -> Self {
            Self::G2Prepared
        }
    }

    #[cfg(feature = "rkyv-impl")]
    impl From<InvalidGt> for RkyvTestDeserializeError {
        fn from(_: InvalidGt) -> Self {
            Self::Gt
        }
    }

    #[cfg(feature = "rkyv-impl")]
    impl From<InvalidMillerLoopResult> for RkyvTestDeserializeError {
        fn from(_: InvalidMillerLoopResult) -> Self {
            Self::MillerLoopResult
        }
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_roundtrips_blst_types() {
        use rkyv::{
            Deserialize,
            ser::{Serializer, serializers::AllocSerializer},
        };

        let g1 = G1Affine::generator();
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&g1).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<G1Affine>(&bytes).unwrap();
        let restored: G1Affine = archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(g1, restored);

        let g2 = G2Affine::generator();
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&g2).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<G2Affine>(&bytes).unwrap();
        let restored: G2Affine = archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(g2, restored);

        let prepared = G2Prepared::from(g2);
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&prepared).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<G2Prepared>(&bytes).unwrap();
        let restored: G2Prepared = archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(prepared.to_raw_bytes(), restored.to_raw_bytes());

        let gt = multi_miller_loop_result(&[(&g1, &prepared)]);
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&gt).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<Gt>(&bytes).unwrap();
        let restored: Gt = archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(gt, restored);

        let miller_loop_result = pairings::multi_miller_loop(&[(&g1, &prepared)]);
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&miller_loop_result).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<pairings::MillerLoopResult>(&bytes).unwrap();
        let restored: pairings::MillerLoopResult =
            archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(
            miller_loop_result.final_exponentiation(),
            restored.final_exponentiation()
        );
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_roundtrips_blst_identities() {
        use rkyv::{
            Deserialize,
            ser::{Serializer, serializers::AllocSerializer},
        };

        let g1 = G1Affine::identity();
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&g1).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<G1Affine>(&bytes).unwrap();
        let restored: G1Affine = archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(g1, restored);

        let g2 = G2Affine::identity();
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&g2).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<G2Affine>(&bytes).unwrap();
        let restored: G2Affine = archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(g2, restored);

        let prepared = G2Prepared::from(g2);
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&prepared).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<G2Prepared>(&bytes).unwrap();
        let restored: G2Prepared = archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(prepared.to_raw_bytes(), restored.to_raw_bytes());

        let gt = Gt::identity();
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&gt).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<Gt>(&bytes).unwrap();
        let restored: Gt = archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(gt, restored);

        let miller_loop_result = pairings::multi_miller_loop(&[]);
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&miller_loop_result).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<pairings::MillerLoopResult>(&bytes).unwrap();
        let restored: pairings::MillerLoopResult =
            archived.deserialize(&mut RkyvTestDeserializer).unwrap();
        assert_eq!(
            miller_loop_result.final_exponentiation(),
            restored.final_exponentiation()
        );
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_rejects_invalid_archived_blst_points() {
        use rkyv::{
            Deserialize,
            ser::{Serializer, serializers::AllocSerializer},
        };

        const FP12_RAW_SIZE: usize = 48 * 12;
        const FP_MODULUS: [u64; 6] = [
            0xb9fe_ffff_ffff_aaab,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ];

        fn make_noncanonical_fp12_archive(bytes: &mut [u8]) {
            bytes[..FP12_RAW_SIZE].fill(0);
            for (chunk, limb) in bytes[..48].chunks_exact_mut(8).zip(FP_MODULUS.iter()) {
                chunk.copy_from_slice(&limb.to_le_bytes());
            }
        }

        let g1 = G1Affine::generator();
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&g1).unwrap();
        let mut bytes = serializer.into_serializer().into_inner();
        bytes[0] = 0xff;
        assert!(rkyv::check_archived_root::<G1Affine>(&bytes).is_err());
        let archived = unsafe { rkyv::archived_root::<G1Affine>(&bytes) };
        let result = <ArchivedG1Affine as Deserialize<G1Affine, RkyvTestDeserializer>>::deserialize(
            archived,
            &mut RkyvTestDeserializer,
        );
        assert!(matches!(result, Err(RkyvTestDeserializeError::G1Affine)));

        let g2 = G2Affine::generator();
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&g2).unwrap();
        let mut bytes = serializer.into_serializer().into_inner();
        bytes[0] = 0xff;
        assert!(rkyv::check_archived_root::<G2Affine>(&bytes).is_err());
        let archived = unsafe { rkyv::archived_root::<G2Affine>(&bytes) };
        let result = <ArchivedG2Affine as Deserialize<G2Affine, RkyvTestDeserializer>>::deserialize(
            archived,
            &mut RkyvTestDeserializer,
        );
        assert!(matches!(result, Err(RkyvTestDeserializeError::G2Affine)));

        let prepared = G2Prepared::from(g2);
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&prepared).unwrap();
        let mut bytes = serializer.into_serializer().into_inner();
        bytes.fill(0);
        assert!(rkyv::check_archived_root::<G2Prepared>(&bytes).is_err());
        let archived = unsafe { rkyv::archived_root::<G2Prepared>(&bytes) };
        let result =
            <ArchivedG2Prepared as Deserialize<G2Prepared, RkyvTestDeserializer>>::deserialize(
                archived,
                &mut RkyvTestDeserializer,
            );
        assert!(matches!(result, Err(RkyvTestDeserializeError::G2Prepared)));

        let gt = multi_miller_loop_result(&[(&g1, &prepared)]);
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&gt).unwrap();
        let mut bytes = serializer.into_serializer().into_inner();
        bytes.fill(0);
        assert!(rkyv::check_archived_root::<Gt>(&bytes).is_err());
        let archived = unsafe { rkyv::archived_root::<Gt>(&bytes) };
        let result = <ArchivedGt as Deserialize<Gt, RkyvTestDeserializer>>::deserialize(
            archived,
            &mut RkyvTestDeserializer,
        );
        assert!(matches!(result, Err(RkyvTestDeserializeError::Gt)));

        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&gt).unwrap();
        let mut bytes = serializer.into_serializer().into_inner();
        make_noncanonical_fp12_archive(&mut bytes);
        assert!(rkyv::check_archived_root::<Gt>(&bytes).is_err());
        let archived = unsafe { rkyv::archived_root::<Gt>(&bytes) };
        let result = <ArchivedGt as Deserialize<Gt, RkyvTestDeserializer>>::deserialize(
            archived,
            &mut RkyvTestDeserializer,
        );
        assert!(matches!(result, Err(RkyvTestDeserializeError::Gt)));

        let miller_loop_result = pairings::multi_miller_loop(&[(&g1, &prepared)]);
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&miller_loop_result).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        assert!(rkyv::check_archived_root::<Gt>(&bytes).is_err());
        let archived = unsafe { rkyv::archived_root::<Gt>(&bytes) };
        let result = <ArchivedGt as Deserialize<Gt, RkyvTestDeserializer>>::deserialize(
            archived,
            &mut RkyvTestDeserializer,
        );
        assert!(matches!(result, Err(RkyvTestDeserializeError::Gt)));

        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&miller_loop_result).unwrap();
        let mut bytes = serializer.into_serializer().into_inner();
        bytes.fill(0);
        assert!(rkyv::check_archived_root::<pairings::MillerLoopResult>(&bytes).is_err());
        let archived = unsafe { rkyv::archived_root::<pairings::MillerLoopResult>(&bytes) };
        let result = <ArchivedMillerLoopResult as Deserialize<
            pairings::MillerLoopResult,
            RkyvTestDeserializer,
        >>::deserialize(archived, &mut RkyvTestDeserializer);
        assert!(matches!(
            result,
            Err(RkyvTestDeserializeError::MillerLoopResult)
        ));

        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&miller_loop_result).unwrap();
        let mut bytes = serializer.into_serializer().into_inner();
        make_noncanonical_fp12_archive(&mut bytes);
        assert!(rkyv::check_archived_root::<pairings::MillerLoopResult>(&bytes).is_err());
        let archived = unsafe { rkyv::archived_root::<pairings::MillerLoopResult>(&bytes) };
        let result = <ArchivedMillerLoopResult as Deserialize<
            pairings::MillerLoopResult,
            RkyvTestDeserializer,
        >>::deserialize(archived, &mut RkyvTestDeserializer);
        assert!(matches!(
            result,
            Err(RkyvTestDeserializeError::MillerLoopResult)
        ));
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
