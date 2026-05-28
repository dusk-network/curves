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

/// Hash arbitrary bytes to a G1 point using the supplied domain separation tag.
#[must_use]
#[inline]
pub fn hash_to_g1(message: &[u8], dst: &[u8]) -> G1Projective {
    let mut out = ::blst::blst_p1::default();
    unsafe {
        ::blst::blst_hash_to_g1(
            &raw mut out,
            message.as_ptr(),
            message.len(),
            dst.as_ptr(),
            dst.len(),
            core::ptr::null(),
            0,
        )
    };
    G1Projective(out)
}

/// Hash arbitrary bytes to a G2 point using the supplied domain separation tag.
#[must_use]
#[inline]
pub fn hash_to_g2(message: &[u8], dst: &[u8]) -> G2Projective {
    let mut out = ::blst::blst_p2::default();
    unsafe {
        ::blst::blst_hash_to_g2(
            &raw mut out,
            message.as_ptr(),
            message.len(),
            dst.as_ptr(),
            dst.len(),
            core::ptr::null(),
            0,
        )
    };
    G2Projective(out)
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
    use dusk_reference::hash_to_curve::{
        ExpandMessageState, ExpandMsgXmd, HashToCurve, InitExpandMessage,
    };
    use sha2::Sha256;

    const G1_RO_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const G2_RO_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

    fn fixed_wide_bytes() -> [u8; 64] {
        let mut bytes = [0u8; 64];
        for (byte_index, byte) in bytes.iter_mut().enumerate() {
            *byte = (byte_index as u8).wrapping_mul(17).wrapping_add(3);
        }
        bytes
    }

    fn oversize_dst(prefix: &[u8]) -> Vec<u8> {
        let mut dst = Vec::from(prefix);
        dst.resize(300, b'1');
        dst
    }

    fn rfc9380_long_xmd_dst() -> Vec<u8> {
        let mut dst = Vec::from(&b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-"[..]);
        dst.resize(256, b'1');
        dst
    }

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

    fn assert_hash_to_g1_matches_dusk(message: &[u8], dst: &[u8]) {
        let blst_point = hash_to_g1(message, dst);
        let blst_affine = G1Affine::from(blst_point);
        let dusk_point =
            <dusk_reference::G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                message, dst,
            );
        let dusk_affine = dusk_reference::G1Affine::from(dusk_point);

        assert!(!bool::from(blst_affine.is_identity()));
        assert!(bool::from(blst_affine.is_on_curve()));
        assert!(bool::from(blst_affine.is_torsion_free()));
        assert_eq!(blst_affine.to_compressed(), dusk_affine.to_compressed());
        assert!(bool::from(
            G1Affine::from_compressed(&blst_affine.to_compressed()).is_some()
        ));
    }

    fn assert_hash_to_g2_matches_dusk(message: &[u8], dst: &[u8]) {
        let blst_point = hash_to_g2(message, dst);
        let blst_affine = G2Affine::from(blst_point);
        let dusk_point =
            <dusk_reference::G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                message, dst,
            );
        let dusk_affine = dusk_reference::G2Affine::from(dusk_point);

        assert!(!bool::from(blst_affine.is_identity()));
        assert!(bool::from(blst_affine.is_on_curve()));
        assert!(bool::from(blst_affine.is_torsion_free()));
        assert_eq!(blst_affine.to_compressed(), dusk_affine.to_compressed());
        assert!(bool::from(
            G2Affine::from_compressed(&blst_affine.to_compressed()).is_some()
        ));
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
    fn expand_message_xmd_matches_rfc9380_long_dst_vector() {
        let dst = rfc9380_long_xmd_dst();
        assert!(dst.len() > 255);

        let mut expanded = ExpandMsgXmd::<Sha256>::init_expand(b"abc", &dst, 0x20).into_vec();
        assert_eq!(
            expanded,
            decode_hex::<32>("52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12")
        );

        expanded = ExpandMsgXmd::<Sha256>::init_expand(b"", &dst, 0x80).into_vec();
        assert_eq!(
            expanded,
            decode_hex::<128>(concat!(
                "14604d85432c68b757e485c8894db3117992fc57e0e136f7",
                "1ad987f789a0abc287c47876978e2388a02af86b1e8d134",
                "2e5ce4f7aaa07a87321e691f6fba7e0072eecc1218aebb",
                "89fb14a0662322d5edbd873f0eb35260145cd4e64f748",
                "c5dfe60567e126604bcab1a3ee2dc0778102ae8a5cfd",
                "1429ebc0fa6bf1a53c36f55dfc",
            ))
        );
    }

    #[test]
    fn hash_to_g1_matches_dusk_backend() {
        const G1_DST: &[u8] = b"DUSK_CURVES_TEST_HASH_TO_G1_XMD:SHA-256_SSWU_RO_";

        for message in [
            b"" as &[u8],
            b"backend parity",
            b"dusk-curves hash-to-curve helpers keep downstream crates backend agnostic",
        ] {
            assert_hash_to_g1_matches_dusk(message, G1_DST);
        }

        let long_dst = oversize_dst(b"DUSK_CURVES_TEST_HASH_TO_G1_XMD:SHA-256_SSWU_RO_LONG_DST_");
        assert!(long_dst.len() > 255);
        assert_hash_to_g1_matches_dusk(b"backend parity with an oversize DST", &long_dst);
    }

    #[test]
    fn hash_to_g2_matches_dusk_backend() {
        const G2_DST: &[u8] = b"DUSK_CURVES_TEST_HASH_TO_G2_XMD:SHA-256_SSWU_RO_";

        for message in [
            b"" as &[u8],
            b"backend parity",
            b"dusk-curves hash-to-curve helpers keep downstream crates backend agnostic",
        ] {
            assert_hash_to_g2_matches_dusk(message, G2_DST);
        }

        let long_dst = oversize_dst(b"DUSK_CURVES_TEST_HASH_TO_G2_XMD:SHA-256_SSWU_RO_LONG_DST_");
        assert!(long_dst.len() > 255);
        assert_hash_to_g2_matches_dusk(b"backend parity with an oversize DST", &long_dst);
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
