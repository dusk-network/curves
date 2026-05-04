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

pub use g1::{G1Affine, G1Projective, msm_variable_base};
pub use g2::{G2Affine, G2Projective};
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

    #[test]
    fn affine_validation_methods_match_expectations() {
        assert!(bool::from(G1Affine::generator().is_on_curve()));
        assert!(bool::from(G1Affine::generator().is_torsion_free()));
        assert!(bool::from(G2Affine::generator().is_on_curve()));
        assert!(bool::from(G2Affine::generator().is_torsion_free()));
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
