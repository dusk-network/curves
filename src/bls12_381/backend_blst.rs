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

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use ::blst::MultiPoint;
use alloc::vec::Vec;
use dusk_bytes::Serializable;

// ── dusk re-exports (non-curve items) ────────────────────────────────────────
//
// BlsScalar and scalar-field constants are re-exported verbatim from the dusk
// crate.  They have no blst counterpart and downstream code depends on their
// rich trait surface (ff::Field, Serializable, etc.).

pub use dusk_bls12_381::{BlsScalar, GENERATOR, ROOT_OF_UNITY, TWO_ADACITY};

/// Scalar type for this backend — same as `BlsScalar`.
pub type Scalar = BlsScalar;

// ── private dusk imports (tests only) ────────────────────────────────────────

#[cfg(test)]
use dusk_bls12_381::G1Affine as DuskG1Affine;
#[cfg(test)]
use dusk_bls12_381::G2Affine as DuskG2Affine;

// ── public type aliases ──────────────────────────────────────────────────────
//
// These are the names that downstream crates import.  They transparently switch
// between dusk and blst depending on the selected feature.

/// G1 affine point backed by blst.
pub type G1Affine = BlstG1Affine;
/// G2 affine point backed by blst.
pub type G2Affine = BlstG2Affine;
/// G1 projective point backed by blst.
pub type G1Projective = BlstG1Projective;
/// G2 projective point backed by blst.
pub type G2Projective = BlstG2Projective;
/// Prepared G2 element for pairing (in blst, this is affine).
pub type G2Prepared = BlstG2Prepared;

// ═══════════════════════════════════════════════════════════════════════════════
//  BlstG1Affine
// ═══════════════════════════════════════════════════════════════════════════════

/// G1 affine point wrapping `blst_p1_affine`.
#[derive(Copy, Clone)]
pub struct BlstG1Affine(pub(crate) ::blst::blst_p1_affine);

impl BlstG1Affine {
    /// The identity (point-at-infinity).
    #[must_use]
    pub fn identity() -> Self {
        Self(::blst::blst_p1_affine::default())
    }

    /// The standard generator of G1.
    #[must_use]
    pub fn generator() -> Self {
        Self(unsafe { *::blst::blst_p1_affine_generator() })
    }

    /// Size of the *uncompressed* serialization (96 bytes).
    pub const RAW_SIZE: usize = 96;

    /// Serialize to uncompressed form (96 bytes, big-endian).
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        let mut out = [0u8; Self::RAW_SIZE];
        unsafe { ::blst::blst_p1_affine_serialize(out.as_mut_ptr(), &raw const self.0) };
        out
    }

    /// Deserialize from uncompressed form **without** group-membership checks.
    ///
    /// # Safety
    /// The caller must ensure the bytes represent a valid on-curve point.
    #[must_use]
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut out = ::blst::blst_p1_affine::default();
        let _ = unsafe { ::blst::blst_p1_deserialize(&raw mut out, bytes.as_ptr()) };
        Self(out)
    }
}

// -- Serializable (compressed, 48 bytes) ------------------------------------

impl Serializable<48> for BlstG1Affine {
    type Error = dusk_bytes::Error;

    fn to_bytes(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        unsafe { ::blst::blst_p1_affine_compress(out.as_mut_ptr(), &raw const self.0) };
        out
    }

    fn from_bytes(buf: &[u8; 48]) -> Result<Self, Self::Error> {
        let mut out = ::blst::blst_p1_affine::default();
        let err = unsafe { ::blst::blst_p1_uncompress(&raw mut out, buf.as_ptr()) };
        if err == ::blst::BLST_ERROR::BLST_SUCCESS {
            Ok(Self(out))
        } else {
            Err(dusk_bytes::Error::InvalidData)
        }
    }
}

// -- Trait helpers -----------------------------------------------------------

impl Default for BlstG1Affine {
    fn default() -> Self {
        Self::identity()
    }
}

impl PartialEq for BlstG1Affine {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BlstG1Affine {}

impl fmt::Debug for BlstG1Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "G1Affine({:?})", &self.to_bytes()[..8])
    }
}

// -- Conversions between affine ↔ projective --------------------------------

impl From<BlstG1Projective> for BlstG1Affine {
    fn from(p: BlstG1Projective) -> Self {
        let mut out = ::blst::blst_p1_affine::default();
        unsafe { ::blst::blst_p1_to_affine(&raw mut out, &raw const p.0) };
        Self(out)
    }
}

// -- Arithmetic for G1Affine ------------------------------------------------

impl Neg for BlstG1Affine {
    type Output = Self;
    fn neg(self) -> Self {
        let mut p = ::blst::blst_p1::default();
        unsafe {
            ::blst::blst_p1_from_affine(&raw mut p, &raw const self.0);
            ::blst::blst_p1_cneg(&raw mut p, true);
        }
        Self::from(BlstG1Projective(p))
    }
}

impl Neg for &BlstG1Affine {
    type Output = BlstG1Affine;
    fn neg(self) -> BlstG1Affine {
        -(*self)
    }
}

impl Mul<BlsScalar> for BlstG1Affine {
    type Output = BlstG1Projective;
    fn mul(self, rhs: BlsScalar) -> BlstG1Projective {
        BlstG1Projective::from(self) * rhs
    }
}

impl Mul<BlsScalar> for &BlstG1Affine {
    type Output = BlstG1Projective;
    fn mul(self, rhs: BlsScalar) -> BlstG1Projective {
        (*self) * rhs
    }
}

impl Mul<&BlsScalar> for BlstG1Affine {
    type Output = BlstG1Projective;
    fn mul(self, rhs: &BlsScalar) -> BlstG1Projective {
        self * (*rhs)
    }
}

impl Mul<&BlsScalar> for &BlstG1Affine {
    type Output = BlstG1Projective;
    fn mul(self, rhs: &BlsScalar) -> BlstG1Projective {
        (*self) * (*rhs)
    }
}

impl Sub<BlstG1Projective> for BlstG1Affine {
    type Output = BlstG1Projective;
    fn sub(self, rhs: BlstG1Projective) -> BlstG1Projective {
        BlstG1Projective::from(self) - rhs
    }
}

impl Add<BlstG1Affine> for BlstG1Affine {
    type Output = BlstG1Projective;
    fn add(self, rhs: BlstG1Affine) -> BlstG1Projective {
        BlstG1Projective::from(self) + BlstG1Projective::from(rhs)
    }
}

impl Add<BlstG1Projective> for BlstG1Affine {
    type Output = BlstG1Projective;
    fn add(self, rhs: BlstG1Projective) -> BlstG1Projective {
        BlstG1Projective::from(self) + rhs
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BlstG1Projective
// ═══════════════════════════════════════════════════════════════════════════════

/// G1 projective point wrapping `blst_p1`.
#[derive(Copy, Clone)]
pub struct BlstG1Projective(pub(crate) ::blst::blst_p1);

impl BlstG1Projective {
    /// The identity element.
    #[must_use]
    pub fn identity() -> Self {
        Self::from(BlstG1Affine::identity())
    }

    /// The standard generator.
    #[must_use]
    pub fn generator() -> Self {
        Self::from(BlstG1Affine::generator())
    }

    /// Batch-convert an array of projective points to affine.
    pub fn batch_normalize(points: &[Self], out: &mut [BlstG1Affine]) {
        let n = core::cmp::min(points.len(), out.len());
        for i in 0..n {
            out[i] = BlstG1Affine::from(points[i]);
        }
    }
}

impl Default for BlstG1Projective {
    fn default() -> Self {
        Self::identity()
    }
}

impl PartialEq for BlstG1Projective {
    fn eq(&self, other: &Self) -> bool {
        BlstG1Affine::from(*self) == BlstG1Affine::from(*other)
    }
}

impl Eq for BlstG1Projective {}

impl fmt::Debug for BlstG1Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "G1Projective({:?})", BlstG1Affine::from(*self))
    }
}

// -- Conversions ------------------------------------------------------------

impl From<BlstG1Affine> for BlstG1Projective {
    fn from(p: BlstG1Affine) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe { ::blst::blst_p1_from_affine(&raw mut out, &raw const p.0) };
        Self(out)
    }
}

// -- Arithmetic for G1Projective --------------------------------------------

impl Add for BlstG1Projective {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe { ::blst::blst_p1_add_or_double(&raw mut out, &raw const self.0, &raw const rhs.0) };
        Self(out)
    }
}

impl AddAssign for BlstG1Projective {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Add<BlstG1Affine> for BlstG1Projective {
    type Output = Self;
    fn add(self, rhs: BlstG1Affine) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe {
            ::blst::blst_p1_add_or_double_affine(&raw mut out, &raw const self.0, &raw const rhs.0);
        };
        Self(out)
    }
}

impl AddAssign<BlstG1Affine> for BlstG1Projective {
    fn add_assign(&mut self, rhs: BlstG1Affine) {
        *self = *self + rhs;
    }
}

impl Neg for BlstG1Projective {
    type Output = Self;
    fn neg(self) -> Self {
        let mut out = self.0;
        unsafe { ::blst::blst_p1_cneg(&raw mut out, true) };
        Self(out)
    }
}

impl Sub for BlstG1Projective {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl SubAssign for BlstG1Projective {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Sub<BlstG1Affine> for BlstG1Projective {
    type Output = Self;
    fn sub(self, rhs: BlstG1Affine) -> Self {
        self - Self::from(rhs)
    }
}

impl SubAssign<BlstG1Affine> for BlstG1Projective {
    fn sub_assign(&mut self, rhs: BlstG1Affine) {
        *self = *self - rhs;
    }
}

impl Mul<BlsScalar> for BlstG1Projective {
    type Output = Self;
    fn mul(self, rhs: BlsScalar) -> Self {
        let bytes = rhs.to_bytes();
        let mut out = ::blst::blst_p1::default();
        unsafe {
            ::blst::blst_p1_mult(&raw mut out, &raw const self.0, bytes.as_ptr(), 256);
        };
        Self(out)
    }
}

impl Mul<&BlsScalar> for BlstG1Projective {
    type Output = Self;
    fn mul(self, rhs: &BlsScalar) -> Self {
        self * (*rhs)
    }
}

impl Mul<BlsScalar> for &BlstG1Projective {
    type Output = BlstG1Projective;
    fn mul(self, rhs: BlsScalar) -> BlstG1Projective {
        (*self) * rhs
    }
}

impl Mul<&BlsScalar> for &BlstG1Projective {
    type Output = BlstG1Projective;
    fn mul(self, rhs: &BlsScalar) -> BlstG1Projective {
        (*self) * (*rhs)
    }
}

impl MulAssign<BlsScalar> for BlstG1Projective {
    fn mul_assign(&mut self, rhs: BlsScalar) {
        *self = *self * rhs;
    }
}

impl core::iter::Sum for BlstG1Projective {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + x)
    }
}

impl<'a> core::iter::Sum<&'a BlstG1Projective> for BlstG1Projective {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + *x)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BlstG2Affine
// ═══════════════════════════════════════════════════════════════════════════════

/// G2 affine point wrapping `blst_p2_affine`.
#[derive(Copy, Clone)]
pub struct BlstG2Affine(pub(crate) ::blst::blst_p2_affine);

impl BlstG2Affine {
    /// The identity (point-at-infinity).
    #[must_use]
    pub fn identity() -> Self {
        Self(::blst::blst_p2_affine::default())
    }

    /// The standard generator of G2.
    #[must_use]
    pub fn generator() -> Self {
        Self(unsafe { *::blst::blst_p2_affine_generator() })
    }
}

// -- Serializable (compressed, 96 bytes) ------------------------------------

impl Serializable<96> for BlstG2Affine {
    type Error = dusk_bytes::Error;

    fn to_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        unsafe { ::blst::blst_p2_affine_compress(out.as_mut_ptr(), &raw const self.0) };
        out
    }

    fn from_bytes(buf: &[u8; 96]) -> Result<Self, Self::Error> {
        let mut out = ::blst::blst_p2_affine::default();
        let err = unsafe { ::blst::blst_p2_uncompress(&raw mut out, buf.as_ptr()) };
        if err == ::blst::BLST_ERROR::BLST_SUCCESS {
            Ok(Self(out))
        } else {
            Err(dusk_bytes::Error::InvalidData)
        }
    }
}

// -- Trait helpers -----------------------------------------------------------

impl Default for BlstG2Affine {
    fn default() -> Self {
        Self::identity()
    }
}

impl PartialEq for BlstG2Affine {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BlstG2Affine {}

impl fmt::Debug for BlstG2Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "G2Affine({:?})", &self.to_bytes()[..8])
    }
}

// -- Conversions between affine ↔ projective --------------------------------

impl From<BlstG2Projective> for BlstG2Affine {
    fn from(p: BlstG2Projective) -> Self {
        let mut out = ::blst::blst_p2_affine::default();
        unsafe { ::blst::blst_p2_to_affine(&raw mut out, &raw const p.0) };
        Self(out)
    }
}

// -- Arithmetic for G2Affine ------------------------------------------------

impl Neg for BlstG2Affine {
    type Output = Self;
    fn neg(self) -> Self {
        let mut p = ::blst::blst_p2::default();
        unsafe {
            ::blst::blst_p2_from_affine(&raw mut p, &raw const self.0);
            ::blst::blst_p2_cneg(&raw mut p, true);
        }
        Self::from(BlstG2Projective(p))
    }
}

impl Neg for &BlstG2Affine {
    type Output = BlstG2Affine;
    fn neg(self) -> BlstG2Affine {
        -(*self)
    }
}

impl Mul<BlsScalar> for BlstG2Affine {
    type Output = BlstG2Projective;
    fn mul(self, rhs: BlsScalar) -> BlstG2Projective {
        BlstG2Projective::from(self) * rhs
    }
}

impl Mul<BlsScalar> for &BlstG2Affine {
    type Output = BlstG2Projective;
    fn mul(self, rhs: BlsScalar) -> BlstG2Projective {
        (*self) * rhs
    }
}

impl Sub<BlstG2Projective> for BlstG2Affine {
    type Output = BlstG2Projective;
    fn sub(self, rhs: BlstG2Projective) -> BlstG2Projective {
        BlstG2Projective::from(self) - rhs
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BlstG2Projective
// ═══════════════════════════════════════════════════════════════════════════════

/// G2 projective point wrapping `blst_p2`.
#[derive(Copy, Clone)]
pub struct BlstG2Projective(pub(crate) ::blst::blst_p2);

impl BlstG2Projective {
    /// The identity element.
    #[must_use]
    pub fn identity() -> Self {
        Self::from(BlstG2Affine::identity())
    }

    /// The standard generator.
    #[must_use]
    pub fn generator() -> Self {
        Self::from(BlstG2Affine::generator())
    }
}

impl Default for BlstG2Projective {
    fn default() -> Self {
        Self::identity()
    }
}

impl fmt::Debug for BlstG2Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "G2Projective({:?})", BlstG2Affine::from(*self))
    }
}

// -- Conversions ------------------------------------------------------------

impl From<BlstG2Affine> for BlstG2Projective {
    fn from(p: BlstG2Affine) -> Self {
        let mut out = ::blst::blst_p2::default();
        unsafe { ::blst::blst_p2_from_affine(&raw mut out, &raw const p.0) };
        Self(out)
    }
}

// -- Arithmetic for G2Projective --------------------------------------------

impl Add for BlstG2Projective {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut out = ::blst::blst_p2::default();
        unsafe { ::blst::blst_p2_add_or_double(&raw mut out, &raw const self.0, &raw const rhs.0) };
        Self(out)
    }
}

impl Neg for BlstG2Projective {
    type Output = Self;
    fn neg(self) -> Self {
        let mut out = self.0;
        unsafe { ::blst::blst_p2_cneg(&raw mut out, true) };
        Self(out)
    }
}

impl Sub for BlstG2Projective {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl Sub<BlstG2Affine> for BlstG2Projective {
    type Output = Self;
    fn sub(self, rhs: BlstG2Affine) -> Self {
        self - Self::from(rhs)
    }
}

impl Mul<BlsScalar> for BlstG2Projective {
    type Output = Self;
    fn mul(self, rhs: BlsScalar) -> Self {
        let bytes = rhs.to_bytes();
        let mut out = ::blst::blst_p2::default();
        unsafe {
            ::blst::blst_p2_mult(&raw mut out, &raw const self.0, bytes.as_ptr(), 256);
        };
        Self(out)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BlstG2Prepared
// ═══════════════════════════════════════════════════════════════════════════════

/// Prepared G2 element for pairing.
///
/// In blst the miller-loop already operates on affine points, so this is
/// essentially a thin wrapper.
#[derive(Copy, Clone, Debug, Default)]
pub struct BlstG2Prepared(pub(crate) ::blst::blst_p2_affine);

impl From<BlstG2Affine> for BlstG2Prepared {
    fn from(p: BlstG2Affine) -> Self {
        Self(p.0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Gt / MillerLoopResult (pairing target group)
// ═══════════════════════════════════════════════════════════════════════════════

/// Target-group element for the BLS12-381 pairing.
#[derive(Copy, Clone)]
pub struct Gt(::blst::blst_fp12);

impl Gt {
    /// The identity (multiplicative) element in Gt.
    #[must_use]
    pub fn identity() -> Self {
        Self(unsafe { *::blst::blst_fp12_one() })
    }
}

impl Default for Gt {
    fn default() -> Self {
        Self::identity()
    }
}

impl PartialEq for Gt {
    fn eq(&self, other: &Self) -> bool {
        let size = core::mem::size_of::<::blst::blst_fp12>();
        let a =
            unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(self.0).cast::<u8>(), size) };
        let b =
            unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(other.0).cast::<u8>(), size) };
        a == b
    }
}

impl Eq for Gt {}

impl fmt::Debug for Gt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gt(..)")
    }
}

/// Result of a multi-Miller loop, before final exponentiation.
pub struct MillerLoopResult(::blst::blst_fp12);

impl MillerLoopResult {
    /// Perform the final exponentiation to obtain a Gt element.
    #[must_use]
    pub fn final_exponentiation(self) -> Gt {
        Gt(self.0.final_exp())
    }
}

/// Multi-Miller loop over pairs of (G1Affine, G2Prepared) points.
#[must_use]
pub fn multi_miller_loop(terms: &[(&G1Affine, &G2Prepared)]) -> MillerLoopResult {
    if terms.is_empty() {
        return MillerLoopResult(::blst::blst_fp12::default());
    }
    let ps: Vec<::blst::blst_p1_affine> = terms.iter().map(|(g1, _)| g1.0).collect();
    let qs: Vec<::blst::blst_p2_affine> = terms.iter().map(|(_, g2)| g2.0).collect();
    MillerLoopResult(::blst::blst_fp12::miller_loop_n(
        qs.as_slice(),
        ps.as_slice(),
    ))
}

/// Variable-base multiscalar multiplication (API-compatible module).
pub mod multiscalar_mul {
    use super::*;

    /// Variable-base multi-scalar multiplication over G1.
    #[must_use]
    pub fn msm_variable_base(points: &[G1Affine], scalars: &[Scalar]) -> G1Projective {
        super::msm_variable_base(points, scalars)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Module-level functions
// ═══════════════════════════════════════════════════════════════════════════════

#[must_use]
#[inline]
pub fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    Scalar::hash_to_scalar(bytes)
}

#[must_use]
#[inline]
pub fn scalar_from_wide(bytes: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_wide(bytes)
}

/// Variable-base multi-scalar multiplication over G1 (blst-accelerated).
#[must_use]
pub fn msm_variable_base(points: &[G1Affine], scalars: &[Scalar]) -> G1Projective {
    let n = core::cmp::min(points.len(), scalars.len());
    if n == 0 {
        return G1Projective::identity();
    }

    let blst_points: Vec<::blst::blst_p1_affine> = points[..n].iter().map(|p| p.0).collect();

    let mut scalar_bytes = Vec::with_capacity(n * 32);
    for scalar in &scalars[..n] {
        scalar_bytes.extend_from_slice(&scalar.to_bytes());
    }

    let out = blst_points.as_slice().mult(&scalar_bytes, 255);
    BlstG1Projective(out)
}

/// Checks whether the product of pairings over `(G1Affine, G2Affine)` terms
/// is the identity element in GT.
#[must_use]
pub fn pairing_product_is_identity(terms: &[(&G1Affine, &G2Affine)]) -> bool {
    if terms.is_empty() {
        return true;
    }

    let ps: Vec<::blst::blst_p1_affine> = terms.iter().map(|(g1, _)| g1.0).collect();
    let qs: Vec<::blst::blst_p2_affine> = terms
        .iter()
        .map(|(_, g2)| G2Prepared::from(**g2).0)
        .collect();

    let fp12 = ::blst::blst_fp12::miller_loop_n(qs.as_slice(), ps.as_slice());
    let gt = fp12.final_exp();
    ::blst::blst_fp12::finalverify(&gt, &::blst::blst_fp12::default())
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use dusk_bytes::Serializable;

    #[test]
    fn g1_affine_identity_roundtrip() {
        let id = G1Affine::identity();
        let bytes = id.to_bytes();
        let decoded = G1Affine::from_bytes(&bytes).expect("identity should roundtrip");
        assert_eq!(id, decoded);
    }

    #[test]
    fn g1_affine_generator_roundtrip() {
        let g = G1Affine::generator();
        let bytes = g.to_bytes();
        let decoded = G1Affine::from_bytes(&bytes).expect("generator should roundtrip");
        assert_eq!(g, decoded);
    }

    #[test]
    fn g1_affine_raw_roundtrip() {
        let g = G1Affine::generator();
        let raw = g.to_raw_bytes();
        let decoded = unsafe { G1Affine::from_slice_unchecked(&raw) };
        assert_eq!(g, decoded);
    }

    #[test]
    fn g2_affine_generator_roundtrip() {
        let g = G2Affine::generator();
        let bytes = g.to_bytes();
        let decoded = G2Affine::from_bytes(&bytes).expect("generator should roundtrip");
        assert_eq!(g, decoded);
    }

    #[test]
    fn g1_projective_identity_converts_to_affine_identity() {
        let id_p = G1Projective::identity();
        let id_a = G1Affine::from(id_p);
        assert_eq!(id_a, G1Affine::identity());
    }

    #[test]
    fn g1_generator_affine_projective_roundtrip() {
        let gen_a = G1Affine::generator();
        let gen_p = G1Projective::from(gen_a);
        let back = G1Affine::from(gen_p);
        assert_eq!(gen_a, back);
    }

    #[test]
    fn g1_batch_normalize_matches_single() {
        let pts = vec![
            G1Projective::generator(),
            G1Projective::identity(),
            G1Projective::generator() + G1Projective::generator(),
        ];
        let mut batch = vec![G1Affine::identity(); 3];
        G1Projective::batch_normalize(&pts, &mut batch);

        for (p, a) in pts.iter().zip(batch.iter()) {
            assert_eq!(G1Affine::from(*p), *a);
        }
    }

    #[test]
    fn scalar_mul_g1_identity_is_identity() {
        let id = G1Affine::identity();
        let result = id * BlsScalar::one();
        assert_eq!(G1Affine::from(result), G1Affine::identity(),);
    }

    #[test]
    fn g1_neg_roundtrip() {
        let g = G1Affine::generator();
        let neg = -g;
        let sum = G1Projective::from(g) + G1Projective::from(neg);
        assert_eq!(G1Affine::from(sum), G1Affine::identity());
    }

    #[test]
    fn msm_single_point() {
        let g = G1Affine::generator();
        let two = BlsScalar::from(2u64);
        let result = msm_variable_base(&[g], &[two]);
        let expected = G1Projective::from(g) + G1Projective::from(g);
        assert_eq!(G1Affine::from(result), G1Affine::from(expected));
    }

    #[test]
    fn pairing_trivial_identity() {
        assert!(pairing_product_is_identity(&[]));
    }

    #[test]
    fn blst_matches_dusk_g1_generator() {
        let blst_gen = G1Affine::generator();
        let dusk_gen = DuskG1Affine::generator();
        let blst_bytes = blst_gen.to_bytes();
        let dusk_bytes = dusk_gen.to_bytes();
        assert_eq!(blst_bytes[..], dusk_bytes[..]);
    }

    #[test]
    fn blst_matches_dusk_g2_generator() {
        let blst_gen = G2Affine::generator();
        let dusk_gen = DuskG2Affine::generator();
        let blst_bytes = blst_gen.to_bytes();
        let dusk_bytes = dusk_gen.to_bytes();
        assert_eq!(blst_bytes[..], dusk_bytes[..]);
    }
}
