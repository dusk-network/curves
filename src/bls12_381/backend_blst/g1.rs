// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! G1 affine and projective point types for the blst backend.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use ::blst::MultiPoint;
use alloc::vec::Vec;
use dusk_bytes::Serializable;
use group::prime::{PrimeCurve, PrimeCurveAffine, PrimeGroup};
use group::{Curve, Group, GroupEncoding, UncompressedEncoding, WnafGroup};
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::{BlsScalar, G1Compressed, G1Uncompressed};

const H_EFF_G1: [u8; 8] = 0xd201_0000_0001_0001u64.to_le_bytes();

// ═══════════════════════════════════════════════════════════════════════════════
//  G1Affine
// ═══════════════════════════════════════════════════════════════════════════════

/// G1 affine point wrapping `blst_p1_affine`.
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct G1Affine(pub(crate) ::blst::blst_p1_affine);

impl G1Affine {
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

    /// Size of the raw representation.
    pub const RAW_SIZE: usize = 97;

    /// Serialize to the dusk-compatible raw representation.
    /// Encoding uses Montgomery-form little-endian limbs, identical to dusk_bls12_381's internal Fp layout.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        let mut out = [0u8; Self::RAW_SIZE];
        if bool::from(self.is_identity()) {
            let dusk_identity = dusk_bls12_381::G1Affine::identity();
            return dusk_identity.to_raw_bytes();
        }
        super::write_raw_limbs(
            &mut out[..Self::RAW_SIZE - 1],
            self.0.x.l.iter().chain(self.0.y.l.iter()),
        );
        out[Self::RAW_SIZE - 1] = self.is_identity().unwrap_u8();
        out
    }

    /// Create a `G1Affine` from bytes created by `G1Affine::to_raw_bytes`.
    ///
    /// # Safety
    /// The caller must guarantee that `bytes` contains a valid raw encoding of
    /// a point that lies on the BLS12-381 G1 curve.
    #[must_use]
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        if bytes.len() >= Self::RAW_SIZE && bytes[Self::RAW_SIZE - 1] != 0 {
            return Self::identity();
        }
        let mut out = ::blst::blst_p1_affine::default();
        super::read_raw_limbs(
            &bytes[..core::cmp::min(bytes.len(), Self::RAW_SIZE - 1)],
            out.x.l.iter_mut().chain(out.y.l.iter_mut()),
        );
        Self(out)
    }

    /// Returns true if this element is the identity.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        let inf = unsafe { ::blst::blst_p1_affine_is_inf(&raw const self.0) };
        Choice::from(inf as u8)
    }

    /// Returns true if this point is in the prime-order subgroup.
    #[must_use]
    pub fn is_torsion_free(&self) -> Choice {
        let in_group = unsafe { ::blst::blst_p1_affine_in_g1(&raw const self.0) };
        Choice::from(in_group as u8)
    }

    /// Returns true if this point is on the curve.
    #[must_use]
    pub fn is_on_curve(&self) -> Choice {
        let on_curve = unsafe { ::blst::blst_p1_affine_on_curve(&raw const self.0) };
        Choice::from(on_curve as u8)
    }

    /// Serialize this element into compressed form (48 bytes).
    ///
    /// Mirrors `dusk_bls12_381::G1Affine::to_compressed`. Equivalent to
    /// `<G1Affine as dusk_bytes::Serializable<48>>::to_bytes(self)` and to
    /// `<G1Affine as group::GroupEncoding>::to_bytes(self).0`.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; 48] {
        <Self as Serializable<48>>::to_bytes(self)
    }

    /// Serialize this element into uncompressed canonical form (96 bytes).
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        unsafe { ::blst::blst_p1_affine_serialize(out.as_mut_ptr(), &raw const self.0) };
        out
    }

    /// Attempt to deserialize a compressed element. Performs both on-curve and
    /// subgroup-membership checks; matches the safe `dusk_bls12_381` API.
    #[must_use]
    pub fn from_compressed(bytes: &[u8; 48]) -> CtOption<Self> {
        <Self as GroupEncoding>::from_bytes(&G1Compressed(*bytes))
    }

    /// Attempt to deserialize a compressed element without subgroup checks.
    /// Caller is responsible for any subgroup validation needed.
    #[must_use]
    pub fn from_compressed_unchecked(bytes: &[u8; 48]) -> CtOption<Self> {
        <Self as GroupEncoding>::from_bytes_unchecked(&G1Compressed(*bytes))
    }

    /// Attempt to deserialize an uncompressed element. Performs both on-curve
    /// and subgroup-membership checks.
    #[must_use]
    pub fn from_uncompressed(bytes: &[u8; 96]) -> CtOption<Self> {
        <Self as UncompressedEncoding>::from_uncompressed(&G1Uncompressed(*bytes))
    }

    /// Attempt to deserialize an uncompressed element without subgroup checks.
    #[must_use]
    pub fn from_uncompressed_unchecked(bytes: &[u8; 96]) -> CtOption<Self> {
        <Self as UncompressedEncoding>::from_uncompressed_unchecked(&G1Uncompressed(*bytes))
    }
}

// -- Serializable (compressed, 48 bytes) ------------------------------------

impl Serializable<48> for G1Affine {
    type Error = dusk_bytes::Error;

    fn to_bytes(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        unsafe { ::blst::blst_p1_affine_compress(out.as_mut_ptr(), &raw const self.0) };
        out
    }

    fn from_bytes(buf: &[u8; 48]) -> Result<Self, Self::Error> {
        let mut out = ::blst::blst_p1_affine::default();
        let err = unsafe { ::blst::blst_p1_uncompress(&raw mut out, buf.as_ptr()) };
        if err != ::blst::BLST_ERROR::BLST_SUCCESS {
            return Err(dusk_bytes::Error::InvalidData);
        }
        let in_group = unsafe { ::blst::blst_p1_affine_in_g1(&raw const out) };
        if !in_group {
            return Err(dusk_bytes::Error::InvalidData);
        }
        Ok(Self(out))
    }
}

// -- Trait helpers -----------------------------------------------------------

impl fmt::Debug for G1Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = <Self as Serializable<48>>::to_bytes(self);
        write!(f, "G1Affine({:?})", &b[..8])
    }
}

// -- Conversions between affine ↔ projective --------------------------------

impl From<G1Projective> for G1Affine {
    fn from(p: G1Projective) -> Self {
        let mut out = ::blst::blst_p1_affine::default();
        unsafe { ::blst::blst_p1_to_affine(&raw mut out, &raw const p.0) };
        Self(out)
    }
}

impl From<&G1Projective> for G1Affine {
    fn from(p: &G1Projective) -> Self {
        Self::from(*p)
    }
}

// -- Arithmetic for G1Affine ------------------------------------------------

impl Neg for G1Affine {
    type Output = Self;
    fn neg(self) -> Self {
        let mut p = ::blst::blst_p1::default();
        unsafe {
            ::blst::blst_p1_from_affine(&raw mut p, &raw const self.0);
            ::blst::blst_p1_cneg(&raw mut p, true);
        }
        Self::from(G1Projective(p))
    }
}

impl Neg for &G1Affine {
    type Output = G1Affine;
    fn neg(self) -> G1Affine {
        -(*self)
    }
}

impl Mul<BlsScalar> for G1Affine {
    type Output = G1Projective;
    fn mul(self, rhs: BlsScalar) -> G1Projective {
        G1Projective::from(self) * rhs
    }
}

impl Mul<BlsScalar> for &G1Affine {
    type Output = G1Projective;
    fn mul(self, rhs: BlsScalar) -> G1Projective {
        (*self) * rhs
    }
}

impl Mul<&BlsScalar> for G1Affine {
    type Output = G1Projective;
    fn mul(self, rhs: &BlsScalar) -> G1Projective {
        self * (*rhs)
    }
}

impl Mul<&BlsScalar> for &G1Affine {
    type Output = G1Projective;
    fn mul(self, rhs: &BlsScalar) -> G1Projective {
        (*self) * (*rhs)
    }
}

impl Sub<G1Projective> for G1Affine {
    type Output = G1Projective;
    fn sub(self, rhs: G1Projective) -> G1Projective {
        G1Projective::from(self) - rhs
    }
}

impl Sub<G1Affine> for G1Affine {
    type Output = G1Projective;
    fn sub(self, rhs: G1Affine) -> G1Projective {
        G1Projective::from(self) - G1Projective::from(rhs)
    }
}

impl Add<G1Affine> for G1Affine {
    type Output = G1Projective;
    fn add(self, rhs: G1Affine) -> G1Projective {
        G1Projective::from(self) + G1Projective::from(rhs)
    }
}

impl Add<G1Projective> for G1Affine {
    type Output = G1Projective;
    fn add(self, rhs: G1Projective) -> G1Projective {
        G1Projective::from(self) + rhs
    }
}

impl Add<&G1Affine> for G1Affine {
    type Output = G1Projective;
    fn add(self, rhs: &G1Affine) -> G1Projective {
        self + *rhs
    }
}

impl Add<&G1Projective> for G1Affine {
    type Output = G1Projective;
    fn add(self, rhs: &G1Projective) -> G1Projective {
        self + *rhs
    }
}

impl Sub<&G1Affine> for G1Affine {
    type Output = G1Projective;
    fn sub(self, rhs: &G1Affine) -> G1Projective {
        self - *rhs
    }
}

impl Sub<&G1Projective> for G1Affine {
    type Output = G1Projective;
    fn sub(self, rhs: &G1Projective) -> G1Projective {
        self - *rhs
    }
}

impl_ref_binops!(Add, add, G1Affine, G1Affine, G1Projective);
impl_ref_binops!(Add, add, G1Affine, G1Projective, G1Projective);
impl_ref_binops!(Sub, sub, G1Affine, G1Affine, G1Projective);
impl_ref_binops!(Sub, sub, G1Affine, G1Projective, G1Projective);

// -- subtle: constant-time equality and selection ---------------------------

impl ConstantTimeEq for G1Affine {
    fn ct_eq(&self, other: &Self) -> Choice {
        <Self as Serializable<48>>::to_bytes(self)
            .ct_eq(&<Self as Serializable<48>>::to_bytes(other))
    }
}

impl ConditionallySelectable for G1Affine {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Select directly on the inner Montgomery-form limbs — no
        // compression, decompression, or subgroup re-check needed.
        let mut out = ::blst::blst_p1_affine::default();
        for i in 0..6 {
            out.x.l[i] = u64::conditional_select(&a.0.x.l[i], &b.0.x.l[i], choice);
            out.y.l[i] = u64::conditional_select(&a.0.y.l[i], &b.0.y.l[i], choice);
        }
        Self(out)
    }
}

// -- group: GroupEncoding (compressed, 48 bytes) ----------------------------

impl GroupEncoding for G1Affine {
    type Repr = G1Compressed;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let mut out = ::blst::blst_p1_affine::default();
        let err = unsafe { ::blst::blst_p1_uncompress(&raw mut out, bytes.0.as_ptr()) };
        let on_curve = err == ::blst::BLST_ERROR::BLST_SUCCESS;
        let in_group = on_curve && unsafe { ::blst::blst_p1_affine_in_g1(&raw const out) };
        CtOption::new(Self(out), Choice::from(in_group as u8))
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        let mut out = ::blst::blst_p1_affine::default();
        let err = unsafe { ::blst::blst_p1_deserialize(&raw mut out, bytes.0.as_ptr()) };
        let is_ok = err == ::blst::BLST_ERROR::BLST_SUCCESS;
        CtOption::new(Self(out), Choice::from(is_ok as u8))
    }

    fn to_bytes(&self) -> Self::Repr {
        G1Compressed(<Self as Serializable<48>>::to_bytes(self))
    }
}

// -- group: UncompressedEncoding (96 bytes) ---------------------------------

impl UncompressedEncoding for G1Affine {
    type Uncompressed = G1Uncompressed;

    fn from_uncompressed(bytes: &Self::Uncompressed) -> CtOption<Self> {
        let mut out = ::blst::blst_p1_affine::default();
        let err = unsafe { ::blst::blst_p1_deserialize(&raw mut out, bytes.0.as_ptr()) };
        let p = Self(out);
        let in_group = unsafe { ::blst::blst_p1_affine_in_g1(&raw const p.0) };
        let ok = (err == ::blst::BLST_ERROR::BLST_SUCCESS) && in_group;
        CtOption::new(p, Choice::from(ok as u8))
    }

    fn from_uncompressed_unchecked(bytes: &Self::Uncompressed) -> CtOption<Self> {
        let mut out = ::blst::blst_p1_affine::default();
        let err = unsafe { ::blst::blst_p1_deserialize(&raw mut out, bytes.0.as_ptr()) };
        let ok = err == ::blst::BLST_ERROR::BLST_SUCCESS;
        CtOption::new(Self(out), Choice::from(ok as u8))
    }

    fn to_uncompressed(&self) -> Self::Uncompressed {
        let mut out = [0u8; 96];
        unsafe { ::blst::blst_p1_affine_serialize(out.as_mut_ptr(), &raw const self.0) };
        G1Uncompressed(out)
    }
}

// -- group: PrimeCurveAffine ------------------------------------------------

impl PrimeCurveAffine for G1Affine {
    type Scalar = BlsScalar;
    type Curve = G1Projective;

    fn identity() -> Self {
        Self::identity()
    }

    fn generator() -> Self {
        Self::generator()
    }

    fn is_identity(&self) -> Choice {
        self.is_identity()
    }

    fn to_curve(&self) -> G1Projective {
        G1Projective::from(*self)
    }
}

// -- scalar-on-left multiplication ------------------------------------------

impl Mul<G1Affine> for BlsScalar {
    type Output = G1Projective;
    fn mul(self, rhs: G1Affine) -> G1Projective {
        rhs * self
    }
}

impl Mul<&G1Affine> for BlsScalar {
    type Output = G1Projective;
    fn mul(self, rhs: &G1Affine) -> G1Projective {
        rhs * self
    }
}

impl Mul<G1Affine> for &BlsScalar {
    type Output = G1Projective;
    fn mul(self, rhs: G1Affine) -> G1Projective {
        rhs * self
    }
}

impl Mul<&G1Affine> for &BlsScalar {
    type Output = G1Projective;
    fn mul(self, rhs: &G1Affine) -> G1Projective {
        rhs * self
    }
}

// -- fmt::Display -----------------------------------------------------------

impl fmt::Display for G1Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = <Self as Serializable<48>>::to_bytes(self);
        write!(f, "G1Affine(0x")?;
        for b in &bytes {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

// -- zeroize ----------------------------------------------------------------

#[cfg(feature = "zeroize")]
impl ::zeroize::DefaultIsZeroes for G1Affine {}

// ═══════════════════════════════════════════════════════════════════════════════
//  G1Projective
// ═══════════════════════════════════════════════════════════════════════════════

/// G1 projective point wrapping `blst_p1`.
#[derive(Copy, Clone)]
pub struct G1Projective(pub(crate) ::blst::blst_p1);

impl PartialEq for G1Projective {
    fn eq(&self, other: &Self) -> bool {
        unsafe { ::blst::blst_p1_is_equal(&raw const self.0, &raw const other.0) }
    }
}

impl Eq for G1Projective {}

impl G1Projective {
    /// The identity element.
    #[must_use]
    pub fn identity() -> Self {
        Self::from(G1Affine::identity())
    }

    /// The standard generator.
    #[must_use]
    pub fn generator() -> Self {
        Self::from(G1Affine::generator())
    }

    /// Batch-convert an array of projective points to affine using blst's
    /// `blst_p1s_to_affine` (Montgomery batch inversion — one field
    /// inversion shared across all points).
    pub fn batch_normalize(points: &[Self], out: &mut [G1Affine]) {
        let n = core::cmp::min(points.len(), out.len());
        if n == 0 {
            return;
        }
        let blst_pts: Vec<::blst::blst_p1> = points[..n].iter().map(|p| p.0).collect();
        let affines = ::blst::p1_affines::from(&blst_pts);
        let affine_slice = affines.as_slice();
        for i in 0..n {
            out[i] = G1Affine(affine_slice[i]);
        }
    }

    /// Returns true if this element is the identity.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        let inf = unsafe { ::blst::blst_p1_is_inf(&raw const self.0) };
        Choice::from(inf as u8)
    }

    /// Returns true if this point lies on the curve.
    #[must_use]
    pub fn is_on_curve(&self) -> Choice {
        let on_curve = unsafe { ::blst::blst_p1_on_curve(&raw const self.0) };
        Choice::from(on_curve as u8)
    }

    /// Compute the doubling of this point.
    #[must_use]
    pub fn double(&self) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe { ::blst::blst_p1_double(&raw mut out, &raw const self.0) };
        Self(out)
    }

    /// Add this point to another projective point.
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe { ::blst::blst_p1_add_or_double(&raw mut out, &raw const self.0, &raw const rhs.0) };
        Self(out)
    }

    /// Add this point to an affine point (mixed addition).
    #[must_use]
    pub fn add_mixed(&self, rhs: &G1Affine) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe {
            ::blst::blst_p1_add_or_double_affine(&raw mut out, &raw const self.0, &raw const rhs.0);
        }
        Self(out)
    }

    /// Clears the cofactor, projecting an on-curve point onto the prime-order
    /// G1 subgroup.
    ///
    /// For G1 this is multiplication by the IETF effective cofactor
    /// `h_eff = 0xd201000000010001`, which matches the dusk backend's
    /// `self - self.mul_by_x()` reference implementation.
    #[must_use]
    pub fn clear_cofactor(&self) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe {
            ::blst::blst_p1_mult(&raw mut out, &raw const self.0, H_EFF_G1.as_ptr(), 64);
        }
        Self(out)
    }
}

impl Default for G1Projective {
    fn default() -> Self {
        Self::identity()
    }
}

impl fmt::Debug for G1Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "G1Projective({:?})", G1Affine::from(*self))
    }
}

// -- Conversions ------------------------------------------------------------

impl From<G1Affine> for G1Projective {
    fn from(p: G1Affine) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe { ::blst::blst_p1_from_affine(&raw mut out, &raw const p.0) };
        Self(out)
    }
}

impl From<&G1Affine> for G1Projective {
    fn from(p: &G1Affine) -> Self {
        Self::from(*p)
    }
}

// -- Arithmetic for G1Projective --------------------------------------------

impl Add for G1Projective {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe { ::blst::blst_p1_add_or_double(&raw mut out, &raw const self.0, &raw const rhs.0) };
        Self(out)
    }
}

impl AddAssign for G1Projective {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Add<&G1Projective> for G1Projective {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self {
        self + *rhs
    }
}

impl AddAssign<&G1Projective> for G1Projective {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + *rhs;
    }
}

impl Add<G1Affine> for G1Projective {
    type Output = Self;
    fn add(self, rhs: G1Affine) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe {
            ::blst::blst_p1_add_or_double_affine(&raw mut out, &raw const self.0, &raw const rhs.0);
        };
        Self(out)
    }
}

impl AddAssign<G1Affine> for G1Projective {
    fn add_assign(&mut self, rhs: G1Affine) {
        *self = *self + rhs;
    }
}

impl Add<&G1Affine> for G1Projective {
    type Output = Self;
    fn add(self, rhs: &G1Affine) -> Self {
        self + *rhs
    }
}

impl AddAssign<&G1Affine> for G1Projective {
    fn add_assign(&mut self, rhs: &G1Affine) {
        *self = *self + *rhs;
    }
}

impl Neg for &G1Projective {
    type Output = G1Projective;

    fn neg(self) -> G1Projective {
        let mut out = self.0;
        unsafe { ::blst::blst_p1_cneg(&raw mut out, true) };
        G1Projective(out)
    }
}

impl Neg for G1Projective {
    type Output = Self;
    fn neg(self) -> Self {
        -&self
    }
}

impl Sub for G1Projective {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl SubAssign for G1Projective {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Sub<&G1Projective> for G1Projective {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        self - *rhs
    }
}

impl SubAssign<&G1Projective> for G1Projective {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - *rhs;
    }
}

impl Sub<G1Affine> for G1Projective {
    type Output = Self;
    fn sub(self, rhs: G1Affine) -> Self {
        self - Self::from(rhs)
    }
}

impl SubAssign<G1Affine> for G1Projective {
    fn sub_assign(&mut self, rhs: G1Affine) {
        *self = *self - rhs;
    }
}

impl Sub<&G1Affine> for G1Projective {
    type Output = Self;
    fn sub(self, rhs: &G1Affine) -> Self {
        self - *rhs
    }
}

impl SubAssign<&G1Affine> for G1Projective {
    fn sub_assign(&mut self, rhs: &G1Affine) {
        *self = *self - *rhs;
    }
}

impl_ref_binops!(Add, add, G1Projective, G1Projective, G1Projective);
impl_ref_binops!(Add, add, G1Projective, G1Affine, G1Projective);
impl_ref_binops!(Sub, sub, G1Projective, G1Projective, G1Projective);
impl_ref_binops!(Sub, sub, G1Projective, G1Affine, G1Projective);

impl Mul<BlsScalar> for G1Projective {
    type Output = Self;
    fn mul(self, rhs: BlsScalar) -> Self {
        let bytes = rhs.to_bytes();
        let mut out = ::blst::blst_p1::default();
        unsafe {
            ::blst::blst_p1_mult(&raw mut out, &raw const self.0, bytes.as_ptr(), 255);
        };
        Self(out)
    }
}

impl Mul<&BlsScalar> for G1Projective {
    type Output = Self;
    fn mul(self, rhs: &BlsScalar) -> Self {
        self * (*rhs)
    }
}

impl Mul<BlsScalar> for &G1Projective {
    type Output = G1Projective;
    fn mul(self, rhs: BlsScalar) -> G1Projective {
        (*self) * rhs
    }
}

impl Mul<&BlsScalar> for &G1Projective {
    type Output = G1Projective;
    fn mul(self, rhs: &BlsScalar) -> G1Projective {
        (*self) * (*rhs)
    }
}

impl MulAssign<BlsScalar> for G1Projective {
    fn mul_assign(&mut self, rhs: BlsScalar) {
        *self = *self * rhs;
    }
}

impl MulAssign<&BlsScalar> for G1Projective {
    fn mul_assign(&mut self, rhs: &BlsScalar) {
        *self = *self * *rhs;
    }
}

impl core::iter::Sum for G1Projective {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + x)
    }
}

impl<'a> core::iter::Sum<&'a G1Projective> for G1Projective {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + *x)
    }
}

// -- subtle: constant-time equality and selection ---------------------------

impl ConstantTimeEq for G1Projective {
    fn ct_eq(&self, other: &Self) -> Choice {
        G1Affine::from(*self).ct_eq(&G1Affine::from(*other))
    }
}

impl ConditionallySelectable for G1Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Select directly on the projective (X, Y, Z) limbs; avoids the
        // two blst_p1_to_affine calls the affine-delegate path would incur.
        let mut out = ::blst::blst_p1::default();
        for i in 0..6 {
            out.x.l[i] = u64::conditional_select(&a.0.x.l[i], &b.0.x.l[i], choice);
            out.y.l[i] = u64::conditional_select(&a.0.y.l[i], &b.0.y.l[i], choice);
            out.z.l[i] = u64::conditional_select(&a.0.z.l[i], &b.0.z.l[i], choice);
        }
        Self(out)
    }
}

// -- group: GroupEncoding ---------------------------------------------------

impl GroupEncoding for G1Projective {
    type Repr = G1Compressed;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <G1Affine as GroupEncoding>::from_bytes(bytes).map(Self::from)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        <G1Affine as GroupEncoding>::from_bytes_unchecked(bytes).map(Self::from)
    }

    fn to_bytes(&self) -> Self::Repr {
        <G1Affine as GroupEncoding>::to_bytes(&G1Affine::from(*self))
    }
}

// -- group: Group -----------------------------------------------------------

impl Group for G1Projective {
    type Scalar = BlsScalar;

    fn random(mut rng: impl RngCore) -> Self {
        // Hash a random 64-byte seed to G1 using blst's hash_to_curve.
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        let mut out = ::blst::blst_p1::default();
        let dst = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
        unsafe {
            ::blst::blst_hash_to_g1(
                &raw mut out,
                buf.as_ptr(),
                buf.len(),
                dst.as_ptr(),
                dst.len(),
                core::ptr::null(),
                0,
            )
        };
        Self(out)
    }

    fn identity() -> Self {
        Self::identity()
    }

    fn generator() -> Self {
        Self::generator()
    }

    fn is_identity(&self) -> Choice {
        self.is_identity()
    }

    fn double(&self) -> Self {
        Self::double(self)
    }
}

// -- group: Curve + PrimeCurve ----------------------------------------------

impl Curve for G1Projective {
    type AffineRepr = G1Affine;

    fn to_affine(&self) -> Self::AffineRepr {
        G1Affine::from(*self)
    }

    fn batch_normalize(points: &[Self], out: &mut [Self::AffineRepr]) {
        Self::batch_normalize(points, out);
    }
}

impl PrimeCurve for G1Projective {
    type Affine = G1Affine;
}

impl PrimeGroup for G1Projective {}

impl WnafGroup for G1Projective {
    /// Returns a recommended wNAF window size for the given number of scalars.
    ///
    /// These thresholds match the ones used by `bls12_381` and `bellman`.
    fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
        match num_scalars {
            0 => 4,
            1 => 4,
            2..=3 => 5,
            4..=10 => 6,
            11..=32 => 7,
            _ => 8,
        }
    }
}

// -- scalar-on-left multiplication ------------------------------------------

impl Mul<G1Projective> for BlsScalar {
    type Output = G1Projective;
    fn mul(self, rhs: G1Projective) -> G1Projective {
        rhs * self
    }
}

impl Mul<&G1Projective> for BlsScalar {
    type Output = G1Projective;
    fn mul(self, rhs: &G1Projective) -> G1Projective {
        rhs * self
    }
}

impl Mul<G1Projective> for &BlsScalar {
    type Output = G1Projective;
    fn mul(self, rhs: G1Projective) -> G1Projective {
        rhs * self
    }
}

impl Mul<&G1Projective> for &BlsScalar {
    type Output = G1Projective;
    fn mul(self, rhs: &G1Projective) -> G1Projective {
        rhs * self
    }
}

// -- fmt::Display -----------------------------------------------------------

impl fmt::Display for G1Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&G1Affine::from(*self), f)
    }
}

// -- zeroize ----------------------------------------------------------------

#[cfg(feature = "zeroize")]
impl ::zeroize::DefaultIsZeroes for G1Projective {}

// ── Variable-base MSM ───────────────────────────────────────────────────────

/// Variable-base multi-scalar multiplication over G1 (blst-accelerated).
#[must_use]
pub fn msm_variable_base(points: &[G1Affine], scalars: &[BlsScalar]) -> G1Projective {
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
    G1Projective(out)
}

// ── Serde support ───────────────────────────────────────────────────────────

#[cfg(feature = "serde")]
mod serde_support {
    extern crate alloc;

    use alloc::format;
    use alloc::string::{String, ToString};

    use serde::de::Error as SerdeError;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    fn decode_hex<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = hex::decode(&s).map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        decoded
            .try_into()
            .map_err(|_| SerdeError::invalid_length(decoded_len, &N.to_string().as_str()))
    }

    impl Serialize for G1Affine {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            hex::encode(dusk_bytes::Serializable::to_bytes(self)).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for G1Affine {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let bytes = decode_hex::<D, 48>(deserializer)?;
            <Self as dusk_bytes::Serializable<48>>::from_bytes(&bytes)
                .map_err(|err| SerdeError::custom(format!("{err:?}")))
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use dusk_bytes::Serializable;

    fn clear_cofactor_via_dusk_roundtrip(point: &G1Projective) -> G1Projective {
        let bytes = <G1Affine as UncompressedEncoding>::to_uncompressed(&G1Affine::from(*point));
        let dusk_aff = dusk_bls12_381::G1Affine::from_uncompressed_unchecked(&bytes.0).unwrap();
        let cleared = dusk_bls12_381::G1Projective::from(dusk_aff).clear_cofactor();
        let cleared_bytes = dusk_bls12_381::G1Affine::from(cleared).to_uncompressed();
        let blst_aff = <G1Affine as UncompressedEncoding>::from_uncompressed(
            &super::super::G1Uncompressed(cleared_bytes),
        )
        .unwrap();
        G1Projective::from(blst_aff)
    }

    fn non_subgroup_g1_sample() -> G1Projective {
        // Mirrors the dusk torsion-free test vector using the same Montgomery limbs.
        G1Projective::from(G1Affine(::blst::blst_p1_affine {
            x: ::blst::blst_fp {
                l: [
                    0x0aba_f895_b97e_43c8,
                    0xba4c_6432_eb9b_61b0,
                    0x1250_6f52_adfe_307f,
                    0x7502_8c34_3933_6b72,
                    0x8474_4f05_b8e9_bd71,
                    0x113d_554f_b095_54f7,
                ],
            },
            y: ::blst::blst_fp {
                l: [
                    0x73e9_0e88_f5cf_01c0,
                    0x3700_7b65_dd31_97e2,
                    0x5cf9_a199_2f0d_7c78,
                    0x4f83_c10b_9eb3_330d,
                    0xf6a6_3f6f_07f6_0961,
                    0x0c53_b5b9_7e63_4df3,
                ],
            },
        }))
    }

    #[test]
    fn g1_affine_identity_roundtrip() {
        let id = G1Affine::identity();
        let bytes = <G1Affine as Serializable<48>>::to_bytes(&id);
        let decoded =
            <G1Affine as Serializable<48>>::from_bytes(&bytes).expect("identity should roundtrip");
        assert_eq!(id, decoded);
    }

    #[test]
    fn g1_affine_generator_roundtrip() {
        let g = G1Affine::generator();
        let bytes = <G1Affine as Serializable<48>>::to_bytes(&g);
        let decoded =
            <G1Affine as Serializable<48>>::from_bytes(&bytes).expect("generator should roundtrip");
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
    fn g1_affine_raw_matches_dusk() {
        let dusk_gen = dusk_bls12_381::G1Affine::generator();
        let dusk_id = dusk_bls12_381::G1Affine::identity();
        assert_eq!(
            G1Affine::generator().to_raw_bytes(),
            dusk_gen.to_raw_bytes()
        );
        assert_eq!(G1Affine::identity().to_raw_bytes(), dusk_id.to_raw_bytes());

        let dusk_double = dusk_bls12_381::G1Affine::from(
            dusk_bls12_381::G1Projective::generator() + dusk_bls12_381::G1Projective::generator(),
        );
        let blst_double = G1Affine::from(G1Projective::generator() + G1Projective::generator());
        assert_eq!(blst_double.to_raw_bytes(), dusk_double.to_raw_bytes());
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
    fn g1_reference_variants_compile_and_match() {
        let a = G1Projective::generator();
        let b = G1Projective::generator();
        assert_eq!(&a + &b, a + b);
        assert_eq!(-&a, -a);
        assert_eq!(G1Affine::from(&a), G1Affine::from(a));

        let aa = G1Affine::generator();
        let bb = G1Affine::generator();
        assert_eq!(&aa + &bb, aa + bb);
        assert_eq!(&aa - &bb, aa - bb);
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
        assert_eq!(G1Affine::from(result), G1Affine::identity());
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
    fn g1_affine_conditional_select_choice_0_returns_a() {
        let a = G1Affine::generator();
        let b = G1Affine::identity();
        let sel = G1Affine::conditional_select(&a, &b, Choice::from(0));
        assert_eq!(sel, a);
    }

    #[test]
    fn g1_affine_conditional_select_choice_1_returns_b() {
        let a = G1Affine::generator();
        let b = G1Affine::identity();
        let sel = G1Affine::conditional_select(&a, &b, Choice::from(1));
        assert_eq!(sel, b);
    }

    #[test]
    fn g1_projective_conditional_select() {
        let a = G1Projective::generator();
        let b = G1Projective::identity();
        assert_eq!(G1Projective::conditional_select(&a, &b, Choice::from(0)), a);
        assert_eq!(G1Projective::conditional_select(&a, &b, Choice::from(1)), b);
    }

    #[test]
    fn g1_conditional_select_non_identity_points() {
        let generator = G1Projective::generator();
        let a = generator + generator;
        let b = generator * BlsScalar::from(5u64);
        let sel_a = G1Projective::conditional_select(&a, &b, Choice::from(0));
        let sel_b = G1Projective::conditional_select(&a, &b, Choice::from(1));

        assert_ne!(a, b);
        assert_eq!(sel_a, a);
        assert_eq!(sel_b, b);
        assert_ne!(sel_a, sel_b);

        let a_affine = G1Affine::from(a);
        let b_affine = G1Affine::from(b);
        let sel_a_affine = G1Affine::conditional_select(&a_affine, &b_affine, Choice::from(0));
        let sel_b_affine = G1Affine::conditional_select(&a_affine, &b_affine, Choice::from(1));

        assert_ne!(a_affine, b_affine);
        assert_eq!(sel_a_affine, a_affine);
        assert_eq!(sel_b_affine, b_affine);
        assert_ne!(sel_a_affine, sel_b_affine);
    }

    #[test]
    fn g1_clear_cofactor_matches_dusk() {
        // On a subgroup-valid input, clear_cofactor must agree with the dusk
        // reference implementation.
        let blst_g = G1Projective::generator();
        let dusk_g = dusk_bls12_381::G1Projective::generator();
        let blst_cleared = G1Affine::from(blst_g.clear_cofactor());
        let dusk_cleared = dusk_bls12_381::G1Affine::from(dusk_g.clear_cofactor());
        assert_eq!(blst_cleared.to_raw_bytes(), dusk_cleared.to_raw_bytes());
        // The generator is already subgroup-valid; clearing the cofactor must
        // not move it off the prime-order subgroup.
        assert!(bool::from(blst_cleared.is_torsion_free()));
    }

    #[test]
    fn g1_clear_cofactor_identity_is_identity() {
        let cleared = G1Projective::identity().clear_cofactor();
        assert!(bool::from(cleared.is_identity()));
    }

    #[test]
    fn g1_clear_cofactor_non_subgroup_matches_dusk_roundtrip() {
        let point = non_subgroup_g1_sample();
        assert!(bool::from(point.is_on_curve()));
        assert!(!bool::from(G1Affine::from(point).is_torsion_free()));

        let blst_cleared = G1Affine::from(point.clear_cofactor());
        let dusk_cleared = G1Affine::from(clear_cofactor_via_dusk_roundtrip(&point));

        assert_eq!(blst_cleared.to_raw_bytes(), dusk_cleared.to_raw_bytes());
        assert!(bool::from(blst_cleared.is_torsion_free()));
    }

    #[test]
    fn g1_affine_inherent_encoding_matches_traits() {
        let g = G1Affine::generator();
        let compressed = g.to_compressed();
        let uncompressed = g.to_uncompressed();
        assert_eq!(compressed, <G1Affine as Serializable<48>>::to_bytes(&g));
        assert_eq!(
            uncompressed,
            <G1Affine as UncompressedEncoding>::to_uncompressed(&g).0
        );
        assert_eq!(G1Affine::from_compressed(&compressed).unwrap(), g);
        assert_eq!(G1Affine::from_compressed_unchecked(&compressed).unwrap(), g);
        assert_eq!(G1Affine::from_uncompressed(&uncompressed).unwrap(), g);
        assert_eq!(
            G1Affine::from_uncompressed_unchecked(&uncompressed).unwrap(),
            g
        );
    }

    #[test]
    fn g1_projective_inherent_arithmetic_matches_trait_impl() {
        let g = G1Projective::generator();
        // Inherent double / add agree with their trait counterparts.
        assert_eq!(g.double(), g + g);
        assert_eq!(g.add(&g), g + g);
        let g_aff = G1Affine::generator();
        assert_eq!(g.add_mixed(&g_aff), g + G1Projective::from(g_aff));
        assert!(bool::from(g.is_on_curve()));
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn g1_zeroize_resets_points_to_default() {
        use zeroize::Zeroize;

        let mut affine = G1Affine::generator();
        affine.zeroize();
        assert_eq!(affine, G1Affine::default());

        let mut projective = G1Projective::generator();
        projective.zeroize();
        assert_eq!(projective, G1Projective::default());
    }
}
