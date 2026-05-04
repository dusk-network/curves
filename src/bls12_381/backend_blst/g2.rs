// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! G2 affine and projective point types for the blst backend.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use alloc::vec::Vec;
use dusk_bytes::Serializable;
use group::prime::{PrimeCurve, PrimeCurveAffine, PrimeGroup};
use group::{Curve, Group, GroupEncoding, UncompressedEncoding, WnafGroup};
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::{BlsScalar, G2Compressed, G2Uncompressed};

// ═══════════════════════════════════════════════════════════════════════════════
//  G2Affine
// ═══════════════════════════════════════════════════════════════════════════════

/// G2 affine point wrapping `blst_p2_affine`.
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct G2Affine(pub(crate) ::blst::blst_p2_affine);

impl G2Affine {
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

    /// Size of the raw representation.
    pub const RAW_SIZE: usize = 193;

    /// Serialize to the dusk-compatible raw representation.
    /// Encoding uses Montgomery-form little-endian limbs, identical to dusk_bls12_381's internal Fp layout.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        let mut out = [0u8; Self::RAW_SIZE];
        if bool::from(self.is_identity()) {
            let dusk_identity = dusk_bls12_381::G2Affine::identity();
            return dusk_identity.to_raw_bytes();
        }
        super::write_raw_limbs(
            &mut out[..Self::RAW_SIZE - 1],
            self.0.x.fp[0]
                .l
                .iter()
                .chain(self.0.x.fp[1].l.iter())
                .chain(self.0.y.fp[0].l.iter())
                .chain(self.0.y.fp[1].l.iter()),
        );
        out[Self::RAW_SIZE - 1] = self.is_identity().unwrap_u8();
        out
    }

    /// Create a `G2Affine` from bytes created by `G2Affine::to_raw_bytes`.
    ///
    /// # Safety
    /// The caller must guarantee that `bytes` contains a valid raw encoding of
    /// a point that lies on the BLS12-381 G2 curve.
    #[must_use]
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        if bytes.len() >= Self::RAW_SIZE && bytes[Self::RAW_SIZE - 1] != 0 {
            return Self::identity();
        }
        let mut out = ::blst::blst_p2_affine::default();
        let raw = &bytes[..core::cmp::min(bytes.len(), Self::RAW_SIZE - 1)];
        let xc0_end = core::cmp::min(raw.len(), 48);
        super::read_raw_limbs(&raw[..xc0_end], out.x.fp[0].l.iter_mut());
        if raw.len() > 48 {
            let xc1_end = core::cmp::min(raw.len(), 96);
            super::read_raw_limbs(&raw[48..xc1_end], out.x.fp[1].l.iter_mut());
        }
        if raw.len() > 96 {
            let yc0_end = core::cmp::min(raw.len(), 144);
            super::read_raw_limbs(&raw[96..yc0_end], out.y.fp[0].l.iter_mut());
        }
        if raw.len() > 144 {
            let yc1_end = core::cmp::min(raw.len(), 192);
            super::read_raw_limbs(&raw[144..yc1_end], out.y.fp[1].l.iter_mut());
        }
        Self(out)
    }

    /// Returns true if this element is the identity.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        let inf = unsafe { ::blst::blst_p2_affine_is_inf(&raw const self.0) };
        Choice::from(inf as u8)
    }

    /// Returns true if this point is in the prime-order subgroup.
    #[must_use]
    pub fn is_torsion_free(&self) -> Choice {
        let in_group = unsafe { ::blst::blst_p2_affine_in_g2(&raw const self.0) };
        Choice::from(in_group as u8)
    }

    /// Returns true if this point is on the curve.
    #[must_use]
    pub fn is_on_curve(&self) -> Choice {
        let on_curve = unsafe { ::blst::blst_p2_affine_on_curve(&raw const self.0) };
        Choice::from(on_curve as u8)
    }
}

// -- Serializable (compressed, 96 bytes) ------------------------------------

impl Serializable<96> for G2Affine {
    type Error = dusk_bytes::Error;

    fn to_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        unsafe { ::blst::blst_p2_affine_compress(out.as_mut_ptr(), &raw const self.0) };
        out
    }

    fn from_bytes(buf: &[u8; 96]) -> Result<Self, Self::Error> {
        let mut out = ::blst::blst_p2_affine::default();
        let err = unsafe { ::blst::blst_p2_uncompress(&raw mut out, buf.as_ptr()) };
        if err != ::blst::BLST_ERROR::BLST_SUCCESS {
            return Err(dusk_bytes::Error::InvalidData);
        }
        let in_group = unsafe { ::blst::blst_p2_affine_in_g2(&raw const out) };
        if !in_group {
            return Err(dusk_bytes::Error::InvalidData);
        }
        Ok(Self(out))
    }
}

// -- Trait helpers -----------------------------------------------------------

impl fmt::Debug for G2Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = <Self as Serializable<96>>::to_bytes(self);
        write!(f, "G2Affine({:?})", &b[..8])
    }
}

// -- Conversions between affine ↔ projective --------------------------------

impl From<G2Projective> for G2Affine {
    fn from(p: G2Projective) -> Self {
        let mut out = ::blst::blst_p2_affine::default();
        unsafe { ::blst::blst_p2_to_affine(&raw mut out, &raw const p.0) };
        Self(out)
    }
}

impl From<&G2Projective> for G2Affine {
    fn from(p: &G2Projective) -> Self {
        Self::from(*p)
    }
}

// -- Arithmetic for G2Affine ------------------------------------------------

impl Neg for G2Affine {
    type Output = Self;
    fn neg(self) -> Self {
        let mut p = ::blst::blst_p2::default();
        unsafe {
            ::blst::blst_p2_from_affine(&raw mut p, &raw const self.0);
            ::blst::blst_p2_cneg(&raw mut p, true);
        }
        Self::from(G2Projective(p))
    }
}

impl Neg for &G2Affine {
    type Output = G2Affine;
    fn neg(self) -> G2Affine {
        -(*self)
    }
}

impl Mul<BlsScalar> for G2Affine {
    type Output = G2Projective;
    fn mul(self, rhs: BlsScalar) -> G2Projective {
        G2Projective::from(self) * rhs
    }
}

impl Mul<BlsScalar> for &G2Affine {
    type Output = G2Projective;
    fn mul(self, rhs: BlsScalar) -> G2Projective {
        (*self) * rhs
    }
}

impl Mul<&BlsScalar> for G2Affine {
    type Output = G2Projective;
    fn mul(self, rhs: &BlsScalar) -> G2Projective {
        self * (*rhs)
    }
}

impl Mul<&BlsScalar> for &G2Affine {
    type Output = G2Projective;
    fn mul(self, rhs: &BlsScalar) -> G2Projective {
        (*self) * (*rhs)
    }
}

impl Add<G2Affine> for G2Affine {
    type Output = G2Projective;
    fn add(self, rhs: G2Affine) -> G2Projective {
        G2Projective::from(self) + G2Projective::from(rhs)
    }
}

impl Add<G2Projective> for G2Affine {
    type Output = G2Projective;
    fn add(self, rhs: G2Projective) -> G2Projective {
        G2Projective::from(self) + rhs
    }
}

impl Sub<G2Projective> for G2Affine {
    type Output = G2Projective;
    fn sub(self, rhs: G2Projective) -> G2Projective {
        G2Projective::from(self) - rhs
    }
}

impl Sub<G2Affine> for G2Affine {
    type Output = G2Projective;
    fn sub(self, rhs: G2Affine) -> G2Projective {
        G2Projective::from(self) - G2Projective::from(rhs)
    }
}

impl Add<&G2Affine> for G2Affine {
    type Output = G2Projective;
    fn add(self, rhs: &G2Affine) -> G2Projective {
        self + *rhs
    }
}

impl Add<&G2Projective> for G2Affine {
    type Output = G2Projective;
    fn add(self, rhs: &G2Projective) -> G2Projective {
        self + *rhs
    }
}

impl Sub<&G2Affine> for G2Affine {
    type Output = G2Projective;
    fn sub(self, rhs: &G2Affine) -> G2Projective {
        self - *rhs
    }
}

impl Sub<&G2Projective> for G2Affine {
    type Output = G2Projective;
    fn sub(self, rhs: &G2Projective) -> G2Projective {
        self - *rhs
    }
}

impl_ref_binops!(Add, add, G2Affine, G2Affine, G2Projective);
impl_ref_binops!(Add, add, G2Affine, G2Projective, G2Projective);
impl_ref_binops!(Sub, sub, G2Affine, G2Affine, G2Projective);
impl_ref_binops!(Sub, sub, G2Affine, G2Projective, G2Projective);

// -- subtle: constant-time equality and selection ---------------------------

impl ConstantTimeEq for G2Affine {
    fn ct_eq(&self, other: &Self) -> Choice {
        <Self as Serializable<96>>::to_bytes(self)
            .ct_eq(&<Self as Serializable<96>>::to_bytes(other))
    }
}

impl ConditionallySelectable for G2Affine {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Select directly on the inner Montgomery-form Fp2 limbs — no
        // compression, decompression, or subgroup re-check needed.
        let mut out = ::blst::blst_p2_affine::default();
        for i in 0..6 {
            out.x.fp[0].l[i] =
                u64::conditional_select(&a.0.x.fp[0].l[i], &b.0.x.fp[0].l[i], choice);
            out.x.fp[1].l[i] =
                u64::conditional_select(&a.0.x.fp[1].l[i], &b.0.x.fp[1].l[i], choice);
            out.y.fp[0].l[i] =
                u64::conditional_select(&a.0.y.fp[0].l[i], &b.0.y.fp[0].l[i], choice);
            out.y.fp[1].l[i] =
                u64::conditional_select(&a.0.y.fp[1].l[i], &b.0.y.fp[1].l[i], choice);
        }
        Self(out)
    }
}

// -- group: GroupEncoding (compressed, 96 bytes) ----------------------------

impl GroupEncoding for G2Affine {
    type Repr = G2Compressed;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let mut out = ::blst::blst_p2_affine::default();
        let err = unsafe { ::blst::blst_p2_uncompress(&raw mut out, bytes.0.as_ptr()) };
        let on_curve = err == ::blst::BLST_ERROR::BLST_SUCCESS;
        let in_group = on_curve && unsafe { ::blst::blst_p2_affine_in_g2(&raw const out) };
        CtOption::new(Self(out), Choice::from(in_group as u8))
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        let mut out = ::blst::blst_p2_affine::default();
        let err = unsafe { ::blst::blst_p2_deserialize(&raw mut out, bytes.0.as_ptr()) };
        let is_ok = err == ::blst::BLST_ERROR::BLST_SUCCESS;
        CtOption::new(Self(out), Choice::from(is_ok as u8))
    }

    fn to_bytes(&self) -> Self::Repr {
        G2Compressed(<Self as Serializable<96>>::to_bytes(self))
    }
}

// -- group: UncompressedEncoding (192 bytes) --------------------------------

impl UncompressedEncoding for G2Affine {
    type Uncompressed = G2Uncompressed;

    fn from_uncompressed(bytes: &Self::Uncompressed) -> CtOption<Self> {
        let mut out = ::blst::blst_p2_affine::default();
        let err = unsafe { ::blst::blst_p2_deserialize(&raw mut out, bytes.0.as_ptr()) };
        let p = Self(out);
        let in_group = unsafe { ::blst::blst_p2_affine_in_g2(&raw const p.0) };
        let ok = (err == ::blst::BLST_ERROR::BLST_SUCCESS) && in_group;
        CtOption::new(p, Choice::from(ok as u8))
    }

    fn from_uncompressed_unchecked(bytes: &Self::Uncompressed) -> CtOption<Self> {
        let mut out = ::blst::blst_p2_affine::default();
        let err = unsafe { ::blst::blst_p2_deserialize(&raw mut out, bytes.0.as_ptr()) };
        let ok = err == ::blst::BLST_ERROR::BLST_SUCCESS;
        CtOption::new(Self(out), Choice::from(ok as u8))
    }

    fn to_uncompressed(&self) -> Self::Uncompressed {
        let mut out = [0u8; 192];
        unsafe { ::blst::blst_p2_affine_serialize(out.as_mut_ptr(), &raw const self.0) };
        G2Uncompressed(out)
    }
}

// -- group: PrimeCurveAffine ------------------------------------------------

impl PrimeCurveAffine for G2Affine {
    type Scalar = BlsScalar;
    type Curve = G2Projective;

    fn identity() -> Self {
        Self::identity()
    }

    fn generator() -> Self {
        Self::generator()
    }

    fn is_identity(&self) -> Choice {
        self.is_identity()
    }

    fn to_curve(&self) -> G2Projective {
        G2Projective::from(*self)
    }
}

// -- scalar-on-left multiplication ------------------------------------------

impl Mul<G2Affine> for BlsScalar {
    type Output = G2Projective;
    fn mul(self, rhs: G2Affine) -> G2Projective {
        rhs * self
    }
}

impl Mul<&G2Affine> for BlsScalar {
    type Output = G2Projective;
    fn mul(self, rhs: &G2Affine) -> G2Projective {
        rhs * self
    }
}

impl Mul<G2Affine> for &BlsScalar {
    type Output = G2Projective;
    fn mul(self, rhs: G2Affine) -> G2Projective {
        rhs * self
    }
}

impl Mul<&G2Affine> for &BlsScalar {
    type Output = G2Projective;
    fn mul(self, rhs: &G2Affine) -> G2Projective {
        rhs * self
    }
}

// -- fmt::Display -----------------------------------------------------------

impl fmt::Display for G2Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = <Self as Serializable<96>>::to_bytes(self);
        write!(f, "G2Affine(0x")?;
        for b in &bytes {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

// -- zeroize ----------------------------------------------------------------

#[cfg(feature = "zeroize")]
impl ::zeroize::Zeroize for G2Affine {
    fn zeroize(&mut self) {
        let ptr = &mut self.0 as *mut ::blst::blst_p2_affine as *mut u8;
        let len = core::mem::size_of::<::blst::blst_p2_affine>();
        unsafe { core::ptr::write_bytes(ptr, 0u8, len) };
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  G2Projective
// ═══════════════════════════════════════════════════════════════════════════════

/// G2 projective point wrapping `blst_p2`.
#[derive(Copy, Clone)]
pub struct G2Projective(pub(crate) ::blst::blst_p2);

impl PartialEq for G2Projective {
    fn eq(&self, other: &Self) -> bool {
        unsafe { ::blst::blst_p2_is_equal(&raw const self.0, &raw const other.0) }
    }
}

impl Eq for G2Projective {}

impl G2Projective {
    /// The identity element.
    #[must_use]
    pub fn identity() -> Self {
        Self::from(G2Affine::identity())
    }

    /// The standard generator.
    #[must_use]
    pub fn generator() -> Self {
        Self::from(G2Affine::generator())
    }

    /// Batch-convert an array of projective points to affine using blst's
    /// `blst_p2s_to_affine` (Montgomery batch inversion — one field
    /// inversion shared across all points).
    pub fn batch_normalize(points: &[Self], out: &mut [G2Affine]) {
        let n = core::cmp::min(points.len(), out.len());
        if n == 0 {
            return;
        }
        let blst_pts: Vec<::blst::blst_p2> = points[..n].iter().map(|p| p.0).collect();
        let affines = ::blst::p2_affines::from(&blst_pts);
        let affine_slice = affines.as_slice();
        for i in 0..n {
            out[i] = G2Affine(affine_slice[i]);
        }
    }

    /// Returns true if this element is the identity.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        let inf = unsafe { ::blst::blst_p2_is_inf(&raw const self.0) };
        Choice::from(inf as u8)
    }

    /// Clears the cofactor, projecting an on-curve point onto the prime-order
    /// G2 subgroup.
    ///
    /// The blst backend bridges through the canonical 192-byte IETF
    /// uncompressed encoding to invoke `dusk_bls12_381::G2Projective::clear_cofactor`,
    /// then re-decodes the cleared point. Bridging via uncompressed bytes is
    /// required because the input may legitimately be on the curve but outside
    /// the prime-order subgroup (e.g. the output of a hash-to-curve mapping),
    /// and the dusk compressed `from_bytes` would reject such points. The
    /// returned point is in the prime-order subgroup by construction.
    ///
    /// This delegation keeps both backends behaviourally identical for
    /// security-sensitive constructions (BLS signatures, hash-to-curve)
    /// without re-deriving the cofactor-clearing scalar in this crate.
    #[must_use]
    pub fn clear_cofactor(&self) -> Self {
        let bytes = <G2Affine as UncompressedEncoding>::to_uncompressed(&G2Affine::from(*self));
        let dusk_aff = dusk_bls12_381::G2Affine::from_uncompressed_unchecked(&bytes.0).unwrap();
        let cleared = dusk_bls12_381::G2Projective::from(dusk_aff).clear_cofactor();
        let cleared_bytes = dusk_bls12_381::G2Affine::from(cleared).to_uncompressed();
        let blst_aff = <G2Affine as UncompressedEncoding>::from_uncompressed(
            &super::G2Uncompressed(cleared_bytes),
        )
        .unwrap();
        Self::from(blst_aff)
    }
}

impl Default for G2Projective {
    fn default() -> Self {
        Self::identity()
    }
}

impl fmt::Debug for G2Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "G2Projective({:?})", G2Affine::from(*self))
    }
}

// -- Conversions ------------------------------------------------------------

impl From<G2Affine> for G2Projective {
    fn from(p: G2Affine) -> Self {
        let mut out = ::blst::blst_p2::default();
        unsafe { ::blst::blst_p2_from_affine(&raw mut out, &raw const p.0) };
        Self(out)
    }
}

impl From<&G2Affine> for G2Projective {
    fn from(p: &G2Affine) -> Self {
        Self::from(*p)
    }
}

// -- Arithmetic for G2Projective --------------------------------------------

impl Add for G2Projective {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut out = ::blst::blst_p2::default();
        unsafe { ::blst::blst_p2_add_or_double(&raw mut out, &raw const self.0, &raw const rhs.0) };
        Self(out)
    }
}

impl AddAssign for G2Projective {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Add<&G2Projective> for G2Projective {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self {
        self + *rhs
    }
}

impl AddAssign<&G2Projective> for G2Projective {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + *rhs;
    }
}

impl Add<G2Affine> for G2Projective {
    type Output = Self;
    fn add(self, rhs: G2Affine) -> Self {
        let mut out = ::blst::blst_p2::default();
        unsafe {
            ::blst::blst_p2_add_or_double_affine(&raw mut out, &raw const self.0, &raw const rhs.0);
        }
        Self(out)
    }
}

impl AddAssign<G2Affine> for G2Projective {
    fn add_assign(&mut self, rhs: G2Affine) {
        *self = *self + rhs;
    }
}

impl Add<&G2Affine> for G2Projective {
    type Output = Self;
    fn add(self, rhs: &G2Affine) -> Self {
        self + *rhs
    }
}

impl AddAssign<&G2Affine> for G2Projective {
    fn add_assign(&mut self, rhs: &G2Affine) {
        *self = *self + *rhs;
    }
}

impl Neg for &G2Projective {
    type Output = G2Projective;

    fn neg(self) -> G2Projective {
        let mut out = self.0;
        unsafe { ::blst::blst_p2_cneg(&raw mut out, true) };
        G2Projective(out)
    }
}

impl Neg for G2Projective {
    type Output = Self;
    fn neg(self) -> Self {
        -&self
    }
}

impl Sub for G2Projective {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl SubAssign for G2Projective {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Sub<&G2Projective> for G2Projective {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        self - *rhs
    }
}

impl SubAssign<&G2Projective> for G2Projective {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - *rhs;
    }
}

impl Sub<G2Affine> for G2Projective {
    type Output = Self;
    fn sub(self, rhs: G2Affine) -> Self {
        self - Self::from(rhs)
    }
}

impl SubAssign<G2Affine> for G2Projective {
    fn sub_assign(&mut self, rhs: G2Affine) {
        *self = *self - rhs;
    }
}

impl Sub<&G2Affine> for G2Projective {
    type Output = Self;
    fn sub(self, rhs: &G2Affine) -> Self {
        self - *rhs
    }
}

impl SubAssign<&G2Affine> for G2Projective {
    fn sub_assign(&mut self, rhs: &G2Affine) {
        *self = *self - *rhs;
    }
}

impl_ref_binops!(Add, add, G2Projective, G2Projective, G2Projective);
impl_ref_binops!(Add, add, G2Projective, G2Affine, G2Projective);
impl_ref_binops!(Sub, sub, G2Projective, G2Projective, G2Projective);
impl_ref_binops!(Sub, sub, G2Projective, G2Affine, G2Projective);

impl Mul<BlsScalar> for G2Projective {
    type Output = Self;
    fn mul(self, rhs: BlsScalar) -> Self {
        let bytes = rhs.to_bytes();
        let mut out = ::blst::blst_p2::default();
        unsafe {
            ::blst::blst_p2_mult(&raw mut out, &raw const self.0, bytes.as_ptr(), 255);
        };
        Self(out)
    }
}

impl Mul<&BlsScalar> for G2Projective {
    type Output = Self;
    fn mul(self, rhs: &BlsScalar) -> Self {
        self * (*rhs)
    }
}

impl Mul<BlsScalar> for &G2Projective {
    type Output = G2Projective;
    fn mul(self, rhs: BlsScalar) -> G2Projective {
        (*self) * rhs
    }
}

impl Mul<&BlsScalar> for &G2Projective {
    type Output = G2Projective;
    fn mul(self, rhs: &BlsScalar) -> G2Projective {
        (*self) * (*rhs)
    }
}

impl MulAssign<BlsScalar> for G2Projective {
    fn mul_assign(&mut self, rhs: BlsScalar) {
        *self = *self * rhs;
    }
}

impl MulAssign<&BlsScalar> for G2Projective {
    fn mul_assign(&mut self, rhs: &BlsScalar) {
        *self = *self * *rhs;
    }
}

impl core::iter::Sum for G2Projective {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + x)
    }
}

impl<'a> core::iter::Sum<&'a G2Projective> for G2Projective {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + *x)
    }
}

// -- subtle: constant-time equality and selection ---------------------------

impl ConstantTimeEq for G2Projective {
    fn ct_eq(&self, other: &Self) -> Choice {
        G2Affine::from(*self).ct_eq(&G2Affine::from(*other))
    }
}

impl ConditionallySelectable for G2Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Select directly on the projective (X, Y, Z) Fp2 limbs; avoids the
        // two blst_p2_to_affine calls the affine-delegate path would incur.
        let mut out = ::blst::blst_p2::default();
        for i in 0..6 {
            out.x.fp[0].l[i] =
                u64::conditional_select(&a.0.x.fp[0].l[i], &b.0.x.fp[0].l[i], choice);
            out.x.fp[1].l[i] =
                u64::conditional_select(&a.0.x.fp[1].l[i], &b.0.x.fp[1].l[i], choice);
            out.y.fp[0].l[i] =
                u64::conditional_select(&a.0.y.fp[0].l[i], &b.0.y.fp[0].l[i], choice);
            out.y.fp[1].l[i] =
                u64::conditional_select(&a.0.y.fp[1].l[i], &b.0.y.fp[1].l[i], choice);
            out.z.fp[0].l[i] =
                u64::conditional_select(&a.0.z.fp[0].l[i], &b.0.z.fp[0].l[i], choice);
            out.z.fp[1].l[i] =
                u64::conditional_select(&a.0.z.fp[1].l[i], &b.0.z.fp[1].l[i], choice);
        }
        Self(out)
    }
}

// -- group: GroupEncoding ---------------------------------------------------

impl GroupEncoding for G2Projective {
    type Repr = G2Compressed;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <G2Affine as GroupEncoding>::from_bytes(bytes).map(Self::from)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        <G2Affine as GroupEncoding>::from_bytes_unchecked(bytes).map(Self::from)
    }

    fn to_bytes(&self) -> Self::Repr {
        <G2Affine as GroupEncoding>::to_bytes(&G2Affine::from(*self))
    }
}

// -- group: Group -----------------------------------------------------------

impl Group for G2Projective {
    type Scalar = BlsScalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        let mut out = ::blst::blst_p2::default();
        let dst = b"BLS12381G2_XMD:SHA-256_SSWU_RO_";
        unsafe {
            ::blst::blst_hash_to_g2(
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
        let mut out = ::blst::blst_p2::default();
        unsafe { ::blst::blst_p2_double(&raw mut out, &raw const self.0) };
        Self(out)
    }
}

// -- group: Curve + PrimeCurve + PrimeGroup + WnafGroup ---------------------

impl Curve for G2Projective {
    type AffineRepr = G2Affine;

    fn to_affine(&self) -> Self::AffineRepr {
        G2Affine::from(*self)
    }

    fn batch_normalize(points: &[Self], out: &mut [Self::AffineRepr]) {
        Self::batch_normalize(points, out);
    }
}

impl PrimeCurve for G2Projective {
    type Affine = G2Affine;
}

impl PrimeGroup for G2Projective {}

impl WnafGroup for G2Projective {
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

impl Mul<G2Projective> for BlsScalar {
    type Output = G2Projective;
    fn mul(self, rhs: G2Projective) -> G2Projective {
        rhs * self
    }
}

impl Mul<&G2Projective> for BlsScalar {
    type Output = G2Projective;
    fn mul(self, rhs: &G2Projective) -> G2Projective {
        rhs * self
    }
}

impl Mul<G2Projective> for &BlsScalar {
    type Output = G2Projective;
    fn mul(self, rhs: G2Projective) -> G2Projective {
        rhs * self
    }
}

impl Mul<&G2Projective> for &BlsScalar {
    type Output = G2Projective;
    fn mul(self, rhs: &G2Projective) -> G2Projective {
        rhs * self
    }
}

// -- fmt::Display -----------------------------------------------------------

impl fmt::Display for G2Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&G2Affine::from(*self), f)
    }
}

// -- zeroize ----------------------------------------------------------------

#[cfg(feature = "zeroize")]
impl ::zeroize::Zeroize for G2Projective {
    fn zeroize(&mut self) {
        let ptr = &mut self.0 as *mut ::blst::blst_p2 as *mut u8;
        let len = core::mem::size_of::<::blst::blst_p2>();
        unsafe { core::ptr::write_bytes(ptr, 0u8, len) };
    }
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

    impl Serialize for G2Affine {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            hex::encode(dusk_bytes::Serializable::to_bytes(self)).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for G2Affine {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let bytes = decode_hex::<D, 96>(deserializer)?;
            <Self as dusk_bytes::Serializable<96>>::from_bytes(&bytes)
                .map_err(|err| SerdeError::custom(format!("{err:?}")))
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_bytes::Serializable;

    #[test]
    fn g2_affine_identity_roundtrip() {
        let id = G2Affine::identity();
        let bytes = <G2Affine as Serializable<96>>::to_bytes(&id);
        let decoded =
            <G2Affine as Serializable<96>>::from_bytes(&bytes).expect("identity should roundtrip");
        assert_eq!(id, decoded);
    }

    #[test]
    fn g2_affine_generator_roundtrip() {
        let g = G2Affine::generator();
        let bytes = <G2Affine as Serializable<96>>::to_bytes(&g);
        let decoded =
            <G2Affine as Serializable<96>>::from_bytes(&bytes).expect("generator should roundtrip");
        assert_eq!(g, decoded);
    }

    #[test]
    fn g2_affine_raw_roundtrip() {
        let g = G2Affine::generator();
        let raw = g.to_raw_bytes();
        let decoded = unsafe { G2Affine::from_slice_unchecked(&raw) };
        assert_eq!(g, decoded);
    }

    #[test]
    fn g2_affine_raw_matches_dusk() {
        let dusk_gen = dusk_bls12_381::G2Affine::generator();
        let dusk_id = dusk_bls12_381::G2Affine::identity();
        assert_eq!(
            G2Affine::generator().to_raw_bytes(),
            dusk_gen.to_raw_bytes()
        );
        assert_eq!(G2Affine::identity().to_raw_bytes(), dusk_id.to_raw_bytes());

        let dusk_double = dusk_bls12_381::G2Affine::from(
            dusk_bls12_381::G2Projective::generator() + dusk_bls12_381::G2Projective::generator(),
        );
        let blst_double = G2Affine::from(G2Projective::generator() + G2Projective::generator());
        assert_eq!(blst_double.to_raw_bytes(), dusk_double.to_raw_bytes());
    }

    #[test]
    fn g2_projective_eq() {
        let a = G2Projective::generator();
        let b = G2Projective::generator();
        assert_eq!(a, b);
        assert_ne!(a, G2Projective::identity());
    }

    #[test]
    fn g2_projective_add_assign() {
        let g = G2Projective::generator();
        let mut acc = G2Projective::identity();
        acc += g;
        assert_eq!(acc, g);
        acc += g;
        let expected = g + g;
        assert_eq!(acc, expected);
    }

    #[test]
    fn g2_projective_add_assign_ref() {
        let g = G2Projective::generator();
        let mut acc = G2Projective::identity();
        acc += &g;
        assert_eq!(acc, g);
    }

    #[test]
    fn g2_projective_add_affine() {
        let a = G2Affine::generator();
        let p = G2Projective::generator();
        let result = p + a;
        let expected = p + G2Projective::from(a);
        assert_eq!(result, expected);
    }

    #[test]
    fn g2_projective_add_assign_affine() {
        let a = G2Affine::generator();
        let mut p = G2Projective::generator();
        let expected = p + G2Projective::from(a);
        p += a;
        assert_eq!(p, expected);
    }

    #[test]
    fn g2_projective_sub_assign() {
        let g = G2Projective::generator();
        let mut acc = g + g;
        acc -= g;
        assert_eq!(acc, g);
    }

    #[test]
    fn g2_projective_mul_assign() {
        let g = G2Projective::generator();
        let two = BlsScalar::from(2u64);
        let mut p = g;
        p *= two;
        assert_eq!(p, g + g);
    }

    #[test]
    fn g2_projective_mul_assign_ref() {
        let g = G2Projective::generator();
        let two = BlsScalar::from(2u64);
        let mut p = g;
        p *= &two;
        assert_eq!(p, g + g);
    }

    #[test]
    fn g2_projective_sum() {
        let g = G2Projective::generator();
        let pts = [g, g, g];
        let total: G2Projective = pts.iter().copied().sum();
        assert_eq!(total, g + g + g);
    }

    #[test]
    fn g2_projective_sum_refs() {
        let g = G2Projective::generator();
        let pts = [g, g];
        let total: G2Projective = pts.iter().sum();
        assert_eq!(total, g + g);
    }

    #[test]
    fn g2_projective_group_trait() {
        let id = <G2Projective as group::Group>::identity();
        let generator = <G2Projective as group::Group>::generator();
        assert!(bool::from(id.is_identity()));
        assert!(!bool::from(generator.is_identity()));
        assert_eq!(generator.double(), generator + generator);
    }

    #[test]
    fn g2_projective_curve_trait() {
        let p = G2Projective::generator();
        let a = <G2Projective as group::Curve>::to_affine(&p);
        assert_eq!(a, G2Affine::generator());
    }

    #[test]
    fn g2_reference_variants_compile_and_match() {
        let a = G2Projective::generator();
        let b = G2Projective::generator();
        assert_eq!(&a + &b, a + b);
        assert_eq!(-&a, -a);
        assert_eq!(G2Affine::from(&a), G2Affine::from(a));

        let aa = G2Affine::generator();
        let bb = G2Affine::generator();
        assert_eq!(&aa + &bb, aa + bb);
        assert_eq!(&aa - &bb, aa - bb);
    }

    #[test]
    fn g2_affine_conditional_select_choice_0_returns_a() {
        let a = G2Affine::generator();
        let b = G2Affine::identity();
        let sel = G2Affine::conditional_select(&a, &b, Choice::from(0));
        assert_eq!(sel, a);
    }

    #[test]
    fn g2_affine_conditional_select_choice_1_returns_b() {
        let a = G2Affine::generator();
        let b = G2Affine::identity();
        let sel = G2Affine::conditional_select(&a, &b, Choice::from(1));
        assert_eq!(sel, b);
    }

    #[test]
    fn g2_projective_conditional_select() {
        let a = G2Projective::generator();
        let b = G2Projective::identity();
        assert_eq!(G2Projective::conditional_select(&a, &b, Choice::from(0)), a);
        assert_eq!(G2Projective::conditional_select(&a, &b, Choice::from(1)), b);
    }

    #[test]
    fn g2_conditional_select_non_identity_points() {
        let generator = G2Projective::generator();
        let a = generator + generator;
        let b = generator * BlsScalar::from(5u64);
        let sel_a = G2Projective::conditional_select(&a, &b, Choice::from(0));
        let sel_b = G2Projective::conditional_select(&a, &b, Choice::from(1));

        assert_ne!(a, b);
        assert_eq!(sel_a, a);
        assert_eq!(sel_b, b);
        assert_ne!(sel_a, sel_b);

        let a_affine = G2Affine::from(a);
        let b_affine = G2Affine::from(b);
        let sel_a_affine = G2Affine::conditional_select(&a_affine, &b_affine, Choice::from(0));
        let sel_b_affine = G2Affine::conditional_select(&a_affine, &b_affine, Choice::from(1));

        assert_ne!(a_affine, b_affine);
        assert_eq!(sel_a_affine, a_affine);
        assert_eq!(sel_b_affine, b_affine);
        assert_ne!(sel_a_affine, sel_b_affine);
    }

    #[test]
    fn g2_clear_cofactor_matches_dusk() {
        let blst_g = G2Projective::generator();
        let dusk_g = dusk_bls12_381::G2Projective::generator();
        let blst_cleared = G2Affine::from(blst_g.clear_cofactor());
        let dusk_cleared = dusk_bls12_381::G2Affine::from(dusk_g.clear_cofactor());
        assert_eq!(blst_cleared.to_raw_bytes(), dusk_cleared.to_raw_bytes());
        assert!(bool::from(blst_cleared.is_torsion_free()));
    }

    #[test]
    fn g2_clear_cofactor_identity_is_identity() {
        let cleared = G2Projective::identity().clear_cofactor();
        assert!(bool::from(cleared.is_identity()));
    }
}
