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
use group::prime::{PrimeCurve, PrimeCurveAffine, PrimeGroup};
use group::{Curve, Group, GroupEncoding, UncompressedEncoding, WnafGroup};
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

// ── dusk re-exports (non-curve items) ────────────────────────────────────────
//
// BlsScalar and scalar-field constants are re-exported verbatim from the dusk
// crate.  They have no blst counterpart and downstream code depends on their
// rich trait surface (ff::Field, Serializable, etc.).

pub use dusk_bls12_381::{BlsScalar, GENERATOR, ROOT_OF_UNITY, TWO_ADACITY};

/// Scalar type for this backend — same as `BlsScalar`.
pub type Scalar = dusk_bls12_381::BlsScalar;

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
#[derive(Copy, Clone, Default, PartialEq, Eq)]
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
    pub fn to_raw_bytes(self) -> [u8; Self::RAW_SIZE] {
        let mut out = [0u8; Self::RAW_SIZE];
        unsafe { ::blst::blst_p1_affine_serialize(out.as_mut_ptr(), &raw const self.0) };
        out
    }

    /// Deserialize from uncompressed form (96 bytes) **without** on-curve or
    /// group-membership checks.
    ///
    /// # Safety
    /// The caller must guarantee that `bytes` contains a valid, uncompressed
    /// encoding of a point that lies on the BLS12-381 G1 curve.  Passing an
    /// invalid encoding produces an undefined (but memory-safe) `BlstG1Affine`
    /// value; subsequent operations on it may give incorrect results.
    #[must_use]
    pub unsafe fn from_slice_unchecked(bytes: &[u8; Self::RAW_SIZE]) -> Self {
        let mut out = ::blst::blst_p1_affine::default();
        unsafe { ::blst::blst_p1_deserialize(&raw mut out, bytes.as_ptr()) };
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

impl fmt::Debug for BlstG1Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = <Self as Serializable<48>>::to_bytes(self);
        write!(f, "G1Affine({:?})", &b[..8])
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

// -- subtle: constant-time equality and selection ---------------------------

impl ConstantTimeEq for BlstG1Affine {
    fn ct_eq(&self, other: &Self) -> Choice {
        <Self as Serializable<48>>::to_bytes(self)
            .ct_eq(&<Self as Serializable<48>>::to_bytes(other))
    }
}

impl ConditionallySelectable for BlstG1Affine {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let a_bytes = <Self as Serializable<48>>::to_bytes(a);
        let b_bytes = <Self as Serializable<48>>::to_bytes(b);
        let mut sel = [0u8; 48];
        for i in 0..48 {
            sel[i] = u8::conditional_select(&a_bytes[i], &b_bytes[i], choice);
        }
        // from_bytes performs subgroup check; fall back to identity on error.
        <Self as Serializable<48>>::from_bytes(&sel).unwrap_or_else(|_| Self::identity())
    }
}

// -- group: GroupEncoding (compressed, 48 bytes) ----------------------------

impl GroupEncoding for BlstG1Affine {
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

impl UncompressedEncoding for BlstG1Affine {
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
        G1Uncompressed(self.to_raw_bytes())
    }
}

// -- group: PrimeCurveAffine ------------------------------------------------

impl PrimeCurveAffine for BlstG1Affine {
    type Scalar = BlsScalar;
    type Curve = BlstG1Projective;

    fn identity() -> Self {
        Self::identity()
    }

    fn generator() -> Self {
        Self::generator()
    }

    fn is_identity(&self) -> Choice {
        let inf = unsafe { ::blst::blst_p1_affine_is_inf(&raw const self.0) };
        Choice::from(inf as u8)
    }

    fn to_curve(&self) -> BlstG1Projective {
        BlstG1Projective::from(*self)
    }
}

// -- scalar-on-left multiplication ------------------------------------------

impl Mul<BlstG1Affine> for BlsScalar {
    type Output = BlstG1Projective;
    fn mul(self, rhs: BlstG1Affine) -> BlstG1Projective {
        rhs * self
    }
}

impl Mul<&BlstG1Affine> for BlsScalar {
    type Output = BlstG1Projective;
    fn mul(self, rhs: &BlstG1Affine) -> BlstG1Projective {
        rhs * self
    }
}

impl Mul<BlstG1Affine> for &BlsScalar {
    type Output = BlstG1Projective;
    fn mul(self, rhs: BlstG1Affine) -> BlstG1Projective {
        rhs * self
    }
}

impl Mul<&BlstG1Affine> for &BlsScalar {
    type Output = BlstG1Projective;
    fn mul(self, rhs: &BlstG1Affine) -> BlstG1Projective {
        rhs * self
    }
}

// -- fmt::Display -----------------------------------------------------------

impl fmt::Display for BlstG1Affine {
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
impl ::zeroize::Zeroize for BlstG1Affine {
    fn zeroize(&mut self) {
        // Overwrite the inner blst_p1_affine memory then re-set to identity
        // so the point is valid (blst may read it again later).
        let ptr = &mut self.0 as *mut ::blst::blst_p1_affine as *mut u8;
        let len = core::mem::size_of::<::blst::blst_p1_affine>();
        unsafe { core::ptr::write_bytes(ptr, 0u8, len) };
        // All-zero blst_p1_affine is the identity, so the wrapper stays valid.
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BlstG1Projective
// ═══════════════════════════════════════════════════════════════════════════════

/// G1 projective point wrapping `blst_p1`.
#[derive(Copy, Clone)]
pub struct BlstG1Projective(pub(crate) ::blst::blst_p1);

impl PartialEq for BlstG1Projective {
    fn eq(&self, other: &Self) -> bool {
        unsafe { ::blst::blst_p1_is_equal(&raw const self.0, &raw const other.0) }
    }
}

impl Eq for BlstG1Projective {}

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

    /// Batch-convert an array of projective points to affine using blst's
    /// `blst_p1s_to_affine` (Montgomery batch inversion — one field
    /// inversion shared across all points).
    pub fn batch_normalize(points: &[Self], out: &mut [BlstG1Affine]) {
        let n = core::cmp::min(points.len(), out.len());
        if n == 0 {
            return;
        }
        let blst_pts: Vec<::blst::blst_p1> = points[..n].iter().map(|p| p.0).collect();
        let affines = ::blst::p1_affines::from(&blst_pts);
        let affine_slice = affines.as_slice();
        for i in 0..n {
            out[i] = BlstG1Affine(affine_slice[i]);
        }
    }
}

impl Default for BlstG1Projective {
    fn default() -> Self {
        Self::identity()
    }
}

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

impl Add<&BlstG1Projective> for BlstG1Projective {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self {
        self + *rhs
    }
}

impl AddAssign<&BlstG1Projective> for BlstG1Projective {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + *rhs;
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

impl Add<&BlstG1Affine> for BlstG1Projective {
    type Output = Self;
    fn add(self, rhs: &BlstG1Affine) -> Self {
        self + *rhs
    }
}

impl AddAssign<&BlstG1Affine> for BlstG1Projective {
    fn add_assign(&mut self, rhs: &BlstG1Affine) {
        *self = *self + *rhs;
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

impl Sub<&BlstG1Projective> for BlstG1Projective {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        self - *rhs
    }
}

impl SubAssign<&BlstG1Projective> for BlstG1Projective {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - *rhs;
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

impl Sub<&BlstG1Affine> for BlstG1Projective {
    type Output = Self;
    fn sub(self, rhs: &BlstG1Affine) -> Self {
        self - *rhs
    }
}

impl SubAssign<&BlstG1Affine> for BlstG1Projective {
    fn sub_assign(&mut self, rhs: &BlstG1Affine) {
        *self = *self - *rhs;
    }
}

impl Mul<BlsScalar> for BlstG1Projective {
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

impl MulAssign<&BlsScalar> for BlstG1Projective {
    fn mul_assign(&mut self, rhs: &BlsScalar) {
        *self = *self * *rhs;
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

// -- subtle: constant-time equality and selection ---------------------------

impl ConstantTimeEq for BlstG1Projective {
    fn ct_eq(&self, other: &Self) -> Choice {
        BlstG1Affine::from(*self).ct_eq(&BlstG1Affine::from(*other))
    }
}

impl ConditionallySelectable for BlstG1Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        BlstG1Projective::from(BlstG1Affine::conditional_select(
            &BlstG1Affine::from(*a),
            &BlstG1Affine::from(*b),
            choice,
        ))
    }
}

// -- group: GroupEncoding ---------------------------------------------------

impl GroupEncoding for BlstG1Projective {
    type Repr = G1Compressed;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <BlstG1Affine as GroupEncoding>::from_bytes(bytes).map(Self::from)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        <BlstG1Affine as GroupEncoding>::from_bytes_unchecked(bytes).map(Self::from)
    }

    fn to_bytes(&self) -> Self::Repr {
        <BlstG1Affine as GroupEncoding>::to_bytes(&BlstG1Affine::from(*self))
    }
}

// -- group: Group -----------------------------------------------------------

impl Group for BlstG1Projective {
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
        let inf = unsafe { ::blst::blst_p1_is_inf(&raw const self.0) };
        Choice::from(inf as u8)
    }

    fn double(&self) -> Self {
        let mut out = ::blst::blst_p1::default();
        unsafe { ::blst::blst_p1_double(&raw mut out, &raw const self.0) };
        Self(out)
    }
}

// -- group: Curve + PrimeCurve ----------------------------------------------

impl Curve for BlstG1Projective {
    type AffineRepr = BlstG1Affine;

    fn to_affine(&self) -> Self::AffineRepr {
        BlstG1Affine::from(*self)
    }

    fn batch_normalize(points: &[Self], out: &mut [Self::AffineRepr]) {
        Self::batch_normalize(points, out);
    }
}

impl PrimeCurve for BlstG1Projective {
    type Affine = BlstG1Affine;
}

impl PrimeGroup for BlstG1Projective {}

impl WnafGroup for BlstG1Projective {
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

impl Mul<BlstG1Projective> for BlsScalar {
    type Output = BlstG1Projective;
    fn mul(self, rhs: BlstG1Projective) -> BlstG1Projective {
        rhs * self
    }
}

impl Mul<&BlstG1Projective> for BlsScalar {
    type Output = BlstG1Projective;
    fn mul(self, rhs: &BlstG1Projective) -> BlstG1Projective {
        rhs * self
    }
}

impl Mul<BlstG1Projective> for &BlsScalar {
    type Output = BlstG1Projective;
    fn mul(self, rhs: BlstG1Projective) -> BlstG1Projective {
        rhs * self
    }
}

impl Mul<&BlstG1Projective> for &BlsScalar {
    type Output = BlstG1Projective;
    fn mul(self, rhs: &BlstG1Projective) -> BlstG1Projective {
        rhs * self
    }
}

// -- fmt::Display -----------------------------------------------------------

impl fmt::Display for BlstG1Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&BlstG1Affine::from(*self), f)
    }
}

// -- zeroize ----------------------------------------------------------------

#[cfg(feature = "zeroize")]
impl ::zeroize::Zeroize for BlstG1Projective {
    fn zeroize(&mut self) {
        let ptr = &mut self.0 as *mut ::blst::blst_p1 as *mut u8;
        let len = core::mem::size_of::<::blst::blst_p1>();
        unsafe { core::ptr::write_bytes(ptr, 0u8, len) };
        // All-zero blst_p1 is the identity in blst's projective coordinates.
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BlstG2Affine
// ═══════════════════════════════════════════════════════════════════════════════

/// G2 affine point wrapping `blst_p2_affine`.
#[derive(Copy, Clone, Default, PartialEq, Eq)]
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

impl fmt::Debug for BlstG2Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = <Self as Serializable<96>>::to_bytes(self);
        write!(f, "G2Affine({:?})", &b[..8])
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

impl Mul<&BlsScalar> for BlstG2Affine {
    type Output = BlstG2Projective;
    fn mul(self, rhs: &BlsScalar) -> BlstG2Projective {
        self * (*rhs)
    }
}

impl Mul<&BlsScalar> for &BlstG2Affine {
    type Output = BlstG2Projective;
    fn mul(self, rhs: &BlsScalar) -> BlstG2Projective {
        (*self) * (*rhs)
    }
}

impl Add<BlstG2Affine> for BlstG2Affine {
    type Output = BlstG2Projective;
    fn add(self, rhs: BlstG2Affine) -> BlstG2Projective {
        BlstG2Projective::from(self) + BlstG2Projective::from(rhs)
    }
}

impl Add<BlstG2Projective> for BlstG2Affine {
    type Output = BlstG2Projective;
    fn add(self, rhs: BlstG2Projective) -> BlstG2Projective {
        BlstG2Projective::from(self) + rhs
    }
}

impl Sub<BlstG2Projective> for BlstG2Affine {
    type Output = BlstG2Projective;
    fn sub(self, rhs: BlstG2Projective) -> BlstG2Projective {
        BlstG2Projective::from(self) - rhs
    }
}

// -- subtle: constant-time equality and selection ---------------------------

impl ConstantTimeEq for BlstG2Affine {
    fn ct_eq(&self, other: &Self) -> Choice {
        <Self as Serializable<96>>::to_bytes(self)
            .ct_eq(&<Self as Serializable<96>>::to_bytes(other))
    }
}

impl ConditionallySelectable for BlstG2Affine {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let a_bytes = <Self as Serializable<96>>::to_bytes(a);
        let b_bytes = <Self as Serializable<96>>::to_bytes(b);
        let mut sel = [0u8; 96];
        for i in 0..96 {
            sel[i] = u8::conditional_select(&a_bytes[i], &b_bytes[i], choice);
        }
        <Self as Serializable<96>>::from_bytes(&sel).unwrap_or_else(|_| Self::identity())
    }
}

// -- group: GroupEncoding (compressed, 96 bytes) ----------------------------

impl GroupEncoding for BlstG2Affine {
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

impl UncompressedEncoding for BlstG2Affine {
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

impl PrimeCurveAffine for BlstG2Affine {
    type Scalar = BlsScalar;
    type Curve = BlstG2Projective;

    fn identity() -> Self {
        Self::identity()
    }

    fn generator() -> Self {
        Self::generator()
    }

    fn is_identity(&self) -> Choice {
        let inf = unsafe { ::blst::blst_p2_affine_is_inf(&raw const self.0) };
        Choice::from(inf as u8)
    }

    fn to_curve(&self) -> BlstG2Projective {
        BlstG2Projective::from(*self)
    }
}

// -- scalar-on-left multiplication ------------------------------------------

impl Mul<BlstG2Affine> for BlsScalar {
    type Output = BlstG2Projective;
    fn mul(self, rhs: BlstG2Affine) -> BlstG2Projective {
        rhs * self
    }
}

impl Mul<&BlstG2Affine> for BlsScalar {
    type Output = BlstG2Projective;
    fn mul(self, rhs: &BlstG2Affine) -> BlstG2Projective {
        rhs * self
    }
}

impl Mul<BlstG2Affine> for &BlsScalar {
    type Output = BlstG2Projective;
    fn mul(self, rhs: BlstG2Affine) -> BlstG2Projective {
        rhs * self
    }
}

impl Mul<&BlstG2Affine> for &BlsScalar {
    type Output = BlstG2Projective;
    fn mul(self, rhs: &BlstG2Affine) -> BlstG2Projective {
        rhs * self
    }
}

// -- fmt::Display -----------------------------------------------------------

impl fmt::Display for BlstG2Affine {
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
impl ::zeroize::Zeroize for BlstG2Affine {
    fn zeroize(&mut self) {
        let ptr = &mut self.0 as *mut ::blst::blst_p2_affine as *mut u8;
        let len = core::mem::size_of::<::blst::blst_p2_affine>();
        unsafe { core::ptr::write_bytes(ptr, 0u8, len) };
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BlstG2Projective
// ═══════════════════════════════════════════════════════════════════════════════

/// G2 projective point wrapping `blst_p2`.
#[derive(Copy, Clone)]
pub struct BlstG2Projective(pub(crate) ::blst::blst_p2);

impl PartialEq for BlstG2Projective {
    fn eq(&self, other: &Self) -> bool {
        unsafe { ::blst::blst_p2_is_equal(&raw const self.0, &raw const other.0) }
    }
}

impl Eq for BlstG2Projective {}

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

    /// Batch-convert an array of projective points to affine using blst's
    /// `blst_p2s_to_affine` (Montgomery batch inversion — one field
    /// inversion shared across all points).
    pub fn batch_normalize(points: &[Self], out: &mut [BlstG2Affine]) {
        let n = core::cmp::min(points.len(), out.len());
        if n == 0 {
            return;
        }
        let blst_pts: Vec<::blst::blst_p2> = points[..n].iter().map(|p| p.0).collect();
        let affines = ::blst::p2_affines::from(&blst_pts);
        let affine_slice = affines.as_slice();
        for i in 0..n {
            out[i] = BlstG2Affine(affine_slice[i]);
        }
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

impl AddAssign for BlstG2Projective {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Add<&BlstG2Projective> for BlstG2Projective {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self {
        self + *rhs
    }
}

impl AddAssign<&BlstG2Projective> for BlstG2Projective {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + *rhs;
    }
}

impl Add<BlstG2Affine> for BlstG2Projective {
    type Output = Self;
    fn add(self, rhs: BlstG2Affine) -> Self {
        let mut out = ::blst::blst_p2::default();
        unsafe {
            ::blst::blst_p2_add_or_double_affine(&raw mut out, &raw const self.0, &raw const rhs.0);
        }
        Self(out)
    }
}

impl AddAssign<BlstG2Affine> for BlstG2Projective {
    fn add_assign(&mut self, rhs: BlstG2Affine) {
        *self = *self + rhs;
    }
}

impl Add<&BlstG2Affine> for BlstG2Projective {
    type Output = Self;
    fn add(self, rhs: &BlstG2Affine) -> Self {
        self + *rhs
    }
}

impl AddAssign<&BlstG2Affine> for BlstG2Projective {
    fn add_assign(&mut self, rhs: &BlstG2Affine) {
        *self = *self + *rhs;
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

impl SubAssign for BlstG2Projective {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Sub<&BlstG2Projective> for BlstG2Projective {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        self - *rhs
    }
}

impl SubAssign<&BlstG2Projective> for BlstG2Projective {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - *rhs;
    }
}

impl Sub<BlstG2Affine> for BlstG2Projective {
    type Output = Self;
    fn sub(self, rhs: BlstG2Affine) -> Self {
        self - Self::from(rhs)
    }
}

impl SubAssign<BlstG2Affine> for BlstG2Projective {
    fn sub_assign(&mut self, rhs: BlstG2Affine) {
        *self = *self - rhs;
    }
}

impl Sub<&BlstG2Affine> for BlstG2Projective {
    type Output = Self;
    fn sub(self, rhs: &BlstG2Affine) -> Self {
        self - *rhs
    }
}

impl SubAssign<&BlstG2Affine> for BlstG2Projective {
    fn sub_assign(&mut self, rhs: &BlstG2Affine) {
        *self = *self - *rhs;
    }
}

impl Mul<BlsScalar> for BlstG2Projective {
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

impl Mul<&BlsScalar> for BlstG2Projective {
    type Output = Self;
    fn mul(self, rhs: &BlsScalar) -> Self {
        self * (*rhs)
    }
}

impl Mul<BlsScalar> for &BlstG2Projective {
    type Output = BlstG2Projective;
    fn mul(self, rhs: BlsScalar) -> BlstG2Projective {
        (*self) * rhs
    }
}

impl Mul<&BlsScalar> for &BlstG2Projective {
    type Output = BlstG2Projective;
    fn mul(self, rhs: &BlsScalar) -> BlstG2Projective {
        (*self) * (*rhs)
    }
}

impl MulAssign<BlsScalar> for BlstG2Projective {
    fn mul_assign(&mut self, rhs: BlsScalar) {
        *self = *self * rhs;
    }
}

impl MulAssign<&BlsScalar> for BlstG2Projective {
    fn mul_assign(&mut self, rhs: &BlsScalar) {
        *self = *self * *rhs;
    }
}

impl core::iter::Sum for BlstG2Projective {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + x)
    }
}

impl<'a> core::iter::Sum<&'a BlstG2Projective> for BlstG2Projective {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + *x)
    }
}

// -- subtle: constant-time equality and selection ---------------------------

impl ConstantTimeEq for BlstG2Projective {
    fn ct_eq(&self, other: &Self) -> Choice {
        BlstG2Affine::from(*self).ct_eq(&BlstG2Affine::from(*other))
    }
}

impl ConditionallySelectable for BlstG2Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::from(BlstG2Affine::conditional_select(
            &BlstG2Affine::from(*a),
            &BlstG2Affine::from(*b),
            choice,
        ))
    }
}

// -- group: GroupEncoding ---------------------------------------------------

impl GroupEncoding for BlstG2Projective {
    type Repr = G2Compressed;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <BlstG2Affine as GroupEncoding>::from_bytes(bytes).map(Self::from)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        <BlstG2Affine as GroupEncoding>::from_bytes_unchecked(bytes).map(Self::from)
    }

    fn to_bytes(&self) -> Self::Repr {
        <BlstG2Affine as GroupEncoding>::to_bytes(&BlstG2Affine::from(*self))
    }
}

// -- group: Group -----------------------------------------------------------

impl Group for BlstG2Projective {
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
        let inf = unsafe { ::blst::blst_p2_is_inf(&raw const self.0) };
        Choice::from(inf as u8)
    }

    fn double(&self) -> Self {
        let mut out = ::blst::blst_p2::default();
        unsafe { ::blst::blst_p2_double(&raw mut out, &raw const self.0) };
        Self(out)
    }
}

// -- group: Curve + PrimeCurve + PrimeGroup + WnafGroup ---------------------

impl Curve for BlstG2Projective {
    type AffineRepr = BlstG2Affine;

    fn to_affine(&self) -> Self::AffineRepr {
        BlstG2Affine::from(*self)
    }

    fn batch_normalize(points: &[Self], out: &mut [Self::AffineRepr]) {
        Self::batch_normalize(points, out);
    }
}

impl PrimeCurve for BlstG2Projective {
    type Affine = BlstG2Affine;
}

impl PrimeGroup for BlstG2Projective {}

impl WnafGroup for BlstG2Projective {
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

impl Mul<BlstG2Projective> for BlsScalar {
    type Output = BlstG2Projective;
    fn mul(self, rhs: BlstG2Projective) -> BlstG2Projective {
        rhs * self
    }
}

impl Mul<&BlstG2Projective> for BlsScalar {
    type Output = BlstG2Projective;
    fn mul(self, rhs: &BlstG2Projective) -> BlstG2Projective {
        rhs * self
    }
}

impl Mul<BlstG2Projective> for &BlsScalar {
    type Output = BlstG2Projective;
    fn mul(self, rhs: BlstG2Projective) -> BlstG2Projective {
        rhs * self
    }
}

impl Mul<&BlstG2Projective> for &BlsScalar {
    type Output = BlstG2Projective;
    fn mul(self, rhs: &BlstG2Projective) -> BlstG2Projective {
        rhs * self
    }
}

// -- fmt::Display -----------------------------------------------------------

impl fmt::Display for BlstG2Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&BlstG2Affine::from(*self), f)
    }
}

// -- zeroize ----------------------------------------------------------------

#[cfg(feature = "zeroize")]
impl ::zeroize::Zeroize for BlstG2Projective {
    fn zeroize(&mut self) {
        let ptr = &mut self.0 as *mut ::blst::blst_p2 as *mut u8;
        let len = core::mem::size_of::<::blst::blst_p2>();
        unsafe { core::ptr::write_bytes(ptr, 0u8, len) };
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
#[derive(Copy, Clone, PartialEq, Eq)]
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
pub(crate) fn multi_miller_loop(terms: &[(&G1Affine, &G2Prepared)]) -> MillerLoopResult {
    if terms.is_empty() {
        return MillerLoopResult(unsafe { *::blst::blst_fp12_one() });
    }
    let ps: Vec<::blst::blst_p1_affine> = terms.iter().map(|(g1, _)| g1.0).collect();
    let qs: Vec<::blst::blst_p2_affine> = terms.iter().map(|(_, g2)| g2.0).collect();
    MillerLoopResult(::blst::blst_fp12::miller_loop_n(
        qs.as_slice(),
        ps.as_slice(),
    ))
}

/// Compute the multi-Miller loop and apply final exponentiation, returning a `Gt` element.
#[must_use]
pub fn multi_miller_loop_result(terms: &[(&G1Affine, &G2Prepared)]) -> Gt {
    multi_miller_loop(terms).final_exponentiation()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Module-level functions
// ═══════════════════════════════════════════════════════════════════════════════

#[must_use]
#[inline]
/// NOTE: internal function comes from the dusk backend, not blst
pub fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    Scalar::hash_to_scalar(bytes)
}

#[must_use]
#[inline]
/// NOTE: internal function comes from the dusk backend, not blst
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
    ::blst::blst_fp12::finalverify(&gt, unsafe { &*::blst::blst_fp12_one() })
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
    fn pairing_trivial_identity() {
        assert!(pairing_product_is_identity(&[]));
    }

    #[test]
    fn pairing_g1_neg_g1_is_identity() {
        // e(G1, G2) · e(-G1, G2) == 1  (exercises miller loop + final_exp)
        let g1 = G1Affine::generator();
        let neg_g1 = -g1;
        let g2 = G2Affine::generator();
        assert!(pairing_product_is_identity(&[(&g1, &g2), (&neg_g1, &g2)]));
    }

    #[test]
    fn pairing_non_identity_is_not_identity() {
        // A single non-trivial pairing term must not equal 1
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        assert!(!pairing_product_is_identity(&[(&g1, &g2)]));
    }
}
