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
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        let mut out = [0u8; Self::RAW_SIZE];
        if bool::from(self.is_identity()) {
            let dusk_identity = dusk_bls12_381::G1Affine::identity();
            return dusk_identity.to_raw_bytes();
        }
        write_raw_limbs(
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
        read_raw_limbs(
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
impl ::zeroize::Zeroize for G1Affine {
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
        G1Projective::from(G1Affine::conditional_select(
            &G1Affine::from(*a),
            &G1Affine::from(*b),
            choice,
        ))
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
        let mut out = ::blst::blst_p1::default();
        unsafe { ::blst::blst_p1_double(&raw mut out, &raw const self.0) };
        Self(out)
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
impl ::zeroize::Zeroize for G1Projective {
    fn zeroize(&mut self) {
        let ptr = &mut self.0 as *mut ::blst::blst_p1 as *mut u8;
        let len = core::mem::size_of::<::blst::blst_p1>();
        unsafe { core::ptr::write_bytes(ptr, 0u8, len) };
        // All-zero blst_p1 is the identity in blst's projective coordinates.
    }
}

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
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        let mut out = [0u8; Self::RAW_SIZE];
        if bool::from(self.is_identity()) {
            let dusk_identity = dusk_bls12_381::G2Affine::identity();
            return dusk_identity.to_raw_bytes();
        }
        write_raw_limbs(
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
        read_raw_limbs(&raw[..xc0_end], out.x.fp[0].l.iter_mut());
        if raw.len() > 48 {
            let xc1_end = core::cmp::min(raw.len(), 96);
            read_raw_limbs(&raw[48..xc1_end], out.x.fp[1].l.iter_mut());
        }
        if raw.len() > 96 {
            let yc0_end = core::cmp::min(raw.len(), 144);
            read_raw_limbs(&raw[96..yc0_end], out.y.fp[0].l.iter_mut());
        }
        if raw.len() > 144 {
            let yc1_end = core::cmp::min(raw.len(), 192);
            read_raw_limbs(&raw[144..yc1_end], out.y.fp[1].l.iter_mut());
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
        Self::from(G2Affine::conditional_select(
            &G2Affine::from(*a),
            &G2Affine::from(*b),
            choice,
        ))
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

// ═══════════════════════════════════════════════════════════════════════════════
//  G2Prepared
// ═══════════════════════════════════════════════════════════════════════════════

/// Prepared G2 element for pairing.
///
/// In the blst backend this is a thin affine wrapper used only to drive
/// pairing operations.
#[derive(Copy, Clone, Debug, Default)]
pub struct G2Prepared(pub(crate) ::blst::blst_p2_affine);

impl From<G2Affine> for G2Prepared {
    fn from(p: G2Affine) -> Self {
        Self(p.0)
    }
}

impl From<&G2Affine> for G2Prepared {
    fn from(p: &G2Affine) -> Self {
        Self::from(*p)
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

impl fmt::Debug for Gt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gt(..)")
    }
}

impl Eq for Gt {}

impl PartialEq for Gt {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.to_bendian().ct_eq(&other.0.to_bendian()))
    }
}

/// Result of a multi-Miller loop, before final exponentiation.
#[derive(Copy, Clone)]
pub struct MillerLoopResult(::blst::blst_fp12);

impl Default for MillerLoopResult {
    fn default() -> Self {
        Self(unsafe { *::blst::blst_fp12_one() })
    }
}

impl fmt::Debug for MillerLoopResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MillerLoopResult(..)")
    }
}

impl MillerLoopResult {
    /// Perform the final exponentiation to obtain a Gt element.
    #[must_use]
    pub fn final_exponentiation(&self) -> Gt {
        Gt(self.0.final_exp())
    }
}

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
    G1Projective(out)
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
    fn affine_validation_methods_match_expectations() {
        assert!(bool::from(G1Affine::generator().is_on_curve()));
        assert!(bool::from(G1Affine::generator().is_torsion_free()));
        assert!(bool::from(G2Affine::generator().is_on_curve()));
        assert!(bool::from(G2Affine::generator().is_torsion_free()));
    }

    #[test]
    fn pairing_result_compares_against_identity() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let prepared = G2Prepared::from(g2);
        let gt = multi_miller_loop_result(&[(&g1, &prepared)]);
        assert_ne!(gt, Gt::identity());
        assert_eq!(multi_miller_loop_result(&[]), Gt::identity());
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
