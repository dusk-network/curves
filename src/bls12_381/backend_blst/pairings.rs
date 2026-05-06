// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Pairing-related types and functions for the blst backend.
//!
//! Contains `G2Prepared`, `Gt`, `MillerLoopResult`, and the
//! pairing-computation entry points.

use core::borrow::Borrow;
use core::fmt;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use alloc::vec::Vec;
use group::Group;
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::{BlsScalar, G1Affine, G2Affine, Scalar};

// ── Internal Fp/Fp2/Fp6/Fp12 conditional-select helpers ──────────────────────

fn conditional_select_fp(
    a: &::blst::blst_fp,
    b: &::blst::blst_fp,
    choice: Choice,
) -> ::blst::blst_fp {
    let mut out = ::blst::blst_fp::default();
    for i in 0..out.l.len() {
        out.l[i] = u64::conditional_select(&a.l[i], &b.l[i], choice);
    }
    out
}

fn conditional_select_fp2(
    a: &::blst::blst_fp2,
    b: &::blst::blst_fp2,
    choice: Choice,
) -> ::blst::blst_fp2 {
    ::blst::blst_fp2 {
        fp: [
            conditional_select_fp(&a.fp[0], &b.fp[0], choice),
            conditional_select_fp(&a.fp[1], &b.fp[1], choice),
        ],
    }
}

fn conditional_select_fp6(
    a: &::blst::blst_fp6,
    b: &::blst::blst_fp6,
    choice: Choice,
) -> ::blst::blst_fp6 {
    ::blst::blst_fp6 {
        fp2: [
            conditional_select_fp2(&a.fp2[0], &b.fp2[0], choice),
            conditional_select_fp2(&a.fp2[1], &b.fp2[1], choice),
            conditional_select_fp2(&a.fp2[2], &b.fp2[2], choice),
        ],
    }
}

fn conditional_select_fp12(
    a: &::blst::blst_fp12,
    b: &::blst::blst_fp12,
    choice: Choice,
) -> ::blst::blst_fp12 {
    ::blst::blst_fp12 {
        fp6: [
            conditional_select_fp6(&a.fp6[0], &b.fp6[0], choice),
            conditional_select_fp6(&a.fp6[1], &b.fp6[1], choice),
        ],
    }
}

const GT_GENERATOR: ::blst::blst_fp12 = ::blst::blst_fp12 {
    fp6: [
        ::blst::blst_fp6 {
            fp2: [
                ::blst::blst_fp2 {
                    fp: [
                        ::blst::blst_fp {
                            l: [
                                0x1972_e433_a01f_85c5,
                                0x97d3_2b76_fd77_2538,
                                0xc8ce_546f_c96b_cdf9,
                                0xcef6_3e73_66d4_0614,
                                0xa611_3427_8184_3780,
                                0x13f3_448a_3fc6_d825,
                            ],
                        },
                        ::blst::blst_fp {
                            l: [
                                0xd263_31b0_2e9d_6995,
                                0x9d68_a482_f779_7e7d,
                                0x9c9b_2924_8d39_ea92,
                                0xf480_1ca2_e131_07aa,
                                0xa16c_0732_bdbc_b066,
                                0x083c_a4af_ba36_0478,
                            ],
                        },
                    ],
                },
                ::blst::blst_fp2 {
                    fp: [
                        ::blst::blst_fp {
                            l: [
                                0x59e2_61db_0916_b641,
                                0x2716_b6f4_b23e_960d,
                                0xc8e5_5b10_a0bd_9c45,
                                0x0bdb_0bd9_9c4d_eda8,
                                0x8cf8_9ebf_57fd_aac5,
                                0x12d6_b792_9e77_7a5e,
                            ],
                        },
                        ::blst::blst_fp {
                            l: [
                                0x5fc8_5188_b0e1_5f35,
                                0x34a0_6e3a_8f09_6365,
                                0xdb31_26a6_e02a_d62c,
                                0xfc6f_5aa9_7d9a_990b,
                                0xa12f_55f5_eb89_c210,
                                0x1723_703a_926f_8889,
                            ],
                        },
                    ],
                },
                ::blst::blst_fp2 {
                    fp: [
                        ::blst::blst_fp {
                            l: [
                                0x9358_8f29_7182_8778,
                                0x43f6_5b86_11ab_7585,
                                0x3183_aaf5_ec27_9fdf,
                                0xfa73_d7e1_8ac9_9df6,
                                0x64e1_76a6_a64c_99b0,
                                0x179f_a78c_5838_8f1f,
                            ],
                        },
                        ::blst::blst_fp {
                            l: [
                                0x672a_0a11_ca2a_ef12,
                                0x0d11_b9b5_2aa3_f16b,
                                0xa444_12d0_699d_056e,
                                0xc01d_0177_221a_5ba5,
                                0x66e0_cede_6c73_5529,
                                0x05f5_a71e_9fdd_c339,
                            ],
                        },
                    ],
                },
            ],
        },
        ::blst::blst_fp6 {
            fp2: [
                ::blst::blst_fp2 {
                    fp: [
                        ::blst::blst_fp {
                            l: [
                                0xd30a_88a1_b062_c679,
                                0x5ac5_6a5d_35fc_8304,
                                0xd0c8_34a6_a81f_290d,
                                0xcd54_30c2_da37_07c7,
                                0xf0c2_7ff7_8050_0af0,
                                0x0924_5da6_e2d7_2eae,
                            ],
                        },
                        ::blst::blst_fp {
                            l: [
                                0x9f2e_0676_791b_5156,
                                0xe2d1_c823_4918_fe13,
                                0x4c9e_459f_3c56_1bf4,
                                0xa3e8_5e53_b9d3_e3c1,
                                0x820a_121e_21a7_0020,
                                0x15af_6183_41c5_9acc,
                            ],
                        },
                    ],
                },
                ::blst::blst_fp2 {
                    fp: [
                        ::blst::blst_fp {
                            l: [
                                0x7c95_658c_2499_3ab1,
                                0x73eb_3872_1ca8_86b9,
                                0x5256_d749_4774_34bc,
                                0x8ba4_1902_ea50_4a8b,
                                0x04a3_d3f8_0c86_ce6d,
                                0x18a6_4a87_fb68_6eaa,
                            ],
                        },
                        ::blst::blst_fp {
                            l: [
                                0xbb83_e71b_b920_cf26,
                                0x2a52_77ac_92a7_3945,
                                0xfc0e_e59f_94f0_46a0,
                                0x7158_cdf3_7860_58f7,
                                0x7cc1_061b_82f9_45f6,
                                0x03f8_47aa_9fdb_e567,
                            ],
                        },
                    ],
                },
                ::blst::blst_fp2 {
                    fp: [
                        ::blst::blst_fp {
                            l: [
                                0x8078_dba5_6134_e657,
                                0x1cd7_ec9a_4399_8a6e,
                                0xb1aa_599a_1a99_3766,
                                0xc9a0_f62f_0842_ee44,
                                0x8e15_9be3_b605_dffa,
                                0x0c86_ba0d_4af1_3fc2,
                            ],
                        },
                        ::blst::blst_fp {
                            l: [
                                0xe80f_f2a0_6a52_ffb1,
                                0x7694_ca48_721a_906c,
                                0x7583_183e_03b0_8514,
                                0xf567_afdd_40ce_e4e2,
                                0x9a6d_96d2_e526_a5fc,
                                0x197e_9f49_861f_2242,
                            ],
                        },
                    ],
                },
            ],
        },
    ],
};

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

impl G2Prepared {
    /// Size of the raw representation.
    pub const RAW_SIZE: usize = G2Affine::RAW_SIZE;

    /// Serialize to the raw affine representation used by the blst backend.
    ///
    /// Bytes are not interchangeable with `dusk_bls12_381::G2Prepared::to_raw_bytes`,
    /// which serializes precomputed Miller coefficients. The blst backend stores a
    /// plain affine point (since the blst Miller loop accepts affine inputs
    /// directly), so the raw bytes match `G2Affine::to_raw_bytes` instead.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        G2Affine(self.0).to_raw_bytes()
    }

    /// Create a prepared element from the raw affine representation.
    ///
    /// # Safety
    /// The caller must guarantee that `bytes` contains a valid raw G2 affine
    /// encoding produced by this backend.
    #[must_use]
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        Self(unsafe { G2Affine::from_slice_unchecked(bytes) }.0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Gt (pairing target group)
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

    /// Doubles this group element in additive notation.
    ///
    /// In Gt the underlying field representation is multiplicative, so
    /// "doubling" in additive notation corresponds to squaring the fp12
    /// element.
    #[must_use]
    pub fn double(&self) -> Self {
        let mut out = ::blst::blst_fp12::default();
        unsafe { ::blst::blst_fp12_sqr(&raw mut out, &raw const self.0) };
        Self(out)
    }

    fn add_group_element(&self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }

    fn mul_scalar(&self, rhs: &BlsScalar) -> Self {
        // Standard left-to-right double-and-add. `to_bytes` returns the scalar
        // in little-endian, so we iterate bytes in reverse to walk MSB-first
        // and process all 256 bits.
        let mut acc = Self::identity();
        for bit in rhs
            .to_bytes()
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8)))
        {
            acc = acc.double();
            acc = Self::conditional_select(&acc, &acc.add_group_element(self), bit);
        }
        acc
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

impl fmt::Display for Gt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ConstantTimeEq for Gt {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.to_bendian().ct_eq(&other.0.to_bendian())
    }
}

impl ConditionallySelectable for Gt {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(conditional_select_fp12(&a.0, &b.0, choice))
    }
}

impl Eq for Gt {}

impl PartialEq for Gt {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

// -- Negation, addition, subtraction (additive notation) --------------------

impl Neg for &Gt {
    type Output = Gt;

    fn neg(self) -> Gt {
        let mut out = self.0;
        unsafe { ::blst::blst_fp12_conjugate(&raw mut out) };
        Gt(out)
    }
}

impl Neg for Gt {
    type Output = Gt;

    fn neg(self) -> Gt {
        -&self
    }
}

impl Add for Gt {
    type Output = Gt;

    fn add(self, rhs: Gt) -> Gt {
        self.add_group_element(&rhs)
    }
}

impl Add<&Gt> for Gt {
    type Output = Gt;

    fn add(self, rhs: &Gt) -> Gt {
        self + *rhs
    }
}

impl Add<Gt> for &Gt {
    type Output = Gt;

    fn add(self, rhs: Gt) -> Gt {
        *self + rhs
    }
}

impl Add<&Gt> for &Gt {
    type Output = Gt;

    fn add(self, rhs: &Gt) -> Gt {
        *self + *rhs
    }
}

impl AddAssign for Gt {
    fn add_assign(&mut self, rhs: Gt) {
        *self = *self + rhs;
    }
}

impl AddAssign<&Gt> for Gt {
    fn add_assign(&mut self, rhs: &Gt) {
        *self = *self + *rhs;
    }
}

impl Sub for Gt {
    type Output = Gt;

    fn sub(self, rhs: Gt) -> Gt {
        self + (-rhs)
    }
}

impl Sub<&Gt> for Gt {
    type Output = Gt;

    fn sub(self, rhs: &Gt) -> Gt {
        self - *rhs
    }
}

impl Sub<Gt> for &Gt {
    type Output = Gt;

    fn sub(self, rhs: Gt) -> Gt {
        *self - rhs
    }
}

impl Sub<&Gt> for &Gt {
    type Output = Gt;

    fn sub(self, rhs: &Gt) -> Gt {
        *self - *rhs
    }
}

impl SubAssign for Gt {
    fn sub_assign(&mut self, rhs: Gt) {
        *self = *self - rhs;
    }
}

impl SubAssign<&Gt> for Gt {
    fn sub_assign(&mut self, rhs: &Gt) {
        *self = *self - *rhs;
    }
}

// -- Scalar multiplication (additive notation) ------------------------------

impl Mul<BlsScalar> for Gt {
    type Output = Gt;

    fn mul(self, rhs: BlsScalar) -> Gt {
        self.mul_scalar(&rhs)
    }
}

impl Mul<&BlsScalar> for Gt {
    type Output = Gt;

    fn mul(self, rhs: &BlsScalar) -> Gt {
        self.mul_scalar(rhs)
    }
}

impl Mul<BlsScalar> for &Gt {
    type Output = Gt;

    fn mul(self, rhs: BlsScalar) -> Gt {
        self.mul_scalar(&rhs)
    }
}

impl Mul<&BlsScalar> for &Gt {
    type Output = Gt;

    fn mul(self, rhs: &BlsScalar) -> Gt {
        self.mul_scalar(rhs)
    }
}

impl MulAssign<BlsScalar> for Gt {
    fn mul_assign(&mut self, rhs: BlsScalar) {
        *self = *self * rhs;
    }
}

impl MulAssign<&BlsScalar> for Gt {
    fn mul_assign(&mut self, rhs: &BlsScalar) {
        *self = *self * *rhs;
    }
}

impl<T> Sum<T> for Gt
where
    T: Borrow<Gt>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

// -- group::Group -----------------------------------------------------------

impl Group for Gt {
    type Scalar = BlsScalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let scalar: Scalar = super::scalar_from_wide(&wide);
        Self::generator() * scalar
    }

    fn identity() -> Self {
        Self::identity()
    }

    fn generator() -> Self {
        Self(GT_GENERATOR)
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::identity())
    }

    fn double(&self) -> Self {
        Self::double(self)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MillerLoopResult
// ═══════════════════════════════════════════════════════════════════════════════

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

impl ConditionallySelectable for MillerLoopResult {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(conditional_select_fp12(&a.0, &b.0, choice))
    }
}

// ── zeroize ─────────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
impl ::zeroize::Zeroize for Gt {
    fn zeroize(&mut self) {
        let ptr = &mut self.0 as *mut ::blst::blst_fp12 as *mut u8;
        let len = core::mem::size_of::<::blst::blst_fp12>();
        // Safety: write_bytes overwrites the fp12 with zero, which is a valid
        // (though degenerate) byte pattern. We immediately reset to the canonical
        // identity element below so the value is left in a usable, non-secret state.
        unsafe { core::ptr::write_bytes(ptr, 0u8, len) };
        *self = Self::identity();
    }
}

#[cfg(feature = "zeroize")]
impl ::zeroize::Zeroize for MillerLoopResult {
    fn zeroize(&mut self) {
        let ptr = &mut self.0 as *mut ::blst::blst_fp12 as *mut u8;
        let len = core::mem::size_of::<::blst::blst_fp12>();
        // Safety: see `Zeroize for Gt`. We restore the default value (one)
        // afterwards to leave the result in a well-defined state.
        unsafe { core::ptr::write_bytes(ptr, 0u8, len) };
        *self = Self::default();
    }
}

// ── serde ────────────────────────────────────────────────────────────────────

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

    impl Serialize for G2Prepared {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            hex::encode(dusk_bytes::Serializable::to_bytes(&G2Affine(self.0))).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for G2Prepared {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let bytes = decode_hex::<D, 96>(deserializer)?;
            let affine = <G2Affine as dusk_bytes::Serializable<96>>::from_bytes(&bytes)
                .map_err(|err| SerdeError::custom(format!("{err:?}")))?;
            Ok(Self::from(affine))
        }
    }
}

// ── Pairing functions ────────────────────────────────────────────────────────

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

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mul_scalar_reference(base: &Gt, scalar: &BlsScalar) -> Gt {
        // Independent right-to-left bit walk over the little-endian encoding.
        let mut acc = Gt::identity();
        let mut current = *base;
        for byte in scalar.to_bytes() {
            for bit_index in 0..8 {
                if ((byte >> bit_index) & 1) == 1 {
                    acc += current;
                }
                current = current.double();
            }
        }
        acc
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

    #[test]
    fn g2_prepared_raw_roundtrip() {
        let prepared = G2Prepared::from(G2Affine::generator());
        let raw = prepared.to_raw_bytes();
        let decoded = unsafe { G2Prepared::from_slice_unchecked(&raw) };
        assert_eq!(G2Affine(decoded.0), G2Affine::generator());
    }

    #[test]
    fn gt_additive_arithmetic_works() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let prepared = G2Prepared::from(g2);
        let gt = multi_miller_loop_result(&[(&g1, &prepared)]);

        // a + (-a) = 0
        assert_eq!(gt + (-gt), Gt::identity());
        // a + a = 2a (via doubling)
        assert_eq!(&gt + &gt, gt.double());
        // 2 · a = a + a
        assert_eq!(gt * BlsScalar::from(2u64), gt + gt);
        // identity scalar yields identity
        assert_eq!(gt * BlsScalar::from(0u64), Gt::identity());
        // sum() over an iterator of Gt
        let sum: Gt = [gt, gt].into_iter().sum();
        assert_eq!(sum, gt + gt);
    }

    #[test]
    fn gt_scalar_mul_matches_reference_cases() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let prepared = G2Prepared::from(g2);
        let gt = multi_miller_loop_result(&[(&g1, &prepared)]);

        let fixed_wide_scalar = super::super::scalar_from_wide(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ]);

        let cases = [
            BlsScalar::one(),
            BlsScalar::from(7u64),
            -&BlsScalar::one(),
            fixed_wide_scalar,
        ];

        assert_eq!(gt * BlsScalar::one(), gt);
        assert_eq!(gt * (-&BlsScalar::one()), -gt);

        for scalar in cases {
            assert_eq!(gt * scalar, mul_scalar_reference(&gt, &scalar));
            assert_eq!((&gt) * &scalar, mul_scalar_reference(&gt, &scalar));
        }
    }

    #[test]
    fn gt_group_trait_is_consistent() {
        let g = <Gt as Group>::generator();
        assert_ne!(g, Gt::identity());
        assert!(bool::from(<Gt as Group>::is_identity(&Gt::identity())));
        assert_eq!(<Gt as Group>::double(&g), g + g);
    }

    #[test]
    fn gt_generator_matches_pairing_of_generators() {
        let g1 = G1Affine::generator();
        let prepared = G2Prepared::from(G2Affine::generator());
        let expected = multi_miller_loop_result(&[(&g1, &prepared)]);
        assert_eq!(Gt::generator(), expected);
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn gt_zeroize_resets_to_identity() {
        use ::zeroize::Zeroize;
        let g1 = G1Affine::generator();
        let prepared = G2Prepared::from(G2Affine::generator());
        let mut gt = multi_miller_loop_result(&[(&g1, &prepared)]);
        gt.zeroize();
        assert_eq!(gt, Gt::identity());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn g2_prepared_serde_roundtrip() {
        let g2 = G2Affine::generator();
        let prepared = G2Prepared::from(g2);
        let json = serde_json::to_string(&prepared).unwrap();
        let back: G2Prepared = serde_json::from_str(&json).unwrap();
        assert_eq!(G2Affine(back.0), g2);
    }
}
