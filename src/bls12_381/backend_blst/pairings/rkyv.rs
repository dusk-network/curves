// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! rkyv support for blst-backed pairing types.

use core::fmt;

use rkyv::{Archive, Deserialize, Fallible, Serialize};

use super::{G2Affine, G2Prepared, Gt, MillerLoopResult};

const FP12_RAW_SIZE: usize = 48 * 12;

const FP_MODULUS: [u64; 6] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

fn fp_raw_bytes_are_canonical(bytes: &[u8]) -> bool {
    let mut limbs = [0u64; 6];
    let mut word = [0u8; 8];
    for (chunk, limb) in bytes.chunks_exact(8).zip(limbs.iter_mut()) {
        word.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(word);
    }

    for (&limb, &modulus_limb) in limbs.iter().zip(FP_MODULUS.iter()).rev() {
        if limb < modulus_limb {
            return true;
        }
        if limb > modulus_limb {
            return false;
        }
    }
    false
}

fn fp12_raw_bytes_are_canonical(bytes: &[u8; FP12_RAW_SIZE]) -> bool {
    bytes.chunks_exact(48).all(fp_raw_bytes_are_canonical)
}

fn fp12_raw_bytes_are_nonzero(bytes: &[u8; FP12_RAW_SIZE]) -> bool {
    bytes.iter().any(|&byte| byte != 0)
}

fn fp12_to_raw_bytes(fp12: &::blst::blst_fp12) -> [u8; FP12_RAW_SIZE] {
    let mut out = [0u8; FP12_RAW_SIZE];
    let mut offset = 0;
    for fp6 in &fp12.fp6 {
        for fp2 in &fp6.fp2 {
            for fp in &fp2.fp {
                super::super::write_raw_limbs(&mut out[offset..offset + 48], fp.l.iter());
                offset += 48;
            }
        }
    }
    out
}

fn fp12_from_raw_bytes(bytes: &[u8; FP12_RAW_SIZE]) -> ::blst::blst_fp12 {
    let mut fp12 = ::blst::blst_fp12::default();
    let mut offset = 0;
    for fp6 in &mut fp12.fp6 {
        for fp2 in &mut fp6.fp2 {
            for fp in &mut fp2.fp {
                super::super::read_raw_limbs(&bytes[offset..offset + 48], fp.l.iter_mut());
                offset += 48;
            }
        }
    }
    fp12
}

fn fp12_from_raw_bytes_checked(bytes: &[u8; FP12_RAW_SIZE]) -> Option<::blst::blst_fp12> {
    fp12_raw_bytes_are_canonical(bytes).then(|| fp12_from_raw_bytes(bytes))
}

fn gt_from_raw_bytes_checked(bytes: &[u8; FP12_RAW_SIZE]) -> Option<Gt> {
    fp12_from_raw_bytes_checked(bytes).and_then(|fp12| fp12.in_group().then_some(Gt(fp12)))
}

fn miller_loop_result_from_raw_bytes_checked(
    bytes: &[u8; FP12_RAW_SIZE],
) -> Option<MillerLoopResult> {
    // Miller-loop results are pre-final-exponentiation Fp12* values, not Gt
    // elements. Archive validation only enforces canonical raw field limbs and
    // rejects zero; subgroup membership is checked separately for archived Gt.
    (fp12_raw_bytes_are_canonical(bytes) && fp12_raw_bytes_are_nonzero(bytes))
        .then(|| MillerLoopResult(fp12_from_raw_bytes(bytes)))
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
/// Archived raw affine representation of a blst-backed prepared G2 point.
pub struct ArchivedG2Prepared([u8; G2Affine::RAW_SIZE]);

/// Resolver for archiving a blst-backed prepared G2 point.
pub type G2PreparedResolver = ();

#[derive(Debug)]
/// Error returned when archived prepared G2 bytes do not encode a valid point.
pub struct InvalidG2Prepared;

impl fmt::Display for InvalidG2Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid archived prepared G2 point")
    }
}

impl core::error::Error for InvalidG2Prepared {}

fn g2_prepared_raw_bytes_are_valid(bytes: &[u8; G2Affine::RAW_SIZE]) -> bool {
    if bytes[G2Affine::RAW_SIZE - 1] != 0 {
        return bytes == &G2Affine::identity().to_raw_bytes();
    }

    let affine = unsafe { G2Affine::from_slice_unchecked(bytes) };

    bytes[..G2Affine::RAW_SIZE - 1]
        .chunks_exact(48)
        .all(fp_raw_bytes_are_canonical)
        && bool::from(affine.is_on_curve())
        && !bool::from(affine.is_identity())
}

fn g2_prepared_from_raw_bytes_checked(bytes: &[u8; G2Affine::RAW_SIZE]) -> Option<G2Prepared> {
    g2_prepared_raw_bytes_are_valid(bytes)
        .then(|| unsafe { G2Prepared::from_slice_unchecked(bytes) })
}

/// Validates archived blst-backed prepared G2 bytes.
///
/// # Caveat
///
/// This check validates canonical raw field limbs, curve membership, and
/// non-identity handling, but it does not validate subgroup membership. This
/// matches the dusk backend's prepared-G2 archive semantics, where prepared
/// Miller coefficients are not subgroup-checked by archive validation either.
/// Callers must not treat successful archive validation as proof that the
/// prepared point is safe for protocols that require subgroup membership.
impl<C: ?Sized> bytecheck::CheckBytes<C> for ArchivedG2Prepared {
    type Error = InvalidG2Prepared;

    unsafe fn check_bytes<'a>(value: *const Self, _: &mut C) -> Result<&'a Self, Self::Error> {
        let value = unsafe { &*value };
        if g2_prepared_from_raw_bytes_checked(&value.0).is_some() {
            Ok(value)
        } else {
            Err(InvalidG2Prepared)
        }
    }
}

/// Archives a blst-backed prepared G2 point as raw affine bytes.
///
/// # Caveat
///
/// The archived representation preserves the point supplied to `G2Prepared`;
/// archive validation for this type does not enforce subgroup membership. This
/// mirrors the dusk backend's `G2Prepared` archive behavior for backend parity.
/// Construct `G2Prepared` from a subgroup-checked `G2Affine` when pairing
/// bilinearity or subgroup membership is required by the protocol.
impl Archive for G2Prepared {
    type Archived = ArchivedG2Prepared;
    type Resolver = G2PreparedResolver;

    unsafe fn resolve(&self, _: usize, _: Self::Resolver, out: *mut Self::Archived) {
        unsafe { out.write(ArchivedG2Prepared(self.to_raw_bytes())) };
    }
}

impl<S: Fallible + ?Sized> Serialize<S> for G2Prepared {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: Fallible + ?Sized> Deserialize<G2Prepared, D> for ArchivedG2Prepared
where
    D::Error: From<InvalidG2Prepared>,
{
    fn deserialize(&self, _: &mut D) -> Result<G2Prepared, D::Error> {
        g2_prepared_from_raw_bytes_checked(&self.0).ok_or_else(|| InvalidG2Prepared.into())
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
/// Archived raw representation of a blst-backed target-group element.
pub struct ArchivedGt([u8; FP12_RAW_SIZE]);

/// Resolver for archiving a blst-backed target-group element.
pub type GtResolver = ();

#[derive(Debug)]
/// Error returned when archived target-group bytes do not encode a valid element.
pub struct InvalidGt;

impl fmt::Display for InvalidGt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid archived target-group element")
    }
}

impl core::error::Error for InvalidGt {}

impl<C: ?Sized> bytecheck::CheckBytes<C> for ArchivedGt {
    type Error = InvalidGt;

    unsafe fn check_bytes<'a>(value: *const Self, _: &mut C) -> Result<&'a Self, Self::Error> {
        let value = unsafe { &*value };
        if gt_from_raw_bytes_checked(&value.0).is_some() {
            Ok(value)
        } else {
            Err(InvalidGt)
        }
    }
}

impl Archive for Gt {
    type Archived = ArchivedGt;
    type Resolver = GtResolver;

    unsafe fn resolve(&self, _: usize, _: Self::Resolver, out: *mut Self::Archived) {
        unsafe { out.write(ArchivedGt(fp12_to_raw_bytes(&self.0))) };
    }
}

impl<S: Fallible + ?Sized> Serialize<S> for Gt {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: Fallible + ?Sized> Deserialize<Gt, D> for ArchivedGt
where
    D::Error: From<InvalidGt>,
{
    fn deserialize(&self, _: &mut D) -> Result<Gt, D::Error> {
        gt_from_raw_bytes_checked(&self.0).ok_or_else(|| InvalidGt.into())
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
/// Archived raw representation of a blst-backed Miller-loop result.
pub struct ArchivedMillerLoopResult([u8; FP12_RAW_SIZE]);

/// Resolver for archiving a blst-backed Miller-loop result.
pub type MillerLoopResultResolver = ();

#[derive(Debug)]
/// Error returned when archived Miller-loop bytes do not encode a valid element.
pub struct InvalidMillerLoopResult;

impl fmt::Display for InvalidMillerLoopResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid archived Miller-loop result")
    }
}

impl core::error::Error for InvalidMillerLoopResult {}

/// Validates archived blst-backed Miller-loop result bytes.
///
/// # Caveat
///
/// This check only validates that the archive contains canonical, non-zero
/// raw Fp12 bytes. It does not prove that the element is the output of an
/// actual Miller loop. Callers must not treat successful archive validation as
/// proof that the value has cryptographic meaning as a pairing computation.
impl<C: ?Sized> bytecheck::CheckBytes<C> for ArchivedMillerLoopResult {
    type Error = InvalidMillerLoopResult;

    unsafe fn check_bytes<'a>(value: *const Self, _: &mut C) -> Result<&'a Self, Self::Error> {
        let value = unsafe { &*value };
        if miller_loop_result_from_raw_bytes_checked(&value.0).is_some() {
            Ok(value)
        } else {
            Err(InvalidMillerLoopResult)
        }
    }
}

/// Archives a blst-backed Miller-loop result as raw Fp12 bytes.
///
/// # Caveat
///
/// The archived representation preserves the supplied Fp12 element. Archive
/// validation for this type only checks canonical, non-zero raw Fp12 bytes; it
/// does not prove that the restored value was produced by an actual Miller
/// loop.
impl Archive for MillerLoopResult {
    type Archived = ArchivedMillerLoopResult;
    type Resolver = MillerLoopResultResolver;

    unsafe fn resolve(&self, _: usize, _: Self::Resolver, out: *mut Self::Archived) {
        unsafe { out.write(ArchivedMillerLoopResult(fp12_to_raw_bytes(&self.0))) };
    }
}

impl<S: Fallible + ?Sized> Serialize<S> for MillerLoopResult {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: Fallible + ?Sized> Deserialize<MillerLoopResult, D> for ArchivedMillerLoopResult
where
    D::Error: From<InvalidMillerLoopResult>,
{
    fn deserialize(&self, _: &mut D) -> Result<MillerLoopResult, D::Error> {
        miller_loop_result_from_raw_bytes_checked(&self.0)
            .ok_or_else(|| InvalidMillerLoopResult.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12_381::backend_blst::pairings::{multi_miller_loop, multi_miller_loop_result};
    use rkyv::ser::{Serializer, serializers::AllocSerializer};

    fn non_subgroup_g2_affine_sample() -> G2Affine {
        G2Affine(::blst::blst_p2_affine {
            x: ::blst::blst_fp2 {
                fp: [
                    ::blst::blst_fp {
                        l: [
                            0x89f5_50c8_13db_6431,
                            0xa50b_e8c4_56cd_8a1a,
                            0xa45b_3741_14ca_e851,
                            0xbb61_90f5_bf7f_ff63,
                            0x970c_a02c_3ba8_0bc7,
                            0x02b8_5d24_e840_fbac,
                        ],
                    },
                    ::blst::blst_fp {
                        l: [
                            0x6888_bc53_d707_16dc,
                            0x3dea_6b41_1768_2d70,
                            0xd8f5_f930_500c_a354,
                            0x6b5e_cb65_56f5_c155,
                            0xc96b_ef04_3477_8ab0,
                            0x0508_1505_5150_06ad,
                        ],
                    },
                ],
            },
            y: ::blst::blst_fp2 {
                fp: [
                    ::blst::blst_fp {
                        l: [
                            0x3cf1_ea0d_434b_0f40,
                            0x1a0d_c610_e603_e333,
                            0x7f89_9561_60c7_2fa0,
                            0x25ee_03de_cf64_31c5,
                            0xeee8_e206_ec0f_e137,
                            0x0975_92b2_26df_ef28,
                        ],
                    },
                    ::blst::blst_fp {
                        l: [
                            0x71e8_bb5f_2924_7367,
                            0xa5fe_049e_2118_31ce,
                            0x0ce6_b354_502a_3896,
                            0x93b0_1200_0997_314e,
                            0x6759_f3b6_aa5b_42ac,
                            0x1569_44c4_dfe9_2bbb,
                        ],
                    },
                ],
            },
        })
    }

    #[test]
    fn fp12_validation_rejects_invalid_archives() {
        let g1 = super::super::G1Affine::generator();
        let g2 = G2Affine::generator();
        let prepared = G2Prepared::from(g2);

        let gt = multi_miller_loop_result(&[(&g1, &prepared)]);
        assert!(gt_from_raw_bytes_checked(&fp12_to_raw_bytes(&gt.0)).is_some());

        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&gt).unwrap();
        let mut gt_bytes = serializer.into_serializer().into_inner();
        assert!(rkyv::check_archived_root::<Gt>(&gt_bytes).is_ok());

        let miller_loop_result = multi_miller_loop(&[(&g1, &prepared)]);
        assert!(
            miller_loop_result_from_raw_bytes_checked(&fp12_to_raw_bytes(&miller_loop_result.0))
                .is_some()
        );

        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&miller_loop_result).unwrap();
        let mut miller_loop_result_bytes = serializer.into_serializer().into_inner();
        assert!(rkyv::check_archived_root::<MillerLoopResult>(&miller_loop_result_bytes).is_ok());

        let zero = [0u8; FP12_RAW_SIZE];
        assert!(gt_from_raw_bytes_checked(&zero).is_none());
        assert!(miller_loop_result_from_raw_bytes_checked(&zero).is_none());

        gt_bytes.fill(0);
        assert!(rkyv::check_archived_root::<Gt>(&gt_bytes).is_err());

        miller_loop_result_bytes.fill(0);
        assert!(rkyv::check_archived_root::<MillerLoopResult>(&miller_loop_result_bytes).is_err());

        let mut noncanonical = [0u8; FP12_RAW_SIZE];
        for (chunk, limb) in noncanonical[..48]
            .chunks_exact_mut(8)
            .zip(FP_MODULUS.iter())
        {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        assert!(!fp12_raw_bytes_are_canonical(&noncanonical));
        assert!(gt_from_raw_bytes_checked(&noncanonical).is_none());
        assert!(miller_loop_result_from_raw_bytes_checked(&noncanonical).is_none());

        gt_bytes[..FP12_RAW_SIZE].copy_from_slice(&noncanonical);
        assert!(rkyv::check_archived_root::<Gt>(&gt_bytes).is_err());

        miller_loop_result_bytes[..FP12_RAW_SIZE].copy_from_slice(&noncanonical);
        assert!(rkyv::check_archived_root::<MillerLoopResult>(&miller_loop_result_bytes).is_err());
    }

    #[test]
    fn g2_prepared_raw_archive_preserves_non_subgroup_affine() {
        use rkyv::Deserialize;

        struct G2PreparedTestDeserializer;

        impl rkyv::Fallible for G2PreparedTestDeserializer {
            type Error = InvalidG2Prepared;
        }

        let affine = non_subgroup_g2_affine_sample();
        assert!(bool::from(affine.is_on_curve()));
        assert!(!bool::from(affine.is_torsion_free()));
        assert!(!bool::from(
            G2Affine::from_compressed(&affine.to_compressed()).is_some()
        ));

        let raw = affine.to_raw_bytes();
        let prepared = unsafe { G2Prepared::from_slice_unchecked(&raw) };
        let mut serializer = AllocSerializer::<1024>::default();
        serializer.serialize_value(&prepared).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let archived = rkyv::check_archived_root::<G2Prepared>(&bytes).unwrap();
        let restored: G2Prepared = archived
            .deserialize(&mut G2PreparedTestDeserializer)
            .unwrap();

        assert_eq!(restored.to_raw_bytes(), prepared.to_raw_bytes());
    }
}
