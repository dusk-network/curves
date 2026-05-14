// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! rkyv tests for the blst backend facade.

use super::*;

use rkyv::{
    Deserialize,
    ser::{Serializer, serializers::AllocSerializer},
};

#[derive(Debug)]
struct RkyvTestDeserializer;

#[derive(Debug, PartialEq, Eq)]
enum RkyvTestDeserializeError {
    G1Affine,
    G2Affine,
    G2Prepared,
    Gt,
    MillerLoopResult,
}

impl rkyv::Fallible for RkyvTestDeserializer {
    type Error = RkyvTestDeserializeError;
}

impl From<InvalidG1Affine> for RkyvTestDeserializeError {
    fn from(_: InvalidG1Affine) -> Self {
        Self::G1Affine
    }
}

impl From<InvalidG2Affine> for RkyvTestDeserializeError {
    fn from(_: InvalidG2Affine) -> Self {
        Self::G2Affine
    }
}

impl From<InvalidG2Prepared> for RkyvTestDeserializeError {
    fn from(_: InvalidG2Prepared) -> Self {
        Self::G2Prepared
    }
}

impl From<InvalidGt> for RkyvTestDeserializeError {
    fn from(_: InvalidGt) -> Self {
        Self::Gt
    }
}

impl From<InvalidMillerLoopResult> for RkyvTestDeserializeError {
    fn from(_: InvalidMillerLoopResult) -> Self {
        Self::MillerLoopResult
    }
}

#[test]
fn rkyv_roundtrips_blst_types() {
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

#[test]
fn rkyv_roundtrips_blst_identities() {
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

#[test]
fn rkyv_rejects_invalid_archived_blst_points() {
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
    let result = <ArchivedG2Prepared as Deserialize<G2Prepared, RkyvTestDeserializer>>::deserialize(
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
