// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Checks the selected backend against the fixtures in `tests/fixtures/v1`.

#[path = "fixtures/v1/mod.rs"]
mod fixtures;

use dusk_bytes::Serializable;
use dusk_curves::bls12_381::{
    BlsScalar, G1Affine, G2Affine, InsufficientBases, msm_variable_base, try_msm_variable_base,
};

/// Returns which decoders accept `bytes`, asserting that every accepted point
/// re-encodes to `bytes`.
fn accepted<P, const N: usize>(
    bytes: &[u8],
    encode: fn(&P) -> [u8; N],
    decoders: &[fn(&[u8; N]) -> Option<P>],
) -> Vec<bool> {
    let bytes = bytes.try_into().expect("fixture length");
    decoders
        .iter()
        .map(|decode| {
            decode(bytes)
                .inspect(|point| assert_eq!(&encode(point), bytes))
                .is_some()
        })
        .collect()
}

#[test]
fn point_encodings_match_fixtures() {
    for ([group, encoding, checked, unchecked, name], bytes) in fixtures::parse(fixtures::POINTS) {
        // Checked decoders first, then the unchecked one.
        let seen = match (group, encoding) {
            ("g1", "compressed") => accepted(
                &bytes,
                G1Affine::to_compressed,
                &[
                    |b| G1Affine::from_compressed(b).into(),
                    |b| G1Affine::from_bytes(b).ok(),
                    |b| G1Affine::from_compressed_unchecked(b).into(),
                ],
            ),
            ("g1", "uncompressed") => accepted(
                &bytes,
                G1Affine::to_uncompressed,
                &[
                    |b| G1Affine::from_uncompressed(b).into(),
                    |b| G1Affine::from_uncompressed_unchecked(b).into(),
                ],
            ),
            ("g2", "compressed") => accepted(
                &bytes,
                G2Affine::to_compressed,
                &[
                    |b| G2Affine::from_compressed(b).into(),
                    |b| G2Affine::from_bytes(b).ok(),
                    |b| G2Affine::from_compressed_unchecked(b).into(),
                ],
            ),
            ("g2", "uncompressed") => accepted(
                &bytes,
                G2Affine::to_uncompressed,
                &[
                    |b| G2Affine::from_uncompressed(b).into(),
                    |b| G2Affine::from_uncompressed_unchecked(b).into(),
                ],
            ),
            _ => panic!("unknown fixture kind: {group} {encoding}"),
        };
        let checked = checked == "accept";
        let unchecked =
            unchecked == "accept" || (unchecked == "dusk" && cfg!(feature = "bls-backend-dusk"));
        let mut expected = vec![checked, unchecked];
        if encoding == "compressed" {
            expected.insert(1, checked);
        }
        assert_eq!(seen, expected, "{group} {encoding} {name}");
    }
}

#[test]
fn msm_rejects_insufficient_bases() {
    let (g, one) = (G1Affine::generator(), BlsScalar::one());
    assert_eq!(
        try_msm_variable_base(&[g], &[one, one]),
        Err(InsufficientBases)
    );
    assert_eq!(
        try_msm_variable_base(&[g, g], &[one]).map(G1Affine::from),
        Ok(g)
    );
}

#[test]
#[should_panic(expected = "fewer points than scalars")]
fn msm_panics_on_insufficient_bases() {
    let _ = msm_variable_base(&[G1Affine::generator()], &[BlsScalar::one(); 2]);
}

/// Validates `bytes`, zero-padded to the archive size, as an archived `T`.
#[cfg(feature = "rkyv-impl")]
fn archive_accepted<T: rkyv::Archive>(bytes: &[u8]) -> bool
where
    T::Archived: for<'a> bytecheck::CheckBytes<rkyv::validation::validators::DefaultValidator<'a>>,
{
    let mut aligned = rkyv::AlignedVec::new();
    aligned.extend_from_slice(bytes);
    aligned.resize(size_of::<T::Archived>(), 0);
    rkyv::check_archived_root::<T>(&aligned).is_ok()
}

#[cfg(all(feature = "rkyv-impl", feature = "bls-backend-blst"))]
#[test]
fn blst_archives_validate_like_from_compressed() {
    for ([group, encoding, checked, _, name], bytes) in fixtures::parse(fixtures::POINTS) {
        let accepted = match (group, encoding) {
            ("g1", "compressed") => archive_accepted::<G1Affine>(&bytes),
            ("g2", "compressed") => archive_accepted::<G2Affine>(&bytes),
            _ => continue,
        };
        assert_eq!(accepted, checked == "accept", "{group} archive {name}");
    }
}

#[cfg(all(feature = "rkyv-impl", feature = "bls-backend-dusk"))]
fn dusk_archives_match_fixtures(semantic: bool) {
    for ([group, structural, semantic_outcome, name], raw) in fixtures::parse(fixtures::ARCHIVES) {
        let accepted = match group {
            "g1" => archive_accepted::<G1Affine>(&raw),
            "g2" => archive_accepted::<G2Affine>(&raw),
            _ => panic!("unknown fixture group: {group}"),
        };
        let expected = if semantic {
            semantic_outcome
        } else {
            structural
        };
        assert_eq!(accepted, expected == "accept", "{group} archive {name}");
    }
}

#[cfg(all(feature = "rkyv-impl", feature = "bls-backend-dusk"))]
#[test]
fn dusk_archives_validate_structurally() {
    dusk_archives_match_fixtures(false);
}

#[cfg(all(feature = "rkyv-impl", feature = "bls-backend-dusk"))]
#[test]
#[ignore = "needs dusk-bls12_381/rkyv-semantic-validation, see make test-dusk-rkyv-semantic"]
fn dusk_archives_validate_semantically() {
    dusk_archives_match_fixtures(true);
}
