// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! BLS12-381 field primitives exposed by `dusk-curves`.
//!
//! Depending on the selected feature, this module re-exports either the
//! original `dusk_bls12_381` types or blst-backed wrappers.  The public
//! names (`G1Affine`, `G2Affine`, `G1Projective`, `Scalar`, etc.) are
//! identical in both backends so downstream crates never need to care
//! which backend is active.

#[cfg(all(feature = "bls-backend-dusk", feature = "bls-backend-blst"))]
compile_error!("features 'bls-backend-dusk' and 'bls-backend-blst' are mutually exclusive");

#[cfg(feature = "bls-backend-blst")]
mod backend_blst;
#[cfg(feature = "bls-backend-blst")]
use backend_blst as backend;

#[cfg(not(feature = "bls-backend-blst"))]
mod backend_dusk;
#[cfg(not(feature = "bls-backend-blst"))]
use backend_dusk as backend;

/// Re-export backend BLS12-381 primitives through `dusk-curves`.
#[allow(clippy::wildcard_imports)]
pub use backend::*;

/// Hash arbitrary bytes to a BLS scalar.
#[must_use]
#[inline]
pub fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    backend::hash_to_scalar(bytes)
}

/// Reduce a wide little-endian integer modulo the scalar field order.
#[must_use]
#[inline]
pub fn scalar_from_wide(bytes: &[u8; 64]) -> Scalar {
    backend::scalar_from_wide(bytes)
}

/// Variable-base multiscalar multiplication over G1.
#[must_use]
#[inline]
pub fn msm_variable_base(points: &[G1Affine], scalars: &[Scalar]) -> G1Projective {
    backend::msm_variable_base(points, scalars)
}

/// Checks whether the product of pairings over `(G1Affine, G2Affine)` terms
/// is the identity element in GT.
#[must_use]
#[inline]
pub fn pairing_product_is_identity(terms: &[(&G1Affine, &G2Affine)]) -> bool {
    backend::pairing_product_is_identity(terms)
}
