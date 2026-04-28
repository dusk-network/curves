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
//!
//! The backend-portable contract is the surface explicitly re-exported or
//! defined in this module. The default dusk backend forwards upstream
//! `dusk_bls12_381` types directly, so some additional inherent methods may
//! still be reachable there. Treat those dusk-only conveniences as backend
//! specific: if code must compile against both backends, prefer the shared
//! facade here and backend-parity methods only.

#[cfg(all(feature = "bls-backend-dusk", feature = "bls-backend-blst"))]
compile_error!("features 'bls-backend-dusk' and 'bls-backend-blst' are mutually exclusive");

#[cfg(not(any(feature = "bls-backend-dusk", feature = "bls-backend-blst")))]
compile_error!(
    "no backend selected: enable either 'bls-backend-dusk' (default) or 'bls-backend-blst'"
);

#[cfg(all(feature = "bls-backend-blst", feature = "rkyv-impl"))]
compile_error!(
    "feature 'rkyv-impl' is not yet supported with 'bls-backend-blst'; \
     use the default 'bls-backend-dusk' backend for rkyv serialization"
);

#[cfg(all(feature = "bls-backend-blst", feature = "parallel"))]
compile_error!(
    "feature 'parallel' is not supported with 'bls-backend-blst': the blst backend \
     uses blst's own multi-scalar multiplication and does not use rayon; \
     use the default 'bls-backend-dusk' backend for parallel support"
);

#[cfg(feature = "bls-backend-blst")]
mod backend_blst;
#[cfg(feature = "bls-backend-blst")]
use backend_blst as backend;

#[cfg(feature = "bls-backend-dusk")]
mod backend_dusk;
#[cfg(feature = "bls-backend-dusk")]
use backend_dusk as backend;

/// Re-export the backend-agnostic BLS12-381 primitives through `dusk-curves`.
///
/// Only items that exist identically in both backends are listed here.
/// Backend-internal helpers (`multi_miller_loop`,
/// `MillerLoopResult`, `multiscalar_mul` mod) are intentionally absent. The
/// dusk backend may still expose extra inherent methods through its direct type
/// re-exports; those are not part of the portability guarantee of this facade.
pub use backend::{
    BlsScalar, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, GENERATOR, Gt,
    ROOT_OF_UNITY, Scalar, TWO_ADACITY,
};

#[cfg(feature = "rkyv-impl")]
pub use backend::{
    ArchivedBlsScalar, ArchivedG1Affine, ArchivedG2Affine, ArchivedG2Prepared, ArchivedGt,
    ArchivedMillerLoopResult, BlsScalarResolver, G1AffineResolver, G2AffineResolver,
    G2PreparedResolver, GtResolver, MillerLoopResultResolver,
};

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

/// Compute the multi-Miller loop over `(G1Affine, G2Prepared)` pairs and apply
/// final exponentiation, returning the result as a `Gt` element.
#[must_use]
#[inline]
pub fn multi_miller_loop_result(terms: &[(&G1Affine, &G2Prepared)]) -> Gt {
    backend::multi_miller_loop_result(terms)
}

/// Checks whether the product of pairings over `(G1Affine, G2Affine)` terms
/// is the identity element in GT.
#[must_use]
#[inline]
pub fn pairing_product_is_identity(terms: &[(&G1Affine, &G2Affine)]) -> bool {
    backend::pairing_product_is_identity(terms)
}
