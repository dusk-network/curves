// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Pairing-related types and functions for the blst backend.
//!
//! Contains `G2Prepared`, `Gt`, `MillerLoopResult`, and the
//! pairing-computation entry points.

use core::fmt;

use alloc::vec::Vec;
use subtle::ConstantTimeEq;

use super::{G1Affine, G2Affine};

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
}
