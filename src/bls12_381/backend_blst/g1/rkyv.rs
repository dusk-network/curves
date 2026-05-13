// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! rkyv support for blst-backed G1 types.

use core::fmt;

use rkyv::{Archive, Deserialize, Fallible, Serialize};

use super::G1Affine;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
/// Archived compressed representation of a blst-backed G1 affine point.
pub struct ArchivedG1Affine([u8; 48]);

/// Resolver for archiving a blst-backed G1 affine point.
pub type G1AffineResolver = ();

#[derive(Debug)]
/// Error returned when archived G1 affine bytes do not encode a valid point.
pub struct InvalidG1Affine;

impl fmt::Display for InvalidG1Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid archived G1 affine point")
    }
}

impl<C: ?Sized> bytecheck::CheckBytes<C> for ArchivedG1Affine {
    type Error = InvalidG1Affine;

    unsafe fn check_bytes<'a>(value: *const Self, _: &mut C) -> Result<&'a Self, Self::Error> {
        let value = unsafe { &*value };
        if bool::from(G1Affine::from_compressed(&value.0).is_some()) {
            Ok(value)
        } else {
            Err(InvalidG1Affine)
        }
    }
}

impl Archive for G1Affine {
    type Archived = ArchivedG1Affine;
    type Resolver = G1AffineResolver;

    unsafe fn resolve(&self, _: usize, _: Self::Resolver, out: *mut Self::Archived) {
        unsafe { out.write(ArchivedG1Affine(self.to_compressed())) };
    }
}

impl<S: Fallible + ?Sized> Serialize<S> for G1Affine {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: Fallible + ?Sized> Deserialize<G1Affine, D> for ArchivedG1Affine
where
    D::Error: From<InvalidG1Affine>,
{
    fn deserialize(&self, _: &mut D) -> Result<G1Affine, D::Error> {
        Option::<G1Affine>::from(G1Affine::from_compressed(&self.0))
            .ok_or_else(|| InvalidG1Affine.into())
    }
}
