// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! rkyv support for blst-backed G2 types.

use core::fmt;

use rkyv::{Archive, Deserialize, Fallible, Serialize};

use super::G2Affine;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
/// Archived compressed representation of a blst-backed G2 affine point.
pub struct ArchivedG2Affine([u8; 96]);

/// Resolver for archiving a blst-backed G2 affine point.
pub type G2AffineResolver = ();

#[derive(Debug)]
/// Error returned when archived G2 affine bytes do not encode a valid point.
pub struct InvalidG2Affine;

impl fmt::Display for InvalidG2Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid archived G2 affine point")
    }
}

impl core::error::Error for InvalidG2Affine {}

impl<C: ?Sized> bytecheck::CheckBytes<C> for ArchivedG2Affine {
    type Error = InvalidG2Affine;

    unsafe fn check_bytes<'a>(value: *const Self, _: &mut C) -> Result<&'a Self, Self::Error> {
        let value = unsafe { &*value };
        if bool::from(G2Affine::from_compressed(&value.0).is_some()) {
            Ok(value)
        } else {
            Err(InvalidG2Affine)
        }
    }
}

impl Archive for G2Affine {
    type Archived = ArchivedG2Affine;
    type Resolver = G2AffineResolver;

    unsafe fn resolve(&self, _: usize, _: Self::Resolver, out: *mut Self::Archived) {
        unsafe { out.write(ArchivedG2Affine(self.to_compressed())) };
    }
}

impl<S: Fallible + ?Sized> Serialize<S> for G2Affine {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: Fallible + ?Sized> Deserialize<G2Affine, D> for ArchivedG2Affine
where
    D::Error: From<InvalidG2Affine>,
{
    fn deserialize(&self, _: &mut D) -> Result<G2Affine, D::Error> {
        Option::<G2Affine>::from(G2Affine::from_compressed(&self.0))
            .ok_or_else(|| InvalidG2Affine.into())
    }
}
