// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Backend-agnostic wrapper for elliptic curve operations.
//!
//! Enable the `bls-backend-dusk` (default) or `bls-backend-blst` feature to
//! select the underlying implementation. The public API is identical
//! regardless of the backend.

#![deny(missing_docs)]

extern crate alloc;

pub mod bls12_381;
