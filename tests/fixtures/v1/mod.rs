// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Loader for the v1 fixture files, shared by every test that checks them.
//! Each line holds words followed by the input as hex; `#` starts a comment.
#![allow(dead_code)]

/// Point encodings and how each decoder must treat them.
pub const POINTS: &str = include_str!("points.txt");

/// dusk-bls12_381 point archives and how validation must treat them.
pub const ARCHIVES: &str = include_str!("archives.txt");

/// Splits each fixture line into its `N` words and its input bytes.
pub fn parse<const N: usize>(
    text: &'static str,
) -> impl Iterator<Item = ([&'static str; N], Vec<u8>)> {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut words = line.split_whitespace();
            let fields = core::array::from_fn(|_| words.next().expect(line));
            let hex = words.next().expect(line);
            assert!(words.next().is_none(), "{line}");
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect(line))
                .collect();
            (fields, bytes)
        })
}
