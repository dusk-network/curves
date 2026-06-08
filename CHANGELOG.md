# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Improve the blst backend `pairing_product_is_identity` path by using BLST's
  raw pairing aggregation and final verification directly, avoiding redundant
  final exponentiation and small-product `miller_loop_n` threadpool overhead.

## [0.2.1] - 2026-06-01

### Added

- Add `hash_to_g1` and `hash_to_g2` helpers for both backends, preserving the
  caller-supplied domain separation tag [#24]

### Changed

- Forward the `zeroize` feature to `dusk-bls12_381` so the re-exported
  `BlsScalar` has its zeroize implementation available [#26]

## [0.2.0] - 2026-05-15

### Changed

- Change the `rkyv-impl` feature to use `rkyv/size_32` [#22]

## [0.1.1] - 2026-05-14

### Added

- Add backend comparison benchmarks for BLS12-381 operations [#18]
- Add `rkyv-impl` support for the blst backend, including archived type
  validation and backend-specific archive documentation [#20]

## [0.1.0] - 2026-05-08

### Added

- Add the initial `dusk-curves` crate with a backend-agnostic BLS12-381 facade,
  default `dusk-bls12_381` backend, alternate `blst` backend, `no_std` support,
  and shared public types and helpers [#1]
- Add Makefile targets and CI coverage for backend-specific checks [#2]
- Add tooling checks and compatibility documentation for backend parity [#5] [#7]
- Add full blst method-surface parity for affine, projective, `G2Prepared`, and
  `Gt` operations used by downstream Dusk crates [#11]
- Add inter-backend parity tests for scalar helpers, group arithmetic,
  encodings, MSM behavior, and pairing identity checks [#3]
- Add package metadata required for publication [#16]

### Changed

- Split the blst backend into focused `g1`, `g2`, and `pairings` modules [#4]
- Replace blst affine `ConditionallySelectable` compression round-trips with
  limb-level selection [#10]

### Fixed

- Align the blst backend public surface and validation helpers with the dusk
  backend for raw bytes, `G2Prepared`, pairing finalization, and `Gt`
  identity/equality behavior [#9]
- Harden blst compressed and uncompressed decoding, including malformed input,
  subgroup, and checked-vs-unchecked behavior [#15]

<!-- Issues -->
[#2]: https://github.com/dusk-network/curves/issues/2
[#3]: https://github.com/dusk-network/curves/issues/3
[#4]: https://github.com/dusk-network/curves/issues/4
[#5]: https://github.com/dusk-network/curves/issues/5
[#7]: https://github.com/dusk-network/curves/issues/7
[#10]: https://github.com/dusk-network/curves/issues/10
[#11]: https://github.com/dusk-network/curves/issues/11
[#24]: https://github.com/dusk-network/curves/issues/24
[#26]: https://github.com/dusk-network/curves/issues/26

<!-- PRs -->
[#1]: https://github.com/dusk-network/curves/pull/1
[#9]: https://github.com/dusk-network/curves/pull/9
[#15]: https://github.com/dusk-network/curves/pull/15
[#16]: https://github.com/dusk-network/curves/pull/16
[#18]: https://github.com/dusk-network/curves/pull/18
[#20]: https://github.com/dusk-network/curves/pull/20
[#22]: https://github.com/dusk-network/curves/pull/22

<!-- Versions -->
[Unreleased]: https://github.com/dusk-network/curves/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/dusk-network/curves/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dusk-network/curves/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/dusk-network/curves/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dusk-network/curves/releases/tag/v0.1.0
