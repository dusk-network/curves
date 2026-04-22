# Dusk Curves

A backend-agnostic wrapper for elliptic curve operations used by Dusk Network.

`dusk-curves` lets downstream Dusk crates work with a single,
stable set of curve types and functions while the underlying implementation can
be swapped at compile time via Cargo features — **with no source changes required if swapping by the same curve construction (e.g. the BLS12-381)**.

Today the crate is focused on BLS12-381. The overall design is intentionally
module-oriented so additional curves can be added later behind the same model:
a stable public facade with interchangeable backends where needed.

## Current support

Today the crate exposes `dusk_curves::bls12_381` and supports the following
BLS12-381 backends:

| Feature | Backend | Description |
|---|---|---|
| `bls-backend-dusk` *(default)* | [`dusk-bls12_381`] | Pure-Rust implementation from the Dusk ecosystem |
| `bls-backend-blst` | [`blst`] | Optimized C/assembly implementation via the blst library |

The two features are **mutually exclusive** — enabling both is a compile error.

[`dusk-bls12_381`]: https://crates.io/crates/dusk-bls12_381
[`blst`]: https://crates.io/crates/blst

## Security and correctness

This crate is security-sensitive. Dusk Network relies on BLS12-381 as a core
primitive, so swapping backends must not change the observable semantics of the
public API.

In practice, that means backend changes and refactors must preserve:

- canonical serialization and deserialization behavior
- rejection of invalid, off-curve, and wrong-subgroup points on safe APIs
- scalar reduction and hashing behavior
- group equality, identity handling, and pairing results

If two backends differ on accepted inputs, encodings, equality, or pairing
results, that is a bug rather than an implementation detail.

## Public API

Regardless of the backend, the crate exposes the same types and functions
through `dusk_curves::bls12_381`:

**Types** — `BlsScalar` (`Scalar`), `G1Affine`, `G1Projective`, `G2Affine`,
`G2Projective`, `G2Prepared`, `Gt`

**Functions** — `hash_to_scalar`, `scalar_from_wide`, `msm_variable_base`,
`multi_miller_loop_result`, `pairing_product_is_identity`

**Constants** — `GENERATOR`, `ROOT_OF_UNITY`, `TWO_ADACITY`

**rkyv types** *(requires `rkyv-impl`, dusk backend only)* —
`ArchivedBlsScalar`, `ArchivedG1Affine`, `ArchivedG2Affine`, `ArchivedG2Prepared`,
`ArchivedGt`, `ArchivedMillerLoopResult`, `BlsScalarResolver`, `G1AffineResolver`,
`G2AffineResolver`, `G2PreparedResolver`, `GtResolver`, `MillerLoopResultResolver`

## Usage

Add the dependency to your `Cargo.toml`:

```toml
# Use the default (dusk) backend
[dependencies]
dusk-curves = "0.1"

# Or select the blst backend
[dependencies]
dusk-curves = { version = "0.1", default-features = false, features = ["bls-backend-blst"] }
```

Then import the curve primitives:

```rust
use dusk_curves::bls12_381::{BlsScalar, G1Affine, G1Projective};
```

## Feature flags

- `bls-backend-dusk` — default backend, based on `dusk-bls12_381`
- `bls-backend-blst` — alternate backend, based on `blst`
- `default-bls` — enables the full default feature set of `dusk-bls12_381`
- `parallel` — enables Rayon parallelism on the dusk backend only
- `rkyv-impl` — enables `rkyv` archiving and serialization on the dusk backend only
- `zeroize` — enables zeroization support in this crate

## Development

Use the `Makefile` targets for local validation and CI parity:

- `make fmt-check`
- `make clippy`
- `make test`
- `make doc`
- `make check-no-std`

Targeted backend checks are also available, including `make clippy-dusk`,
`make clippy-blst`, `make test-dusk`, and `make test-blst`.

## License

This Source Code Form is subject to the terms of the [Mozilla Public License,
v. 2.0](./LICENSE).
