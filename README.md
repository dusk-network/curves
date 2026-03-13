# Dusk Curves

A backend-agnostic wrapper for elliptic curve operations.

`dusk-curves` lets downstream Dusk crates work with a single,
stable set of curve types and functions while the underlying implementation can
be swapped at compile time via Cargo features — **with no source changes required if swapping by the same curve construction (e.g. the BLS12-381)**.

## Backends

At the moment we support the following curves / backends:

| Feature | Backend | Description |
|---|---|---|
| `bls-backend-dusk` *(default)* | [`dusk-bls12_381`] | Pure-Rust implementation from the Dusk ecosystem |
| `bls-backend-blst` | [`blst`] | Optimized C/assembly implementation via the blst library |

The two features are **mutually exclusive** — enabling both is a compile error.

[`dusk-bls12_381`]: https://crates.io/crates/dusk-bls12_381
[`blst`]: https://crates.io/crates/blst

## Public API

Regardless of the backend, the crate exposes the same types and functions
through `dusk_curves::bls12_381`:

**Types** — `BlsScalar` (`Scalar`), `G1Affine`, `G1Projective`, `G2Affine`,
`G2Projective`, `G2Prepared`, `Gt`, `MillerLoopResult`

**Functions** — `hash_to_scalar`, `scalar_from_wide`, `msm_variable_base`,
`multi_miller_loop`, `pairing_product_is_identity`

**Constants** — `GENERATOR`, `ROOT_OF_UNITY`, `TWO_ADACITY`

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

## Feature forwarding

Some `dusk-bls12_381` features are forwarded for downstream convenience:

- `default-bls` — enables the full default feature set (includes `parallel`)
- `parallel` — enables Rayon parallelism
- `rkyv-impl` — enables `rkyv` (de)serialization

## License

This Source Code Form is subject to the terms of the [Mozilla Public License,
v. 2.0](./LICENSE).
