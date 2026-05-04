<div align="center">

# dusk-curves

**Backend-agnostic BLS12-381 primitives**

*One public API. Interchangeable backends. Security-sensitive semantics.*

<p>
	<img alt="Rust stable" src="https://img.shields.io/badge/rust-stable-f74c00?logo=rust&logoColor=white">
    <a href="./Cargo.toml">
		<img alt="Version 0.1.0" src="https://img.shields.io/badge/version-0.1.0-2563eb">
	</a>
	<img alt="License MPL-2.0" src="https://img.shields.io/badge/license-MPL--2.0-eab308">
</p>

</div>

`dusk-curves` gives downstream crates a stable curve API while letting the
underlying implementation be swapped through Cargo features. The goal is not
just flexibility, but backend interchangeability **without changing the meaning
of the public API**.

That also makes backend replacement fast if an implementation bug,
security vulnerability, or correctness issue is ever discovered: downstream
code can move to another backend with minimal disruption while a fix is being
developed.

Today the crate is focused on `dusk_curves::bls12_381`. The structure is kept
module-oriented so more curve families can be added later under the same model,
but BLS12-381 is the only supported curve today.

## ✨ Why this crate?

- stable public facade for downstream crates
- backend swapping without downstream source changes
- easier operational response if a backend needs to be replaced quickly
- `no_std` + `alloc` friendly
- explicit focus on correctness, subgroup safety, and backend parity

## 📌 Current support

The crate currently exposes `dusk_curves::bls12_381` with two interchangeable
BLS12-381 backends:

| Feature | Backend | Description |
|---|---|---|
| `bls-backend-dusk` *(default)* | [`dusk-bls12_381`] | Pure-Rust implementation from the Dusk ecosystem |
| `bls-backend-blst` | [`blst`] | Optimized C/assembly implementation via the blst library |

The two backend features are **mutually exclusive**.

## 🔐 Security and correctness

This crate sits on a security-sensitive boundary. Backend changes and refactors
must preserve observable behavior.

One reason this crate exists is to reduce recovery time if a backend-specific
problem is found. If a vulnerability or correctness bug ever affects one
implementation, switching to another backend should be possible without forcing
downstream API churn.

That includes:

- canonical serialization and deserialization
- rejection of invalid, off-curve, and wrong-subgroup points on safe APIs
- scalar reduction and hashing behavior
- group equality and identity handling
- pairing and product-of-pairings semantics

If two backends disagree on accepted inputs, encodings, equality, or pairing
results, that is a bug, not an implementation detail.

## 📚 Public API

Regardless of the backend, `dusk_curves::bls12_381` exposes the same public
surface:

- **Types:** `BlsScalar` (`Scalar`), `G1Affine`, `G1Projective`, `G2Affine`, `G2Projective`, `G2Prepared`, `Gt`
- **Functions:** `hash_to_scalar`, `scalar_from_wide`, `msm_variable_base`, `multi_miller_loop_result`, `pairing_product_is_identity`
- **Constants:** `GENERATOR`, `ROOT_OF_UNITY`, `TWO_ADACITY`

The portability guarantee applies to that shared facade. Both backends now also
implement a consistent set of inherent convenience methods that match the
`dusk_bls12_381` API:

| Group | Methods available on both backends |
|---|---|
| `G1Affine` / `G2Affine` | `to_compressed`, `to_uncompressed`, `from_compressed`, `from_compressed_unchecked`, `from_uncompressed`, `from_uncompressed_unchecked` |
| `G1Projective` / `G2Projective` | `double`, `add`, `add_mixed`, `is_on_curve`, `clear_cofactor` |
| `Gt` | `double`, `Add`/`Sub`/`Neg`/`Mul<BlsScalar>`, `Sum`, `group::Group` |
| `G2Prepared` | `RAW_SIZE`, `to_raw_bytes`, unsafe `from_slice_unchecked` |

The default dusk backend forwards upstream `dusk-bls12_381` types directly, so
a small number of additional inherent methods from that crate are still
reachable there (e.g. `pairing()`, `MillerLoopResult::Add`). Treat those as
dusk-specific extras; they are intentionally absent from the public facade in
`src/bls12_381.rs`.

<details>
<summary><strong><code>rkyv-impl</code> additions</strong> <em>(dusk backend only)</em></summary>

- `ArchivedBlsScalar`
- `ArchivedG1Affine`
- `ArchivedG2Affine`
- `ArchivedG2Prepared`
- `ArchivedGt`
- `ArchivedMillerLoopResult`
- `BlsScalarResolver`
- `G1AffineResolver`
- `G2AffineResolver`
- `G2PreparedResolver`
- `GtResolver`
- `MillerLoopResultResolver`

</details>

## 📦 Usage

Add the dependency to `Cargo.toml`:

```toml
# Default backend: dusk-bls12_381
[dependencies]
dusk-curves = "0.1"

# Alternate backend: blst
[dependencies]
dusk-curves = { version = "0.1", default-features = false, features = ["bls-backend-blst"] }
```

Import the curve primitives:

```rust
use dusk_curves::bls12_381::{BlsScalar, G1Affine, G1Projective};
```

### Quick example

```rust
use dusk_curves::bls12_381::{
	hash_to_scalar, msm_variable_base, pairing_product_is_identity, G1Affine, G2Affine,
};

let g1 = G1Affine::generator();
let g2 = G2Affine::generator();

let scalar = hash_to_scalar(b"dusk-network");
let msm_result = msm_variable_base(&[g1], &[scalar]);
let expected = g1 * scalar;

assert_eq!(msm_result, expected);

let minus_g2 = -g2;
assert!(pairing_product_is_identity(&[(&g1, &g2), (&g1, &minus_g2)]));
```

## ⚙️ Feature flags

- `bls-backend-dusk` — default backend, based on `dusk-bls12_381`
- `bls-backend-blst` — alternate backend, based on `blst`
- `default-bls` — forwards the default feature set of `dusk-bls12_381`
- `parallel` — enables Rayon parallelism on the dusk backend only
- `rkyv-impl` — enables `rkyv` archiving and serialization on the dusk backend only
- `zeroize` — enables zeroization support in this crate

## 🛠 Development

Use the `Makefile` targets for local validation and CI parity:

- `make fmt-check`
- `make clippy`
- `make test`
- `make doc`
- `make no-std`

Targeted checks are also available, including:

- `make clippy-dusk`
- `make clippy-dusk-rkyv`
- `make clippy-dusk-zeroize`
- `make clippy-dusk-parallel`
- `make clippy-blst`
- `make test-dusk`
- `make test-dusk-rkyv`
- `make test-blst`

## 📄 License

This Source Code Form is subject to the terms of the [Mozilla Public License,
v. 2.0](./LICENSE).

[`dusk-bls12_381`]: https://crates.io/crates/dusk-bls12_381
[`blst`]: https://crates.io/crates/blst
