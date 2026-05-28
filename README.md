<div align="center">

# dusk-curves

**Backend-agnostic BLS12-381 primitives**

*One public API. Interchangeable backends. Security-sensitive semantics.*

<p>
	<img alt="Rust stable" src="https://img.shields.io/badge/rust-stable-f74c00?logo=rust&logoColor=white">
    <a href="https://crates.io/crates/dusk-curves">
		<img alt="crates.io" src="https://img.shields.io/crates/v/dusk-curves.svg">
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

### Backend-specific rkyv archives

The public API is backend-agnostic, but `rkyv` archived bytes are **not** a
backend-portable storage format. The same facade type name can have different
archived layouts depending on the selected backend; for example, the dusk
backend archives affine points using its field-level layout, while the blst
backend archives its wrapper types using backend-specific byte layouts.

Do not read archives produced with one backend after switching to another
backend unless the data has been explicitly migrated or reserialized. If an
application stores `rkyv` blobs across process versions, include an external
format version and backend identifier such as `bls-backend-dusk` or
`bls-backend-blst`, reject mismatches before deserializing, and reserialize
under the new backend during migration.

`rkyv` validation of `G2Prepared` does not prove subgroup membership. The blst
backend validates canonical raw affine field limbs, curve membership, and
non-identity handling for archived `G2Prepared`; it deliberately does not add a
subgroup check because the dusk backend's prepared Miller coefficients are not
subgroup-checked by archive validation either. If pairing inputs must satisfy
subgroup membership, enforce that before constructing or archiving
`G2Prepared`.

`rkyv` validation of `MillerLoopResult` only proves that the archived bytes are
a canonical, non-zero Fp12 element. It does not prove that the element was
produced by an actual Miller loop, so applications must not treat archive
validation as a cryptographic statement about the pairing computation.

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

The blst backend test suite includes inter-backend parity tests against the
dusk implementation for scalar helpers, G1/G2 arithmetic, canonical encodings,
MSM behavior, and pairing identity checks. Those tests are intended to catch
observable backend drift before it reaches downstream code. Hash-to-curve
helpers are covered by compressed-encoding parity checks.

## 📚 Public API

Regardless of the backend, `dusk_curves::bls12_381` exposes the same public
surface:

- **Types:** `BlsScalar` (`Scalar`), `G1Affine`, `G1Projective`, `G2Affine`, `G2Projective`, `G2Prepared`, `Gt`
- **Functions:** `hash_to_scalar`, `hash_to_g1`, `hash_to_g2`, `scalar_from_wide`, `msm_variable_base`, `multi_miller_loop_result`, `pairing_product_is_identity`
- **Constants:** `GENERATOR`, `ROOT_OF_UNITY`, `TWO_ADACITY`

`hash_to_g1` and `hash_to_g2` take both the message and the caller-selected
domain separation tag. Protocol code is responsible for passing the exact
domain required by its transcript or signature scheme.

The portability guarantee applies to that shared facade. Both backends now also
implement a consistent set of inherent convenience methods that match the
`dusk_bls12_381` API:

| Group | Methods available on both backends |
|---|---|
| `G1Affine` / `G2Affine` | `to_compressed`, `to_uncompressed`, `from_compressed`, `from_compressed_unchecked`, `from_uncompressed`, `from_uncompressed_unchecked` |
| `G1Projective` / `G2Projective` | `double`, `add`, `add_mixed`, `is_on_curve`, `clear_cofactor` |
| `Gt` | `double`, `Add`/`Sub`/`Neg`/`Mul<BlsScalar>`, `Sum`, `group::Group` |
| `G2Prepared` | `RAW_SIZE`, `to_raw_bytes`, unsafe `from_slice_unchecked` (`RAW_SIZE` and `to_raw_bytes` exist on both backends but their values are deliberately not portable across backends) |

The default dusk backend forwards upstream `dusk-bls12_381` types directly, so
a small number of additional inherent methods and external trait impls from
that crate are still reachable there (e.g. `pairing()`,
`MillerLoopResult::Add`, and `pairing::PairingCurveAffine` with
`pairing_with()` / `Pair` / `PairingResult`). Treat those as dusk-specific
extras; they are intentionally absent from the public facade in
`src/bls12_381.rs`, and the blst backend does not currently implement the
pairing crate's affine pairing traits.

<details>
<summary><strong><code>rkyv-impl</code> additions</strong></summary>

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

The `rkyv-impl` feature is available with either backend. Archived type names
are shared through the facade, but the bytes are backend-specific. See
"Backend-specific rkyv archives" above before using archives for persisted
storage.

The blst backend also exports explicit archived-value validation error names:
`InvalidG1Affine`, `InvalidG2Affine`, `InvalidG2Prepared`, `InvalidGt`, and
`InvalidMillerLoopResult`. These names are blst-only. The dusk backend forwards
the upstream `dusk-bls12_381` archived types directly, and its bytecheck errors
come from upstream derives rather than facade-level named errors. Code that
implements `From<Invalid*>` for an rkyv deserializer must cfg-gate those impls
on `bls-backend-blst`.

## 📦 Usage

Add the dependency to `Cargo.toml`:

```toml
# Default backend: dusk-bls12_381
[dependencies]
dusk-curves = "0.2"

# Alternate backend: blst
[dependencies]
dusk-curves = { version = "0.2", default-features = false, features = ["bls-backend-blst"] }
```

Import the curve primitives:

```rust
use dusk_curves::bls12_381::{BlsScalar, G1Affine, G1Projective};
```

### Quick example

```rust
use dusk_curves::bls12_381::{
	hash_to_g1, hash_to_scalar, msm_variable_base, pairing_product_is_identity, G1Affine,
	G2Affine,
};

let g1 = G1Affine::generator();
let g2 = G2Affine::generator();

let scalar = hash_to_scalar(b"dusk-network");
let hashed_g1 = hash_to_g1(b"dusk-network", b"DUSK_CURVES_README_HASH_TO_G1");
let msm_result = msm_variable_base(&[g1], &[scalar]);
let expected = g1 * scalar;

assert!(!bool::from(G1Affine::from(hashed_g1).is_identity()));
assert_eq!(msm_result, expected);

let minus_g2 = -g2;
assert!(pairing_product_is_identity(&[(&g1, &g2), (&g1, &minus_g2)]));
```

## ⚙️ Feature flags

- `bls-backend-dusk` — default backend, based on `dusk-bls12_381`
- `bls-backend-blst` — alternate backend, based on `blst`
- `default-bls` — forwards the default feature set of `dusk-bls12_381`
- `parallel` — enables Rayon parallelism on the dusk backend only
- `rkyv-impl` — enables `rkyv` archiving, validation, and serialization; archived bytes are backend-specific
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
- `make clippy-blst-rkyv`
- `make test-dusk`
- `make test-dusk-rkyv`
- `make test-dusk-zeroize`
- `make test-blst`
- `make test-blst-rkyv`
- `make test-blst-zeroize`
- `make test-blst-serde-zeroize`

### Benchmarks

Criterion benchmarks cover the shared BLS12-381 facade for variable-base MSM,
multi-Miller-loop plus final exponentiation, and product-of-pairings identity
checks.

Run the default dusk backend:

```sh
make bench-dusk
```

Run the blst backend:

```sh
make bench-blst
```

## 📄 License

This Source Code Form is subject to the terms of the [Mozilla Public License,
v. 2.0](./LICENSE).

[`dusk-bls12_381`]: https://crates.io/crates/dusk-bls12_381
[`blst`]: https://crates.io/crates/blst
