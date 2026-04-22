# AGENTS.md

Instructions for automated coding agents working in this repository.

## Mission and security posture

This repository contains `dusk-curves`, a `no_std` + `alloc` Rust crate that
exposes a backend-agnostic BLS12-381 API.

Dusk Network is a blockchain system that relies on BLS12-381 as a core
primitive. This makes the crate security-sensitive and consensus-adjacent:

- correctness is more important than convenience or micro-optimizations
- backend divergence is a potential consensus and security risk
- malformed inputs must be treated as adversarial
- serialization, equality, subgroup checks, and pairing behavior are all
  security-sensitive surfaces

The purpose of this crate is to let downstream Dusk code depend on a stable API
while being able to switch the underlying backend if needed. That only works if
both backends preserve the same public semantics.

If a change trades clarity or safety for cleverness, do not make it.

## Repository layout

- `src/lib.rs`: crate root, `#![no_std]`, exports the BLS12-381 module.
- `src/bls12_381.rs`: backend-agnostic facade, compile-time feature guards,
  public re-exports, and shared helper functions.
- `src/bls12_381/backend_dusk.rs`: default pure-Rust backend built on
  `dusk-bls12_381`.
- `src/bls12_381/backend_blst.rs`: blst-backed wrapper types and trait impls.
- `Makefile`: canonical local and CI commands.
- `.github/workflows/dusk_ci.yml`: CI entrypoint; jobs should call `make`
  targets instead of hand-written cargo command lines.

## Backends and features

- Default backend: `bls-backend-dusk`
- Alternate backend: `bls-backend-blst`
- The two backend features are mutually exclusive.
- `parallel` is dusk-only.
- `rkyv-impl` is dusk-only.
- `zeroize` is supported independently of backend.

When changing the public API, keep `src/bls12_381.rs` backend-agnostic unless a
feature gate is explicitly required.

## Domain context: what must stay true

This crate exposes curve and scalar operations over BLS12-381. Any edit that
changes arithmetic, decoding, encoding, equality, or pairing behavior must be
treated as a cryptographic change, not a refactor.

These invariants matter:

- `Scalar` and `BlsScalar` represent elements of the scalar field modulo the
  BLS12-381 scalar order.
- `G1Affine`, `G1Projective`, `G2Affine`, `G2Projective`, `G2Prepared`, and
  `Gt` must refer to the same mathematical objects regardless of backend.
- `hash_to_scalar` must remain deterministic and backend-independent.
- `scalar_from_wide` must preserve its exact reduction behavior and endianness.
- serialization and deserialization must remain canonical and predictable.
- equality must reflect group equality, not accidental memory equality.
- identity handling must remain correct and consistent in affine and projective
  forms.
- pairing-related operations must preserve exact semantics across backends,
  including the product-of-pairings identity check.

If you are not certain a change preserves these invariants, do not ship it
without stronger validation.

## Threat model and security constraints

Assume all external byte inputs are attacker-controlled.

When editing decode, encode, or conversion code:

- reject invalid encodings
- reject off-curve points unless the API is explicitly unchecked and unsafe
- reject points not in the correct subgroup when the safe API claims group
  membership
- preserve canonical encodings and failure behavior
- do not silently relax validation for performance reasons

Unchecked constructors and unchecked decoding are allowed only when they are
explicitly marked unsafe or clearly internal. Keep their surface area small and
their contracts documented.

Consensus-sensitive rule: if two backends accept different bytes, produce
different encodings, disagree on equality, or differ on pairing results, that is
not a cosmetic difference. It is a security bug until proven otherwise.

## Constant-time and secret-handling guidance

Treat scalars and scalar-derived operations as potentially sensitive.

- avoid introducing secret-dependent branching or secret-dependent early returns
  in arithmetic code paths
- preserve or improve constant-time behavior where `subtle` traits or equality
  helpers are involved
- do not add debug logging or display formatting that leaks secret material
- do not remove or weaken `zeroize` behavior when the feature is enabled

Not every type here is secret by default, but edits should assume that scalar
operations may be used in sensitive contexts.

## Unsafe and FFI rules

`backend_blst.rs` wraps an FFI library. Treat every unsafe change as
security-sensitive.

- keep unsafe blocks as small as possible
- prefer using documented blst conversion and arithmetic functions over raw
  layout assumptions
- document the preconditions when unsafe code relies on on-curve, subgroup, or
  encoding invariants
- do not introduce `transmute`, pointer casting, or layout assumptions unless
  there is no better option and the safety argument is explicit
- do not assume all-zero or default representations are valid beyond the cases
  already verified against blst behavior and current code comments

When touching wrapper semantics in `backend_blst.rs`, keep behavior explicit.
For example, projective equality should use blst equality helpers rather than
opaque derives or raw field comparisons.

## Dependency constraints

- `group`, `rand_core`, and `subtle` are optional on purpose and are only
  activated from `bls-backend-blst`.
- `rkyv` is a direct optional dependency on purpose. It enables `rkyv/size_64`
  for this crate's `rkyv-impl` feature. Do not remove it unless upstream
  feature wiring changes.
- `ff` is intentionally not a direct dependency anymore. The crate gets it
  transitively from `dusk-bls12_381` where needed.

Dependency and feature changes can alter validation behavior, no_std behavior,
or backend parity. Treat them as security-relevant.

## Editing rules

- prefer minimal changes that preserve the existing public API and naming
- keep the dusk and blst backends aligned where the API is meant to match
- if you add or remove a re-export in the dusk backend, check whether the same
  change is needed in `src/bls12_381.rs`
- avoid introducing `std`; this crate is `no_std` and uses `alloc`
- preserve current style: explicit trait impls, focused comments, and small
  wrapper helpers over large abstractions
- preserve public behavior unless the task is explicitly to change it
- when behavior is ambiguous, prefer existing tested semantics over guessed
  cleanup

If you change arithmetic or security-sensitive behavior, add or update tests.
Do not stop at code changes alone.

## Validation commands

Use the `Makefile` targets instead of ad hoc cargo invocations.

- `make fmt-check`
- `make clippy`
- `make test`
- `make doc`
- `make no-std`

Targeted commands:

- `make clippy-dusk`
- `make clippy-dusk-rkyv`
- `make clippy-dusk-zeroize`
- `make clippy-dusk-parallel`
- `make clippy-blst`
- `make test-dusk`
- `make test-dusk-rkyv`
- `make test-blst`
- `make doc-dusk`
- `make doc-blst`

## What to run after changes

- shared facade or feature/Cargo changes: run both backend checks, relevant
  feature variants, and docs if the public API changed
- `backend_dusk.rs`: run at least `make clippy-dusk`; also run
  `make clippy-dusk-rkyv` or `make clippy-dusk-parallel` if those code paths are
  affected
- `backend_blst.rs`: run at least `make clippy-blst` and `make test-blst`
- serialization, decoding, equality, or pairing changes: run both backends and
  add targeted tests for malformed inputs, identity handling, and canonical
  round-trips when possible
- `Makefile` or workflow changes: run the touched `make` targets locally

If a change is security-sensitive and there is no focused test yet, add one.

## Common pitfalls

- do not enable dusk-only features on the blst backend
- do not forget subgroup checks after deserialization on safe APIs
- do not rely on raw memory equality when mathematical equality is required
- do not let the two backends drift in public error behavior, encoding, or
  equality semantics
- do not remove the direct `rkyv` dependency unless upstream feature wiring is
  changed and revalidated
- do not widen unsafe surfaces unnecessarily
- do not accept non-canonical encodings just because an upstream primitive can
  parse them
- do not treat backend-only differences as harmless if they are observable from
  the public API
- keep re-exports synchronized between backend modules and the public facade
- `no-std` uses `wasm32-unknown-unknown` because the crate needs `alloc`
  but not `std`
- CI intentionally lints dusk and blst separately; do not collapse those into a
  single backend-specific command

## Review mindset for agents

When reviewing or implementing changes here, think like a cryptography and
consensus engineer first, and a refactoring tool second.

Ask these questions before finishing:

- could this change alter accepted inputs or rejected inputs?
- could this change make one backend behave differently from the other?
- could this change weaken subgroup, identity, or canonical encoding checks?
- could this change introduce secret-dependent behavior or unsafe assumptions?
- did I validate the exact feature/backend combinations affected?

If the answer might be yes, keep going until the risk is resolved or clearly
documented.