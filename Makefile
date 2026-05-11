BLST                 := --no-default-features --features bls-backend-blst
BLST_ZEROIZE         := --no-default-features --features bls-backend-blst,zeroize
BLST_SERDE_ZEROIZE   := --no-default-features --features bls-backend-blst,serde,zeroize
RKYV                 := --features rkyv-impl
ZEROIZE              := --features zeroize
PARALLEL             := --features parallel

CLIPPY   := --release -- -D warnings

.PHONY: all \
        fmt fmt-check \
        clippy clippy-dusk clippy-dusk-rkyv clippy-dusk-zeroize clippy-dusk-parallel clippy-blst \
        test test-dusk test-dusk-rkyv test-dusk-zeroize \
		test-blst test-blst-zeroize test-blst-serde-zeroize \
		bench bench-dusk bench-blst \
        doc doc-dusk doc-blst \
        cq \
        no-std

all: cq test doc no-std

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy: clippy-dusk clippy-dusk-rkyv clippy-dusk-zeroize clippy-dusk-parallel clippy-blst

clippy-dusk:
	cargo clippy $(CLIPPY)

clippy-dusk-rkyv:
	cargo clippy $(RKYV) $(CLIPPY)

clippy-dusk-zeroize:
	cargo clippy $(ZEROIZE) $(CLIPPY)

clippy-dusk-parallel:
	cargo clippy $(PARALLEL) $(CLIPPY)

clippy-blst:
	cargo clippy $(BLST) $(CLIPPY)

test: test-dusk test-dusk-rkyv test-dusk-zeroize test-blst test-blst-zeroize test-blst-serde-zeroize

test-dusk:
	cargo test

test-dusk-rkyv:
	cargo test $(RKYV)

test-dusk-zeroize:
	cargo test $(ZEROIZE)

test-blst:
	cargo test $(BLST)

test-blst-zeroize:
	cargo test $(BLST_ZEROIZE)

test-blst-serde-zeroize:
	cargo test $(BLST_SERDE_ZEROIZE)

bench: bench-dusk

bench-dusk:
	cargo bench --bench bls12_381

bench-blst:
	cargo bench $(BLST) --bench bls12_381

doc: doc-dusk doc-blst

doc-dusk:
	cargo doc --no-deps

doc-blst:
	cargo doc --no-deps $(BLST)

cq: fmt-check clippy

# This currently checks the default dusk backend on a no_std target.
no-std:
	cargo check --target wasm32-unknown-unknown