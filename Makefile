# ── Feature sets ─────────────────────────────────────────────────────────────
BLST     := --no-default-features --features bls-backend-blst
RKYV     := --features rkyv-impl
ZEROIZE  := --features zeroize
PARALLEL := --features parallel

# Common clippy flags (release profile; treat all warnings as errors)
CLIPPY := --release -- -D warnings

.PHONY: all fmt fmt-check \
        clippy clippy-dusk clippy-dusk-rkyv clippy-dusk-zeroize \
        clippy-dusk-parallel clippy-blst \
        test test-dusk test-dusk-rkyv test-blst \
        doc doc-dusk doc-blst \
        check-no-std

all: fmt-check clippy test doc

# ── Formatting ────────────────────────────────────────────────────────────────
fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

# ── Clippy ────────────────────────────────────────────────────────────────────
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

# ── Tests ─────────────────────────────────────────────────────────────────────
test: test-dusk test-dusk-rkyv test-blst

test-dusk:
	cargo test

test-dusk-rkyv:
	cargo test $(RKYV)

test-blst:
	cargo test $(BLST)

# ── Documentation ─────────────────────────────────────────────────────────────
doc: doc-dusk doc-blst

doc-dusk:
	cargo doc --no-deps

doc-blst:
	cargo doc --no-deps $(BLST)

# ── no_std compatibility ──────────────────────────────────────────────────────
# Uses wasm32-unknown-unknown: a no_std target with alloc, suitable for
# pure-Rust crates.  Run `rustup target add wasm32-unknown-unknown` first.
check-no-std:
	cargo check --target wasm32-unknown-unknown
