# CLAUDE.md

This repository uses [AGENTS.md](AGENTS.md) as the canonical instruction file
for coding agents.

Apply the guidance in `AGENTS.md` when working here. If this file and
`AGENTS.md` ever diverge, treat `AGENTS.md` as the source of truth.

Quick reminders:

- This crate is `no_std` + `alloc`.
- The default backend is `bls-backend-dusk`; `bls-backend-blst` is mutually
  exclusive.
- `parallel` and `rkyv-impl` are dusk-only.
- Use `make` targets for validation: `make fmt-check`, `make clippy`,
  `make test`, `make doc`, `make no-std`.