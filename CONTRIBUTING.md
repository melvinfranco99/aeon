# Contributing to Aeon

Thanks for considering contributing! Aeon is a hobby/educational
BlockDAG proof-of-work cryptocurrency (see the README and
`docs/CONSENSUS.md` for what that means precisely, including its honest
scope limitations relative to Kaspa).

## Before you start

For anything beyond a small fix, please open an issue first describing
what you'd like to change and why — especially for anything touching
consensus rules (`crates/core/src/ghostdag.rs`, `emission.rs`,
`difficulty.rs`, `validation.rs`), since those need to stay in sync across
every node on the network.

## Development setup

See `docs/GETTING_STARTED.md` for installing Rust. Then:

```
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

All four must pass before a PR is merged; CI runs them on every push (see
`.github/workflows/ci.yml`).

## Code style

- Run `cargo fmt` before committing.
- Prefer small, focused commits with a clear message.
- Add tests for new behavior, especially anything consensus-related — see
  the existing tests in `crates/core/src/ghostdag.rs` and `emission.rs`
  for the style used (hand-built toy DAGs / simulated emission schedules
  rather than mocks).
- Document *why*, not *what*, in comments — the code should already say
  what it does.

## Reporting security issues

Aeon is a hobby project without a bug bounty program, but if you find a
consensus-breaking bug (e.g. a way to forge blocks, double-spend, or
inflate supply beyond the schedule in `docs/CONSENSUS.md`), please open an
issue describing it — responsible disclosure is appreciated even here.
