# Aeon (AEON)

[![CI](https://github.com/melvinfranco99/aeon/actions/workflows/ci.yml/badge.svg)](https://github.com/melvinfranco99/aeon/actions/workflows/ci.yml)

A proof-of-work **BlockDAG** cryptocurrency, in the spirit of
[Kaspa](https://kaspa.org): fast, parallel block production ordered by
**GHOSTDAG** consensus, instead of a single Nakamoto chain. Unlike Kaspa,
Aeon's monetary policy mirrors **Bitcoin's**: a hard cap of
**21,000,000 AEON**, released via halvings that wind down to (almost)
zero issuance roughly **114 years after genesis — around the year 2140**.

Implemented from scratch in Rust as a Cargo workspace: a full node, a CPU
miner, and a CLI wallet, talking to each other over a real (if
appropriately scoped-down) P2P network and JSON-RPC API. See
[`docs/CONSENSUS.md`](docs/CONSENSUS.md) for exactly what's implemented
and — just as importantly — where it deliberately simplifies relative to
Kaspa's production codebase, and why.

> **Status:** a from-scratch, functional educational/hobby implementation,
> not an audited, battle-tested cryptocurrency. Read
> [`docs/CONSENSUS.md`](docs/CONSENSUS.md) before relying on it for
> anything beyond learning and experimentation.

## Why Aeon exists

Kaspa proved that a BlockDAG ordered by GHOSTDAG can safely produce blocks
far faster than a single chain ever could. Aeon keeps that architecture
but swaps in Bitcoin's most famous property — a hard, shrinking, publicly
verifiable supply schedule — so the two most-asked "can you combine X and
Y" cryptocurrency design questions have a working answer in one small
codebase.

## Key properties

| Property | Aeon |
|---|---|
| Consensus | GHOSTDAG BlockDAG (`k`-cluster blue/red coloring), `k = 18` by default |
| Proof-of-work | BLAKE3 (see [`docs/CONSENSUS.md`](docs/CONSENSUS.md) for why not kHeavyHash) |
| Target block time | 1 second, retargeted **every block** (not every epoch) |
| Max supply | 21,000,000 AEON (8 decimals; smallest unit is called a `quark`) |
| Emission | Halving schedule, ≈114 years to full emission (~year 2140) |
| Signatures | Schnorr / BIP340 over secp256k1 (via pure-Rust `k256`) |
| Addresses | bech32m, `aeon1...` (same encoding family as Kaspa's `kaspa:...`) |
| Storage | `sled` (pure Rust, no C/C++ toolchain required) |

## Quickstart

```
git clone <this repository's URL>
cd aeon
cargo build --release
cargo test --workspace

cargo run --release -p aeon-node -- --datadir ./node-data
```

Then, in another terminal:

```
cargo run --release -p aeon-wallet -- create --wallet alice.json
cargo run --release -p aeon-miner -- --address <address printed above>
cargo run --release -p aeon-wallet -- balance --wallet alice.json
```

Full walkthrough (installing Rust with no Visual Studio required, creating
two real wallets, mining, and sending AEON between them):
**[`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)**.

## Documentation

- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) — install, build, create wallets, mine, send AEON
- [`docs/CONSENSUS.md`](docs/CONSENSUS.md) — GHOSTDAG, emission schedule, difficulty adjustment, and honest scope limitations
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — crate layout and data flow
- [`docs/MINING.md`](docs/MINING.md) — running the miner, connecting multiple nodes
- [`docs/WALLET.md`](docs/WALLET.md) — wallet command reference and file format

## Repository layout

```
crates/
  crypto/    hashing, keys/signatures, addresses, mnemonics, keystores
  core/      GHOSTDAG engine, ledger, emission schedule, validation
  storage/   sled-backed persistence, reorg handling
  network/   P2P gossip (TCP + bincode)
  rpc/       JSON-RPC types, axum server, HTTP client
  node/      the node daemon (binary + library)
  miner/     the CPU miner (binary)
  wallet/    the CLI wallet (binary)
docs/        the documents linked above
scripts/     scripts/run-local-testnet.ps1 — two local nodes for testing
```

## Testing

```
cargo test --workspace
```

This includes unit tests for GHOSTDAG coloring against hand-built DAGs,
the emission schedule's convergence to 21M AEON and ~2140 exhaustion,
difficulty adjustment, transaction/block validation (including
double-spend rejection), and an end-to-end integration test
(`crates/node/tests/two_node_integration.rs`) that runs two full nodes,
mines blocks, sends a real signed transaction between two wallets, and
verifies both nodes converge on the same ledger state.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

[MIT](LICENSE).
