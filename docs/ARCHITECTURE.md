# Architecture

Aeon is a Rust Cargo workspace of small, single-purpose crates:

```
aeon/
  crates/
    crypto/    Hashing (BLAKE3), Schnorr (BIP340) keys/signatures,
               bech32m addresses, BIP39 mnemonics, encrypted keystores.
    core/      Block/transaction types, the GHOSTDAG consensus engine,
               the UTXO ledger, the emission schedule, difficulty
               adjustment, and transaction/block validation rules.
               Storage-agnostic: it only depends on small traits
               (`GhostdagStore`, `UtxoView`, `ShieldedPoolView`) that
               `aeon-storage` implements.
    shielded/  Aeon's optional shielded pool (see `docs/PRIVACY.md`):
               wraps Zcash's audited `orchard` crate end to end — key
               derivation, building/proving/verifying bundles, manual
               wire (de)serialization (orchard has none built in), and
               the note-commitment tree/Merkle-witness logic.
    storage/   Persistent storage on `sled` (pure Rust, no C/C++ toolchain
               needed — see "Why sled" below): blocks, GHOSTDAG metadata,
               the UTXO set, DAG-tip tracking, and the shielded pool's
               nullifier set/note-commitment frontier, including reorg
               (undo/redo) handling for all of the above.
    network/   Peer-to-peer gossip: TCP + length-prefixed bincode framing,
               a handshake, and inv/getdata-style block/tx announcement.
    rpc/       Shared JSON-RPC types, an axum HTTP server, and an HTTP
               client — the interface `aeon-node` exposes and
               `aeon-wallet`/`aeon-miner` consume.
    node/      The node binary: wires storage + consensus + network + RPC
               together behind a single-threaded "actor" that owns all
               mutable state, so block/ledger bookkeeping never races
               against itself. Also a library crate, so integration tests
               can drive multiple in-process nodes directly.
    miner/     A CPU miner binary: fetches block templates over RPC,
               searches for a valid nonce, submits solved blocks.
    wallet/    A CLI wallet binary: BIP39 mnemonic generation, a
               password-encrypted keystore, and sending/receiving AEON
               over a node's RPC API.
```

## Data flow

```
 aeon-wallet ──┐                              ┌── aeon-miner
               │  HTTP/JSON (aeon-rpc)         │
               ▼                               ▼
                         aeon-node
              (actor: owns Store + Mempool exclusively)
                    │                    │
                    ▼                    ▼
             aeon-storage           aeon-network
             (sled: blocks,         (TCP gossip to/from
              UTXOs, GHOSTDAG)       other aeon-node peers)
                    │
                    ▼
                aeon-core
        (GHOSTDAG engine, validation,
         emission schedule, block/tx types)
                    │
                    ▼
              aeon-shielded
     (Orchard bundles: build/prove/verify,
      note commitment tree, wire format)
```

`aeon-node`'s "actor" pattern: a single async task owns the `Store` and
mempool and processes one command at a time — RPC requests (arriving via a
channel from the RPC server) and network events (arriving via a channel
from a task pumping `Network::next_event`) are both funnelled through the
same queue. This means block acceptance, reorgs, and UTXO updates are
never happening concurrently with each other, without needing a mutex
around the whole node.

## Why sled (not RocksDB)?

Many Rust blockchain projects use RocksDB, which requires a C++ compiler
and the RocksDB library itself to build. On a fresh Windows machine (no
Visual Studio, no vcpkg) that's a substantial extra install. `sled` is a
pure-Rust embedded database with no C/C++ dependency, so `cargo build` just
works anywhere a Rust toolchain is installed — including with the
lightweight GNU/MinGW toolchain (see `docs/GETTING_STARTED.md`), without
needing Visual Studio Build Tools at all.

## Why BLAKE3 and `k256` (not kHeavyHash / libsecp256k1)?

Same reasoning: both are pure Rust with no C dependency, both are modern
and well-audited, and both avoid needing any C/C++ toolchain to build.
`k256`'s `schnorr` module implements BIP340 Schnorr signatures over
secp256k1 — the same curve and signature scheme Bitcoin and Kaspa use —
just via a pure-Rust implementation (RustCrypto's `k256`) instead of
bindings to the C `libsecp256k1` library. See `docs/CONSENSUS.md` for why
BLAKE3 replaces kHeavyHash specifically.

## Why reuse Zcash's `orchard` crate for the shielded pool?

Every other cryptographic primitive in this list is a case of "use a
mature, audited implementation instead of writing our own." The shielded
pool is the same principle applied to the highest-stakes component in the
whole codebase: a hand-rolled zk-SNARK circuit is exactly the kind of code
where a subtle mistake can mean silently forgeable money or silently
broken privacy, with no visible symptom until it's exploited. `orchard` is
Zcash's own real, audited, in-production shielded-pool implementation;
`aeon-shielded` wraps it rather than reimplementing zero-knowledge
cryptography from scratch. See [`docs/PRIVACY.md`](PRIVACY.md) for the
full design and an honest assessment of what *isn't* covered by reusing
an audited primitive (the integration code around it is still new and
unaudited).
