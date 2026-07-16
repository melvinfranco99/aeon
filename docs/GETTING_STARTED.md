# Getting started

This walks through everything end to end: installing the toolchain,
building Aeon, running a node, creating two wallets, mining AEON, and
sending a real transaction between them.

## 1. Install Rust

Aeon is a Rust project; you need `cargo` and `rustc` (1.75 or newer).

**Windows, without Visual Studio installed:** the standard Rust installer
defaults to the MSVC toolchain, which needs Visual Studio's C++ Build
Tools. Since every one of Aeon's dependencies is pure Rust, you can skip
that multi-gigabyte install entirely by choosing the **GNU** toolchain
instead:

1. Download `rustup-init.exe` from <https://rustup.rs>.
2. Run it from a terminal with:
   ```
   rustup-init.exe --default-host x86_64-pc-windows-gnu
   ```
   (or run it with no arguments and choose "customize installation" →
   host triple `x86_64-pc-windows-gnu`).
3. Restart your terminal so `cargo`/`rustc` are on `PATH`.

The GNU toolchain needs a MinGW-w64 linker. If `cargo build` fails with a
`dlltool.exe` or linker-not-found error, download a standalone MinGW-w64
build (e.g. from <https://winlibs.com>, no installer needed — just unzip
it) and add its `bin` directory to your `PATH`.

**macOS / Linux, or Windows with Visual Studio already installed:** just
follow the default instructions at <https://rustup.rs> — no special flags
needed.

Verify the install:

```
cargo --version
rustc --version
```

## 2. Build Aeon

```
git clone <this repository's URL>
cd aeon
cargo build --release
```

This produces four binaries in `target/release/`: `aeon-node`,
`aeon-miner`, `aeon-wallet`, plus their debug symbols. The first build
compiles Aeon's full dependency tree and takes a few minutes; subsequent
builds are incremental and fast.

Run the test suite to confirm everything works on your machine:

```
cargo test --workspace
```

## 3. Start a node

```
cargo run --release -p aeon-node -- --datadir ./node-data
```

On first run this creates `./node-data` and inserts Aeon's genesis block.
You'll see log lines like:

```
initialized new datadir with the Aeon genesis block
P2P listening on 127.0.0.1:16110
RPC listening on 127.0.0.1:16111
```

Leave this running in its own terminal. `aeon-node --help` lists all
options (`--p2p-listen`, `--rpc-listen`, `--addnode`, `--ghostdag-k`).

## 4. Create two wallets — your own, not throwaway test ones

Open a second terminal (keep the node running in the first) and create
**two separate wallet files**, e.g. one for yourself and one representing
a friend/second device:

```
cargo run --release -p aeon-wallet -- create --wallet alice.json
cargo run --release -p aeon-wallet -- create --wallet bob.json
```

Each prints a 12-word recovery phrase (**write it down — it is the only
way to recover the wallet**) and asks you to choose a password that
encrypts the wallet file on disk. Note each wallet's printed address
(`aeon1...`); you'll need both in a moment.

Check either wallet's address any time without a password:

```
cargo run --release -p aeon-wallet -- address --wallet alice.json
```

## 5. Mine AEON to your wallet

```
cargo run --release -p aeon-miner -- --address <alice's aeon1... address>
```

The miner fetches a block template from the node, searches for a valid
proof-of-work nonce, and submits solved blocks. Genesis difficulty is
intentionally easy, so a single CPU should find blocks almost immediately;
watch the node's terminal log each accepted block. Let it mine a handful
of blocks, then stop it with Ctrl+C.

Check the balance:

```
cargo run --release -p aeon-wallet -- balance --wallet alice.json
```

## 6. Send AEON to the other wallet

```
cargo run --release -p aeon-wallet -- send --wallet alice.json --to <bob's aeon1... address> --amount 5.0
```

This asks for Alice's wallet password, builds and signs a transaction
locally (the private key never leaves your machine), and submits it to the
node over RPC. It prints a `txid` once accepted.

The transaction sits in the node's mempool until it's mined into a block —
run the miner for a little while longer (mining to either address is
fine) so it gets confirmed:

```
cargo run --release -p aeon-miner -- --address <alice's address>
```

Then check both balances:

```
cargo run --release -p aeon-wallet -- balance --wallet alice.json
cargo run --release -p aeon-wallet -- balance --wallet bob.json
```

Bob's balance should now reflect the amount sent, and Alice's should be
reduced by that amount (plus any block rewards mined after the send).

## 7. Optional: run a second node and see the network in action

See `docs/MINING.md` for connecting two `aeon-node` instances (either on
the same machine on different ports, or over a LAN/the internet) so mined
blocks and transactions propagate between them — the same P2P flow
exercised automatically by `crates/node/tests/two_node_integration.rs`.

A ready-made two-node local script is provided at
`scripts/run-local-testnet.ps1` (PowerShell).
