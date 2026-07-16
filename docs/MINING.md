# Mining

`aeon-miner` is a CPU miner that talks to a node over RPC — the same
getBlockTemplate/submitBlock flow Kaspa's own miners use, just over a
plain HTTP/JSON API instead of gRPC:

```
cargo run --release -p aeon-miner -- --node http://127.0.0.1:16111 --address <aeon1...>
```

Options (`aeon-miner --help`):

| Flag | Default | Meaning |
|---|---|---|
| `--node` | `http://127.0.0.1:16111` | Node RPC URL to mine against |
| `--address` | *(required)* | Address to receive block rewards |
| `--refresh-secs` | `5` | How long to search a template before fetching a fresh one |

The miner loops: fetch a template → brute-force nonces against the
template's target using BLAKE3 → submit any solved block → repeat. It
prints a running hashrate estimate and the hash of any block it finds.

## Running two nodes and mining across a small network

This is what actually makes Aeon a *network* rather than a single
process. On one machine:

```
cargo run --release -p aeon-node -- --datadir ./node-a --p2p-listen 127.0.0.1:16110 --rpc-listen 127.0.0.1:16111
```

On a second machine (or a second terminal on the same one, using
different ports):

```
cargo run --release -p aeon-node -- --datadir ./node-b --p2p-listen 127.0.0.1:16120 --rpc-listen 127.0.0.1:16121 --addnode 127.0.0.1:16110
```

`--addnode` tells node B to connect to node A on startup; from then on
both directions of gossip (new blocks, new transactions) flow over that
connection. Point a miner at either node's RPC address — blocks it mines
propagate to the other node automatically:

```
cargo run --release -p aeon-miner -- --node http://127.0.0.1:16121 --address <aeon1...>
```

To mine across the real internet with a friend rather than two processes
on one machine, replace `127.0.0.1` with a real reachable IP/port (you'll
need to forward the P2P port through any NAT/firewall in front of the
node accepting connections). A ready-made two-node **local** setup is in
`scripts/run-local-testnet.ps1`.

## Difficulty

Genesis difficulty is deliberately easy (see `docs/CONSENSUS.md` §3) so a
lone CPU finds blocks almost instantly on a fresh network. Aeon's
difficulty adjustment algorithm (DAA) retargets **every block** (not every
few thousand like Bitcoin) toward the 1-block-per-second target, so if you
mine continuously with meaningful hashrate, expect difficulty — and thus
the time between found blocks — to climb quickly. This is correct,
expected behavior, not a bug: it's the same mechanism that keeps a real
network's block time stable regardless of how much total hashrate joins
or leaves.

## Security note

Genesis-level difficulty has essentially no proof-of-work security — it
exists purely so a single hobbyist machine can bootstrap and test a fresh
network immediately. A network's actual security (resistance to
double-spends via a competing chain) comes from real, sustained hashrate
across independent miners, same as any other proof-of-work chain.
