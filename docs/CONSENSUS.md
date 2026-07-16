# Aeon consensus

Aeon is a proof-of-work **BlockDAG**, not a single chain: blocks may have
more than one parent, and multiple blocks can be mined in parallel without
either being "orphaned". Ordering and security come from **GHOSTDAG**, the
same family of protocol Kaspa uses (a concrete instance of the more general
PHANTOM protocol, from the paper *"PHANTOM GHOSTDAG: A Scalable Generalization
of Nakamoto Consensus"* by Sompolinsky, Wyborski and Zohar).

This document explains, precisely, what Aeon implements, and where it
deliberately simplifies relative to Kaspa's production implementation.

## 1. Blocks are a DAG, not a chain

An Aeon `BlockHeader` looks like this (see `crates/core/src/types.rs`):

```rust
pub struct BlockHeader {
    pub parents: Vec<Hash>,   // one or more parents, not just one
    pub merkle_root: Hash,
    pub timestamp: u64,
    pub bits: u32,            // compact difficulty target
    pub nonce: u64,
}
```

A miner builds a block on top of **every current tip** of the DAG (every
block that isn't yet any other block's parent), not just "the longest
chain". `aeon-storage` tracks this tip set explicitly (`Store::tips`) so
block templates are genuine multi-parent DAG blocks whenever more than one
tip exists (e.g. because two miners found a block around the same time).

## 2. GHOSTDAG: coloring blocks blue and red

Given a new block `B` with parents `P`:

1. **Selected parent.** The parent with the greatest accumulated
   `blue_work` becomes `B`'s selected parent (ties broken by the smaller
   hash). This is GHOSTDAG's analogue of "the tip of the longest chain".
2. **Merge set.** Every block reachable from `B`'s other parents that
   *isn't* already an ancestor of the selected parent joins the merge set —
   these are blocks that were mined "in parallel" and are now being
   reconciled into one DAG.
3. **Blue/red coloring.** Merge-set blocks are processed in topological
   order. A block joins the growing **blue set** if doing so keeps every
   pair of blue blocks' mutual anticone (blocks neither is an ancestor of)
   at or below `k`, the protocol's security parameter (default `18`,
   configurable via `--ghostdag-k`). Otherwise it's colored **red**.
4. **Scoring.** `blue_score(B) = blue_score(selected_parent) + 1 +
   |blue merge-set blocks|` — this is Aeon's analogue of "block height".
   `blue_work(B)` accumulates the proof-of-work of `B` and every blue block
   in its past, **excluding red blocks' work entirely** — this exclusion is
   exactly what makes GHOSTDAG secure against an attacker who mines blocks
   but tries to have them ignored: red blocks contribute nothing to the
   score that determines the winning tip.
5. **Selected tip.** Whichever block has the greatest `blue_work` is the
   DAG's current "selected tip" — GHOSTDAG's equivalent of Bitcoin's
   heaviest chain.

Transactions are only applied to the ledger along the selected-parent
chain (see §5); the DAG structure and blue/red coloring above is what
determines *which* chain that is, exactly as in Kaspa.

## 3. Difficulty: adjusted every block, not every epoch

Bitcoin retargets difficulty every 2016 blocks (about two weeks). At
Aeon's 1-block-per-second target that would let the network drift wildly
off-pace between retargets, so — like Kaspa — Aeon recomputes the target
**for every block**, from a sliding window of the last
`DAA_WINDOW_SIZE` (60) blocks along the selected chain (see
`crates/core/src/difficulty.rs`). The adjustment factor is clamped to
`[0.25x, 4x]` per block to damp oscillation.

The genesis difficulty is intentionally easy (`max_target`, the top 8 bits
of a header's hash must be zero — roughly a 1-in-256 chance per try) so a
single CPU can mine blocks almost immediately on a fresh network; the DAA
pushes difficulty up quickly once real mining starts.

## 4. Monetary policy: 21,000,000 AEON, exhausted around 2140

See `crates/core/src/emission.rs` for the full derivation. In short: Aeon
reuses Bitcoin's issuance *mechanism* — an integer block reward that halves
every fixed number of blocks, via a right-shift that naturally reaches
exactly zero — but with different constants, chosen so that at Aeon's
1-block/second cadence:

- the total supply converges to (just under) **21,000,000 AEON**, and
- full emission completes roughly **114 years** after genesis (around the
  year **2140**, for Aeon's ~2026 genesis),

instead of Bitcoin's ~131 years from a 2009 genesis. `crates/core/src/emission.rs`'s
tests simulate the entire schedule and assert both properties hold.

## 5. Scope: what's simplified relative to Kaspa

Being upfront about this matters more than pretending otherwise:

- **Reachability queries** (`is a block an ancestor of another?`, used
  throughout GHOSTDAG) are answered by walking the selected-parent chain
  and each block's recorded merge sets (see `ghostdag::is_ancestor`), which
  is correct but costs time proportional to the difference in blue score
  between the two blocks being compared. Kaspa's production implementation
  instead maintains an interval-tree index that answers these in
  near-constant time, which matters at a much larger scale than a
  hobby/testnet network ever reaches.
- **Blue-set coloring** only re-checks the *candidate* block's own anticone
  size against the current blue set. The full GHOSTDAG specification also
  re-verifies that accepting a candidate doesn't push an *already-blue*
  block over the `k` limit. This edge case only arises under heavy
  concurrent mining (far more parallel tips than `k`), which won't happen
  on a small network.
- **The ledger (UTXO set) only reflects the selected-parent chain**, the
  same way Bitcoin's UTXO set only reflects its single best chain. Kaspa's
  real design also incorporates merge-set (including red) blocks'
  transactions into one total order specifically to resist censorship by
  whoever produces the selected chain; Aeon does not do this. In exchange,
  reorg handling (`aeon-storage`'s `Store::reorg_to`) stays as simple and
  well-understood as Bitcoin's chain-reorg logic.
- **Proof-of-work is BLAKE3**, not Kaspa's kHeavyHash (Keccak + a
  nonce-derived matrix multiplication, originally intended to resist
  ASICs). BLAKE3 is a modern, extensively audited hash function with a
  mature Rust implementation; reproducing kHeavyHash's non-standard
  construction correctly was judged not to be worth the added risk for
  what the hash function's role actually is here.
- **Locking script is P2PKH-only** (pay to a public-key hash, verified with
  a Schnorr/BIP340 signature) — there's no scripting VM. This covers
  "send AEON to an address" completely; it doesn't support Bitcoin
  Script-style programmability.

None of these are silent shortcuts — each one is called out here and in
the relevant module's doc comments, precisely so nobody mistakes Aeon for
a byte-for-byte reimplementation of Kaspa's mainnet.
