# Aeon's shielded pool: optional, Zcash-grade privacy

Aeon has a second, **optional** transaction pool alongside the transparent
one described in the rest of this repo: a *shielded* pool where the
amount and both the sending and receiving addresses are hidden from
everyone except the participants. Using it is entirely your choice,
transaction by transaction — the transparent pool keeps working exactly as
documented elsewhere, unchanged.

> **Read this whole document before relying on the shielded pool for
> anything you actually care about.** It is real, working code with real
> zk-SNARK proofs — not a mock — but it is also new, unaudited, and has
> already had one real bug found and fixed during this project's own
> integration testing (see [§6](#6-honest-risk-assessment)). Treat it as
> an experimental, educational implementation.

## 1. What's hidden, and how

Aeon does **not** invent its own zero-knowledge cryptography. It embeds
Zcash's real, audited **Orchard** protocol (the shielded-pool design Zcash
has used in production since its NU5 upgrade): Halo2-based zk-SNARKs,
which — unlike Zcash's original Sapling pool — need **no trusted-setup
ceremony** at all. Concretely, Aeon depends on the `orchard` crate
(published by the Electric Coin Company / Zcash on crates.io) as its
shielded-pool engine, exactly the way it depends on `k256` for
transparent signatures or `sled` for storage: reuse a real, reviewed
implementation instead of hand-rolling cryptography for the part of the
system where a subtle mistake is most catastrophic (an unsound circuit
can mean silently forgeable money; a flawed encryption scheme can mean
silently broken privacy).

A shielded transaction (see `crates/shielded/src/bundle.rs`) hides:

- **The amount.** Each shielded output is a Pedersen-style value
  commitment, not a plaintext number; a zk-SNARK proves the amounts
  balance without revealing any of them.
- **The sender.** A spend reveals only a *nullifier* — a value
  deterministically tied to the note being spent, but computationally
  unlinkable to it without the spender's own viewing key.
- **The recipient.** Outputs are addressed to one-time note ciphertexts;
  only the holder of the matching incoming viewing key can tell it's
  theirs.

What it does **not** hide:

- **That a shielded transaction happened, and roughly when.** Block
  timestamps, transaction sizes, and network metadata are all public, the
  same as for any blockchain (Aeon's or otherwise).
- **Coinbase.** Mining rewards are always transparent — see
  [§5](#5-scope-and-simplifications).
- **Shielding/deshielding amounts.** Moving value *into* or *out of* the
  shielded pool necessarily reveals that amount on the transparent side
  (the same is true of Zcash). Only transfers that stay
  shielded-to-shielded hide the amount end to end.

## 2. Addresses and keys

A wallet derives **one shielded address per seed**, from the same BIP39
mnemonic already used for its transparent address (see
`crates/shielded/src/keys.rs`) — one recovery phrase backs both. The
derivation uses ZIP 32 (the same hierarchical scheme Zcash's own wallets
use), with an Aeon-specific "coin type" constant purely for domain
separation (not a registered SLIP-44 value — Aeon isn't Zcash and doesn't
claim to be).

Shielded addresses are bech32m-encoded with the human-readable prefix
`aeonz` (e.g. `aeonz1...`), visually distinct from transparent `aeon1...`
addresses so the two can never be confused — analogous to Zcash's own
`t1.../zs1...` distinction.

**Scope reduction:** Aeon derives only the single default address (ZIP
32 account 0, external scope) per seed, not a full tree of diversified
addresses. A production Zcash-style wallet can hand out a different
diversified address to every sender for extra unlinkability; Aeon's
simplified wallet does not.

## 3. How a wallet finds its own money

A shielded output doesn't reveal who it's for — so how does a wallet know
which ones are its own? By **local trial-decryption**: it downloads every
confirmed shielded bundle from a node's `GET /shielded-actions` endpoint
and tries to decrypt each one with its own incoming viewing key.
Decryption only succeeds for outputs actually addressed to that key.

This is a deliberate design choice for maximum privacy: **the node never
learns any wallet's viewing key.** A "light wallet" service that
outsources this scanning to a server (as some real Zcash wallets do, for
efficiency on a huge chain) would need to hand that server a viewing key,
which reveals which transactions belong to that wallet (though still not
its spending power). At Aeon's hobby scale, full local scanning by the
wallet itself is entirely practical and strictly more private.

To *spend* one of its own notes, the wallet also needs a Merkle witness
(proof the note commitment is in the global note-commitment tree). It
gets this by rebuilding the **entire** tree locally from the same
`/shielded-actions` stream (see `crates/shielded/src/tree.rs`,
`witness_for_position`). This is simple and correct, but it means every
`aeon-wallet shield`/`send-shielded`/`deshield` invocation rescans and
rebuilds the tree from genesis — fine for a hobby chain with a few
thousand shielded actions, not how a production wallet at Zcash's scale
would do it (a real wallet keeps incremental, cached state).

## 4. Nodes: nullifiers and anchors, not witnesses

A full node (`crates/aeon-storage`) needs much less than a wallet does:

- A **nullifier set** — every nullifier ever confirmed, so a shielded
  spend reusing one can be rejected (the shielded-pool equivalent of
  double-spend prevention).
- The current **anchor** (note-commitment-tree root) and a short history
  of recent-past anchors, so an incoming shielded transaction's proof
  (built against whatever anchor was current when the wallet started
  building it) is still accepted even if a few blocks have since passed.
- The ability to **append** new commitments as blocks confirm them.

Notably, a node does **not** need to produce Merkle witnesses for
arbitrary historical notes (only the spending wallet ever needs that), so
it tracks the tree as a lean *frontier* (the O(depth) rightmost-path state
needed to append and compute the root) rather than a full witness-capable
structure — see the module-level comment in `crates/shielded/src/tree.rs`.
Reorgs work by snapshotting this small frontier state (and the nullifier
set's recent changes) before applying each block and restoring the
snapshot verbatim if that block is later un-applied — much simpler than
incrementally rewinding a Merkle tree, and cheap enough at this scale.

## 5. Scope and simplifications

Documented here so nobody mistakes Aeon's shielded pool for a
line-for-line reimplementation of Zcash's:

- **Coinbase is always transparent.** Mining rewards never start
  shielded — the same as Zcash's original design (Zcash later added
  shielded coinbase for mining pools; Aeon does not).
- **Single-note spends.** `aeon-wallet send-shielded`/`deshield` spend
  exactly one note per transaction (with a shielded change output back to
  the sender if needed) rather than joining multiple notes together. If
  no single note covers the requested amount, the command fails rather
  than combining several.
- **Full rescans, no incremental client state** (see §3): every wallet
  operation rescans from genesis.
- **One address per seed, no ZIP-32 diversification** (see §2).
- **The `orchard`/`halo2` crate versions are consensus-critical and
  pinned.** Every node validating the shielded pool must run the exact
  dependency versions in `Cargo.lock` — a circuit-affecting upgrade would
  need a coordinated network upgrade, the same as Zcash's own network
  upgrades.
- **64-bit only.** The Orchard circuit's layout (and therefore its
  verifying key) can differ between 32-bit and 64-bit targets due to an
  internal sorting algorithm in `halo2`. Every Aeon node validating the
  shielded pool must run on a 64-bit architecture — true of essentially
  every real deployment target, but worth stating explicitly.
- **Fee model:** consistent with Aeon's zero-fee transparent design, a
  shielded/mixed transaction's transparent and shielded sides must balance
  exactly (see `docs/CONSENSUS.md`); there's no shielded-pool fee market.

## 6. Honest risk assessment

Reusing Zcash's audited `orchard` crate removes the single riskiest
category of bug (an unsound proving/verifying circuit) from Aeon's own
surface area. It does **not** remove risk from the code that *integrates*
that crate: the transparent/shielded balance equation
(`aeon-core::validation`), the nullifier/anchor bookkeeping and reorg
handling (`aeon-storage`), and the RPC/mempool plumbing (`aeon-node`) are
all new, Aeon-specific, unaudited code. A bug there could still allow
double-spending or a supply-conservation violation, even with a perfectly
sound `orchard` underneath.

This isn't a hypothetical concern: this project's own end-to-end test
(`crates/node/tests/shielded_integration.rs`, which genuinely shields
funds, sends them privately, and deshields them across two networked
nodes) caught exactly this kind of integration bug during development —
the mempool didn't prune a confirmed *shielded* transaction the same way
it pruned a confirmed transparent one (since a shielded-only transaction
has no transparent inputs to check against), which caused every
subsequent block template to silently drop its entire mempool batch. It's
fixed (see `crates/node/src/mempool.rs`), but its existence is a concrete
illustration of why "built on an audited primitive" is not the same claim
as "audited system." Treat Aeon's shielded pool accordingly.
