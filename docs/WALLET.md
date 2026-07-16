# Wallet

`aeon-wallet` is a CLI wallet: a single BIP39 mnemonic backing **both** a
transparent (`aeon1...`) and a shielded (`aeonz1...`, see
[`docs/PRIVACY.md`](PRIVACY.md)) identity, a password-encrypted keystore
file, and commands to check balances and send AEON — privately or not —
via a node's RPC API. Private keys are decrypted only in memory, only for
as long as a command needs them, and are never sent anywhere over the
network — only signed transactions (and, for shielded scanning, read-only
requests for public chain data) are.

## Commands

### `create`

```
aeon-wallet create --wallet alice.json
```

Generates a new 12-word BIP39 mnemonic and prints it once — **write it
down**; it is the only way to recover the wallet if the file is lost, and
Aeon has no way to recover it for you. You then choose a password, which
encrypts the wallet's raw 64-byte seed (via scrypt + AES-256-GCM) before
it's written to `alice.json`. Prints both derived addresses. Refuses to
overwrite an existing file.

### `address`

```
aeon-wallet address --wallet alice.json
```

Prints the wallet's transparent (`aeon1...`) and shielded (`aeonz1...`)
addresses. Does not need the password — both are stored in plaintext
alongside the encrypted seed, since an address is meant to be shared.

### `balance`

```
aeon-wallet balance --wallet alice.json --node http://127.0.0.1:16111
```

Queries the given node for the wallet's current confirmed **transparent**
balance. For the shielded balance, see `shielded-balance` below.

### `send`

```
aeon-wallet send --wallet alice.json --node http://127.0.0.1:16111 --to <aeon1...> --amount 12.5
```

Prompts for the wallet's password, decrypts the seed, selects enough
unspent transparent outputs (UTXOs) to cover the amount, builds a
transaction (with a change output back to the sender if needed), signs it
locally, and submits it to the node. Amounts are plain decimal AEON (up to
8 decimal places, e.g. `0.00000001`). There is no separate fee in Aeon's
current fee model — a transaction's outputs simply must not exceed its
inputs.

### `shield`

```
aeon-wallet shield --wallet alice.json --node http://127.0.0.1:16111 --amount 5.0
```

Moves AEON from the wallet's transparent balance into its own shielded
balance: spends transparent UTXOs (with transparent change back to
yourself if needed) and creates a new shielded note for the same wallet.
Builds a real zk-SNARK proof — expect this to take real time (seconds,
not milliseconds).

### `shielded-balance`

```
aeon-wallet shielded-balance --wallet alice.json --node http://127.0.0.1:16111
```

Downloads every confirmed shielded action from the node and decrypts each
one locally with the wallet's own viewing key to find its spendable notes
(see [`docs/PRIVACY.md`](PRIVACY.md) §3) — the node itself never sees this
key. Rescans from genesis every time, so it's slower than `balance`.

### `send-shielded`

```
aeon-wallet send-shielded --wallet alice.json --node http://127.0.0.1:16111 --to <aeonz1...> --amount 2.0
```

Sends AEON privately from the wallet's shielded balance to another
shielded address — the amount and both addresses stay hidden on-chain.
Spends a single note covering the amount (with shielded change back to
yourself if needed); if no single note is large enough, this fails rather
than combining multiple notes (see [`docs/PRIVACY.md`](PRIVACY.md) §5).
Builds a real zk-SNARK proof.

### `deshield`

```
aeon-wallet deshield --wallet alice.json --node http://127.0.0.1:16111 --amount 2.0 [--to <aeon1...>]
```

Moves AEON from the wallet's shielded balance back to a transparent
address — your own wallet's transparent address by default, or `--to` any
other one. Builds a real zk-SNARK proof.

## The wallet file format

A wallet file is JSON:

```json
{
  "address": "aeon1...",
  "shielded_address": "aeonz1...",
  "keystore": {
    "log_n": 15, "r": 8, "p": 1,
    "salt": "...", "nonce": "...", "ciphertext": "..."
  }
}
```

`address`/`shielded_address` are plaintext (not secret). `keystore` is the
password-encrypted raw 64-byte BIP39 seed (scrypt for key derivation,
AES-256-GCM for encryption) — both the transparent key and the shielded
spending key are re-derived from this same seed on every unlock (see
`crates/crypto/src/mnemonic.rs` and `crates/shielded/src/keys.rs`), rather
than each being stored separately. Losing this file *and* the recovery
phrase means the funds (transparent and shielded) are unrecoverable; there
is no third party who can reset it.

## Where addresses come from

A **transparent** Aeon address is a bech32m encoding (human-readable
prefix `aeon`) of the BLAKE3 hash of a Schnorr (BIP340/secp256k1) public
key — conceptually identical to Kaspa's own `kaspa:`-prefixed bech32
addresses, just with BLAKE3 in place of Kaspa's hash function. See
`crates/crypto/src/address.rs`.

A **shielded** Aeon address is a bech32m encoding (human-readable prefix
`aeonz`) of a raw Orchard address, derived via ZIP 32 from the same seed.
See [`docs/PRIVACY.md`](PRIVACY.md) §2 and `crates/shielded/src/keys.rs`.
