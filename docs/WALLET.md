# Wallet

`aeon-wallet` is a CLI wallet: a BIP39 mnemonic, a password-encrypted
keystore file, and commands to check balances and send AEON via a node's
RPC API. Private keys are decrypted only in memory, only for as long as a
command needs them, and are never sent anywhere over the network — only
signed transactions are.

## Commands

### `create`

```
aeon-wallet create --wallet alice.json
```

Generates a new 12-word BIP39 mnemonic and prints it once — **write it
down**; it is the only way to recover the wallet if the file is lost, and
Aeon has no way to recover it for you. You then choose a password, which
encrypts the wallet's seed (via scrypt + AES-256-GCM) before it's written
to `alice.json`. Refuses to overwrite an existing file.

### `address`

```
aeon-wallet address --wallet alice.json
```

Prints the wallet's `aeon1...` address. Does not need the password — the
address is stored in plaintext alongside the encrypted seed, since an
address is meant to be shared.

### `balance`

```
aeon-wallet balance --wallet alice.json --node http://127.0.0.1:16111
```

Queries the given node for the wallet's current confirmed balance.

### `send`

```
aeon-wallet send --wallet alice.json --node http://127.0.0.1:16111 --to <aeon1...> --amount 12.5
```

Prompts for the wallet's password, decrypts the seed, selects enough
unspent outputs (UTXOs) to cover the amount, builds a transaction (with a
change output back to the sender if needed), signs it locally, and
submits it to the node. Amounts are plain decimal AEON (up to 8 decimal
places, e.g. `0.00000001`). There is no separate fee in Aeon's current fee
model — a transaction's outputs simply must not exceed its inputs.

## The wallet file format

A wallet file is JSON:

```json
{
  "address": "aeon1...",
  "keystore": {
    "log_n": 15, "r": 8, "p": 1,
    "salt": "...", "nonce": "...", "ciphertext": "..."
  }
}
```

`address` is plaintext (not secret). `keystore` is the password-encrypted
32-byte seed (scrypt for key derivation, AES-256-GCM for encryption) that
everything else — the private key, every address the wallet could ever
derive — comes from. Losing this file *and* the recovery phrase means the
funds are unrecoverable; there is no third party who can reset it.

## Where addresses come from

An Aeon address is a bech32m encoding (human-readable prefix `aeon`) of
the BLAKE3 hash of a Schnorr (BIP340/secp256k1) public key — conceptually
identical to Kaspa's own `kaspa:`-prefixed bech32 addresses, just with
BLAKE3 in place of Kaspa's hash function. See `crates/crypto/src/address.rs`.
