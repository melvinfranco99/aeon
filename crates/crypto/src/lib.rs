//! Cryptographic primitives for the Aeon network: BLAKE3 hashing, Schnorr
//! (BIP340) keys and signatures, bech32m addresses, BIP39 mnemonics and
//! password-encrypted keystores.

pub mod address;
pub mod hash;
pub mod keys;
pub mod keystore;
pub mod mnemonic;

pub use address::{Address, AddressError};
pub use hash::{blake3_hash, merkle_root, Hash};
pub use keys::{CryptoError, KeyPair, PublicKey, SchnorrSignature};
pub use keystore::{Keystore, KeystoreError};
pub use mnemonic::{generate_mnemonic, parse_mnemonic, seed_to_key_material, MnemonicError};
