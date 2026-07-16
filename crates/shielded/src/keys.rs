//! Shielded key derivation and addresses.
//!
//! Aeon derives a single default shielded (Orchard) address per wallet, from
//! the *same* BIP39 mnemonic already used for the wallet's transparent
//! address — one recovery phrase backs both. Derivation uses ZIP 32 (the
//! same hierarchical scheme Zcash's own wallets use) with an Aeon-specific
//! "coin type" for domain separation; this is a deliberate scope reduction
//! from full ZIP 32 (Aeon only ever derives account 0's external address,
//! not a whole diversified-address tree — see `docs/PRIVACY.md`).

use bech32::{FromBase32, ToBase32, Variant};
use bip39::Mnemonic;
use orchard::keys::{FullViewingKey, IncomingViewingKey, Scope, SpendingKey};
use orchard::Address;
use thiserror::Error;
use zip32::AccountId;

/// Not a registered SLIP-44 coin type — just a fixed constant so Aeon's
/// ZIP-32-style derivation path is distinct from Zcash's and from any other
/// chain's, even when (as recommended) a user reuses one seed phrase.
pub const AEON_ORCHARD_COIN_TYPE: u32 = 917_001;

/// Human-readable part for Aeon's shielded addresses, distinct from `aeon`
/// (transparent) so the two can never be visually confused.
pub const SHIELDED_HRP: &str = "aeonz";

#[derive(Debug, Error)]
pub enum ShieldedAddressError {
    #[error("bech32 decoding error: {0}")]
    Bech32(#[from] bech32::Error),
    #[error("wrong human-readable part: expected '{SHIELDED_HRP}', got '{0}'")]
    WrongHrp(String),
    #[error("wrong bech32 variant, shielded addresses must use bech32m")]
    WrongVariant,
    #[error("decoded payload has the wrong length for an Orchard address")]
    WrongLength,
    #[error("decoded bytes are not a valid Orchard address")]
    InvalidAddress,
}

/// Derives this wallet's Orchard spending key from its BIP39 mnemonic. Uses
/// the mnemonic's full 64-byte seed (same as Zcash's own unified wallets),
/// so this is deterministic and reproducible from the recovery phrase alone.
pub fn derive_spending_key(mnemonic: &Mnemonic, passphrase: &str) -> SpendingKey {
    derive_spending_key_from_seed(&mnemonic.to_seed(passphrase))
}

/// The same derivation as [`derive_spending_key`], starting from an
/// already-computed raw 64-byte BIP39 seed — what a wallet uses after
/// unlocking its keystore (which stores the raw seed, not the mnemonic
/// phrase itself, so it can derive both the transparent and shielded keys
/// from one secret; see `aeon_crypto::seed64_to_key_material`).
pub fn derive_spending_key_from_seed(seed64: &[u8; 64]) -> SpendingKey {
    SpendingKey::from_zip32_seed(seed64, AEON_ORCHARD_COIN_TYPE, AccountId::ZERO)
        .expect("a 64-byte BIP39 seed always yields a valid ZIP-32-derived spending key")
}

pub fn full_viewing_key(sk: &SpendingKey) -> FullViewingKey {
    FullViewingKey::from(sk)
}

pub fn incoming_viewing_key(fvk: &FullViewingKey) -> IncomingViewingKey {
    fvk.to_ivk(Scope::External)
}

/// The wallet's single default receiving address (account 0, address index
/// 0, external scope — i.e. meant to be shared with senders).
pub fn default_address(sk: &SpendingKey) -> Address {
    full_viewing_key(sk).address_at(0u32, Scope::External)
}

/// Encodes an Orchard address as bech32m with Aeon's `aeonz` HRP.
pub fn encode_address(address: &Address) -> String {
    bech32::encode(
        SHIELDED_HRP,
        address.to_raw_address_bytes().to_base32(),
        Variant::Bech32m,
    )
    .expect("hrp and data are always valid")
}

/// Decodes a bech32m `aeonz...` string back into an Orchard address.
pub fn decode_address(s: &str) -> Result<Address, ShieldedAddressError> {
    let (hrp, data, variant) = bech32::decode(s)?;
    if hrp != SHIELDED_HRP {
        return Err(ShieldedAddressError::WrongHrp(hrp));
    }
    if variant != Variant::Bech32m {
        return Err(ShieldedAddressError::WrongVariant);
    }
    let bytes = Vec::<u8>::from_base32(&data)?;
    let bytes: [u8; 43] = bytes
        .try_into()
        .map_err(|_| ShieldedAddressError::WrongLength)?;
    Option::from(Address::from_raw_address_bytes(&bytes))
        .ok_or(ShieldedAddressError::InvalidAddress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_from_the_same_mnemonic() {
        let mnemonic = aeon_crypto::generate_mnemonic();
        let sk1 = derive_spending_key(&mnemonic, "");
        let sk2 = derive_spending_key(&mnemonic, "");
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn different_mnemonics_give_different_spending_keys() {
        let sk1 = derive_spending_key(&aeon_crypto::generate_mnemonic(), "");
        let sk2 = derive_spending_key(&aeon_crypto::generate_mnemonic(), "");
        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn address_roundtrips_through_bech32m() {
        let mnemonic = aeon_crypto::generate_mnemonic();
        let sk = derive_spending_key(&mnemonic, "");
        let address = default_address(&sk);
        let encoded = encode_address(&address);
        assert!(encoded.starts_with("aeonz1"));
        let decoded = decode_address(&encoded).unwrap();
        assert_eq!(
            decoded.to_raw_address_bytes(),
            address.to_raw_address_bytes()
        );
    }

    #[test]
    fn rejects_wrong_hrp() {
        let bad = bech32::encode("aeon", vec![0u8; 43].to_base32(), Variant::Bech32m).unwrap();
        assert!(matches!(
            decode_address(&bad),
            Err(ShieldedAddressError::WrongHrp(_))
        ));
    }
}
