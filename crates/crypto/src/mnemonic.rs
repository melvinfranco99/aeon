use bip39::Mnemonic;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("mnemonic error: {0}")]
    Bip39(String),
}

/// Generates a new random 12-word BIP39 mnemonic (128 bits of entropy).
pub fn generate_mnemonic() -> Mnemonic {
    Mnemonic::generate(12).expect("12 is a valid BIP39 word count")
}

pub fn parse_mnemonic(phrase: &str) -> Result<Mnemonic, MnemonicError> {
    Mnemonic::parse(phrase).map_err(|e| MnemonicError::Bip39(e.to_string()))
}

/// Derives a 32-byte deterministic seed for Aeon's transparent (secp256k1)
/// key, domain-separated and compressed with BLAKE3 from the raw 64-byte
/// BIP39 seed so it can be fed directly into `KeyPair::from_seed_bytes`.
///
/// A wallet's shielded (Orchard) spending key is derived from the *same*
/// raw 64-byte seed too, via a completely different path (ZIP 32, in
/// `aeon-shielded`) — the domain separation there comes from ZIP 32's own
/// purpose/coin-type constants, not from this function. This is why
/// `aeon-wallet` persists the encrypted 64-byte seed itself (see
/// `seed64_to_key_material`) rather than this function's 32-byte output:
/// the latter can't be reversed back into a seed the shielded side could
/// also use.
pub fn seed_to_key_material(mnemonic: &Mnemonic, passphrase: &str) -> [u8; 32] {
    seed64_to_key_material(&mnemonic.to_seed(passphrase))
}

/// The same derivation as [`seed_to_key_material`], starting from an
/// already-computed raw 64-byte BIP39 seed rather than a [`Mnemonic`] —
/// what a wallet uses after unlocking its keystore (which stores the raw
/// seed, not the mnemonic phrase itself).
pub fn seed64_to_key_material(seed64: &[u8; 64]) -> [u8; 32] {
    let mut data = Vec::with_capacity(64 + 16);
    data.extend_from_slice(b"aeon-wallet-seed-v1");
    data.extend_from_slice(seed64);
    *crate::hash::blake3_hash(&data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_mnemonic_round_trips_through_parsing() {
        let m = generate_mnemonic();
        let parsed = parse_mnemonic(&m.to_string()).unwrap();
        assert_eq!(m.to_seed(""), parsed.to_seed(""));
    }

    #[test]
    fn same_mnemonic_and_passphrase_give_same_key_material() {
        let m = generate_mnemonic();
        let a = seed_to_key_material(&m, "");
        let b = seed_to_key_material(&m, "");
        assert_eq!(a, b);
    }

    #[test]
    fn different_passphrase_gives_different_key_material() {
        let m = generate_mnemonic();
        let a = seed_to_key_material(&m, "");
        let b = seed_to_key_material(&m, "extra-passphrase");
        assert_ne!(a, b);
    }
}
