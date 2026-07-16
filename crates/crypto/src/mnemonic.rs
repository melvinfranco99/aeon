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

/// Derives a 32-byte deterministic seed for Aeon's (simplified, single
/// account/address) key derivation: BIP39 seed, domain-separated and
/// compressed to 32 bytes with BLAKE3 so it can be fed directly into
/// `KeyPair::from_seed_bytes`.
pub fn seed_to_key_material(mnemonic: &Mnemonic, passphrase: &str) -> [u8; 32] {
    let seed64 = mnemonic.to_seed(passphrase);
    let mut data = Vec::with_capacity(64 + 16);
    data.extend_from_slice(b"aeon-wallet-seed-v1");
    data.extend_from_slice(&seed64);
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
