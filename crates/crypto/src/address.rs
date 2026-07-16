use crate::keys::PublicKey;
use bech32::{FromBase32, ToBase32, Variant};
use thiserror::Error;

/// Human-readable part for all Aeon addresses, e.g. `aeon:qpz...`.
pub const HRP: &str = "aeon";

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("bech32 decoding error: {0}")]
    Bech32(#[from] bech32::Error),
    #[error("wrong human-readable part: expected '{expected}', got '{actual}'")]
    WrongHrp { expected: String, actual: String },
    #[error("wrong bech32 variant, addresses must use bech32m")]
    WrongVariant,
    #[error("decoded payload has wrong length: expected 20 bytes, got {0}")]
    WrongLength(usize),
}

/// An Aeon address: a bech32m encoding of a 20-byte BLAKE3 public-key hash,
/// analogous in spirit to Kaspa's `kaspa:` bech32 addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address(String);

impl Address {
    pub fn from_pubkey(pubkey: &PublicKey) -> Self {
        Self::from_pubkey_hash(&pubkey.pubkey_hash())
    }

    pub fn from_pubkey_hash(hash: &[u8; 20]) -> Self {
        let encoded = bech32::encode(HRP, hash.to_base32(), Variant::Bech32m)
            .expect("hrp and data are always valid");
        Address(encoded)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes a bech32m address string back into its 20-byte pubkey hash.
    pub fn decode(s: &str) -> Result<[u8; 20], AddressError> {
        let (hrp, data, variant) = bech32::decode(s)?;
        if hrp != HRP {
            return Err(AddressError::WrongHrp {
                expected: HRP.to_string(),
                actual: hrp,
            });
        }
        if variant != Variant::Bech32m {
            return Err(AddressError::WrongVariant);
        }
        let bytes = Vec::<u8>::from_base32(&data)?;
        if bytes.len() != 20 {
            return Err(AddressError::WrongLength(bytes.len()));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn address_roundtrip() {
        let kp = KeyPair::generate();
        let addr = Address::from_pubkey(&kp.public_key());
        assert!(addr.as_str().starts_with("aeon1"));
        let decoded = Address::decode(addr.as_str()).unwrap();
        assert_eq!(decoded, kp.public_key().pubkey_hash());
    }

    #[test]
    fn rejects_wrong_hrp() {
        let bad = bech32::encode("btc", vec![].to_base32(), Variant::Bech32m).unwrap();
        assert!(matches!(
            Address::decode(&bad),
            Err(AddressError::WrongHrp { .. })
        ));
    }
}
