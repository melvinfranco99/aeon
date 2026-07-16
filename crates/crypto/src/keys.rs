use crate::hash::Hash;
use k256::schnorr::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid private key bytes")]
    InvalidPrivateKey,
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
}

/// A Schnorr (BIP340) key pair over the secp256k1 curve.
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generates a new random key pair using the OS CSPRNG.
    pub fn generate() -> Self {
        KeyPair {
            signing_key: SigningKey::random(&mut OsRng),
        }
    }

    /// Deterministically derives a key pair from 32 bytes of seed material
    /// (e.g. produced from a BIP39 mnemonic). The bytes are reduced modulo
    /// the curve order by `SigningKey::from_bytes`.
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let signing_key =
            SigningKey::from_bytes(seed).map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(KeyPair { signing_key })
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(*self.signing_key.verifying_key())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    /// Signs an arbitrary message digest with Schnorr/BIP340.
    pub fn sign(&self, message: &[u8]) -> SchnorrSignature {
        SchnorrSignature(self.signing_key.sign(message))
    }
}

#[derive(Clone, Copy)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let vk = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(PublicKey(vk))
    }

    pub fn verify(&self, message: &[u8], signature: &SchnorrSignature) -> Result<(), CryptoError> {
        self.0
            .verify(message, &signature.0)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// The BLAKE3-based "pubkey hash" used to lock outputs to this key,
    /// analogous to Bitcoin's HASH160(pubkey). Truncated to 20 bytes.
    pub fn pubkey_hash(&self) -> [u8; 20] {
        let full = crate::hash::blake3_hash(&self.to_bytes());
        let mut out = [0u8; 20];
        out.copy_from_slice(&full.as_bytes()[..20]);
        out
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        PublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone)]
pub struct SchnorrSignature(Signature);

impl std::fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl SchnorrSignature {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let sig = Signature::try_from(bytes).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(SchnorrSignature(sig))
    }
}

impl Serialize for SchnorrSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for SchnorrSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        SchnorrSignature::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Hashes a transaction/message payload before signing, so that `sign`
/// always operates over a fixed-size 32-byte digest.
pub fn sighash(data: &[u8]) -> Hash {
    crate::hash::blake3_hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = KeyPair::generate();
        let msg = b"transfer 5 AEON";
        let sig = kp.sign(msg);
        assert!(kp.public_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn verification_fails_for_tampered_message() {
        let kp = KeyPair::generate();
        let sig = kp.sign(b"transfer 5 AEON");
        assert!(kp.public_key().verify(b"transfer 500 AEON", &sig).is_err());
    }

    #[test]
    fn verification_fails_for_wrong_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let sig = kp1.sign(b"transfer 5 AEON");
        assert!(kp2.public_key().verify(b"transfer 5 AEON", &sig).is_err());
    }

    #[test]
    fn deterministic_seed_derivation_is_stable() {
        let seed = [7u8; 32];
        let kp1 = KeyPair::from_seed_bytes(&seed).unwrap();
        let kp2 = KeyPair::from_seed_bytes(&seed).unwrap();
        assert_eq!(kp1.public_key().to_bytes(), kp2.public_key().to_bytes());
    }
}
