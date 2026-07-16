use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand_core::{OsRng, RngCore};
use scrypt::Params;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("scrypt key derivation failed")]
    Kdf,
    #[error("decryption failed: wrong password or corrupted keystore")]
    Decrypt,
}

/// A password-encrypted wallet keystore, persisted to disk as JSON.
/// The wallet's 32-byte seed material is never stored in plaintext.
#[derive(Serialize, Deserialize)]
pub struct Keystore {
    /// scrypt parameters, stored so decryption works even if defaults change.
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    #[serde(with = "hex_bytes")]
    pub salt: [u8; 16],
    #[serde(with = "hex_bytes")]
    pub nonce: [u8; 12],
    pub ciphertext: String,
}

impl Keystore {
    pub fn encrypt(secret: &[u8], password: &str) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let log_n = 15u8; // scrypt N = 2^15 = 32768, r=8, p=1: solid interactive-use parameters
        let r = 8u32;
        let p = 1u32;
        let key_bytes = derive_key(password, &salt, log_n, r, p).expect("valid scrypt params");

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, secret)
            .expect("AES-GCM encryption cannot fail for valid inputs");

        Keystore {
            log_n,
            r,
            p,
            salt,
            nonce: nonce_bytes,
            ciphertext: hex::encode(ciphertext),
        }
    }

    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, KeystoreError> {
        let key_bytes = derive_key(password, &self.salt, self.log_n, self.r, self.p)
            .map_err(|_| KeystoreError::Kdf)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&self.nonce);
        let ciphertext = hex::decode(&self.ciphertext).map_err(|_| KeystoreError::Decrypt)?;
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| KeystoreError::Decrypt)
    }
}

fn derive_key(password: &str, salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<[u8; 32], ()> {
    let params = Params::new(log_n, r, p, 32).map_err(|_| ())?;
    let mut out = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut out).map_err(|_| ())?;
    Ok(out)
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        hex::encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("unexpected byte length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let secret = b"super secret seed material......";
        let ks = Keystore::encrypt(secret, "correct horse battery staple");
        let decrypted = ks.decrypt("correct horse battery staple").unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn wrong_password_fails() {
        let secret = [42u8; 32];
        let ks = Keystore::encrypt(&secret, "hunter2");
        assert!(ks.decrypt("wrong password").is_err());
    }

    #[test]
    fn serializes_to_and_from_json() {
        let secret = [1u8; 32];
        let ks = Keystore::encrypt(&secret, "pw");
        let json = serde_json::to_string(&ks).unwrap();
        let parsed: Keystore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decrypt("pw").unwrap(), secret.to_vec());
    }
}
