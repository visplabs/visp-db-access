//! Credential encryption with cluster UUID as authenticated associated data.
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use uuid::Uuid;

/// Authenticated credential encryption and record signing; debug output never
/// includes a key.
#[derive(Clone)]
pub struct Crypto {
    cipher: Aes256Gcm,
    /// A key for signing records, derived from the master key, so a signature
    /// never reveals or reuses the encryption key.
    signing: [u8; 32],
}
impl std::fmt::Debug for Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Crypto([redacted])")
    }
}
/// Invalid key or ciphertext.
#[derive(Debug, thiserror::Error)]
#[error("invalid encryption key or ciphertext")]
pub struct CryptoError;
impl Crypto {
    /// Initialize a cipher from a 256-bit key.
    pub fn new(key: &[u8; 32]) -> Self {
        use sha2::{Digest, Sha256};
        let mut signing = Sha256::new();
        signing.update(b"visp-db-access record signing key v1\0");
        signing.update(key);
        Self {
            cipher: Aes256Gcm::new(key.into()),
            signing: signing.finalize().into(),
        }
    }
    /// An HMAC-SHA256 signature of `message`, in lower-case hex. Anyone with
    /// write access to the metadata store but not the master key cannot make
    /// a signature that verifies.
    pub fn sign(&self, message: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        let mut mac = match <Hmac<sha2::Sha256> as Mac>::new_from_slice(&self.signing) {
            Ok(mac) => mac,
            // A 32-byte key is always accepted.
            Err(_) => return String::new(),
        };
        mac.update(message);
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    /// Whether `signature` is this key's signature of `message`, compared in
    /// constant time.
    pub fn verify(&self, message: &[u8], signature: &str) -> bool {
        use subtle::ConstantTimeEq;
        let expected = self.sign(message);
        !expected.is_empty() && bool::from(expected.as_bytes().ct_eq(signature.as_bytes()))
    }
    /// Decode the required standard-base64 master key.
    pub fn from_base64(key: &str) -> Result<Self, CryptoError> {
        let bytes = STANDARD.decode(key).map_err(|_| CryptoError)?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| CryptoError)?;
        Ok(Self::new(&key))
    }
    /// Encrypt with a fresh 96-bit nonce and the cluster identity.
    pub fn encrypt(&self, cluster: Uuid, secret: &str) -> Result<String, CryptoError> {
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret.as_bytes(),
                    aad: cluster.as_bytes(),
                },
            )
            .map_err(|_| CryptoError)?;
        let mut bytes = nonce.to_vec();
        bytes.extend(ciphertext);
        Ok(format!("v1:{}", STANDARD.encode(bytes)))
    }
    /// Decrypt and authenticate a versioned ciphertext.
    pub fn decrypt(&self, cluster: Uuid, encoded: &str) -> Result<String, CryptoError> {
        let bytes = STANDARD
            .decode(encoded.strip_prefix("v1:").ok_or(CryptoError)?)
            .map_err(|_| CryptoError)?;
        let nonce = bytes.get(..12).ok_or(CryptoError)?;
        let data = bytes.get(12..).ok_or(CryptoError)?;
        let clear = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: data,
                    aad: cluster.as_bytes(),
                },
            )
            .map_err(|_| CryptoError)?;
        String::from_utf8(clear).map_err(|_| CryptoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_only_with_the_same_key_and_message() {
        let crypto = Crypto::new(&[3; 32]);
        let signature = crypto.sign(b"receipt");
        assert_eq!(signature.len(), 64);
        assert!(crypto.verify(b"receipt", &signature));
        assert!(!crypto.verify(b"receipt.", &signature));
        assert!(!Crypto::new(&[4; 32]).verify(b"receipt", &signature));
        assert!(!crypto.verify(b"receipt", ""));
    }
}
