//! The private keys of an installation (AXT `spec/keys.md`, sections 2.1 and 4.2).
//!
//! The app keeps the private keys; it hands the library the 32-byte seeds of its Ed25519
//! signing key and of its X25519 encryption key, and the library never writes them to the
//! store. A seed is held in memory that is zeroed when it is dropped, and it has neither
//! `Debug` nor `Display`, so that it does not end up in a log.

use zeroize::Zeroizing;

/// The 32-byte seed of an Ed25519 signing key (RFC 8032, section 5.1.5), the private key
/// whose public key is the `sender` of every message the installation sends.
pub struct SigningSeed(Zeroizing<[u8; 32]>);

impl SigningSeed {
    /// The signing key of the seed `seed`.
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }

    /// The seed's bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SigningSeed {
    fn from(seed: [u8; 32]) -> Self {
        Self::new(seed)
    }
}

/// The 32-byte private key of an X25519 encryption key (RFC 7748), with which the
/// installation opens the messages sealed for it through a relay.
pub struct EncryptionSeed(Zeroizing<[u8; 32]>);

impl EncryptionSeed {
    /// The encryption key of the private key `seed`.
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }

    /// The private key's bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for EncryptionSeed {
    fn from(seed: [u8; 32]) -> Self {
        Self::new(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_keeps_its_bytes() {
        let seed = SigningSeed::from([7; 32]);
        assert_eq!(seed.as_bytes(), &[7; 32]);
        let seed = EncryptionSeed::new([9; 32]);
        assert_eq!(seed.as_bytes(), &[9; 32]);
    }
}
