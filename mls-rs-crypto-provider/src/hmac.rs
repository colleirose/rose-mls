// Copyright by contributors to this project.
// SPDX-License-Identifier: MIT

use crate::MlsCryptoError;
use hmac::{Hmac, Mac};
use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_hpke::kem_combiner::ghp::RandomOracle;
use sha2::{Sha256, Sha384, Sha512};

/// Supported HMAC algorithms
#[derive(Clone, Copy, Debug)]
pub enum HmacAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// RustCrypto HMAC wrapper
#[derive(Clone, Copy, Debug)]
pub struct RustCryptoHmac {
    pub algo: HmacAlgorithm,
}

impl RustCryptoHmac {
    /// Construct a new HMAC wrapper for a given cipher suite
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let algo = match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::CURVE25519_CHACHA
            | CipherSuite::P256_AES128 => HmacAlgorithm::Sha256,
            CipherSuite::P384_AES256 => HmacAlgorithm::Sha384,
            CipherSuite::P521_AES256
            | CipherSuite::CURVE448_CHACHA
            | CipherSuite::CURVE448_AES256 => HmacAlgorithm::Sha512,
            _ => return None,
        };
        Some(Self { algo })
    }

    /// Compute HMAC for the selected algorithm
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, MlsCryptoError> {
        match self.algo {
            HmacAlgorithm::Sha256 => {
                let mut h = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| MlsCryptoError::InvalidKeyData)?;
                h.update(data);
                Ok(h.finalize().into_bytes().to_vec())
            }
            HmacAlgorithm::Sha384 => {
                let mut h = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| MlsCryptoError::InvalidKeyData)?;
                h.update(data);
                Ok(h.finalize().into_bytes().to_vec())
            }
            HmacAlgorithm::Sha512 => {
                let mut h = Hmac::<Sha512>::new_from_slice(key)
                    .map_err(|_| MlsCryptoError::InvalidKeyData)?;
                h.update(data);
                Ok(h.finalize().into_bytes().to_vec())
            }
        }
    }
}

impl RandomOracle for RustCryptoHmac {
    type Error = MlsCryptoError;

    fn eval(&self, data: &[u8]) -> Result<Vec<u8>, MlsCryptoError> {
        self.hmac(&[], data)
    }
}
