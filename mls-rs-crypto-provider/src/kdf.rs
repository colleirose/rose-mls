// Copyright by contributors to this project.
// SPDX-License-Identifier: MIT

use hmac::{Hmac, Mac};
use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_traits::{Hash, KdfId, KdfType};
#[cfg(feature = "post-quantum")]
use sha2::Digest;
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

use crate::MlsCryptoError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    #[cfg(feature = "post-quantum")]
    Sha3_256,
    #[cfg(feature = "post-quantum")]
    Sha3_384,
    #[cfg(feature = "post-quantum")]
    Sha3_512,
}

#[derive(Clone, Copy, Debug)]
pub struct RustCryptoHash {
    pub(crate) kind: HashAlgorithm,
}

impl RustCryptoHash {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let kind = match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::CURVE25519_CHACHA
            | CipherSuite::P256_AES128 => HashAlgorithm::Sha256,
            CipherSuite::P384_AES256 => HashAlgorithm::Sha384,
            CipherSuite::CURVE448_CHACHA
            | CipherSuite::CURVE448_AES256
            | CipherSuite::P521_AES256 => HashAlgorithm::Sha512,
            _ => return None,
        };
        Some(Self { kind })
    }

    #[cfg(feature = "post-quantum")]
    pub fn new_sha3(sha3: Sha3) -> Option<Self> {
        let kind = match sha3 {
            Sha3::SHA3_256 => HashAlgorithm::Sha3_256,
            Sha3::SHA3_384 => HashAlgorithm::Sha3_384,
            Sha3::SHA3_512 => HashAlgorithm::Sha3_512,
        };
        Some(Self { kind })
    }
}

#[cfg(feature = "post-quantum")]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Sha3 {
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl Hash for RustCryptoHash {
    type Error = MlsCryptoError;

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let out = match self.kind {
            HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
            #[cfg(feature = "post-quantum")]
            HashAlgorithm::Sha3_256 => Sha3_256::digest(data).to_vec(),
            #[cfg(feature = "post-quantum")]
            HashAlgorithm::Sha3_384 => Sha3_384::digest(data).to_vec(),
            #[cfg(feature = "post-quantum")]
            HashAlgorithm::Sha3_512 => Sha3_512::digest(data).to_vec(),
        };
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RustCryptoHkdf(pub(crate) KdfId);

impl RustCryptoHkdf {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        KdfId::new(cipher_suite).map(Self)
    }

    fn digest_len(&self) -> usize {
        self.0.extract_size()
    }

    fn hash_function(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, MlsCryptoError> {
        match self.0 {
            KdfId::HkdfSha256 => {
                let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
                h.update(data);
                Ok(h.finalize().into_bytes().to_vec())
            }
            KdfId::HkdfSha384 => {
                let mut h = Hmac::<Sha384>::new_from_slice(key).unwrap();
                h.update(data);
                Ok(h.finalize().into_bytes().to_vec())
            }
            KdfId::HkdfSha512 => {
                let mut h = Hmac::<Sha512>::new_from_slice(key).unwrap();
                h.update(data);
                Ok(h.finalize().into_bytes().to_vec())
            }
            _ => Err(MlsCryptoError::InvalidKeyData),
        }
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl KdfType for RustCryptoHkdf {
    type Error = MlsCryptoError;

    fn kdf_id(&self) -> u16 {
        self.0 as u16
    }

    async fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.hash_function(salt, ikm)
    }

    async fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        let hash_len = self.digest_len();
        let n = (len + hash_len - 1) / hash_len;

        let mut okm = Vec::with_capacity(len);
        let mut previous_block = Vec::new();

        for i in 1..=n {
            let mut input = previous_block.clone();
            input.extend_from_slice(info);
            input.push(i as u8);

            previous_block = self.hash_function(prk, &input)?;
            okm.extend_from_slice(&previous_block);
        }

        okm.truncate(len);
        Ok(okm)
    }

    fn extract_size(&self) -> usize {
        self.digest_len()
    }
}

#[cfg(feature = "post-quantum")]
pub mod shake {
    use crate::MlsCryptoError;
    use mls_rs_crypto_traits::VariableLengthHash;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128,
    };

    #[derive(Clone, Copy, Debug)]
    pub struct RustCryptoShake128;

    impl VariableLengthHash for RustCryptoShake128 {
        type Error = MlsCryptoError;

        fn hash(&self, input: &[u8], out_len: usize) -> Result<Vec<u8>, Self::Error> {
            let mut hasher = Shake128::default();
            hasher.update(input);
            let mut reader = hasher.finalize_xof();

            let mut output = vec![0u8; out_len];
            reader.read(&mut output);
            Ok(output)
        }
    }
}
