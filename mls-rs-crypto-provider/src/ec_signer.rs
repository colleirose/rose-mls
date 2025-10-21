// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::{ffi::c_void, mem::MaybeUninit, ops::Deref};

use aws_lc_rs::{digest, signature};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_sys::{ECDSA_SIG_free, ECDSA_SIG_to_bytes, ECDSA_do_sign, ED25519_sign, OPENSSL_free, ED25519_PRIVATE_KEY_LEN, ED25519_SIGNATURE_LEN};
use mls_rs_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_traits::Curve;
use openssl::hash::MessageDigest;

use thiserror::Error;

use crate::ec::{
    ec_generate, AwsLcPrivateKey, EcError, EcPrivateKey, EcPublicKey
};
use crate::ed448::{ed448_private_key_from_bytes, ed448_pub_key_from_uncompressed};
use crate::MlsCryptoError;

#[derive(Debug, Error)]
pub enum EcSignerError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    EcError(#[from] EcError),
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct EcSigner(pub(crate) Curve);

impl Deref for EcSigner {
    type Target = Curve;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EcSigner {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        Curve::from_ciphersuite(cipher_suite, true).map(Self)
    }

    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), MlsCryptoError> {
        let key_pair = ec_generate(self.0)?;
        Ok((key_pair.0.into(), key_pair.1.into()))
    }

    pub fn signature_key_import_der_public(
        &self,
        der_data: &[u8],
    ) -> Result<SignaturePublicKey, MlsCryptoError> {
        Ok(EcPublicKey::from_bytes(der_data, self.0)
            .map_err(|_| MlsCryptoError::InvalidKeyData)?
            .to_vec()?
            .into())
    }

    pub fn signature_key_import_der_private(
        &self,
        der_data: &[u8],
    ) -> Result<SignatureSecretKey, MlsCryptoError> {
        Ok(EcPrivateKey::from_der(der_data, self.0)
            .map_err(|_| MlsCryptoError::InvalidKeyData)?
            .to_vec()?
            .into())
    }

    pub fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, MlsCryptoError> {
        let bytes = EcPrivateKey::from_bytes(&secret_key, self.0)?.public_key()?.to_vec()?;
        Ok(bytes.into())
    }

    #[cfg(feature = "x509")]
    pub(crate) fn ec_key_from_signature_secret_key(
        &self,
        key: &SignatureSecretKey,
    ) -> Result<EcPrivateKey, MlsCryptoError> {
        EcPrivateKey::from_bytes(key, self.0).map_err(Into::into)
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, MlsCryptoError> {
        match self.0 {
            Curve::P256 => Ok(digest::digest(&digest::SHA256, data).as_ref().to_vec()),
            Curve::P384 => Ok(digest::digest(&digest::SHA384, data).as_ref().to_vec()),
            Curve::P521 => Ok(digest::digest(&digest::SHA512, data).as_ref().to_vec()),
            _ => Err(MlsCryptoError::UnsupportedCipherSuite),
        }
    }

    pub fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, MlsCryptoError> {
        let ec = EcPrivateKey::from_bytes(secret_key, self.0)?;

        if ec.curve == Curve::Ed448 {
            let key = ed448_private_key_from_bytes(data)?;

            let mut signer = match self.message_digest() {
                Some(md) => openssl::sign::Signer::new(md, &key),
                None => openssl::sign::Signer::new_without_digest(&key),
            }?;

            Ok(signer.sign_oneshot_to_vec(data)?)
        } else if self.0 == Curve::Ed25519 {
            (secret_key.len() == ED25519_PRIVATE_KEY_LEN as usize)
                .then_some(())
                .ok_or(MlsCryptoError::InvalidKeyData)?;

            let mut signature = vec![0u8; ED25519_SIGNATURE_LEN as usize];

            // returns one on success or zero on allocation failure
            let res = unsafe {
                ED25519_sign(
                    signature.as_mut_ptr(),
                    data.as_ptr(),
                    data.len(),
                    secret_key.as_ptr(),
                )
            };

            (res == 1).then_some(signature).ok_or(Unspecified.into())
        } else {
            let hash = self.hash(data)?;
            let aws_lc_key = AwsLcPrivateKey::from_bytes(data, self.0)?;

            let signature = unsafe { ECDSA_do_sign(hash.as_ptr(), hash.len(), aws_lc_key.inner) };

            if signature.is_null() {
                return Err(Unspecified.into());
            }

            let mut out_bytes = MaybeUninit::<*mut u8>::uninit();
            let mut out_len = MaybeUninit::<usize>::uninit();

            unsafe {
                if 1 != ECDSA_SIG_to_bytes(out_bytes.as_mut_ptr(), out_len.as_mut_ptr(), signature) {
                    ECDSA_SIG_free(signature);
                    return Err(Unspecified.into());
                }

                ECDSA_SIG_free(signature);

                let ret = core::slice::from_raw_parts(out_bytes.assume_init(), out_len.assume_init())
                    .to_vec();

                OPENSSL_free(out_bytes.assume_init() as *mut c_void);

                Ok(ret)
            }
        }
    }

    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), MlsCryptoError> {
        let ec = EcPublicKey::from_bytes(public_key, self.0)?;

        if ec.curve == Curve::Ed448 {
            let public_key = ed448_pub_key_from_uncompressed(data)?;

            let mut verifier = match self.message_digest() {
                Some(md) => openssl::sign::Verifier::new(md, &public_key),
                None => openssl::sign::Verifier::new_without_digest(&public_key),
            }?;

            verifier
                .verify_oneshot(signature, data)?
                .then_some(())
                .ok_or(MlsCryptoError::InvalidSignature)
        } else {
            let public_key = match self.0 {
                Curve::Ed25519 => UnparsedPublicKey::new(&signature::ED25519, public_key.as_ref()),
                Curve::P256 => {
                    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key.as_ref())
                }
                Curve::P384 => {
                    UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, public_key.as_ref())
                }
                Curve::P521 => {
                    UnparsedPublicKey::new(&signature::ECDSA_P521_SHA512_ASN1, public_key.as_ref())
                }
                _ => return Err(MlsCryptoError::UnsupportedCipherSuite),
            };

            public_key
                .verify(data, signature)
                .map_err(|_| MlsCryptoError::InvalidSignature)
        }
    }

    pub(crate) fn message_digest(&self) -> Option<MessageDigest> {
        match self.0 {
            Curve::P256 => Some(MessageDigest::sha256()),
            Curve::P384 => Some(MessageDigest::sha384()),
            Curve::P521 => Some(MessageDigest::sha512()),
            _ => None,
        }
    }
}
