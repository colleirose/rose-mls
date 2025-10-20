// Copyright by contributors to this project.
// SPDX-License-Identifier: MIT

use std::{ffi::c_void, mem::MaybeUninit, ops::Deref};

use aws_lc_rs::{
 digest, error::Unspecified, signature::{self, UnparsedPublicKey, ED25519_PUBLIC_KEY_LEN}
};
use aws_lc_sys::EVP_PKEY_ED448;
use openssl::sign::Signer;

use crate::aws_lc_sys_impl::{
    ECDSA_SIG_free, ECDSA_SIG_to_bytes, ECDSA_do_sign, ED25519_keypair, ED25519_sign,
    EVP_PKEY_new_raw_private_key, OPENSSL_free,
    ED25519_PRIVATE_KEY_LEN, ED25519_SIGNATURE_LEN, EVP_PKEY_ED25519,
};
use mls_rs_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_traits::Curve;

use crate::ec::{EcPrivateKey, EcPublicKey, EvpPkey, ec_generate, private_key_bytes_to_public, AwsLcPrivateKey, PrivateKeyValue, PublicKeyValue, SUPPORTED_NIST_CURVES};

use crate::{
    check_non_null,
    MlsCryptoError,
};

#[derive(Clone)]
pub struct AwsLcEcdsa(pub(crate) Curve);

impl Deref for AwsLcEcdsa {
    type Target = Curve;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AwsLcEcdsa {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let curve = Curve::from_ciphersuite(cipher_suite, true)?;
        (SUPPORTED_NIST_CURVES.contains(&curve) || curve == Curve::Ed25519).then_some(Self(curve))
    }

    pub fn import_ec_der_private_key(
        &self,
        bytes: &[u8],
    ) -> Result<SignatureSecretKey, MlsCryptoError> {
        Ok(EcPrivateKey::from_der(bytes, self.0)
            .map_err(|_| MlsCryptoError::InvalidKeyData)?
            .to_vec()?
            .into())
    }

    pub fn import_ec_der_public_key(
        &self,
        bytes: &[u8],
    ) -> Result<SignaturePublicKey, MlsCryptoError> {
        Ok(EcPublicKey::from_bytes(bytes, self.0)
            .map_err(|_| MlsCryptoError::InvalidKeyData)?
            .to_vec()?
            .into())
    }

    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), MlsCryptoError> {
        let (secret, public) = if self.0 == Curve::Ed25519 {
            ed25519_generate()
        } else {
            ec_generate(self.0)
        }?;

        Ok((secret.into(), public.into()))
    }

    pub(crate) fn evp_public_key(
        &self,
        key: &SignaturePublicKey,
    ) -> Result<PublicKeyValue, MlsCryptoError> {
        match self.0 {
            Curve::Ed448 => {
                // TODO: set proper ED448 length checks later
                let pkey = openssl::pkey::PKey::public_key_from_raw_bytes(
                    key.as_ref(),
                    openssl::pkey::Id::ED448
                ).map_err(|_| MlsCryptoError::InvalidKeyData)?;
                Ok(PublicKeyValue::OpenSSL(pkey))
            }
            _ => {
                let ec_key = EcPublicKey::from_bytes(key, self.0)?;
                Ok(ec_key.value)
            }
        }
    }


    pub(crate) fn evp_private_key(
        &self,
        key: &SignatureSecretKey,
    ) -> Result<EvpPkey, MlsCryptoError> {
        match self.0 {
            Curve::Ed25519 => {
                if key.len() != ED25519_PUBLIC_KEY_LEN * 2 {
                    return Err(MlsCryptoError::InvalidKeyData);
                }

                unsafe {
                    check_non_null(EVP_PKEY_new_raw_private_key(
                        EVP_PKEY_ED25519,
                        std::ptr::null_mut(),
                        key.as_ptr(),
                        key.len() / 2,
                    ))
                    .map(EvpPkey)
                }
            }

            Curve::Ed448 => {
                // TODO: set proper ED448 length checks later

                // if key.len() != ED448_PRIVATE_KEY_LEN {
                //     return Err(MlsCryptoError::InvalidKeyData);
                // }

                unsafe {
                    check_non_null(EVP_PKEY_new_raw_private_key(
                        EVP_PKEY_ED448,
                        std::ptr::null_mut(),
                        key.as_ptr(),
                        key.len(),
                    ))
                    .map(EvpPkey)
                }
            }

            _ => {
                let ec_key = EcPrivateKey::from_bytes(key, self.0)?;
                match ec_key.value {
                    PrivateKeyValue::AwsLC(inner) => {
                        inner.try_into().map_err(|_| MlsCryptoError::CryptoError)
                    }
                    PrivateKeyValue::OpenSSL(_) => {
                        // OpenSSL keys should only be used for Ed448
                        // TODO: This might not be needed
                        Err(MlsCryptoError::InvalidKeyData)
                    }
                }
            }
        }
    }


    pub fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, MlsCryptoError> {
        let public = if self.0 == Curve::Ed25519 {
            ed25519_public_key(secret_key)
        } else {
            private_key_bytes_to_public(self.0, secret_key)
        }?;

        Ok(public.into())
    }

    pub fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, MlsCryptoError> {
        if self.0 == Curve::Ed25519 {
            ed25519_sign(secret_key, data)
        } else {
            self.ecdsa_sign(secret_key, data)
        }
    }

    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), MlsCryptoError> {
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

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, MlsCryptoError> {
        match self.0 {
            Curve::P256 => Ok(digest::digest(&digest::SHA256, data).as_ref().to_vec()),
            Curve::P384 => Ok(digest::digest(&digest::SHA384, data).as_ref().to_vec()),
            Curve::P521 => Ok(digest::digest(&digest::SHA512, data).as_ref().to_vec()),
            _ => Err(MlsCryptoError::UnsupportedCipherSuite),
        }
    }

    fn ecdsa_sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, MlsCryptoError> {
        
        let hash = self.hash(data)?;

        let key = EcPrivateKey::from_bytes(secret_key, self.0)?;
        let curve = key.curve;

        match curve {
            Curve::Ed448 => {
                if let PrivateKeyValue::OpenSSL(ref sk) = key.value {
                    let mut signer = Signer::new_without_digest(sk)
                        .map_err(|_| MlsCryptoError::CryptoError)?;

                    signer.update(data).map_err(|_| MlsCryptoError::CryptoError)?;
                    let signature = signer.sign_to_vec().map_err(|_| MlsCryptoError::CryptoError)?;

                    Ok(signature)
                } else {
                    Err(MlsCryptoError::CryptoError) // this shouldn't happen
                }
            }
            _ => {
                let aws_lc_key = AwsLcPrivateKey::from_bytes(secret_key, curve)?;
                let signature = unsafe { ECDSA_do_sign(hash.as_ptr(), hash.len(), aws_lc_key.inner) };

                if signature.is_null() {
                    return Err(MlsCryptoError::CryptoError);
                }

                let mut out_bytes = MaybeUninit::<*mut u8>::uninit();
                let mut out_len = MaybeUninit::<usize>::uninit();

                unsafe {
                    if 1 != ECDSA_SIG_to_bytes(out_bytes.as_mut_ptr(), out_len.as_mut_ptr(), signature) {
                        ECDSA_SIG_free(signature);
                        return Err(MlsCryptoError::CryptoError);
                    }

                    ECDSA_SIG_free(signature);

                    let ret = core::slice::from_raw_parts(out_bytes.assume_init(), out_len.assume_init())
                        .to_vec();

                    OPENSSL_free(out_bytes.assume_init() as *mut c_void);

                    Ok(ret)
                }
            }
        }


    }
}

fn ed25519_sign(secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, MlsCryptoError> {
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
}

fn ed25519_generate() -> Result<(Vec<u8>, Vec<u8>), MlsCryptoError> {
    let mut private_key = vec![0u8; ED25519_PRIVATE_KEY_LEN as usize];
    let mut public_key = vec![0u8; ED25519_PUBLIC_KEY_LEN];

    unsafe { ED25519_keypair(public_key.as_mut_ptr(), private_key.as_mut_ptr()) }

    Ok((private_key, public_key))
}

fn ed25519_public_key(secret_key: &SignatureSecretKey) -> Result<Vec<u8>, MlsCryptoError> {
    (secret_key.len() == 2 * ED25519_PUBLIC_KEY_LEN)
        .then_some(secret_key[ED25519_PUBLIC_KEY_LEN..].to_vec())
        .ok_or(MlsCryptoError::InvalidKeyData)
}