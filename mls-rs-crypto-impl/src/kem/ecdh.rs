use std::os::raw::c_void;

use crate::{aws_lc_sys_impl::{
    ECDH_compute_key, X25519_keypair, X25519_public_from_private, X25519,
}, ec::{AwsLcPrivateKey, AwsLcPublicKey}};
use aws_lc_rs::error::Unspecified;
use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
use mls_rs_crypto_traits::{Curve, SamplingMethod};

use crate::{
    ec::{ec_generate, private_key_bytes_to_public, EcPrivateKey, EcPublicKey, SUPPORTED_NIST_CURVES},
    MlsCryptoError,
};

#[derive(Clone, Copy)]
pub struct Ecdh {
    curve: Curve,
    sampling_method: SamplingMethod,
}

impl Ecdh {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let curve = Curve::from_ciphersuite(cipher_suite, false)?;

        (SUPPORTED_NIST_CURVES.contains(&curve) || curve == Curve::X25519).then_some(Self {
            curve,
            sampling_method: curve.hpke_sampling_method(),
        })
    }

    pub fn with_sampling_method(self, sampling_method: SamplingMethod) -> Self {
        Self {
            sampling_method,
            ..self
        }
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl mls_rs_crypto_traits::DhType for Ecdh {
    type Error = MlsCryptoError;

    async fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        if self.curve == Curve::X25519 {
            x25519(secret_key, public_key)
        } else {
            ecdh(self.curve, secret_key, public_key)
        }
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let (secret, public) = if self.curve == Curve::X25519 {
            x25519_generate()
        } else {
            ec_generate(self.curve)
        }?;

        Ok((secret.into(), public.into()))
    }

    async fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error> {
        let public = if self.curve == Curve::X25519 {
            x25519_public_key(secret_key)
        } else {
            private_key_bytes_to_public(self.curve, secret_key)
        }?;

        Ok(public.into())
    }

    fn bitmask_for_rejection_sampling(&self) -> SamplingMethod {
        self.sampling_method
    }

    fn secret_key_size(&self) -> usize {
        self.curve.secret_key_size()
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        if self.curve != Curve::X25519 {
            EcPublicKey::from_bytes(key, self.curve)?;
        }

        Ok(())
    }

    fn public_key_size(&self) -> usize {
        self.curve.public_key_size()
    }
}

pub fn ecdh(
    curve: Curve,
    secret_key: &HpkeSecretKey,
    public_key: &HpkePublicKey,
) -> Result<Vec<u8>, MlsCryptoError> {
    let privk = EcPrivateKey::from_bytes(secret_key, curve)?;
    let pubk = EcPublicKey::from_bytes(public_key, curve)?;

    if curve == Curve::Ed448 {
        let der_priv = match &privk.value {
            crate::ec::PrivateKeyValue::OpenSSL(sk) => sk.clone(),
            _ => return Err(MlsCryptoError::CryptoError),
        };
        let der_pub = match &pubk.value {
            crate::ec::PublicKeyValue::OpenSSL(pk) => pk.clone(),
            _ => return Err(MlsCryptoError::CryptoError),
        };

        let mut deriver = openssl::derive::Deriver::new(&der_priv)
            .map_err(|_| MlsCryptoError::CryptoError)?;
        deriver.set_peer(&der_pub).map_err(|_| MlsCryptoError::CryptoError)?;
        let shared = deriver.derive_to_vec().map_err(|_| MlsCryptoError::CryptoError)?;
        Ok(shared)
    } else {
        let mut secret_buf = vec![0u8; curve.secret_key_size()];
        
        let aws_lc_secret_key = AwsLcPrivateKey::from_bytes(secret_key, curve)?;
        let aws_lc_public_key = AwsLcPublicKey::from_bytes(secret_key, curve)?;
        let out_len = unsafe {
            ECDH_compute_key(
                secret_buf.as_mut_ptr() as *mut c_void,
                secret_buf.len(),
                aws_lc_public_key.inner,
                aws_lc_secret_key.inner,
                None,
            )
        };

        if (out_len as usize) != secret_buf.len() {
            return Err(MlsCryptoError::CryptoError);
        }

        Ok(secret_buf)
    }
}

pub fn x25519(
    secret_key: &HpkeSecretKey,
    public_key: &HpkePublicKey,
) -> Result<Vec<u8>, MlsCryptoError> {
    let curve = Curve::X25519;

    (secret_key.len() == curve.secret_key_size() && public_key.len() == curve.public_key_size())
        .then_some(())
        .ok_or(MlsCryptoError::InvalidKeyData)?;

    let mut secret = vec![0u8; curve.secret_key_size()];

    // returns one on success and zero on error
    let res = unsafe {
        X25519(
            secret.as_mut_ptr(),
            secret_key.as_ptr(),
            public_key.as_ptr(),
        )
    };

    (res == 1).then_some(secret).ok_or(Unspecified.into())
}

pub fn x25519_generate() -> Result<(Vec<u8>, Vec<u8>), MlsCryptoError> {
    let curve = Curve::X25519;

    let mut private_key = vec![0u8; curve.secret_key_size()];
    let mut public_key = vec![0u8; curve.public_key_size()];

    unsafe { X25519_keypair(public_key.as_mut_ptr(), private_key.as_mut_ptr()) }

    Ok((private_key, public_key))
}

pub fn x25519_public_key(secret_key: &[u8]) -> Result<Vec<u8>, MlsCryptoError> {
    let mut public_key = vec![0u8; Curve::X25519.public_key_size()];

    unsafe { X25519_public_from_private(public_key.as_mut_ptr(), secret_key.as_ptr()) }

    Ok(public_key)
}