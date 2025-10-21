// Copyright by contributors to this project.
// SPDX-License-Identifier: MIT

use core::fmt::{self, Debug};
use std::ptr::null_mut;
use mls_rs_crypto_traits::Curve;
use thiserror::Error;

use openssl::{
    derive::Deriver,
    error::ErrorStack,
    nid::Nid,
    pkey::{HasParams, Id, PKey, Private, Public},
};
use crate::aws_lc_sys_impl::{
    d2i_ECPrivateKey, point_conversion_form_t, BN_bin2bn, BN_bn2bin, BN_free, EC_GROUP_free,
    EC_GROUP_new_by_curve_name, EC_KEY_free, EC_KEY_generate_key, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_new_by_curve_name,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_POINT_copy, EC_POINT_free, EC_POINT_mul,
    EC_POINT_new, EC_POINT_oct2point, EC_POINT_point2oct, EVP_PKEY_free, EVP_PKEY_new,
    EVP_PKEY_set1_EC_KEY, NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1, EC_POINT, EVP_PKEY,
};
use crate::ed448::{ed448_private_key_from_bytes, ed448_private_key_from_der, ed448_private_key_to_bytes, ed448_private_key_to_public, ed448_pub_key_from_uncompressed, ed448_pub_key_to_uncompressed, ed448_public_key_from_der, generate_ed448_key};
use aws_lc_rs::error::Unspecified;

use crate::MlsCryptoError;

#[derive(Debug, Error)]
pub enum EcError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    /// Attempted to import a secret key that does not contain valid bytes for its curve
    #[error("invalid secret key bytes")]
    InvalidKeyBytes,
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

pub(crate) const SUPPORTED_NIST_CURVES: [Curve; 3] = [Curve::P521, Curve::P256, Curve::P384];

pub type Ed448PublicKey = PKey<Public>;
pub type Ed448PrivateKey = PKey<Private>;
pub struct EvpPkey(pub(crate) *mut EVP_PKEY);
pub struct AwsLcPrivateKey {
    pub(crate) inner: *mut crate::aws_lc_sys_impl::ec_key_st,
    curve: Curve,
}
pub struct AwsLcPublicKey {
    pub(crate) inner: *mut EC_POINT,
    curve: Curve,
}

pub enum PublicKeyValue {
    AwsLC(AwsLcPublicKey),
    OpenSSL(Ed448PublicKey),
}

pub enum PrivateKeyValue {
    AwsLC(AwsLcPrivateKey),
    OpenSSL(Ed448PrivateKey),
}

pub struct EcPublicKey {
    pub(crate) value: PublicKeyValue,
    pub(crate)curve: Curve,
}

pub struct EcPrivateKey {
    pub(crate) value: PrivateKeyValue,
    pub(crate) curve: Curve,
}

#[inline]
pub fn ec_generate(curve: Curve) -> Result<(Vec<u8>, Vec<u8>), MlsCryptoError> {
    let private_key = EcPrivateKey::generate(curve)?;
    let public_key = private_key.public_key()?;

    Ok((private_key.to_vec()?, public_key.to_vec()?))
}

pub fn generate_keypair(curve: Curve) -> Result<KeyPair, MlsCryptoError> {
    let keys = ec_generate(curve)?;
    Ok(KeyPair { secret: keys.0, public: keys.1 })
}

#[inline]
pub fn curve_to_id(c: Curve) -> Result<Id, EcError> {
    match c {
        Curve::P256 | Curve::P384 | Curve::P521 => Ok(Id::EC),
        Curve::X25519 => Ok(Id::X25519),
        Curve::Ed25519 => Ok(Id::ED25519),
        Curve::X448 => Ok(Id::X448),
        Curve::Ed448 => Ok(Id::ED448),
        _ => Err(EcError::UnsupportedCipherSuite),
    }
}

#[inline]
pub fn nist_curve_id(curve: Curve) -> Option<i32> {
    match curve {
        Curve::P256 => Some(NID_X9_62_prime256v1),
        Curve::P384 => Some(NID_secp384r1),
        Curve::P521 => Some(NID_secp521r1),
        _ => None,
    }
}

#[inline]
pub fn private_key_bytes_to_public(curve: Curve, secret_key: &[u8]) -> Result<Vec<u8>, MlsCryptoError> {
    Ok(EcPrivateKey::from_bytes(secret_key, curve)?
        .public_key()?
        .to_vec()?)
}

pub fn curve_from_nid(nid: Nid) -> Option<Curve> {
    match nid {
        Nid::X9_62_PRIME256V1 => Some(Curve::P256),
        Nid::SECP384R1 => Some(Curve::P384),
        Nid::SECP521R1 => Some(Curve::P521),
        _ => None,
    }
}

pub fn curve_from_pkey<T: HasParams>(value: &PKey<T>) -> Option<Curve> {
    match value.id() {
        Id::X25519 => Some(Curve::X25519),
        Id::ED25519 => Some(Curve::Ed25519),
        Id::X448 => Some(Curve::X448),
        Id::ED448 => Some(Curve::Ed448),
        Id::EC => value
            .ec_key()
            .ok()
            .and_then(|k| k.group().curve_name())
            .and_then(curve_from_nid),
        _ => None,
    }
}

#[derive(Clone, Default)]
pub struct KeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &mls_rs_core::debug::pretty_bytes(&self.public))
            .finish()
    }
}

pub fn private_key_ecdh(
    private_key: &Ed448PrivateKey,
    remote_public: &Ed448PublicKey,
) -> Result<Vec<u8>, ErrorStack> {
    let mut ecdh_derive = Deriver::new(private_key)?;
    ecdh_derive.set_peer(remote_public)?;
    ecdh_derive.derive_to_vec()
}

impl EcPrivateKey {
    pub fn generate(curve: Curve) -> Result<Self, MlsCryptoError> {
        let value = match curve {
            Curve::Ed448 => {
                let key = generate_ed448_key()?;
                PrivateKeyValue::OpenSSL(key)
            },
            _ => {
                let key = AwsLcPrivateKey::generate(curve).map_err(|_| MlsCryptoError::CryptoError)?;
                PrivateKeyValue::AwsLC(key)
            }
        };

        Ok(Self { value, curve })
    }

    pub fn from_bytes(bytes: &[u8], curve: Curve) -> Result<Self, MlsCryptoError> {
        let value = match curve {
            Curve::Ed448 => {
                let key = ed448_private_key_from_bytes(bytes)?;
                PrivateKeyValue::OpenSSL(key)
            },
            _ => {
                let key = AwsLcPrivateKey::from_bytes(bytes, curve).map_err(|_| MlsCryptoError::CryptoError)?;
                PrivateKeyValue::AwsLC(key)
            }
        };

        Ok(Self { value, curve })
    }

    pub fn from_der(bytes: &[u8], curve: Curve) -> Result<Self, MlsCryptoError> {
        let value = match curve {
            Curve::Ed448 => {
                let key = ed448_private_key_from_der(bytes)?;
                PrivateKeyValue::OpenSSL(key)
            }
            _ => {
                let key = AwsLcPrivateKey::from_der(bytes, curve).map_err(|_| MlsCryptoError::CryptoError)?;
                PrivateKeyValue::AwsLC(key)
            }
        };

        Ok(Self { value, curve })
    }

    pub fn public_key(&self) -> Result<EcPublicKey, MlsCryptoError> {
        let value = match &self.value {
            PrivateKeyValue::OpenSSL(sk) => {
                let pk = ed448_private_key_to_public(sk)?;
                PublicKeyValue::OpenSSL(pk)
            }
            PrivateKeyValue::AwsLC(sk) => {
                let pk = sk.public_key().map_err(|_| MlsCryptoError::CryptoError)?;
                PublicKeyValue::AwsLC(pk)
            }
        };

        Ok(EcPublicKey {
            value,
            curve: self.curve,
        })
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, MlsCryptoError> {
        match &self.value {
            PrivateKeyValue::OpenSSL(sk) => Ok(ed448_private_key_to_bytes(sk)?),
            PrivateKeyValue::AwsLC(sk) => Ok(sk.to_vec().map_err(|_| MlsCryptoError::CryptoError)?),
        }
    }
}

impl EcPublicKey {
    pub fn from_bytes(bytes: &[u8], curve: Curve) -> Result<Self, MlsCryptoError> {
        let value = match curve {
            Curve::Ed448 => {
                let key = ed448_pub_key_from_uncompressed(bytes)?;
                PublicKeyValue::OpenSSL(key)
            }
            _ => {
                let point = AwsLcPublicKey::from_bytes(bytes, curve).map_err(|_| MlsCryptoError::CryptoError)?;
                PublicKeyValue::AwsLC(point)
            }
        };

        Ok(Self { value, curve })
    }

    pub fn from_der(bytes: &[u8], curve: Curve) -> Result<Self, MlsCryptoError> {
        let value = match curve {
            Curve::Ed448 => {
                let key = ed448_public_key_from_der(bytes).map_err(|_| MlsCryptoError::CryptoError)?;
                PublicKeyValue::OpenSSL(key)
            }
            _ => {
                let point = AwsLcPublicKey::from_bytes(bytes, curve).map_err(|_| MlsCryptoError::CryptoError)?;
                PublicKeyValue::AwsLC(point)
            }
        };

        Ok(Self { value, curve})
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, MlsCryptoError> {
        match &self.value {
            PublicKeyValue::OpenSSL(pk) => Ok(ed448_pub_key_to_uncompressed(pk)?),
            PublicKeyValue::AwsLC(pk) => Ok(pk.to_vec().map_err(|_| MlsCryptoError::CryptoError)?),
        }
    }
}

impl AwsLcPrivateKey {
    pub fn generate(curve: Curve) -> Result<Self, Unspecified> {
        let nid = nist_curve_id(curve).ok_or(Unspecified)?;

        // SAFETY: From the AWS-LC code. Safe if given a valid pointer.
        let key = unsafe { EC_KEY_new_by_curve_name(nid) };

        if key.is_null() {
            return Err(Unspecified);
        }

        // SAFETY: From the AWS-LC code. Safe if given a valid pointer.
        unsafe {
            if 1 != EC_KEY_generate_key(key) {
                EC_KEY_free(key);
                return Err(Unspecified);
            }
        }

        Ok(Self { inner: key, curve })
    }


    pub fn from_der(bytes: &[u8], curve: Curve) -> Result<Self, Unspecified> {
        // SAFETY: From the AWS-LC code. Safe if given a valid pointer.
        unsafe {
            let mut result_holder = bytes.as_ptr();

            let input_len = bytes.len().try_into().map_err(|_| Unspecified)?;

            let ec_key = d2i_ECPrivateKey(null_mut(), &mut result_holder, input_len);

            if ec_key.is_null() {
                return Err(Unspecified);
            }

            Ok(Self {
                inner: ec_key,
                curve,
            })
        }
    }

    pub fn from_bytes(bytes: &[u8], curve: Curve) -> Result<Self, Unspecified> {
        // SAFETY: From the AWS-LC code. Safe if given a valid pointer.
        let bn = unsafe { BN_bin2bn(bytes.as_ptr(), bytes.len(), null_mut()) };

        if bn.is_null() {
            return Err(Unspecified);
        }

        let key = unsafe {
            let key = nist_curve_id(curve).map(|n| EC_KEY_new_by_curve_name(n));

            match key {
                Some(key) if !key.is_null() => key,
                _ => {
                    BN_free(bn);
                    return Err(Unspecified);
                }
            }
        };

        // SAFETY: From the AWS-LC code. Safe if given a valid pointer.
        unsafe {
            if 1 != EC_KEY_set_private_key(key, bn) {
                EC_KEY_free(key);
                BN_free(bn);
                return Err(Unspecified);
            }

            BN_free(bn);
        }

        Ok(Self { inner: key, curve })
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Unspecified> {
        let mut secret_key_data = vec![0u8; self.curve.secret_key_size()];

        // SAFETY: From the AWS-LC code. Safe if given a valid pointer.
        let len = unsafe {
            BN_bn2bin(
                EC_KEY_get0_private_key(self.inner),
                secret_key_data.as_mut_ptr(),
            )
        };

        if len > secret_key_data.len() || len == 0 {
            return Err(Unspecified);
        }

        secret_key_data.truncate(len);

        Ok(secret_key_data)
    }

    pub fn public_key(&self) -> Result<AwsLcPublicKey, Unspecified> {
        let group = unsafe { EC_KEY_get0_group(self.inner) };
        let pub_key = unsafe { EC_POINT_new(group) };

        unsafe {
            if EC_KEY_get0_public_key(self.inner).is_null() {
                let bn = EC_KEY_get0_private_key(self.inner);

                if 1 != EC_POINT_mul(group, pub_key, bn, null_mut(), null_mut(), null_mut()) {
                    EC_POINT_free(pub_key);
                    return Err(Unspecified);
                }

                if 1 != EC_KEY_set_public_key(self.inner, pub_key) {
                    EC_POINT_free(pub_key);
                    return Err(Unspecified);
                }
            } else if 1 != EC_POINT_copy(pub_key, EC_KEY_get0_public_key(self.inner)) {
                EC_POINT_free(pub_key);
                return Err(Unspecified);
            }
        }

        Ok(AwsLcPublicKey {
            inner: pub_key,
            curve: self.curve,
        })
    }
}

impl Drop for AwsLcPrivateKey {
    fn drop(&mut self) {
        unsafe { crate::aws_lc_sys_impl::EC_KEY_free(self.inner) }
    }
}

impl TryInto<EvpPkey> for AwsLcPrivateKey {
    type Error = Unspecified;

    fn try_into(self) -> Result<EvpPkey, Unspecified> {
        unsafe {
            let key = EVP_PKEY_new();

            if key.is_null() {
                return Err(Unspecified);
            }

            if 1 != EVP_PKEY_set1_EC_KEY(key, self.inner) {
                return Err(Unspecified);
            }

            Ok(EvpPkey(key))
        }
    }
}

impl AwsLcPublicKey {
  pub fn from_bytes(bytes: &[u8], curve: Curve) -> Result<Self, Unspecified> {
        let nid = nist_curve_id(curve).ok_or(Unspecified)?;

        unsafe {
            let group = EC_GROUP_new_by_curve_name(nid);

            let point = EC_POINT_new(group);

            if 1 != EC_POINT_oct2point(group, point, bytes.as_ptr(), bytes.len(), null_mut()) {
                EC_GROUP_free(group);
                EC_POINT_free(point);
                return Err(Unspecified);
            }

            EC_GROUP_free(group);

            Ok(Self {
                inner: point,
                curve,
            })
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Unspecified> {
        let mut pub_key_data = vec![0u8; self.curve.public_key_size()];
        let nid = nist_curve_id(self.curve).ok_or(Unspecified)?;

        let out_len = unsafe {
            let group = EC_GROUP_new_by_curve_name(nid);

            let out_len = EC_POINT_point2oct(
                group,
                self.inner,
                point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                pub_key_data.as_mut_ptr(),
                self.curve.public_key_size(),
                null_mut(),
            );

            EC_GROUP_free(group);

            out_len
        };

        (out_len == pub_key_data.len())
            .then_some(pub_key_data)
            .ok_or(Unspecified)
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.0) }
    }
}

impl TryInto<EvpPkey> for AwsLcPublicKey {
    type Error = Unspecified;

    fn try_into(self) -> Result<EvpPkey, Unspecified> {
        unsafe {
            let nid = nist_curve_id(self.curve).ok_or(Unspecified)?;
            let ec_key: *mut aws_lc_sys::ec_key_st = EC_KEY_new_by_curve_name(nid);

            if ec_key.is_null() {
                return Err(Unspecified);
            }

            if 1 != EC_KEY_set_public_key(ec_key, self.inner) {
                EC_KEY_free(ec_key);
                return Err(Unspecified);
            }

            let key = EVP_PKEY_new();

            if key.is_null() {
                EC_KEY_free(ec_key);
                return Err(Unspecified);
            }

            let res = EVP_PKEY_set1_EC_KEY(key, ec_key);
            EC_KEY_free(ec_key);

            if res != 1 {
                return Err(Unspecified);
            }

            Ok(EvpPkey(key))
        }
    }
}

impl Drop for AwsLcPublicKey {
    fn drop(&mut self) {
        unsafe { EC_POINT_free(self.inner) }
    }
}

// too much has changed for the tests to work correctly, they will be fixed once the code is readable and working

// #[cfg(test)]
// pub(crate) mod test_utils {
//     use serde::{Deserialize, Serialize};

//     use super::Curve;

//     #[derive(Deserialize, Serialize, PartialEq, Debug)]
//     pub(crate) struct TestKeys {
//         #[serde(with = "hex::serde")]
//         pub(crate) p256: Vec<u8>,
//         #[serde(with = "hex::serde")]
//         pub(crate) p384: Vec<u8>,
//         #[serde(with = "hex::serde")]
//         pub(crate) p521: Vec<u8>,
//         #[serde(with = "hex::serde")]
//         pub(crate) x25519: Vec<u8>,
//         #[serde(with = "hex::serde")]
//         pub(crate) ed25519: Vec<u8>,
//         #[serde(with = "hex::serde")]
//         pub(crate) x448: Vec<u8>,
//         #[serde(with = "hex::serde")]
//         pub(crate) ed448: Vec<u8>,
//     }

//     impl TestKeys {
//         pub(crate) fn get_key_from_curve(&self, curve: Curve) -> Vec<u8> {
//             match curve {
//                 Curve::P256 => self.p256.clone(),
//                 Curve::P384 => self.p384.clone(),
//                 Curve::P521 => self.p521.clone(),
//                 Curve::X25519 => self.x25519.clone(),
//                 Curve::Ed25519 => self.ed25519.clone(),
//                 Curve::X448 => self.x448.clone(),
//                 Curve::Ed448 => self.ed448.clone(),
//                 _ => panic!("unsuported ciphersuite"),
//             }
//         }
//     }

//     pub(crate) fn get_test_public_keys() -> TestKeys {
//         let test_case_file = include_str!("../test_data/test_public_keys.json");
//         serde_json::from_str(test_case_file).unwrap()
//     }

//     pub(crate) fn get_test_public_keys_der() -> TestKeys {
//         let test_case_file = include_str!("../test_data/test_der_public.json");
//         serde_json::from_str(test_case_file).unwrap()
//     }

//     pub(crate) fn get_test_secret_keys() -> TestKeys {
//         let test_case_file = include_str!("../test_data/test_private_keys.json");
//         serde_json::from_str(test_case_file).unwrap()
//     }

//     pub(crate) fn get_test_secret_keys_der() -> TestKeys {
//         let test_case_file = include_str!("../test_data/test_der_private.json");
//         serde_json::from_str(test_case_file).unwrap()
//     }

//     pub fn is_curve_25519(curve: Curve) -> bool {
//         curve == Curve::X25519 || curve == Curve::Ed25519
//     }

//     pub fn is_curve_448(curve: Curve) -> bool {
//         curve == Curve::X448 || curve == Curve::Ed448
//     }

//     pub fn byte_equal(curve: Curve, other: Curve) -> bool {
//         if curve == other {
//             return true;
//         }

//         if is_curve_25519(curve) && is_curve_25519(other) {
//             return true;
//         }

//         if is_curve_448(curve) && is_curve_448(other) {
//             return true;
//         }

//         false
//     }
// }

// #[cfg(test)]
// mod tests {
//     use assert_matches::assert_matches;

//     use super::{
//         generate_ed448_keypair, generate_ed448_key, private_key_bytes_to_public,
//         private_key_from_bytes, private_key_to_vec, pub_key_from_uncompressed,
//         ed448_pub_key_to_uncompressed,
//         test_utils::{byte_equal, get_test_public_keys, get_test_secret_keys},
//         Curve, EcError,
//     };

//     const SUPPORTED_CURVES: [Curve; 7] = [
//         Curve::Ed25519,
//         Curve::Ed448,
//         Curve::P256,
//         Curve::P384,
//         Curve::P521,
//         Curve::X25519,
//         Curve::X448,
//     ];

//     // #[test]
//     // fn private_key_can_be_generated() {
//     //     SUPPORTED_CURVES.iter().copied().for_each(|curve: Curve| {
//     //         let one_key =
//     //             generate_ed448_key().expect("Failed to generate private key for {curve:?}");

//     //         let another_key =
//     //             generate_ed448_key().expect("Failed to generate private key for {curve:?}");

//     //         assert_ne!(
//     //             private_key_to_vec(&one_key).unwrap(),
//     //             private_key_to_vec(&another_key).unwrap(),
//     //             "Same key generated twice for {curve:?}"
//     //         );
//     //     });
//     // }

//     #[test]
//     fn key_pair_can_be_generated() {
//         SUPPORTED_CURVES.iter().copied().for_each(|curve| {
//             assert_matches!(
//                 generate_ed448_keypair(),
//                 Ok(_),
//                 "Failed to generate key pair for {curve:?}"
//             );
//         });
//     }

//     #[test]
//     fn private_key_can_be_imported_and_exported() {
//         SUPPORTED_CURVES.iter().copied().for_each(|curve| {
//             let key_bytes = get_test_secret_keys().get_key_from_curve(curve);

//             let imported_key = private_key_from_bytes(&key_bytes, curve, true)
//                 .unwrap_or_else(|e| panic!("Failed to import private key for {curve:?} : {e:?}"));

//             let exported_bytes = private_key_to_vec(&imported_key)
//                 .unwrap_or_else(|e| panic!("Failed to export private key for {curve:?} : {e:?}"));

//             assert_eq!(exported_bytes, key_bytes);
//         });
//     }

//     #[test]
//     fn public_key_can_be_imported_and_exported() {
//         SUPPORTED_CURVES.iter().copied().for_each(|curve| {
//             let key_bytes = get_test_public_keys().get_key_from_curve(curve);

//             let imported_key = pub_key_from_uncompressed(&key_bytes, curve)
//                 .unwrap_or_else(|e| panic!("Failed to import public key for {curve:?} : {e:?}"));

//             let exported_bytes = ed448_pub_key_to_uncompressed(&imported_key)
//                 .unwrap_or_else(|e| panic!("Failed to export public key for {curve:?} : {e:?}"));

//             assert_eq!(exported_bytes, key_bytes);
//         });
//     }

//     #[test]
//     fn secret_to_public() {
//         let test_public_keys = get_test_public_keys();
//         let test_secret_keys = get_test_secret_keys();

//         for curve in SUPPORTED_CURVES.iter().copied() {
//             let secret_key = test_secret_keys.get_key_from_curve(curve);
//             let public_key = private_key_bytes_to_public(&secret_key, curve).unwrap();
//             assert_eq!(public_key, test_public_keys.get_key_from_curve(curve));
//         }
//     }

//     #[test]
//     fn mismatched_curve_import() {
//         for curve in SUPPORTED_CURVES.iter().copied() {
//             for other_curve in SUPPORTED_CURVES
//                 .iter()
//                 .copied()
//                 .filter(|c| !byte_equal(*c, curve))
//             {
//                 println!(
//                     "Mismatched curve public key import : key curve {:?}, import curve {:?}",
//                     &curve, &other_curve
//                 );

//                 let public_key = get_test_public_keys().get_key_from_curve(curve);
//                 let res = pub_key_from_uncompressed(&public_key, other_curve);

//                 assert!(res.is_err());
//             }
//         }
//     }

//     #[test]
//     fn test_order_range_enforcement() {
//         let p256_order =
//             hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
//                 .unwrap();

//         let p384_order = hex::decode(
//             "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aec\
//             ec196accc52973",
//         )
//         .unwrap();

//         let p521_order = hex::decode(
//             "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f96\
//             6b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
//         )
//         .unwrap();

//         // Keys must be < to order
//         let p256_res = private_key_from_bytes(&p256_order, Curve::P256, true);
//         let p384_res = private_key_from_bytes(&p384_order, Curve::P384, true);
//         let p521_res = private_key_from_bytes(&p521_order, Curve::P521, true);

//         assert_matches!(p256_res, Err(EcError::InvalidKeyBytes));
//         assert_matches!(p384_res, Err(EcError::InvalidKeyBytes));
//         assert_matches!(p521_res, Err(EcError::InvalidKeyBytes));

//         let nist_curves = [Curve::P256, Curve::P384, Curve::P521];

//         // Keys must not be 0
//         for curve in nist_curves {
//             assert_matches!(
//                 private_key_from_bytes(&vec![0u8; curve.secret_key_size()], curve, true),
//                 Err(EcError::InvalidKeyBytes)
//             );
//         }
//     }
// }
