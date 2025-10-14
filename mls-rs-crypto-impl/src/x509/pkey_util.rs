use std::ptr::null_mut;

use crate::{aws_lc_sys_impl::{
    NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1,
}, check_non_null, ec::{EcPublicKey, EvpPkey}, MlsCryptoError};
use aws_lc_sys::{EC_GROUP_free, EC_GROUP_new_by_curve_name, EC_POINT_free, EC_POINT_new, EC_POINT_oct2point, EVP_PKEY_new_raw_public_key, EVP_PKEY_ED25519};
use mls_rs_core::crypto::SignaturePublicKey;
use mls_rs_crypto_traits::Curve;

pub(crate) fn evp_public_key(
    key: &SignaturePublicKey,
    curve: Curve,
) -> Result<EvpPkey, MlsCryptoError> {
    if curve == Curve::Ed25519 {
        unsafe {
            check_non_null(EVP_PKEY_new_raw_public_key(
                EVP_PKEY_ED25519,
                null_mut(),
                key.as_ptr(),
                key.len(),
            ))
            .map(EvpPkey)
        }
    } else {
        let nid = nid(curve).ok_or(MlsCryptoError::UnsupportedCipherSuite)?;

        unsafe {
            let group = EC_GROUP_new_by_curve_name(nid);

            let point = EC_POINT_new(group);

            if 1 != EC_POINT_oct2point(group, point, key.as_ptr(), key.len(), null_mut()) {
                EC_GROUP_free(group);
                EC_POINT_free(point);
                return Err(MlsCryptoError::CryptoError);
            }

            EC_GROUP_free(group);

            point.into()
        }
    }
}

fn nid(curve: Curve) -> Option<i32> {
    match curve {
        Curve::P256 => Some(NID_X9_62_prime256v1),
        Curve::P384 => Some(NID_secp384r1),
        Curve::P521 => Some(NID_secp521r1),
        _ => None,
    }
}