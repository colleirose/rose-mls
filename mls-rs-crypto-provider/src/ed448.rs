// Copyright by contributors to this project.
// SPDX-License-Identifier: MIT

use mls_rs_crypto_traits::Curve;

use openssl::{
    bn::BigNumContext,
    ec::{EcKey, PointConversionForm},
    error::ErrorStack,
    pkey::{Id, PKey},
};

use crate::ec::{curve_to_id, EcError, Ed448PrivateKey, Ed448PublicKey};

pub fn generate_ed448_key() -> Result<Ed448PrivateKey, EcError> {
    Ok(PKey::generate_x448()?)
}

pub fn ed448_private_key_from_der(data: &[u8]) -> Result<Ed448PrivateKey, ErrorStack> {
    PKey::private_key_from_der(data)
}

pub fn ed448_public_key_from_der(data: &[u8]) -> Result<Ed448PublicKey, ErrorStack> {
    PKey::public_key_from_der(data)
}

fn openssl_pub_key_from_uncompressed_non_nist(bytes: &[u8], id: Id) -> Result<Ed448PublicKey, ErrorStack> {
    PKey::public_key_from_raw_bytes(bytes, id)
}

pub fn ed448_pub_key_from_uncompressed(bytes: &[u8]) -> Result<Ed448PublicKey, EcError> {
    let id = curve_to_id(Curve::Ed448)?;
    Ok(PKey::public_key_from_raw_bytes(bytes, id)?)
}

pub fn ed448_pub_key_to_uncompressed(key: &Ed448PublicKey) -> Result<Vec<u8>, ErrorStack> {
    if let Ok(ec_key) = key.ec_key() {
        let mut ctx = BigNumContext::new()?;

        ec_key
            .public_key()
            .to_bytes(ec_key.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
    } else {
        key.raw_public_key()
    }
}

pub fn ed448_private_key_from_bytes(
    bytes: &[u8],
) -> Result<Ed448PrivateKey, EcError> {
    let openssl_secret_len = Curve::Ed448.secret_key_size() / 2;

    (openssl_secret_len <= bytes.len())
        .then_some(())
        .ok_or(EcError::InvalidKeyBytes)?;

    let bytes = &bytes[..openssl_secret_len];
    let id = curve_to_id(Curve::Ed448)?;

    Ok(PKey::private_key_from_raw_bytes(bytes, id)?)
}

pub fn ed448_private_key_to_bytes(private_key: &Ed448PrivateKey) -> Result<Vec<u8>, EcError> {
    if private_key.id() != Id::X448 {
        return Err(EcError::InvalidKeyBytes)
    }

    if let Ok(ec_key) = private_key.ec_key() {
        Ok(ec_key.private_key().to_vec())
    } else {
        Ok(private_key.raw_private_key()?)
    }
}

pub fn ed448_private_key_to_public(private_key: &Ed448PrivateKey) -> Result<Ed448PublicKey, EcError> {
    if private_key.id() != Id::X448 {
        return Err(EcError::InvalidKeyBytes)
    }

    if let Ok(ec_key) = private_key.ec_key() {
        let pub_key = EcKey::from_public_key(ec_key.group(), ec_key.public_key())?;
        Ok(PKey::from_ec_key(pub_key)?)
    } else {
        let key_data = private_key.raw_public_key()?;
        Ok(openssl_pub_key_from_uncompressed_non_nist(&key_data, Id::X448)?)
    }
}