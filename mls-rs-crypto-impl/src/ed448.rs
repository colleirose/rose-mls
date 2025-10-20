// Copyright by contributors to this project.
// SPDX-License-Identifier: MIT

use mls_rs_crypto_traits::Curve;

use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    error::ErrorStack,
    nid::Nid,
    pkey::{Id, PKey},
};

use crate::ec::{curve_to_id, nist_curve_id, EcError, Ed448PrivateKey, Ed448PublicKey};

pub fn generate_ed448_key() -> Result<Ed448PrivateKey, EcError> {
    Ok(PKey::generate_x448()?)
}

// pub fn generate_ed448_keypair() -> Result<KeyPair, EcError> {
//     let secret = generate_ed448_key()?;
//     let public = ed448_private_key_to_public(&secret)?;
//     let secret = ed448_private_key_to_bytes(&secret)?;
//     let public = ed448_pub_key_to_uncompressed(&public)?;
//     Ok(KeyPair { public, secret })
// }

pub fn ed448_private_key_from_der(data: &[u8]) -> Result<Ed448PrivateKey, ErrorStack> {
    PKey::private_key_from_der(data)
}

pub fn ed448_public_key_from_der(data: &[u8]) -> Result<Ed448PublicKey, ErrorStack> {
    PKey::public_key_from_der(data)
}

// #[derive(Clone, Default)]
// pub struct KeyPair {
//     pub public: Vec<u8>,
//     pub secret: Vec<u8>,
// }

// impl Debug for KeyPair {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         f.debug_struct("KeyPair")
//             .field("public", &mls_rs_core::debug::pretty_bytes(&self.public))
//             .finish()
//     }
// }

fn openssl_pub_key_from_uncompressed_nist(bytes: &[u8], nid: Nid) -> Result<Ed448PublicKey, ErrorStack> {
    let group = EcGroup::from_curve_name(nid)?;
    let mut ctx = BigNumContext::new_secure()?;
    let point = EcPoint::from_bytes(&group, bytes, &mut ctx)?;
    let key = EcKey::from_public_key(&group, &point)?;

    PKey::from_ec_key(key)
}

fn openssl_pub_key_from_uncompressed_non_nist(bytes: &[u8], id: Id) -> Result<Ed448PublicKey, ErrorStack> {
    PKey::public_key_from_raw_bytes(bytes, id)
}

pub fn ed448_pub_key_from_uncompressed(bytes: &[u8]) -> Result<Ed448PublicKey, EcError> {
    let pubkey = if let Some(nist_id) = nist_curve_id(Curve::Ed448) {
        openssl_pub_key_from_uncompressed_nist(bytes, Nid::from_raw(nist_id))
    } else {
        openssl_pub_key_from_uncompressed_non_nist(bytes, curve_to_id(Curve::Ed448)?)
    }?;

    Ok(pubkey)
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

fn private_key_from_bytes_nist(
    bytes: &[u8],
    nid: Nid,
    with_public: bool,
) -> Result<Ed448PrivateKey, EcError> {
    // Get the order and verify that the bytes are in range
    let mut ctx = BigNumContext::new_secure()?;

    let group = EcGroup::from_curve_name(nid)?;
    let mut order = BigNum::new_secure()?;
    order.set_const_time();
    group.order(&mut order, &mut ctx)?;

    // Create a BigNum from our sk_val
    let mut sk_val = BigNum::from_slice(bytes)?;
    sk_val.set_const_time();

    (sk_val < order && sk_val > BigNum::new()?)
        .then_some(())
        .ok_or(EcError::InvalidKeyBytes)?;

    let mut pk_val = EcPoint::new(&group)?;

    if with_public {
        pk_val.mul_generator(&group, &sk_val, &ctx)?;
    }

    let key = EcKey::from_private_components(&group, &sk_val, &pk_val)?;

    sk_val.clear();

    Ok(PKey::from_ec_key(key)?)
}

fn private_key_from_bytes_non_nist(bytes: &[u8]) -> Result<Ed448PrivateKey, EcError> {
    let curve = Curve::Ed448;
    let id = curve_to_id(curve)?;

    // TODO investigate if it is possible to provide an already known public key to OpenSSL,
    // to avoid recomputing it
    let openssl_secret_len = match curve {
        Curve::Ed25519 | Curve::Ed448 => curve.secret_key_size() / 2,
        _ => curve.secret_key_size(),
    };

    (openssl_secret_len <= bytes.len())
        .then_some(())
        .ok_or(EcError::InvalidKeyBytes)?;

    let bytes = &bytes[..openssl_secret_len];

    Ok(PKey::private_key_from_raw_bytes(bytes, id)?)
}

pub fn ed448_private_key_from_bytes(
    bytes: &[u8],
    with_public: bool,
) -> Result<Ed448PrivateKey, EcError> {
    if let Some(nist_id) = nist_curve_id(Curve::Ed448) {
        private_key_from_bytes_nist(bytes, Nid::from_raw(nist_id), with_public)
    } else {
        Ok(private_key_from_bytes_non_nist(bytes)?)
    }
}

pub fn ed448_private_key_to_bytes(key: &Ed448PrivateKey) -> Result<Vec<u8>, ErrorStack> {
    key.raw_private_key()
    // if let Ok(ec_key) = key.ec_key() {
    //     Ok(ec_key.private_key().to_vec())
    // } else if [Some(Curve::X25519), Some(Curve::X448)].contains(&ed448_curve_from_private_key(key)) {
    //     key.raw_private_key()
    // } else {
    //     Ok([key.raw_private_key()?, key.raw_public_key()?].concat())
    // }
}

pub fn ed448_private_key_bytes_to_public(secret_key: &[u8]) -> Result<Vec<u8>, EcError> {
    let secret_key = ed448_private_key_from_bytes(secret_key, true)?;
    let public_key = ed448_private_key_to_public(&secret_key)?;
    Ok(ed448_pub_key_to_uncompressed(&public_key)?)
}

pub fn ed448_private_key_to_public(private_key: &Ed448PrivateKey) -> Result<Ed448PublicKey, ErrorStack> {
    if let Ok(ec_key) = private_key.ec_key() {
        let pub_key = EcKey::from_public_key(ec_key.group(), ec_key.public_key())?;
        PKey::from_ec_key(pub_key)
    } else {
        let key_data = private_key.raw_public_key()?;
        openssl_pub_key_from_uncompressed_non_nist(&key_data, private_key.id())
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