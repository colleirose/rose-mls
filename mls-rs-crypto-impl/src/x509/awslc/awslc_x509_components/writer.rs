// Copyright by contributors to this project.
// SPDX-License-Identifier: MIT

use mls_rs_core::crypto::{CipherSuite, SignatureSecretKey};
use mls_rs_identity_x509::{
    CertificateRequestParameters, DerCertificateRequest, X509RequestWriter,
};

use crate::{ecdsa::AwsLcEcdsa, MlsCryptoError};

use super::{
    component::{KeyUsage, Stack, X509Extension, X509Name},
    request::{self, X509Request},
};

pub struct CertificateRequestWriter {
    signer: AwsLcEcdsa,
    signing_key: SignatureSecretKey,
}

impl CertificateRequestWriter {
    pub fn new(
        cipher_suite: CipherSuite,
        signing_key: SignatureSecretKey,
    ) -> Result<Self, MlsCryptoError> {
        let signer =
            AwsLcEcdsa::new(cipher_suite).ok_or(MlsCryptoError::UnsupportedCipherSuite)?;

        Ok(Self {
            signer,
            signing_key,
        })
    }
}

impl X509RequestWriter for CertificateRequestWriter {
    type Error = MlsCryptoError;

    fn write(
        &self,
        params: CertificateRequestParameters,
    ) -> Result<DerCertificateRequest, Self::Error> {
        let mut request = X509Request::new()?;

        request.set_version(request::X509RequestVersion::V1)?;
        request.set_subject(X509Name::new_components(&params.subject)?)?;

        let mut extensions = Stack::new()?;

        if !params.subject_alt_names.is_empty() {
            extensions.push(X509Extension::subject_alt_name(&params.subject_alt_names)?);
        }

        extensions.push(X509Extension::basic_constraints(true, params.is_ca, None)?);

        if params.is_ca {
            extensions.push(X509Extension::key_usage(
                true,
                &[KeyUsage::KeyCertSign, KeyUsage::CrlSign],
            )?);
        }

        request.add_extensions(extensions)?;

        request
            .sign(&self.signer, &self.signing_key)
            .map(DerCertificateRequest::new)
    }
}
