// Copyright by contributors to this project.
// SPDX-License-Identifier: MIT

use mls_rs_core::crypto::SignaturePublicKey;
use mls_rs_identity_x509::{
    DerCertificate, SubjectAltName, SubjectComponent, X509CertificateReader,
};

use crate::MlsCryptoError;

use super::certificate::Certificate;

#[derive(Debug, Clone, Copy, Default)]
pub struct CertificateParser;

impl CertificateParser {
    pub fn new() -> Self {
        Default::default()
    }
}

impl X509CertificateReader for CertificateParser {
    type Error = MlsCryptoError;

    #[doc = " Der encoded bytes of a certificate subject field."]
    fn subject_bytes(&self, certificate: &DerCertificate) -> Result<Vec<u8>, Self::Error> {
        let parsed = Certificate::try_from(certificate)?;
        parsed.subject_bytes()
    }

    #[doc = " Parsed certificate subject field components."]
    fn subject_components(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectComponent>, Self::Error> {
        let parsed = Certificate::try_from(certificate)?;
        parsed.subject_components()
    }

    #[doc = " Parsed subject alt name extensions of a certificate."]
    fn subject_alt_names(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectAltName>, Self::Error> {
        let parsed = Certificate::try_from(certificate)?;
        parsed.subject_alt_names()
    }

    #[doc = " Get the subject public key of a certificate."]
    fn public_key(&self, certificate: &DerCertificate) -> Result<SignaturePublicKey, Self::Error> {
        let parsed = Certificate::try_from(certificate)?;
        parsed.public_key()
    }
}
