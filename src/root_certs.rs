use std::io::Error;
use std::ops::Deref;
use std::sync::LazyLock;

use x509_cert::der::asn1::BitString;
use x509_cert::der::Decode;
use x509_cert::Certificate;

#[cfg(feature = "apple-root-cert")]
#[allow(clippy::expect_used)]
pub(crate) static APPLE_ROOT_PUBLIC_KEY: LazyLock<BitString> = LazyLock::new(|| {
    let der = include_bytes!("../certs/apple.der");
    let cert = Certificate::from_der(&der[..]).expect("Failed to parse Apple root certificate");
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
});

/// Root certificate verifier.
///
/// This trait is used to verify the self-signed root certificate stored in the archive (trusted or
/// not trusted).
pub trait RootCertVerifier {
    /// Verify `candidate` as trusted or not trusted.
    fn verify(&self, candidate: &Certificate) -> Result<(), Error>;
}

/// Default root certificate verifier implementation.
///
/// Trusts only Apple root certificate when feature `apple-root-cert` is enabled,
/// otherwise trusts none.
#[derive(Default)]
pub struct DefaultRootCertVerifier;

impl RootCertVerifier for DefaultRootCertVerifier {
    fn verify(&self, candidate: &Certificate) -> Result<(), Error> {
        #[cfg(feature = "apple-root-cert")]
        if &candidate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            == APPLE_ROOT_PUBLIC_KEY.deref()
        {
            return Ok(());
        }
        Err(Error::other("root certificate verification error"))
    }
}

/// Root certificate verifier that trusts the supplied list of certificates.
///
/// Only verifies the public keys.
pub struct TrustCerts(Vec<Certificate>);

impl TrustCerts {
    /// Create a new verifier that trusts the supplied certificates.
    pub fn new(certs: Vec<Certificate>) -> Self {
        Self(certs)
    }
}

impl RootCertVerifier for TrustCerts {
    fn verify(&self, candidate: &Certificate) -> Result<(), Error> {
        for cert in self.0.iter() {
            if candidate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                == cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
            {
                return Ok(());
            }
        }
        Err(Error::other("root certificate verification error"))
    }
}
