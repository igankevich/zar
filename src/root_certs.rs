use std::io::Error;

use x509_cert::Certificate;

/// Root certificate verifier.
///
/// This trait is used to verify the self-signed root certificate stored in the archive (trusted or
/// not trusted).
pub trait RootCertVerifier {
    /// Verify `candidate` as trusted or not trusted.
    fn verify(&self, candidate: &Certificate) -> Result<(), Error>;
}

/// A [`RootCertVerifier`] that trusts any certificate.
pub struct TrustAny;

impl RootCertVerifier for TrustAny {
    fn verify(&self, _candidate: &Certificate) -> Result<(), Error> {
        Ok(())
    }
}

/// A [`RootCertVerifier`] that trusts the supplied list of certificates.
///
/// Only compares the public keys.
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
        Err(Error::other("untrusted root certificate"))
    }
}
