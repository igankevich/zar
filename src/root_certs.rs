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

pub trait RootCertVerifier {
    fn verify(&self, candidate: &Certificate) -> Result<(), Error>;
}

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

pub struct TrustCerts(Vec<Certificate>);

impl TrustCerts {
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
