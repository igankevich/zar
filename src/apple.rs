use std::io::Error;
use std::sync::LazyLock;

use x509_cert::der::asn1::BitStringRef;
use x509_cert::der::referenced::OwnedToRef;
use x509_cert::Certificate;

use crate::RootCertVerifier;

#[allow(clippy::expect_used)]
static APPLE_ROOT_PUBLIC_KEY: LazyLock<BitStringRef<'static>> = LazyLock::new(|| {
    let der = include_bytes!(concat!(env!("OUT_DIR"), "/apple-bit-string"));
    BitStringRef::from_bytes(&der[..]).expect("Failed to parse Apple root public key")
});

/// A [`RootCertVerifier`] that trusts only Apple root certificate.
///
/// Only compares the public key.
#[cfg_attr(docsrs, doc(cfg(feature = "apple-root-cert")))]
pub struct AppleRootCertVerifier;

impl RootCertVerifier for AppleRootCertVerifier {
    fn verify(&self, candidate: &Certificate) -> Result<(), Error> {
        if candidate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .owned_to_ref()
            == *APPLE_ROOT_PUBLIC_KEY
        {
            return Ok(());
        }
        Err(Error::other("untrusted root certificate"))
    }
}
