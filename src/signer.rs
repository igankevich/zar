use std::io::Error;

use x509_cert::Certificate;

/// Archive signer.
pub trait Signer {
    /// Sign the data returning the signature.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Get signature algorithm, e.g. "RSA".
    fn signature_style(&self) -> &str;

    /// Get signature length.
    fn signature_len(&self) -> usize;

    /// Get certificate chain to include in the archive.
    fn certs(&self) -> &[Certificate];
}

impl<'a, S: Signer> Signer for &'a S {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        (*self).sign(data)
    }

    fn signature_style(&self) -> &str {
        (*self).signature_style()
    }

    fn signature_len(&self) -> usize {
        (*self).signature_len()
    }

    fn certs(&self) -> &[Certificate] {
        (*self).certs()
    }
}
