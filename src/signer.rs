use std::io::Error;

use x509_cert::Certificate;

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn signature_style(&self) -> &str;
    fn signature_len(&self) -> usize;
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
