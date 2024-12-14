use std::io::Error;

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn signature_style(&self) -> &str;
    fn signature_len(&self) -> usize;
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
}

pub trait Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}

impl<'a, V: Verifier> Verifier for &'a V {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        (*self).verify(data, signature)
    }
}
