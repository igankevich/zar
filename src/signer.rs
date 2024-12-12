use std::io::Error;

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn signature_style(&self) -> &str;
    fn signature_len(&self) -> usize;
}

pub trait Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}
