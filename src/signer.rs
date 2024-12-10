use std::io::Error;

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn signature_style(&self) -> &str;
    fn signature_len(&self) -> usize;
}
