use std::io::Error;

use rsa::pkcs1v15::Signature;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs1v15::VerifyingKey;
use rsa::rand_core::OsRng;
use rsa::signature::RandomizedSigner;
use rsa::signature::SignatureEncoding;
use rsa::signature::Verifier as RsaVerifierTrait;
use sha2::Sha256;

use crate::Signer;
use crate::Verifier;

pub type RsaSigner = SigningKey<Sha256>;
pub type RsaVerifier = VerifyingKey<Sha256>;
pub use rsa::signature::Keypair as RsaKeypair;
pub use rsa::RsaPrivateKey;

impl Signer for RsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let signature = self.sign_with_rng(&mut OsRng, data).to_bytes();
        debug_assert!(self.signature_len() == signature.len());
        Ok(signature.to_vec())
    }

    fn signature_style(&self) -> &str {
        "RSA"
    }

    fn signature_len(&self) -> usize {
        256
    }
}

impl Verifier for RsaVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let signature: Signature = signature
            .try_into()
            .map_err(|_| Error::other("invalid signature"))?;
        RsaVerifierTrait::verify(self, data, &signature).map_err(Error::other)
    }
}
