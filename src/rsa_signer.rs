use std::io::Error;
use std::io::ErrorKind;

use rsa::pkcs1v15::Signature as RsaSignature;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs1v15::VerifyingKey;
use rsa::rand_core::OsRng;
use rsa::signature::RandomizedSigner;
use rsa::signature::SignatureEncoding;
use rsa::signature::Verifier as RsaVerifierTrait;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use sha1::Sha1;
use sha2::Sha256;
use x509_cert::Certificate;

use crate::ChecksumAlgo;
use crate::Signer;

#[derive(Debug)]
pub struct RsaSigner {
    signing_key: SigningKeyInner,
    certs: Vec<Certificate>,
}

impl RsaSigner {
    pub fn new(
        algo: ChecksumAlgo,
        private_key: RsaPrivateKey,
        certs: Vec<Certificate>,
    ) -> Result<Self, Error> {
        use SigningKeyInner::*;
        let signing_key = match algo {
            ChecksumAlgo::Sha1 => Sha1(SigningKey::new(private_key)),
            ChecksumAlgo::Sha256 => Sha256(SigningKey::new(private_key)),
            _ => return Err(ErrorKind::InvalidData.into()),
        };
        Ok(Self { signing_key, certs })
    }

    pub fn with_sha1(signing_key: SigningKey<Sha1>, certs: Vec<Certificate>) -> Self {
        use SigningKeyInner::*;
        let signing_key = Sha1(signing_key);
        Self { signing_key, certs }
    }
}

impl Signer for RsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        use SigningKeyInner::*;
        let signature = match self.signing_key {
            Sha1(ref s) => s.sign_with_rng(&mut OsRng, data).to_bytes(),
            Sha256(ref s) => s.sign_with_rng(&mut OsRng, data).to_bytes(),
        };
        debug_assert!(self.signature_len() == signature.len());
        Ok(signature.to_vec())
    }

    fn signature_style(&self) -> &str {
        "RSA"
    }

    fn signature_len(&self) -> usize {
        256
    }

    fn certs(&self) -> &[Certificate] {
        &self.certs
    }
}

pub struct RsaVerifier {
    inner: RsaVerifierInner,
}

impl RsaVerifier {
    pub fn new(algo: ChecksumAlgo, public_key: RsaPublicKey) -> Result<Self, Error> {
        use RsaVerifierInner::*;
        let inner = match algo {
            ChecksumAlgo::Sha1 => Sha1(VerifyingKey::new(public_key)),
            ChecksumAlgo::Sha256 => Sha256(VerifyingKey::new(public_key)),
            _ => return Err(ErrorKind::InvalidData.into()),
        };
        Ok(Self { inner })
    }

    pub fn verify(&self, data: &[u8], signature: &RsaSignature) -> Result<(), Error> {
        use RsaVerifierInner::*;
        match self.inner {
            Sha1(ref v) => RsaVerifierTrait::verify(v, data, signature),
            Sha256(ref v) => RsaVerifierTrait::verify(v, data, signature),
        }
        .map_err(|_| Error::other("signature verification error"))
    }

    pub fn into_inner(self) -> RsaPublicKey {
        use RsaVerifierInner::*;
        match self.inner {
            Sha1(v) => v.into(),
            Sha256(v) => v.into(),
        }
    }
}

enum RsaVerifierInner {
    Sha1(VerifyingKey<Sha1>),
    Sha256(VerifyingKey<Sha256>),
}

#[derive(Debug)]
enum SigningKeyInner {
    Sha1(SigningKey<Sha1>),
    Sha256(SigningKey<Sha256>),
}
