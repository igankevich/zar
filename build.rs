#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use std::path::Path;

use x509_cert::der::Decode;
use x509_cert::Certificate;

fn main() {
    let root_dir = std::env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let der = std::fs::read(Path::new(&root_dir).join("certs/apple.der")).unwrap();
    let cert = Certificate::from_der(&der[..]).unwrap();
    let public_key_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap();
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("apple-bit-string");
    std::fs::write(dest_path, public_key_bytes).unwrap();
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=certs/apple.der");
}
