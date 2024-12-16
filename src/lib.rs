#![doc = include_str!("../README.md")]

#[cfg(feature = "apple-root-cert")]
mod apple;
mod archive;
mod builder;
mod checksum;
mod compression;
mod file_mode;
mod file_type;
mod header;
mod mk;
mod root_certs;
mod rsa_signer;
mod signer;
mod walk;
mod xml;

// Re-exports.
pub use rsa;
pub use x509_cert;

#[cfg(feature = "apple-root-cert")]
pub use self::apple::*;
pub use self::archive::*;
pub use self::builder::*;
pub use self::checksum::*;
pub use self::compression::*;
pub use self::file_mode::*;
pub use self::file_type::*;
pub(crate) use self::header::*;
pub(crate) use self::mk::*;
pub use self::root_certs::*;
pub use self::rsa_signer::*;
pub use self::signer::*;
pub(crate) use self::walk::*;
pub use self::xml::Device;
pub use self::xml::Encoding;
pub use self::xml::File;
pub use self::xml::FileChecksum;
pub use self::xml::FileData;
pub use self::xml::Link;
pub use self::xml::Timestamp;
