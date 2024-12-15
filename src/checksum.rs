use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::ErrorKind;
use std::str::FromStr;

use base16ct::HexDisplay;
use digest::Digest;
use serde::Deserialize;
use serde::Serialize;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Sha512;

/// A hash that is used to verify archive metadata and file contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[serde(into = "String", try_from = "String")]
pub enum Checksum {
    None,
    Md5([u8; MD5_LEN]),
    Sha1([u8; SHA1_LEN]),
    Sha256([u8; SHA256_LEN]),
    Sha512([u8; SHA512_LEN]),
}

impl Checksum {
    /// Create a new hash from the specified algorithm and its pre-computed binary representation.
    pub fn new(algo: ChecksumAlgo, hash: &[u8]) -> Result<Self, Error> {
        use ChecksumAlgo::*;
        Ok(match algo {
            None => Self::None,
            Md5 => Self::Md5(hash.try_into().map_err(|_| ErrorKind::InvalidData)?),
            Sha1 => Self::Sha1(hash.try_into().map_err(|_| ErrorKind::InvalidData)?),
            Sha256 => Self::Sha256(hash.try_into().map_err(|_| ErrorKind::InvalidData)?),
            Sha512 => Self::Sha512(hash.try_into().map_err(|_| ErrorKind::InvalidData)?),
        })
    }

    /// Hash the data using the specified algorithm.
    pub fn compute(algo: ChecksumAlgo, data: &[u8]) -> Self {
        match algo {
            ChecksumAlgo::None => Self::None,
            ChecksumAlgo::Md5 => Self::Md5(md5::compute(data).into()),
            ChecksumAlgo::Sha1 => Self::Sha1(Sha1::digest(data).into()),
            ChecksumAlgo::Sha256 => Self::Sha256(Sha256::digest(data).into()),
            ChecksumAlgo::Sha512 => Self::Sha512(Sha512::digest(data).into()),
        }
    }

    /// Get hash algorithm.
    pub fn algo(&self) -> ChecksumAlgo {
        match self {
            Self::None => ChecksumAlgo::None,
            Self::Md5(..) => ChecksumAlgo::Md5,
            Self::Sha1(..) => ChecksumAlgo::Sha1,
            Self::Sha256(..) => ChecksumAlgo::Sha256,
            Self::Sha512(..) => ChecksumAlgo::Sha512,
        }
    }
}

impl FromStr for Checksum {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        macro_rules! decode_hex {
            ($string:expr, $len:expr) => {{
                use base16ct::mixed::decode;
                let mut bytes = [0_u8; $len];
                decode($string, &mut bytes[..]).map_err(|_| ErrorKind::InvalidData)?;
                bytes
            }};
        }

        let s = s.trim();
        match s.len() {
            0 => Ok(Self::None),
            MD5_HEX_LEN => Ok(Self::Md5(decode_hex!(s, MD5_LEN))),
            SHA1_HEX_LEN => Ok(Self::Sha1(decode_hex!(s, SHA1_LEN))),
            SHA256_HEX_LEN => Ok(Self::Sha256(decode_hex!(s, SHA256_LEN))),
            SHA512_HEX_LEN => Ok(Self::Sha512(decode_hex!(s, SHA512_LEN))),
            _ => Err(ErrorKind::InvalidData.into()),
        }
    }
}

impl Display for Checksum {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:x}", HexDisplay(self.as_ref()))
    }
}

impl TryFrom<String> for Checksum {
    type Error = Error;
    fn try_from(other: String) -> Result<Self, Self::Error> {
        other.as_str().parse()
    }
}

impl From<Checksum> for String {
    fn from(other: Checksum) -> String {
        use base16ct::lower::encode_string;
        use Checksum::*;
        match other {
            None => String::new(),
            Md5(hash) => encode_string(&hash),
            Sha1(hash) => encode_string(&hash),
            Sha256(hash) => encode_string(&hash),
            Sha512(hash) => encode_string(&hash),
        }
    }
}

impl AsRef<[u8]> for Checksum {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::None => &[],
            Self::Md5(h) => h.as_ref(),
            Self::Sha1(h) => h.as_ref(),
            Self::Sha256(h) => h.as_ref(),
            Self::Sha512(h) => h.as_ref(),
        }
    }
}

/// Hash algorithm of [`Checksum`].
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[serde(rename_all = "lowercase")]
#[repr(u32)]
pub enum ChecksumAlgo {
    None = 0,
    Sha1 = 1,
    Md5 = 2,
    #[default]
    Sha256 = 3,
    Sha512 = 4,
}

impl ChecksumAlgo {
    /// Hash the data.
    pub fn hash(self, data: &[u8]) -> Checksum {
        Checksum::compute(self, data)
    }

    /// Get hash size.
    pub fn hash_len(self) -> usize {
        use ChecksumAlgo::*;
        match self {
            None => 0,
            Md5 => MD5_LEN,
            Sha1 => SHA1_LEN,
            Sha256 => SHA256_LEN,
            Sha512 => SHA512_LEN,
        }
    }
}

impl From<ChecksumAlgo> for u32 {
    fn from(other: ChecksumAlgo) -> u32 {
        other as u32
    }
}

impl TryFrom<u32> for ChecksumAlgo {
    type Error = Error;
    fn try_from(code: u32) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(Self::None),
            1 => Ok(Self::Sha1),
            2 => Ok(Self::Md5),
            3 => Ok(Self::Sha256),
            4 => Ok(Self::Sha512),
            _ => Err(Error::other("unknown hashing algorithm")),
        }
    }
}

const MD5_LEN: usize = 16;
const SHA1_LEN: usize = 20;
const SHA256_LEN: usize = 32;
const SHA512_LEN: usize = 64;

const MD5_HEX_LEN: usize = 2 * MD5_LEN;
const SHA1_HEX_LEN: usize = 2 * SHA1_LEN;
const SHA256_HEX_LEN: usize = 2 * SHA256_LEN;
const SHA512_HEX_LEN: usize = 2 * SHA512_LEN;

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use arbtest::arbtest;

    use super::*;

    #[test]
    fn to_string_parse_symmetry() {
        arbtest(|u| {
            let expected: Checksum = u.arbitrary()?;
            let string = expected.to_string();
            let actual: Checksum = string
                .parse()
                .inspect_err(|_| panic!("failed to parse {:?} as {:?}", string, expected))
                .unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    #[test]
    fn try_from_string_into_string_symmetry() {
        arbtest(|u| {
            let expected: Checksum = u.arbitrary()?;
            let string: String = expected.clone().into();
            let actual: Checksum = string
                .clone()
                .try_into()
                .inspect_err(|_| panic!("failed to parse {:?} as {:?}", string, expected))
                .unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    #[test]
    fn new_as_ref_compatibility() {
        arbtest(|u| {
            let expected: Checksum = u.arbitrary()?;
            let actual = Checksum::new(expected.algo(), expected.as_ref()).unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    #[test]
    fn hash_len_as_ref_len_equality() {
        arbtest(|u| {
            let c: Checksum = u.arbitrary()?;
            assert_eq!(c.algo().hash_len(), c.as_ref().len());
            Ok(())
        });
    }

    #[test]
    fn try_from_u32_into_u32_symmetry() {
        arbtest(|u| {
            let expected: ChecksumAlgo = u.arbitrary()?;
            let number: u32 = expected.into();
            let actual: ChecksumAlgo = number
                .try_into()
                .inspect_err(|_| panic!("failed to parse {:?} as {:?}", number, expected))
                .unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }
}
