use std::io::Error;

use digest::Digest;
use serde::Deserialize;
use serde::Serialize;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Sha512;

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
    pub fn new(algo: ChecksumAlgo, data: &[u8]) -> Result<Self, Error> {
        use ChecksumAlgo::*;
        Ok(match algo {
            None => Self::None,
            Md5 => Self::Md5(
                data.try_into()
                    .map_err(|_| Error::other("invalid sha1 length"))?,
            ),
            Sha1 => Self::Sha1(
                data.try_into()
                    .map_err(|_| Error::other("invalid sha1 length"))?,
            ),
            Sha256 => Self::Sha256(
                data.try_into()
                    .map_err(|_| Error::other("invalid sha256 length"))?,
            ),
            Sha512 => Self::Sha512(
                data.try_into()
                    .map_err(|_| Error::other("invalid sha512 length"))?,
            ),
        })
    }

    pub fn new_from_data(algo: ChecksumAlgo, data: &[u8]) -> Self {
        match algo {
            ChecksumAlgo::None => Self::None,
            ChecksumAlgo::Md5 => Self::Md5(md5::compute(data).into()),
            ChecksumAlgo::Sha1 => Self::Sha1(Sha1::digest(data).into()),
            ChecksumAlgo::Sha256 => Self::Sha256(Sha256::digest(data).into()),
            ChecksumAlgo::Sha512 => Self::Sha512(Sha512::digest(data).into()),
        }
    }

    pub fn compute(&self, data: &[u8]) -> Self {
        match self {
            Self::None => Self::None,
            Self::Md5(..) => Self::Md5(md5::compute(data).into()),
            Self::Sha1(..) => Self::Sha1(Sha1::digest(data).into()),
            Self::Sha256(..) => Self::Sha256(Sha256::digest(data).into()),
            Self::Sha512(..) => Self::Sha512(Sha512::digest(data).into()),
        }
    }

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

impl TryFrom<String> for Checksum {
    type Error = Error;
    fn try_from(other: String) -> Result<Self, Self::Error> {
        use base16ct::mixed::decode;
        let other = other.trim();
        match other.len() {
            MD5_HEX_LEN => {
                let mut bytes = [0_u8; MD5_LEN];
                decode(other, &mut bytes[..]).map_err(|_| Error::other("invalid md5 string"))?;
                Ok(Self::Md5(bytes))
            }
            SHA1_HEX_LEN => {
                let mut bytes = [0_u8; SHA1_LEN];
                decode(other, &mut bytes[..]).map_err(|_| Error::other("invalid sha1 string"))?;
                Ok(Self::Sha1(bytes))
            }
            SHA256_HEX_LEN => {
                let mut bytes = [0_u8; SHA256_LEN];
                decode(other, &mut bytes[..]).map_err(|_| Error::other("invalid sha256 string"))?;
                Ok(Self::Sha256(bytes))
            }
            SHA512_HEX_LEN => {
                let mut bytes = [0_u8; SHA512_LEN];
                decode(other, &mut bytes[..]).map_err(|_| Error::other("invalid sha512 string"))?;
                Ok(Self::Sha512(bytes))
            }
            _ => Err(Error::other("invalid hash length")),
        }
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

#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq))]
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
    pub fn size(self) -> usize {
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
