use std::ffi::CString;
use std::io::Error;
use std::io::Read;
use std::io::Write;

use crate::ChecksumAlgo;

#[derive(Debug)]
#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq))]
pub struct Header {
    pub toc_len_compressed: u64,
    pub toc_len_uncompressed: u64,
    pub checksum_algo: ChecksumAlgo,
}

impl Header {
    pub fn read<R: Read>(mut reader: R) -> Result<Self, Error> {
        let mut header = [0_u8; HEADER_LEN];
        reader.read_exact(&mut header[..])?;
        if header[0..MAGIC.len()] != MAGIC[..] {
            return Err(Error::other("not a xar file"));
        }
        let header_len = u16_read(&header[4..6]) as usize;
        let _version = u16_read(&header[6..8]);
        let toc_len_compressed = u64_read(&header[8..16]);
        let toc_len_uncompressed = u64_read(&header[16..24]);
        let checksum_algo = u32_read(&header[24..28]);
        let checksum_algo_name = if checksum_algo == CHECKSUM_ALGO_OTHER {
            if header_len < HEADER_LEN {
                return Err(Error::other("invalid header length"));
            }
            let remaining = header_len - HEADER_LEN;
            let mut name = vec![0_u8; remaining];
            reader.read_exact(&mut name[..])?;
            // Remove the padding.
            if let Some(n) = name.iter().position(|b| *b == 0) {
                name.truncate(n + 1);
            }
            let name = CString::from_vec_with_nul(name)
                .map_err(|_| Error::other("invalid checksum algo name"))?;
            name.into_string()
                .map_err(|_| Error::other("invalid checksum algo name"))?
        } else {
            if header_len > HEADER_LEN {
                // consume the rest of the header
                let remaining = header_len - HEADER_LEN;
                let mut reader = reader.take(remaining as u64);
                std::io::copy(&mut reader, &mut std::io::empty())?;
            }
            String::new()
        };
        let checksum_algo = (checksum_algo, checksum_algo_name).try_into()?;
        Ok(Self {
            toc_len_compressed,
            toc_len_uncompressed,
            checksum_algo,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        let (checksum_algo, checksum_algo_name): (u32, &str) = self.checksum_algo.into();
        let (header_len, padding) = if checksum_algo != 0 {
            // +1 for NUL byte
            let name_len = checksum_algo_name.len() + 1;
            let rem = name_len % ALIGN;
            let padding = if rem != 0 { ALIGN - rem } else { 0 };
            let header_len = HEADER_LEN + name_len + padding;
            debug_assert!(header_len % 4 == 0);
            (header_len, padding)
        } else {
            (HEADER_LEN, 0)
        };
        writer.write_all(&MAGIC[..])?;
        writer.write_all(&(header_len as u16).to_be_bytes()[..])?;
        writer.write_all(&1_u16.to_be_bytes()[..])?;
        writer.write_all(&self.toc_len_compressed.to_be_bytes()[..])?;
        writer.write_all(&self.toc_len_uncompressed.to_be_bytes()[..])?;
        writer.write_all(&checksum_algo.to_be_bytes()[..])?;
        if checksum_algo == CHECKSUM_ALGO_OTHER {
            debug_assert!(!checksum_algo_name.is_empty());
            writer.write_all(checksum_algo_name.as_bytes())?;
            writer.write_all(&[0_u8])?;
        }
        if padding != 0 {
            writer.write_all(&PADDING[..padding])?;
        }
        Ok(())
    }
}

fn u16_read(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

fn u32_read(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

fn u64_read(data: &[u8]) -> u64 {
    u64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

const HEADER_LEN: usize = 4 + 2 + 2 + 8 + 8 + 4;
const MAGIC: [u8; 4] = *b"xar!";
const ALIGN: usize = 4;
const PADDING: [u8; ALIGN] = [0_u8; ALIGN];
const CHECKSUM_ALGO_OTHER: u32 = 3;
