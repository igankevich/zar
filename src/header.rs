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
        let checksum_algo = u32_read(&header[24..28]).try_into()?;
        if header_len > HEADER_LEN {
            // consume the rest of the header
            let remaining = header_len - HEADER_LEN;
            let mut reader = reader.take(remaining as u64);
            std::io::copy(&mut reader, &mut std::io::empty())?;
        }
        Ok(Self {
            toc_len_compressed,
            toc_len_uncompressed,
            checksum_algo,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        let checksum_algo = self.checksum_algo as u32;
        writer.write_all(&MAGIC[..])?;
        writer.write_all(&(HEADER_LEN as u16).to_be_bytes()[..])?;
        writer.write_all(&1_u16.to_be_bytes()[..])?;
        writer.write_all(&self.toc_len_compressed.to_be_bytes()[..])?;
        writer.write_all(&self.toc_len_uncompressed.to_be_bytes()[..])?;
        writer.write_all(&checksum_algo.to_be_bytes()[..])?;
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
