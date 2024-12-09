use std::io::Error;
use std::io::Read;
use std::io::Write;

use bzip2::read::BzDecoder;
use deko::write::AnyEncoder;
use deko::write::Compression as DekoCompression;
use deko::Format;
use flate2::read::ZlibDecoder;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum Compression {
    None,
    #[default]
    Gzip,
    Bzip2,
    // TODO lzfse
}

impl Compression {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => OCTET_STREAM_MIME_TYPE,
            Self::Gzip => GZIP_MIME_TYPE,
            Self::Bzip2 => BZIP2_MIME_TYPE,
        }
    }

    pub fn encoder<W: Write>(self, writer: W) -> Result<AnyEncoder<W>, Error> {
        match self {
            Self::None => AnyEncoder::new(writer, Format::Verbatim, DekoCompression::Best),
            Self::Gzip => AnyEncoder::new(writer, Format::Zlib, DekoCompression::Best),
            Self::Bzip2 => AnyEncoder::new(writer, Format::Bz, DekoCompression::Best),
        }
    }

    pub fn decoder<R: Read>(self, reader: R) -> XarDecoder<R> {
        match self {
            Self::None => XarDecoder::OctetStream(reader),
            Self::Gzip => XarDecoder::Gzip(ZlibDecoder::new(reader)),
            Self::Bzip2 => XarDecoder::Bzip2(BzDecoder::new(reader)),
        }
    }
}

impl From<&str> for Compression {
    fn from(s: &str) -> Self {
        match s {
            GZIP_MIME_TYPE => Self::Gzip,
            BZIP2_MIME_TYPE => Self::Bzip2,
            _ => Self::None,
        }
    }
}

pub enum XarDecoder<R: Read> {
    OctetStream(R),
    Gzip(ZlibDecoder<R>),
    Bzip2(BzDecoder<R>),
}

impl<R: Read> Read for XarDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::OctetStream(r) => r.read(buf),
            Self::Gzip(r) => r.read(buf),
            Self::Bzip2(r) => r.read(buf),
        }
    }
}

const OCTET_STREAM_MIME_TYPE: &str = "application/octet-stream";
const GZIP_MIME_TYPE: &str = "application/x-gzip";
const BZIP2_MIME_TYPE: &str = "application/x-bzip2";
