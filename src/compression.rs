use std::io::Error;
use std::io::Read;
use std::io::Write;

use bzip2::read::BzDecoder;
use deko::write::AnyEncoder;
use deko::write::Compression as DekoCompression;
use deko::Format;
use flate2::read::ZlibDecoder;
use xz::read::XzDecoder;

/// Compression codec that is used to compress files and table of contents.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum Compression {
    /// No compression.
    ///
    /// Write the contents verbatim.
    None,
    /// GZIP compression.
    #[default]
    Gzip,
    /// BZIP2 compression.
    Bzip2,
    /// XZ compression.
    Xz,
}

impl Compression {
    /// Get codec name as written in table of contents.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => OCTET_STREAM_MIME_TYPE,
            Self::Gzip => GZIP_MIME_TYPE,
            Self::Bzip2 => BZIP2_MIME_TYPE,
            Self::Xz => XZ_MIME_TYPE,
        }
    }

    /// Create new encoder for this compression codec.
    pub fn encoder<W: Write>(self, writer: W) -> Result<AnyEncoder<W>, Error> {
        match self {
            Self::None => AnyEncoder::new(writer, Format::Verbatim, DekoCompression::Best),
            Self::Gzip => AnyEncoder::new(writer, Format::Zlib, DekoCompression::Best),
            Self::Bzip2 => AnyEncoder::new(writer, Format::Bz, DekoCompression::Best),
            Self::Xz => AnyEncoder::new(writer, Format::Xz, DekoCompression::Best),
        }
    }

    /// Create new decoder for this compression codec.
    pub fn decoder<R: Read>(self, reader: R) -> XarDecoder<R> {
        match self {
            Self::None => XarDecoder::OctetStream(reader),
            Self::Gzip => XarDecoder::Gzip(ZlibDecoder::new(reader)),
            Self::Bzip2 => XarDecoder::Bzip2(BzDecoder::new(reader)),
            Self::Xz => XarDecoder::Xz(XzDecoder::new(reader)),
        }
    }
}

impl From<&str> for Compression {
    fn from(s: &str) -> Self {
        match s {
            GZIP_MIME_TYPE | ZLIB_MIME_TYPE => Self::Gzip,
            BZIP2_MIME_TYPE => Self::Bzip2,
            XZ_MIME_TYPE => Self::Xz,
            _ => Self::None,
        }
    }
}

/// Decoder for [`Compression`] codec.
pub enum XarDecoder<R: Read> {
    /// No compression.
    OctetStream(R),
    /// GZIP compression.
    Gzip(ZlibDecoder<R>),
    /// BZIP2 compression.
    Bzip2(BzDecoder<R>),
    /// XZ compression.
    Xz(XzDecoder<R>),
}

impl<R: Read> Read for XarDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::OctetStream(r) => r.read(buf),
            Self::Gzip(r) => r.read(buf),
            Self::Bzip2(r) => r.read(buf),
            Self::Xz(r) => r.read(buf),
        }
    }

    // TODO other methods
}

const OCTET_STREAM_MIME_TYPE: &str = "application/octet-stream";
const GZIP_MIME_TYPE: &str = "application/x-gzip";
const BZIP2_MIME_TYPE: &str = "application/x-bzip2";
const ZLIB_MIME_TYPE: &str = "application/zlib";
const XZ_MIME_TYPE: &str = "application/x-xz";
