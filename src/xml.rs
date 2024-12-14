use std::collections::VecDeque;
use std::io::BufReader;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use chrono::format::SecondsFormat;
use chrono::DateTime;
use chrono::Utc;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use quick_xml::de::from_reader;
use quick_xml::se::to_writer;
use serde::ser::SerializeStruct;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;

use crate::Checksum;
use crate::ChecksumAlgo;
use crate::FileMode;
use crate::FileStatus;
use crate::Header;
use crate::Signer;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "xar")]
pub struct Xar {
    pub toc: Toc,
}

impl Xar {
    #[cfg(debug_assertions)]
    pub fn read<R: Read>(reader: R) -> Result<Self, Error> {
        let mut reader = ZlibDecoder::new(reader);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        eprintln!("read toc {}", String::from_utf8_lossy(&bytes[..]));
        let reader = BufReader::new(std::io::Cursor::new(bytes));
        from_reader(reader).map_err(Error::other)
    }

    #[cfg(not(debug_assertions))]
    pub fn read<R: Read>(reader: R) -> Result<Self, Error> {
        let reader = ZlibDecoder::new(reader);
        let reader = BufReader::new(reader);
        from_reader(reader).map_err(Error::other)
    }

    pub fn write<W: Write, S: Signer>(
        &self,
        mut writer: W,
        checksum_algo: ChecksumAlgo,
        signer: Option<&S>,
    ) -> Result<(), Error> {
        let mut toc_uncompressed = String::new();
        toc_uncompressed.push_str(XML_DECLARATION);
        to_writer(&mut toc_uncompressed, self).map_err(Error::other)?;
        #[cfg(debug_assertions)]
        eprintln!("write toc {}", toc_uncompressed);
        let toc_len_uncompressed = toc_uncompressed.as_bytes().len();
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(toc_uncompressed.as_bytes())?;
        let toc_compressed = encoder.finish()?;
        let header = Header {
            toc_len_compressed: toc_compressed.len() as u64,
            toc_len_uncompressed: toc_len_uncompressed as u64,
            checksum_algo,
        };
        header.write(writer.by_ref())?;
        writer.write_all(&toc_compressed)?;
        let checksum = Checksum::new_from_data(checksum_algo, &toc_compressed);
        // heap starts
        debug_assert!(checksum.as_ref().len() == checksum_algo.size());
        writer.write_all(checksum.as_ref())?;
        if let Some(signer) = signer {
            let signature = signer
                .sign(checksum.as_ref())
                .map_err(|_| Error::other("failed to sign"))?;
            writer.write_all(&signature)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "toc", rename_all = "kebab-case")]
pub struct Toc {
    pub checksum: TocChecksum,
    #[serde(default)]
    pub creation_time: Timestamp,
    #[serde(rename = "file", default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<File>,
    #[serde(rename = "signature", default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "checksum")]
pub struct TocChecksum {
    #[serde(rename = "@style")]
    pub algo: ChecksumAlgo,
    pub offset: u64,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename = "file")]
pub struct File {
    #[serde(rename = "@id")]
    pub id: u64,
    pub name: PathBuf,
    #[serde(rename = "type", default)]
    pub kind: FileType,
    #[serde(default)]
    pub inode: u64,
    #[serde(default)]
    pub deviceno: u64,
    #[serde(default)]
    pub mode: FileMode,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(default)]
    pub atime: Timestamp,
    #[serde(default)]
    pub mtime: Timestamp,
    #[serde(default)]
    pub ctime: Timestamp,
    #[serde(default)]
    #[serde(rename = "file", skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<File>,
    // TODO files can be nested if type == directory
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Data>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<Link>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<Device>,
}

impl File {
    pub fn new(
        id: u64,
        status: FileStatus,
        data: Option<Data>,
        link: Option<Link>,
        device: Option<Device>,
    ) -> Self {
        Self {
            id,
            name: status.name,
            kind: status.kind.into(),
            inode: status.inode,
            deviceno: status.dev,
            mode: status.mode,
            uid: status.uid,
            gid: status.gid,
            atime: status.atime,
            mtime: status.mtime,
            ctime: status.ctime,
            children: Default::default(),
            data,
            link,
            device,
        }
    }

    pub fn into_vec(self) -> Vec<File> {
        let mut queue = VecDeque::new();
        queue.push_back(self);
        let mut files = Vec::new();
        while let Some(mut file) = queue.pop_front() {
            queue.extend(std::mem::take(&mut file.children));
            files.push(file);
        }
        files
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename = "type", rename_all = "kebab-case")]
pub struct FileType {
    #[serde(rename = "@link", skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(rename = "$value")]
    pub value: String,
}

impl Default for FileType {
    fn default() -> Self {
        Self {
            link: None,
            value: "file".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename = "link", rename_all = "kebab-case")]
pub struct Link {
    #[serde(rename = "@type")]
    pub kind: String,
    #[serde(rename = "$value")]
    pub target: PathBuf,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename = "device", rename_all = "kebab-case")]
pub struct Device {
    #[serde(rename = "major")]
    pub major: u32,
    #[serde(rename = "minor")]
    pub minor: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename = "data", rename_all = "kebab-case")]
pub struct Data {
    // TODO add custom properties here
    // ignore <contents>
    pub archived_checksum: FileChecksum,
    pub extracted_checksum: FileChecksum,
    pub encoding: Encoding,
    pub offset: u64,
    pub size: u64,
    pub length: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename = "encoding")]
pub struct Encoding {
    #[serde(rename = "@style")]
    pub style: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct FileChecksum {
    #[serde(rename = "@style")]
    pub algo: ChecksumAlgo,
    #[serde(rename = "$value")]
    pub value: Checksum,
}

impl From<Checksum> for FileChecksum {
    fn from(other: Checksum) -> Self {
        Self {
            algo: other.algo(),
            value: other,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "signature")]
pub struct Signature {
    #[serde(rename = "@style")]
    pub style: String,
    pub offset: u64,
    pub size: u64,
    #[serde(rename = "KeyInfo")]
    pub key_info: KeyInfo,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "KeyInfo")]
pub struct KeyInfo {
    #[serde(rename = "X509Data")]
    pub data: X509Data,
}

impl Serialize for KeyInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("KeyInfo", 2)?;
        state.serialize_field("@xmlns", "http://www.w3.org/2000/09/xmldsig#")?;
        state.serialize_field("X509Data", &self.data)?;
        state.end()
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "X509Data")]
pub struct X509Data {
    #[serde(
        rename = "X509Certificate",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub certificates: Vec<X509Certificate>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "X509Certificate")]
pub struct X509Certificate {
    #[serde(rename = "$value")]
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct Timestamp(pub SystemTime);

impl From<Timestamp> for String {
    fn from(other: Timestamp) -> String {
        let date_time: DateTime<Utc> = other.0.into();
        date_time.to_rfc3339_opts(SecondsFormat::Secs, true)
    }
}

impl TryFrom<String> for Timestamp {
    type Error = Error;
    fn try_from(other: String) -> Result<Self, Self::Error> {
        let Ok(t) = DateTime::parse_from_rfc3339(&other) else {
            return Ok(Default::default());
        };
        Ok(Self(t.to_utc().into()))
    }
}

impl TryFrom<u64> for Timestamp {
    type Error = Error;
    fn try_from(other: u64) -> Result<Self, Self::Error> {
        let t = UNIX_EPOCH
            .checked_add(Duration::from_secs(other))
            .ok_or_else(|| Error::other("invalid timestamp"))?;
        Ok(Self(t))
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self(UNIX_EPOCH)
    }
}

const XML_DECLARATION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;
