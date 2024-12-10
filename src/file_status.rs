use std::fs::Metadata;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::FileMode;
use crate::FileType;
use crate::xml;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct FileStatus {
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
    pub atime: xml::Timestamp,
    #[serde(default)]
    pub mtime: xml::Timestamp,
    #[serde(default)]
    pub ctime: xml::Timestamp,
}

impl From<Metadata> for FileStatus {
    fn from(other: Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            kind: other.file_type().into(),
            inode: other.ino(),
            deviceno: other.rdev(),
            mode: other.mode().into(),
            uid: other.uid(),
            gid: other.gid(),
            atime: (other.atime() as u64).try_into().unwrap_or_default(),
            mtime: (other.mtime() as u64).try_into().unwrap_or_default(),
            ctime: (other.ctime() as u64).try_into().unwrap_or_default(),
            ..Default::default()
        }
    }
}
