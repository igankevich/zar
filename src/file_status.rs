use std::path::PathBuf;

use crate::xml;
use crate::FileMode;
use crate::FileType;

#[derive(Default)]
pub struct FileStatus {
    pub name: PathBuf,
    pub kind: FileType,
    pub inode: u64,
    pub deviceno: u64,
    pub mode: FileMode,
    pub uid: u32,
    pub gid: u32,
    pub atime: xml::Timestamp,
    pub mtime: xml::Timestamp,
    pub ctime: xml::Timestamp,
}

impl From<std::fs::Metadata> for FileStatus {
    fn from(other: std::fs::Metadata) -> Self {
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
