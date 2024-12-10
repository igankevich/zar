use serde::Deserialize;
use serde::Serialize;

#[derive(
    Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default,
)]
pub enum FileType {
    #[default]
    #[serde(rename = "file")]
    File,
    #[serde(rename = "hardlink")]
    Hardlink,
    #[serde(rename = "directory")]
    Directory,
    #[serde(rename = "symlink")]
    Symlink,
    #[serde(rename = "fifo")]
    Fifo,
    #[serde(rename = "character special")]
    CharacterSpecial,
    #[serde(rename = "block special")]
    BlockSpecial,
    #[serde(rename = "socket")]
    Socket,
    #[serde(rename = "whiteout")]
    Whiteout,
}

impl From<std::fs::FileType> for FileType {
    fn from(other: std::fs::FileType) -> Self {
        use std::os::unix::fs::FileTypeExt;
        if other.is_dir() {
            Self::Directory
        } else if other.is_symlink() {
            Self::Symlink
        } else if other.is_block_device() {
            Self::BlockSpecial
        } else if other.is_char_device() {
            Self::CharacterSpecial
        } else if other.is_fifo() {
            Self::Fifo
        } else if other.is_socket() {
            Self::Socket
        } else if other.is_file() {
            Self::File
        } else {
            Default::default()
        }
    }
}
