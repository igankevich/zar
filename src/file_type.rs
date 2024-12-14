use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::str::FromStr;

use crate::xml;

// TODO custom serialize/deserialize
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum FileType {
    #[default]
    File,
    Hardlink(Hardlink),
    Directory,
    Symlink,
    Fifo,
    CharacterSpecial,
    BlockSpecial,
    Socket,
    Whiteout,
}

impl FileType {
    pub fn as_str(self) -> &'static str {
        use FileType::*;
        match self {
            File => "file",
            Hardlink(..) => "hardlink",
            Directory => "directory",
            Symlink => "symlink",
            Fifo => "fifo",
            CharacterSpecial => "character special",
            BlockSpecial => "block special",
            Socket => "socket",
            Whiteout => "whiteout",
        }
    }
}

impl TryFrom<xml::FileType> for FileType {
    type Error = Error;

    fn try_from(other: xml::FileType) -> Result<Self, Self::Error> {
        use FileType::*;
        match other.value.as_str() {
            "file" => Ok(File),
            "hardlink" => Ok(Hardlink(other.link.unwrap().parse()?)),
            "directory" => Ok(Directory),
            "symlink" => Ok(Symlink),
            "fifo" => Ok(Fifo),
            "character special" => Ok(CharacterSpecial),
            "block special" => Ok(BlockSpecial),
            "socket" => Ok(Socket),
            "whiteout" => Ok(Whiteout),
            _ => Err(Error::other("invalid file type")),
        }
    }
}

impl From<FileType> for xml::FileType {
    fn from(other: FileType) -> Self {
        use FileType::*;
        let link = match other {
            Hardlink(hard_link) => Some(hard_link.to_string()),
            _ => None,
        };
        Self {
            link,
            value: other.as_str().to_string(),
        }
    }
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum Hardlink {
    #[default]
    Original,
    Id(u64),
}

impl Display for Hardlink {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::Original => f.write_str("original"),
            Self::Id(id) => write!(f, "{}", id),
        }
    }
}

impl FromStr for Hardlink {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "original" {
            Ok(Self::Original)
        } else {
            Ok(Self::Id(s.parse().map_err(Error::other)?))
        }
    }
}
