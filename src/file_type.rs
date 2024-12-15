use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::ErrorKind;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;

/// File type.
///
/// Includes hard links besides the usual file types.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, Serialize, Deserialize,
)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[serde(try_from = "XmlFileType", into = "XmlFileType")]
pub enum FileType {
    /// Regular file.
    #[default]
    File,
    /// Hard link.
    HardLink(HardLink),
    /// A directory.
    Directory,
    /// Symbolic link,
    Symlink,
    /// Named pipe.
    Fifo,
    /// Character device.
    CharacterSpecial,
    /// Block device.
    BlockSpecial,
    /// UNIX socket.
    Socket,
    /// Whiteout.
    Whiteout,
}

impl FileType {
    /// Get file type name as written in XML.
    pub fn as_str(self) -> &'static str {
        use FileType::*;
        match self {
            File => FILE,
            HardLink(..) => HARD_LINK,
            Directory => DIRECTORY,
            Symlink => SYMLINK,
            Fifo => FIFO,
            CharacterSpecial => CHARACTER_SPECIAL,
            BlockSpecial => BLOCK_SPECIAL,
            Socket => SOCKET,
            Whiteout => WHITEOUT,
        }
    }
}

impl Display for FileType {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<XmlFileType> for FileType {
    type Error = Error;

    fn try_from(other: XmlFileType) -> Result<Self, Self::Error> {
        use FileType::*;
        match other.value.as_str() {
            FILE => Ok(File),
            HARD_LINK => {
                let hard_link = match other.link {
                    Some(link) => link.parse()?,
                    None => Default::default(),
                };
                Ok(HardLink(hard_link))
            }
            DIRECTORY => Ok(Directory),
            SYMLINK => Ok(Symlink),
            FIFO => Ok(Fifo),
            CHARACTER_SPECIAL => Ok(CharacterSpecial),
            BLOCK_SPECIAL => Ok(BlockSpecial),
            SOCKET => Ok(Socket),
            WHITEOUT => Ok(Whiteout),
            _ => Err(ErrorKind::InvalidData.into()),
        }
    }
}

impl From<FileType> for XmlFileType {
    fn from(other: FileType) -> Self {
        use FileType::*;
        let link = match other {
            HardLink(hard_link) => Some(hard_link.to_string()),
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

/// A hard link.
///
/// Either an original file or an id of the original file.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum HardLink {
    #[default]
    Original,
    Id(u64),
}

impl Display for HardLink {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::Original => f.write_str(ORIGINAL),
            Self::Id(id) => write!(f, "{}", id),
        }
    }
}

impl FromStr for HardLink {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == ORIGINAL {
            Ok(Self::Original)
        } else {
            Ok(Self::Id(s.parse().map_err(|_| ErrorKind::InvalidData)?))
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename = "type")]
struct XmlFileType {
    #[serde(rename = "@link", skip_serializing_if = "Option::is_none")]
    link: Option<String>,
    #[serde(rename = "$value")]
    value: String,
}

impl Default for XmlFileType {
    fn default() -> Self {
        Self {
            link: None,
            value: FILE.into(),
        }
    }
}

const FILE: &str = "file";
const HARD_LINK: &str = "hardlink";
const DIRECTORY: &str = "directory";
const SYMLINK: &str = "symlink";
const FIFO: &str = "fifo";
const CHARACTER_SPECIAL: &str = "character special";
const BLOCK_SPECIAL: &str = "block special";
const SOCKET: &str = "socket";
const WHITEOUT: &str = "whiteout";

const ORIGINAL: &str = "original";

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use arbtest::arbtest;

    use super::*;

    #[test]
    fn file_type_from_xml_to_xml_symmetry() {
        arbtest(|u| {
            let expected: FileType = u.arbitrary()?;
            let xml: XmlFileType = expected.into();
            let actual: FileType = xml
                .clone()
                .try_into()
                .inspect_err(|_| panic!("failed to parse {:?} as {:?}", xml, expected))
                .unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    #[test]
    fn hard_link_to_string_parse_symmetry() {
        arbtest(|u| {
            let expected: HardLink = u.arbitrary()?;
            let string = expected.to_string();
            let actual: HardLink = string
                .parse()
                .inspect_err(|_| panic!("failed to parse {:?} as {:?}", string, expected))
                .unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }
}
