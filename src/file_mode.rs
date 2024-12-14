use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[serde(into = "String", try_from = "String")]
pub struct FileMode(u32);

impl FileMode {
    pub fn into_inner(self) -> u32 {
        self.0
    }
}

impl Default for FileMode {
    fn default() -> Self {
        FileMode(0o644)
    }
}

impl FromStr for FileMode {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            u32::from_str_radix(value, 8).map_err(|_| Error::other("invalid file mode"))?,
        ))
    }
}

impl Display for FileMode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

impl TryFrom<String> for FileMode {
    type Error = Error;
    fn try_from(other: String) -> Result<Self, Self::Error> {
        other.parse()
    }
}

impl From<FileMode> for String {
    fn from(other: FileMode) -> String {
        other.to_string()
    }
}

impl From<FileMode> for u32 {
    fn from(other: FileMode) -> u32 {
        other.0
    }
}

impl From<u32> for FileMode {
    fn from(other: u32) -> Self {
        Self(other & 0o7777)
    }
}
