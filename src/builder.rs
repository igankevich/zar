use std::collections::hash_map::Entry::Occupied;
use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::fs::read_link;
use std::fs::symlink_metadata;
use std::io::Error;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use normalize_path::NormalizePath;

use crate::xml;
use crate::Checksum;
use crate::ChecksumAlgo;
use crate::Compression;
use crate::FileStatus;
use crate::FileType;
use crate::Signer;
use crate::Walk;

pub struct Options {
    file_checksum_algo: ChecksumAlgo,
    toc_checksum_algo: ChecksumAlgo,
}

impl Options {
    pub fn new() -> Self {
        Self {
            file_checksum_algo: Default::default(),
            toc_checksum_algo: Default::default(),
        }
    }

    pub fn file_checksum_algo(mut self, algo: ChecksumAlgo) -> Self {
        self.file_checksum_algo = algo;
        self
    }

    pub fn toc_checksum_algo(mut self, algo: ChecksumAlgo) -> Self {
        self.toc_checksum_algo = algo;
        self
    }

    pub fn create<W: Write, S: Signer>(self, writer: W, signer: Option<S>) -> Builder<W, S> {
        let toc_checksum_len = self.toc_checksum_algo.size();
        let offset = if let Some(ref signer) = signer {
            toc_checksum_len + signer.signature_len()
        } else {
            toc_checksum_len
        };
        Builder {
            writer,
            signer,
            offset: offset as u64,
            file_checksum_algo: self.file_checksum_algo,
            toc_checksum_algo: self.toc_checksum_algo,
            files: Default::default(),
            contents: Default::default(),
            inodes: Default::default(),
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Builder<W: Write, S: Signer> {
    writer: W,
    signer: Option<S>,
    file_checksum_algo: ChecksumAlgo,
    toc_checksum_algo: ChecksumAlgo,
    files: Vec<xml::File>,
    contents: Vec<Vec<u8>>,
    // (dev, inode) -> file index
    inodes: HashMap<(u64, u64), usize>,
    offset: u64,
}

impl<W: Write, S: Signer> Builder<W, S> {
    pub fn new(writer: W, signer: Option<S>) -> Self {
        Options::new().create(writer, signer)
    }

    pub fn files(&self) -> &[xml::File] {
        &self.files[..]
    }

    pub fn append_path_all<P: AsRef<Path>>(
        &mut self,
        path: P,
        compression: Compression,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        if path.is_dir() {
            self.append_dir_all(path, compression)
        } else {
            self.append_file(path, path.to_path_buf(), path, compression)
        }
    }

    pub fn append_dir_all<P: AsRef<Path>>(
        &mut self,
        path: P,
        compression: Compression,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        let mut walker = path.walk()?;
        while let Some(entry) = walker.next() {
            let entry = entry?;
            let entry_path = entry.path().strip_prefix(path).unwrap().normalize();
            if entry_path == Path::new("") {
                continue;
            }
            self.append_file(path, entry_path, entry.path(), compression)?;
        }
        Ok(())
    }

    pub fn append_file<P: AsRef<Path>>(
        &mut self,
        prefix: &Path,
        archive_path: PathBuf,
        path: P,
        compression: Compression,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        let metadata = symlink_metadata(path)?;
        let (has_contents, link) = if metadata.is_file() {
            (true, None)
        } else if metadata.is_symlink() {
            // resolve symlink
            let (has_contents, broken) = match path.metadata() {
                Ok(target_meta) => (target_meta.is_file(), false),
                Err(_) => {
                    // broken symlink
                    (false, true)
                }
            };
            let target = read_link(path)?;
            let target = target.strip_prefix(prefix).unwrap_or(target.as_path());
            let link = Some(xml::Link {
                kind: if broken { "broken" } else { "file" }.into(),
                target: target.to_path_buf(),
            });
            (has_contents, link)
        } else {
            (false, None)
        };
        let contents = if has_contents {
            std::fs::read(path)?
        } else {
            Vec::new()
        };
        let mut status: FileStatus = metadata.into();
        status.name = archive_path;
        self.append_raw(status, &contents, link, compression)
    }

    pub fn append_raw<C: AsRef<[u8]>>(
        &mut self,
        status: FileStatus,
        contents: C,
        link: Option<xml::Link>,
        compression: Compression,
    ) -> Result<(), Error> {
        let contents = contents.as_ref();
        let (data, archived) = if !contents.is_empty() {
            let extracted_checksum = Checksum::new_from_data(self.file_checksum_algo, contents);
            let mut encoder = compression.encoder(Vec::new())?;
            encoder.write_all(contents)?;
            let archived = encoder.finish()?;
            let archived_checksum = Checksum::new_from_data(self.file_checksum_algo, &archived);
            let data = xml::Data {
                archived_checksum: archived_checksum.into(),
                extracted_checksum: extracted_checksum.into(),
                encoding: xml::Encoding {
                    style: compression.as_str().into(),
                },
                size: contents.len() as u64,
                length: archived.len() as u64,
                offset: self.offset,
            };
            (Some(data), archived)
        } else {
            (None, Vec::new())
        };
        let device =
            if status.kind == FileType::CharacterSpecial || status.kind == FileType::BlockSpecial {
                Some(xml::Device {
                    major: unsafe { libc::major(status.rdev as _) } as _,
                    minor: unsafe { libc::minor(status.rdev as _) } as _,
                })
            } else {
                None
            };
        let mut file = xml::File::new(self.files.len() as u64 + 1, status, data, link, device);
        // handle hard links
        match self.inodes.entry((file.deviceno, file.inode)) {
            Vacant(v) => {
                let i = self.files.len();
                v.insert(i);
            }
            Occupied(o) => {
                let i = *o.get();
                let original_file = &mut self.files[i];
                file.kind.link = Some(original_file.id.to_string());
                if original_file.kind.link.is_none() {
                    original_file.kind.link = Some("original".into());
                }
            }
        }
        self.offset += archived.len() as u64;
        self.files.push(file);
        self.contents.push(archived);
        Ok(())
    }

    pub fn finish(mut self) -> Result<W, Error> {
        let checksum_len = self.toc_checksum_algo.size() as u64;
        let xar = xml::Xar {
            toc: xml::Toc {
                checksum: xml::TocChecksum {
                    algo: self.toc_checksum_algo,
                    offset: 0,
                    size: checksum_len,
                },
                files: self.files,
                // http://users.wfu.edu/cottrell/productsign/productsign_linux.html
                signature: self.signer.as_ref().map(|signer| xml::Signature {
                    style: signer.signature_style().into(),
                    offset: checksum_len,
                    size: signer.signature_len() as u64,
                    key_info: xml::KeyInfo {
                        data: xml::X509Data {
                            // TODO certs
                            certificates: Default::default(),
                        },
                    },
                }),
                creation_time: xml::Timestamp(SystemTime::now()),
            },
        };
        // write header and toc
        xar.write(
            self.writer.by_ref(),
            self.toc_checksum_algo,
            self.signer.as_ref(),
        )?;
        for content in self.contents.into_iter() {
            self.writer.write_all(&content)?;
        }
        Ok(self.writer)
    }

    pub fn get_mut(&mut self) -> &mut W {
        self.writer.by_ref()
    }

    pub fn get(&self) -> &W {
        &self.writer
    }
}

// A stub to produce unsigned archives.
pub struct NoSigner;

impl Signer for NoSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(Vec::new())
    }

    fn signature_style(&self) -> &str {
        ""
    }

    fn signature_len(&self) -> usize {
        0
    }
}
