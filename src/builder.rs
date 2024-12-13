use std::fs::symlink_metadata;
use std::io::Error;
use std::io::Write;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use normalize_path::NormalizePath;

use crate::xml;
use crate::Checksum;
use crate::ChecksumAlgo;
use crate::Compression;
use crate::FileStatus;
use crate::Signer;
use crate::Walk;

pub struct Builder<W: Write> {
    writer: W,
    checksum_algo: ChecksumAlgo,
    files: Vec<xml::File>,
    contents: Vec<Vec<u8>>,
    offset: u64,
}

impl<W: Write> Builder<W> {
    pub fn new(writer: W) -> Self {
        Self::do_new(writer, &NoSigner)
    }

    fn do_new<S: Signer>(writer: W, signer: &S) -> Self {
        let checksum_algo = ChecksumAlgo::Sha256;
        Self {
            offset: (checksum_algo.size() + signer.signature_len()) as u64,
            writer,
            checksum_algo,
            files: Default::default(),
            contents: Default::default(),
        }
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
            self.append_file(path.to_path_buf(), path, compression)
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
            self.append_file(entry_path, entry.path(), compression)?;
        }
        Ok(())
    }

    pub fn append_file<P: AsRef<Path>>(
        &mut self,
        archive_path: PathBuf,
        path: P,
        compression: Compression,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        let metadata = symlink_metadata(path)?;
        let has_contents = if metadata.is_file() {
            true
        } else if metadata.is_symlink() {
            // resolve symlink
            let target = path.metadata()?;
            target.is_file()
        } else {
            false
        };
        let contents = if has_contents {
            std::fs::read(path)?
        } else {
            Vec::new()
        };
        let mut status: FileStatus = metadata.into();
        status.name = archive_path;
        self.append_raw(status, &contents, compression)
    }

    pub fn append_raw<C: AsRef<[u8]>>(
        &mut self,
        status: FileStatus,
        contents: C,
        compression: Compression,
    ) -> Result<(), Error> {
        let contents = contents.as_ref();
        let extracted_checksum = Checksum::new_from_data(self.checksum_algo, contents);
        let mut encoder = compression.encoder(Vec::new())?;
        encoder.write_all(contents)?;
        let archived = encoder.finish()?;
        let archived_checksum = Checksum::new_from_data(self.checksum_algo, &archived);
        let file = xml::File::new(
            self.files.len() as u64,
            status,
            xml::Data {
                archived_checksum: archived_checksum.into(),
                extracted_checksum: extracted_checksum.into(),
                encoding: xml::Encoding {
                    style: compression.as_str().into(),
                },
                size: contents.len() as u64,
                length: archived.len() as u64,
                offset: self.offset,
            },
        );
        self.offset += archived.len() as u64;
        self.files.push(file);
        self.contents.push(archived);
        Ok(())
    }

    pub fn finish(self) -> Result<W, Error> {
        self.do_finish(&NoSigner)
    }

    fn do_finish<S: Signer>(mut self, signer: &S) -> Result<W, Error> {
        let checksum_len = self.checksum_algo.size() as u64;
        let signature_len = signer.signature_len();
        let xar = xml::Xar {
            toc: xml::Toc {
                checksum: xml::TocChecksum {
                    algo: self.checksum_algo,
                    offset: 0,
                    size: checksum_len,
                },
                files: self.files,
                // http://users.wfu.edu/cottrell/productsign/productsign_linux.html
                signature: (signature_len != 0).then_some(xml::Signature {
                    style: signer.signature_style().into(),
                    offset: checksum_len,
                    size: signature_len as u64,
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
        xar.write(self.writer.by_ref(), self.checksum_algo, signer)?;
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

pub struct SignedBuilder<W: Write>(Builder<W>);

impl<W: Write> SignedBuilder<W> {
    pub fn new<S: Signer>(writer: W, signer: &S) -> Self {
        Self(Builder::do_new(writer, signer))
    }

    pub fn sign<S: Signer>(self, signer: &S) -> Result<W, Error> {
        self.0.do_finish(signer)
    }
}

impl<W: Write> Deref for SignedBuilder<W> {
    type Target = Builder<W>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<W: Write> DerefMut for SignedBuilder<W> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// A stub to produce unsigned archives.
pub(crate) struct NoSigner;

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
