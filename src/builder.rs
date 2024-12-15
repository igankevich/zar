use std::collections::hash_map::Entry::Occupied;
use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::io::Error;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use normalize_path::NormalizePath;
use serde::Deserialize;
use serde::Serialize;

use crate::xml;
use crate::ChecksumAlgo;
use crate::Compression;
use crate::FileType;
use crate::HardLink;
use crate::Signer;
use crate::Walk;

pub struct BuilderOptions {
    file_checksum_algo: ChecksumAlgo,
    toc_checksum_algo: ChecksumAlgo,
}

impl BuilderOptions {
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

    pub fn create<W: Write, S: Signer, X>(
        self,
        writer: W,
        signer: Option<S>,
    ) -> ExtendedBuilder<W, S, X> {
        let toc_checksum_len = self.toc_checksum_algo.hash_len();
        let offset = if let Some(ref signer) = signer {
            toc_checksum_len + signer.signature_len()
        } else {
            toc_checksum_len
        };
        ExtendedBuilder {
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

impl Default for BuilderOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// A builder without extra data.
pub type Builder<W, S> = ExtendedBuilder<W, S, ()>;

pub struct ExtendedBuilder<W: Write, S: Signer, X = ()> {
    writer: W,
    signer: Option<S>,
    file_checksum_algo: ChecksumAlgo,
    toc_checksum_algo: ChecksumAlgo,
    files: Vec<xml::File<X>>,
    contents: Vec<Vec<u8>>,
    // (dev, inode) -> file index
    inodes: HashMap<(u64, u64), usize>,
    offset: u64,
}

impl<W: Write, S: Signer, X> ExtendedBuilder<W, S, X> {
    pub fn new(writer: W, signer: Option<S>) -> Self {
        BuilderOptions::new().create(writer, signer)
    }

    pub fn files(&self) -> &[xml::File<X>] {
        &self.files[..]
    }

    pub fn append_path_all<F, P>(
        &mut self,
        path: P,
        compression: Compression,
        extra: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&xml::File<X>, &Path, &Path) -> Result<Option<X>, Error>,
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        if path.is_dir() {
            self.append_dir_all(path, compression, extra)
        } else {
            self.append_file(path, path.to_path_buf(), path, compression, extra)
        }
    }

    pub fn append_dir_all<F, P>(
        &mut self,
        path: P,
        compression: Compression,
        mut extra: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&xml::File<X>, &Path, &Path) -> Result<Option<X>, Error>,
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let mut next_id = self.files.len() as u64 + 1;
        let mut next_offset = self.offset;
        let mut tree = HashMap::new();
        for entry in path.walk()? {
            let entry = entry?;
            let archive_path = entry.path().strip_prefix(path).unwrap().normalize();
            if archive_path == Path::new("") {
                continue;
            }
            let (file, archived_contents) = xml::File::<X>::new(
                next_id,
                path,
                entry.path(),
                Path::new(archive_path.file_name().unwrap_or_default()).to_path_buf(),
                compression,
                self.file_checksum_algo,
                next_offset,
                None,
            )?;
            next_id += 1;
            next_offset += archived_contents.len() as u64;
            let parent = archive_path
                .parent()
                .map(|x| x.to_path_buf())
                .unwrap_or_default();
            if parent == Path::new("") {
                tree.insert(archive_path, (file, archived_contents, entry.path()));
                continue;
            }
            let parent = tree.get_mut(&parent).unwrap();
            parent.0.children.push(file);
        }
        let mut files: Vec<_> = tree.into_iter().collect();
        files.sort_unstable_by_key(|entry| entry.1 .0.id);
        for (archive_path, (mut file, archived_contents, real_path)) in files.into_iter() {
            file.extra = extra(&file, &archive_path, &real_path)?;
            self.append_raw(file, archived_contents)?;
        }
        Ok(())
    }

    // TODO do we need that? no nesting here
    pub fn append_file<F, P>(
        &mut self,
        prefix: &Path,
        archive_path: PathBuf,
        path: P,
        compression: Compression,
        mut extra: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&xml::File<X>, &Path, &Path) -> Result<Option<X>, Error>,
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let (mut file, archived_contents) = xml::File::new(
            self.files.len() as u64 + 1,
            prefix,
            path,
            archive_path.clone(),
            compression,
            self.file_checksum_algo,
            self.offset,
            None,
        )?;
        file.extra = extra(&file, &archive_path, path)?;
        self.append_raw(file, archived_contents)
    }

    pub fn append_raw(
        &mut self,
        mut file: xml::File<X>,
        archived_contents: Vec<u8>,
    ) -> Result<(), Error> {
        self.handle_hard_links(&mut file);
        self.offset += archived_contents.len() as u64;
        self.files.push(file);
        self.contents.push(archived_contents);
        Ok(())
    }

    pub fn get_mut(&mut self) -> &mut W {
        self.writer.by_ref()
    }

    pub fn get(&self) -> &W {
        &self.writer
    }

    fn handle_hard_links(&mut self, file: &mut xml::File<X>) {
        match self.inodes.entry((file.deviceno, file.inode)) {
            Vacant(v) => {
                let i = self.files.len();
                v.insert(i);
            }
            Occupied(o) => {
                let i = *o.get();
                let original_file = &mut self.files[i];
                file.kind = FileType::HardLink(HardLink::Id(original_file.id));
                // Do not overwrite original file type if it is already `HardLink`.
                if !matches!(original_file.kind, FileType::HardLink(..)) {
                    original_file.kind = FileType::HardLink(HardLink::Original);
                }
            }
        }
    }
}

impl<W: Write, S: Signer, X: Serialize + for<'a> Deserialize<'a> + Default>
    ExtendedBuilder<W, S, X>
{
    pub fn finish(mut self) -> Result<W, Error> {
        let checksum_len = self.toc_checksum_algo.hash_len() as u64;
        let xar = xml::Xar::<X> {
            toc: xml::Toc::<X> {
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

pub fn no_extra_contents(_: &xml::File<()>, _: &Path, _: &Path) -> Result<Option<()>, Error> {
    Ok(None)
}
