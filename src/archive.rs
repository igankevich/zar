use std::collections::HashMap;
use std::fs::create_dir_all;
use std::fs::set_permissions;
use std::fs::File;
use std::fs::Permissions;
use std::io::Error;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Take;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

use libc::makedev;
use serde::Deserialize;

use crate::mkfifo;
use crate::mknod;
use crate::path_to_c_string;
use crate::set_file_modified_time;
use crate::xml;
use crate::Checksum;
use crate::Compression;
use crate::FileType;
use crate::HardLink;
use crate::Header;
use crate::Verifier;
use crate::XarDecoder;

/// An archive without extra data.
pub type Archive<R> = ExtendedArchive<R, ()>;

pub struct ExtendedArchive<R: Read + Seek, X = ()> {
    files: Vec<xml::File<X>>,
    reader: R,
    heap_offset: u64,
}

impl<R: Read + Seek, X: for<'a> Deserialize<'a> + Default> ExtendedArchive<R, X> {
    pub fn new_unsigned(reader: R) -> Result<Self, Error> {
        Self::new::<NoVerifier>(reader, None)
    }

    pub fn new<V: Verifier>(mut reader: R, verifier: Option<&V>) -> Result<Self, Error> {
        let header = Header::read(&mut reader)?;
        let mut toc_bytes = vec![0_u8; header.toc_len_compressed as usize];
        reader.read_exact(&mut toc_bytes[..])?;
        let toc = xml::Xar::<X>::read(&toc_bytes[..])?.toc;
        let heap_offset = reader.stream_position()?;
        reader.seek(SeekFrom::Start(heap_offset + toc.checksum.offset))?;
        let mut checksum_bytes = vec![0_u8; toc.checksum.size as usize];
        reader.read_exact(&mut checksum_bytes[..])?;
        let checksum = Checksum::new(toc.checksum.algo, &checksum_bytes[..])?;
        let actual_checksum = checksum.algo().hash(&toc_bytes[..]);
        if checksum != actual_checksum {
            return Err(Error::other("toc checksum mismatch"));
        }
        if let Some(verifier) = verifier {
            let signature_bytes = match toc.signature {
                Some(signature) => {
                    reader.seek(SeekFrom::Start(heap_offset + signature.offset))?;
                    let mut signature_bytes = vec![0_u8; signature.size as usize];
                    reader.read_exact(&mut signature_bytes[..])?;
                    signature_bytes
                }
                None => Vec::new(),
            };
            verifier.verify(&checksum_bytes, &signature_bytes)?;
        }
        Ok(Self {
            files: toc.files,
            reader,
            heap_offset,
        })
    }
}

impl<R: Read + Seek, X> ExtendedArchive<R, X> {
    pub fn files(&self) -> &[xml::File<X>] {
        self.files.as_slice()
    }

    pub fn num_entries(&self) -> usize {
        self.files.len()
    }

    pub fn entry(&mut self, i: usize) -> Entry<R, X> {
        Entry { i, archive: self }
    }

    pub fn extract<P: AsRef<Path>>(mut self, dest_dir: P) -> Result<(), Error> {
        use std::collections::hash_map::Entry::*;
        let dest_dir = dest_dir.as_ref();
        let mut dirs = Vec::new();
        // id -> path
        let mut file_paths = HashMap::new();
        let mut hard_links = Vec::new();
        // (dev, inode) -> id
        let mut inodes = HashMap::new();
        for i in 0..self.num_entries() {
            let mut entry = self.entry(i);
            let dest_file = dest_dir.join(&entry.file().name);
            let file_type: FileType = entry.file().kind;
            file_paths.insert(entry.file().id, dest_file.clone());
            match inodes.entry((entry.file().deviceno, entry.file().inode)) {
                Vacant(v) => {
                    if !matches!(file_type, FileType::HardLink(HardLink::Id(..))) {
                        v.insert(entry.file().id);
                    }
                }
                Occupied(o) => {
                    let id = *o.get();
                    // hard link
                    hard_links.push((id, dest_file));
                    continue;
                }
            }
            match entry.reader()? {
                Some(mut reader) => {
                    let mut file = File::create(&dest_file)?;
                    std::io::copy(&mut reader, &mut file)?;
                    file.set_permissions(Permissions::from_mode(entry.file().mode.into()))?;
                    file.set_modified(entry.file().mtime.0)?;
                }
                None => match file_type {
                    FileType::File => {
                        // TODO refactor
                        // should not happen
                    }
                    FileType::Directory => {
                        create_dir_all(&dest_file)?;
                        File::open(&dest_file)?.set_modified(entry.file().mtime.0)?;
                        // apply proper permissions later when we have written all other files
                        dirs.push((dest_file, entry.file().mode));
                    }
                    FileType::HardLink(hard_link) => match hard_link {
                        HardLink::Original => {
                            // ignore
                        }
                        HardLink::Id(id) => {
                            // create hard links later because we might not have written
                            // the original files by now
                            hard_links.push((id, dest_file));
                        }
                    },
                    FileType::Symlink => {
                        let target = entry.file().link().unwrap().target.as_path();
                        symlink(target, &dest_file)?;
                        let path = path_to_c_string(dest_file)?;
                        set_file_modified_time(&path, entry.file().mtime.0)?;
                    }
                    FileType::Fifo => {
                        let path = path_to_c_string(dest_file)?;
                        mkfifo(&path, entry.file().mode.into_inner() as _)?;
                        set_file_modified_time(&path, entry.file().mtime.0)?;
                    }
                    #[allow(unused_unsafe)]
                    FileType::CharacterSpecial | FileType::BlockSpecial => {
                        let path = path_to_c_string(dest_file)?;
                        let dev = entry.file().device().unwrap();
                        let dev = unsafe { makedev(dev.major as _, dev.minor as _) };
                        mknod(&path, entry.file().mode.into_inner() as _, dev as _)?;
                    }
                    FileType::Socket => {
                        UnixDatagram::bind(&dest_file)?;
                        let path = path_to_c_string(dest_file)?;
                        set_file_modified_time(&path, entry.file().mtime.0)?;
                    }
                    FileType::Whiteout => {
                        // TODO
                    }
                },
            }
        }
        for (id, dest_file) in hard_links.into_iter() {
            let original = file_paths.get(&id).unwrap();
            std::fs::hard_link(original, &dest_file)?;
        }
        dirs.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        for (path, mode) in dirs.into_iter() {
            let perms = Permissions::from_mode(mode.into());
            set_permissions(&path, perms)?;
        }
        Ok(())
    }
}

fn seek_to_file<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    length: u64,
    archived_checksum: &Checksum,
) -> Result<(), Error> {
    let mut file_bytes = vec![0_u8; length as usize];
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(&mut file_bytes[..])?;
    let actual_checksum = archived_checksum.algo().hash(&file_bytes[..]);
    if archived_checksum != &actual_checksum {
        eprintln!(
            "expected = {}, actual = {}",
            archived_checksum, actual_checksum
        );
        return Err(Error::other("file checksum mismatch"));
    }
    reader.seek(SeekFrom::Start(offset))?;
    Ok(())
}

pub struct Entry<'a, R: Read + Seek, X> {
    archive: &'a mut ExtendedArchive<R, X>,
    i: usize,
}

impl<'a, R: Read + Seek, X> Entry<'a, R, X> {
    pub fn reader(&mut self) -> Result<Option<XarDecoder<Take<&mut R>>>, Error> {
        let file = &self.archive.files[self.i];
        match file.data() {
            Some(data) => {
                debug_assert!(data.archived_checksum.algo == data.archived_checksum.value.algo());
                let compression: Compression = data.encoding.style.as_str().into();
                let length = data.length;
                seek_to_file(
                    self.archive.reader.by_ref(),
                    self.archive.heap_offset + data.offset,
                    data.length,
                    &data.archived_checksum.value,
                )?;
                // we need decoder based on compression, otherwise we can accidentally decompress the
                // file with octet-stream compression
                Ok(Some(
                    compression.decoder(self.archive.reader.by_ref().take(length)),
                ))
            }
            None if file.kind == FileType::File
                || file.kind == FileType::HardLink(HardLink::Original) =>
            {
                // The `Data` may not be stored for empty files.
                let compression = Compression::None;
                Ok(Some(
                    compression.decoder(self.archive.reader.by_ref().take(0)),
                ))
            }
            // Not a regular file.
            None => Ok(None),
        }
    }

    pub fn file(&self) -> &xml::File<X> {
        &self.archive.files[self.i]
    }
}

// A stub to read unsigned archives.
pub struct NoVerifier;

impl Verifier for NoVerifier {
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::Once;

    use arbtest::arbtest;
    use random_dir::DirBuilder;
    use rsa::rand_core::OsRng;
    use tempfile::TempDir;

    use super::*;
    use crate::ExtendedBuilder;
    use crate::NoSigner;
    use crate::RsaKeypair;
    use crate::RsaPrivateKey;
    use crate::RsaSigner;
    use crate::Signer;

    #[test]
    fn xar_unsigned_write_read() {
        test_xar_write_read(NoSigner, NoVerifier);
    }

    #[test]
    fn xar_signed_write_read() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let signer = RsaSigner::new(private_key);
        let verifier = signer.verifying_key();
        test_xar_write_read(signer, verifier);
    }

    fn test_xar_write_read<S: Signer, V: Verifier>(signer: S, verifier: V) {
        do_not_truncate_assertions();
        let workdir = TempDir::new().unwrap();
        arbtest(|u| {
            let directory = DirBuilder::new().printable_names(true).create(u)?;
            let extra = u.arbitrary()?;
            let xar_path = workdir.path().join("test.xar");
            let mut xar = ExtendedBuilder::new(File::create(&xar_path).unwrap(), Some(&signer));
            xar.append_dir_all(
                directory.path(),
                Compression::Gzip,
                |_file: &xml::File<u64>, _: &Path, _: &Path| Ok(Some(extra)),
            )
            .unwrap();
            let expected_files = xar.files().to_vec();
            xar.finish().unwrap();
            let reader = File::open(&xar_path).unwrap();
            let mut xar_archive =
                ExtendedArchive::<std::fs::File, u64>::new(reader, Some(&verifier)).unwrap();
            let mut actual_files = Vec::new();
            for i in 0..xar_archive.num_entries() {
                let mut entry = xar_archive.entry(i);
                actual_files.push(entry.file().clone());
                if let Some(mut reader) = entry.reader().unwrap() {
                    let mut buf = Vec::new();
                    reader.read_to_end(&mut buf).unwrap();
                    assert_eq!(extra, entry.file().extra.unwrap());
                    match entry.file().data() {
                        Some(data) => {
                            debug_assert!(
                                data.extracted_checksum.algo
                                    == data.extracted_checksum.value.algo()
                            );
                            let actual_checksum = data.extracted_checksum.algo.hash(&buf);
                            assert_eq!(
                                data.extracted_checksum.value,
                                actual_checksum,
                                "file = {:?}",
                                entry.file()
                            );
                        }
                        None => {
                            assert!(buf.is_empty());
                        }
                    }
                }
            }
            similar_asserts::assert_eq!(expected_files, actual_files);
            Ok(())
        });
    }

    fn do_not_truncate_assertions() {
        NO_TRUNCATE.call_once(|| {
            std::env::set_var("SIMILAR_ASSERTS_MAX_STRING_LENGTH", "0");
        });
    }

    static NO_TRUNCATE: Once = Once::new();
}
