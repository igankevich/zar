use std::io::Error;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::ops::Deref;
use std::ops::DerefMut;

use crate::xml;
use crate::Checksum;
use crate::Compression;
use crate::Header;
use crate::Verifier;
use crate::XarDecoder;

pub struct Archive<R: Read + Seek> {
    files: Vec<xml::File>,
    reader: R,
    heap_offset: u64,
}

impl<R: Read + Seek> Archive<R> {
    pub fn new(reader: R) -> Result<Self, Error> {
        Self::do_new::<NoVerifier>(reader, None)
    }

    fn do_new<V: Verifier>(mut reader: R, verifier: Option<&V>) -> Result<Self, Error> {
        let header = Header::read(&mut reader)?;
        let mut toc_bytes = vec![0_u8; header.toc_len_compressed as usize];
        reader.read_exact(&mut toc_bytes[..])?;
        let toc = xml::Xar::read(&toc_bytes[..])?.toc;
        let heap_offset = reader.stream_position()?;
        reader.seek(SeekFrom::Start(heap_offset + toc.checksum.offset))?;
        let mut checksum_bytes = vec![0_u8; toc.checksum.size as usize];
        reader.read_exact(&mut checksum_bytes[..])?;
        let checksum = Checksum::new(toc.checksum.algo, &checksum_bytes[..])?;
        let actual_checksum = checksum.compute(&toc_bytes[..]);
        eprintln!("signature {:?}", toc.signature);
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

    pub fn files(&self) -> &[xml::File] {
        self.files.as_slice()
    }

    pub fn num_entries(&self) -> usize {
        self.files.len()
    }

    pub fn entry(&mut self, i: usize) -> Entry<R> {
        Entry { i, archive: self }
    }

    fn seek_to_file(
        &mut self,
        offset: u64,
        length: u64,
        archived_checksum: Checksum,
    ) -> Result<(), Error> {
        let offset = self.heap_offset + offset;
        let mut file_bytes = vec![0_u8; length as usize];
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(&mut file_bytes[..])?;
        let actual_checksum = archived_checksum.compute(&file_bytes[..]);
        if archived_checksum != actual_checksum {
            return Err(Error::other("file checksum mismatch"));
        }
        self.reader.seek(SeekFrom::Start(offset))?;
        Ok(())
    }
}

pub struct Entry<'a, R: Read + Seek> {
    archive: &'a mut Archive<R>,
    i: usize,
}

impl<'a, R: Read + Seek> Entry<'a, R> {
    pub fn reader(&mut self) -> Result<Option<XarDecoder<&mut R>>, Error> {
        // TODO clone
        let Some(data) = self.archive.files[self.i].data.clone() else {
            return Ok(None);
        };
        self.archive
            .seek_to_file(data.offset, data.length, data.archived_checksum.value)?;
        // we need decoder based on compression, otherwise we can accidentally decompress the
        // file with octet-stream compression
        let compression: Compression = data.encoding.style.as_str().into();
        Ok(Some(compression.decoder(self.archive.reader.by_ref())))
    }

    pub fn file(&self) -> &xml::File {
        &self.archive.files[self.i]
    }
}

pub struct SignedArchive<R: Read + Seek>(Archive<R>);

impl<R: Read + Seek> SignedArchive<R> {
    pub fn new<V: Verifier>(reader: R, verifier: &V) -> Result<Self, Error> {
        let archive = Archive::do_new(reader, Some(verifier))?;
        Ok(Self(archive))
    }
}

impl<R: Read + Seek> Deref for SignedArchive<R> {
    type Target = Archive<R>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<R: Read + Seek> DerefMut for SignedArchive<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// A stub to read unsigned archives.
pub(crate) struct NoVerifier;

impl Verifier for NoVerifier {
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;

    use arbtest::arbtest;
    use normalize_path::NormalizePath;
    use random_dir::DirBuilder;
    use rsa::rand_core::OsRng;
    use tempfile::TempDir;
    use walkdir::WalkDir;

    use super::*;
    use crate::NoSigner;
    use crate::RsaKeypair;
    use crate::RsaPrivateKey;
    use crate::RsaSigner;
    use crate::SignedBuilder;
    use crate::Signer;

    #[test]
    fn xar_read() {
        for entry in WalkDir::new("pkgs").into_iter() {
            let entry = entry.unwrap();
            if entry.path().metadata().unwrap().is_dir() {
                continue;
            }
            //eprintln!("file {:?}", entry.path());
            let file = File::open(entry.path()).unwrap();
            let mut archive = Archive::new(file).unwrap();
            for i in 0..archive.num_entries() {
                let entry = archive.entry(i);
                if let Some(ref data) = entry.file().data {
                    eprintln!("file {:?}", data.encoding.style);
                }
            }
        }
    }

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
        let workdir = TempDir::new().unwrap();
        arbtest(|u| {
            let directory = DirBuilder::new().printable_names(true).create(u)?;
            let xar_path = workdir.path().join("test.xar");
            let mut xar = SignedBuilder::new(File::create(&xar_path).unwrap(), &signer);
            for entry in WalkDir::new(directory.path()).into_iter() {
                let entry = entry.unwrap();
                let entry_path = entry
                    .path()
                    .strip_prefix(directory.path())
                    .unwrap()
                    .normalize();
                if entry_path == Path::new("") {
                    continue;
                }
                xar.add_file_by_path(entry_path, entry.path(), Compression::Gzip)
                    .unwrap();
            }
            let expected_files = xar.files().to_vec();
            xar.sign(&signer).unwrap();
            let reader = File::open(&xar_path).unwrap();
            let mut xar_archive = SignedArchive::new(reader, &verifier).unwrap();
            let mut actual_files = Vec::new();
            for i in 0..xar_archive.num_entries() {
                let mut entry = xar_archive.entry(i);
                actual_files.push(entry.file().clone());
                if let Some(mut reader) = entry.reader().unwrap() {
                    let mut buf = Vec::new();
                    reader.read_to_end(&mut buf).unwrap();
                    let data = entry.file().data.clone().unwrap();
                    let actual_checksum = data.extracted_checksum.value.compute(&buf);
                    assert_eq!(
                        data.extracted_checksum.value,
                        actual_checksum,
                        "file = {:?}",
                        entry.file()
                    );
                }
            }
            assert_eq!(expected_files, actual_files);
            Ok(())
        });
    }
}
