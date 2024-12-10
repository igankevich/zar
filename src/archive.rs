use std::io::Error;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use crate::xml;
use crate::Checksum;
use crate::Compression;
use crate::Header;
use crate::XarDecoder;

pub struct Archive<R: Read + Seek> {
    files: Vec<xml::File>,
    reader: R,
    heap_offset: u64,
}

impl<R: Read + Seek> Archive<R> {
    pub fn new(mut reader: R) -> Result<Self, Error> {
        let header = Header::read(&mut reader)?;
        let mut toc_bytes = vec![0_u8; header.toc_len_compressed as usize];
        reader.read_exact(&mut toc_bytes[..])?;
        let toc = xml::Xar::read(&toc_bytes[..])?.toc;
        let heap_offset = reader.stream_position()?;
        reader.seek(SeekFrom::Start(heap_offset + toc.checksum.offset))?;
        let mut checksum = vec![0_u8; toc.checksum.size as usize];
        reader.read_exact(&mut checksum[..])?;
        let checksum = Checksum::new(toc.checksum.algo, &checksum[..])?;
        let actual_checksum = checksum.compute(&toc_bytes[..]);
        if checksum != actual_checksum {
            return Err(Error::other("toc checksum mismatch"));
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

    fn seek_to_file(&mut self, i: usize) -> Result<(), Error> {
        let offset = self.heap_offset + self.files[i].data.offset;
        let mut file_bytes = vec![0_u8; self.files[i].data.length as usize];
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(&mut file_bytes[..])?;
        let actual_checksum = self.files[i]
            .data
            .archived_checksum
            .value
            .compute(&file_bytes[..]);
        if self.files[i].data.archived_checksum.value != actual_checksum {
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
    pub fn reader(&mut self) -> Result<XarDecoder<&mut R>, Error> {
        self.archive.seek_to_file(self.i)?;
        // we need decoder based on compression, otherwise we can accidentally decompress the
        // file with octet-stream compression
        let compression: Compression = self.archive.files[self.i]
            .data
            .encoding
            .style
            .as_str()
            .into();
        Ok(compression.decoder(self.archive.reader.by_ref()))
    }

    pub fn file(&self) -> &xml::File {
        &self.archive.files[self.i]
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;

    use arbtest::arbtest;
    use normalize_path::NormalizePath;
    use random_dir::DirBuilder;
    use tempfile::TempDir;
    use walkdir::WalkDir;

    use super::*;
    use crate::Builder;

    /*
    #[test]
    fn xar_read() {
        let reader = File::open("tmp.sh.xar").unwrap();
        let mut xar_archive = Archive::new(reader).unwrap();
        for mut entry in xar_archive.files() {
            eprintln!("file {:?}", entry.file());
            eprintln!(
                "{}",
                std::io::read_to_string(entry.reader().unwrap()).unwrap()
            );
        }
    }
    */

    #[test]
    fn xar_write_read() {
        let workdir = TempDir::new().unwrap();
        arbtest(|u| {
            let directory = DirBuilder::new().printable_names(true).create(u)?;
            let xar_path = workdir.path().join("test.xar");
            let mut xar = Builder::new(File::create(&xar_path).unwrap());
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
            xar.finish().unwrap();
            let reader = File::open(&xar_path).unwrap();
            let mut xar_archive = Archive::new(reader).unwrap();
            let mut actual_files = Vec::new();
            for i in 0..xar_archive.num_entries() {
                let mut entry = xar_archive.entry(i);
                actual_files.push(entry.file().clone());
                let mut buf = Vec::new();
                entry.reader().unwrap().read_to_end(&mut buf).unwrap();
                let actual_checksum = entry.file().data.extracted_checksum.value.compute(&buf);
                assert_eq!(
                    entry.file().data.extracted_checksum.value,
                    actual_checksum,
                    "file = {:?}",
                    entry.file()
                );
            }
            assert_eq!(expected_files, actual_files);
            Ok(())
        });
    }
}
