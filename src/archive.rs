use std::collections::HashMap;
use std::collections::VecDeque;
use std::ffi::CStr;
use std::fs::create_dir_all;
use std::fs::set_permissions;
use std::fs::File;
use std::fs::Permissions;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Take;
use std::os::unix::fs::lchown;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

use base64ct::Base64;
use base64ct::Encoding;
use libc::makedev;
use rsa::pkcs1v15::Signature as RsaSignature;
use rsa::RsaPublicKey;
use serde::Deserialize;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::referenced::OwnedToRef;
use x509_cert::der::Decode;
use x509_cert::der::Encode;
use x509_cert::Certificate;

use crate::lchown as c_lchown;
use crate::mkfifo;
use crate::mknod;
use crate::path_to_c_string;
use crate::set_file_modified_time;
use crate::xml;
use crate::Checksum;
use crate::ChecksumAlgo;
use crate::Compression;
use crate::FileType;
use crate::HardLink;
use crate::Header;
use crate::RootCertVerifier;
use crate::RsaVerifier;
use crate::TrustAny;
use crate::XarDecoder;

/// Archive reading and extraction options.
#[derive(Clone, Debug)]
pub struct ArchiveOptions {
    preserve_mtime: bool,
    preserve_owner: bool,
    check_toc: bool,
    check_files: bool,
    verify: bool,
}

impl ArchiveOptions {
    /// Use default options.
    pub fn new() -> Self {
        Self {
            preserve_mtime: false,
            preserve_owner: false,
            check_toc: true,
            check_files: true,
            verify: false,
        }
    }

    /// Preserve file modification time.
    ///
    /// `false` by default.
    pub fn preserve_mtime(mut self, value: bool) -> Self {
        self.preserve_mtime = value;
        self
    }

    /// Preserve file's user and group IDs.
    ///
    /// `false` by default.
    pub fn preserve_owner(mut self, value: bool) -> Self {
        self.preserve_owner = value;
        self
    }

    /// Check table of contents hash.
    ///
    /// `true` by default.
    pub fn check_toc(mut self, value: bool) -> Self {
        self.check_toc = value;
        self
    }

    /// Check files' hashes.
    ///
    /// `true` by default.
    pub fn check_files(mut self, value: bool) -> Self {
        self.check_files = value;
        self
    }

    /// Verify archive's signature.
    ///
    /// `false` by default.
    pub fn verify(mut self, value: bool) -> Self {
        self.verify = value;
        self
    }
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// XAR archive without any extra data.
pub type Archive<R> = ExtendedArchive<R, ()>;

/// XAR archive with extra data.
pub struct ExtendedArchive<R: Read + Seek, X = ()> {
    files: Vec<xml::File<X>>,
    reader: R,
    heap_offset: u64,
    preserve_mtime: bool,
    preserve_owner: bool,
    check_files: bool,
}

impl<R: Read + Seek, X: for<'a> Deserialize<'a> + Default> ExtendedArchive<R, X> {
    /// Create new archive with the [default](crate::TrustAny) root certificate
    /// verifier and non-default options.
    pub fn with_options(reader: R, options: ArchiveOptions) -> Result<Self, Error> {
        Self::with_root_cert_verifier(reader, &TrustAny, options)
    }

    /// Create new archive with the [default](crate::TrustAny) root certificate
    /// verifier and default options.
    pub fn new(reader: R) -> Result<Self, Error> {
        Self::with_options(reader, Default::default())
    }

    /// Create new archive with the specified root certificate verifier.
    pub fn with_root_cert_verifier<V: RootCertVerifier>(
        mut reader: R,
        root_cert_verifier: &V,
        options: ArchiveOptions,
    ) -> Result<Self, Error> {
        let header = Header::read(&mut reader)?;
        let mut toc_bytes = vec![0_u8; header.toc_len_compressed as usize];
        reader.read_exact(&mut toc_bytes[..])?;
        let toc = xml::Xar::<X>::read(&toc_bytes[..])?.toc;
        let heap_offset = reader.stream_position()?;
        reader.seek(SeekFrom::Start(heap_offset + toc.checksum.offset))?;
        let mut checksum_bytes = vec![0_u8; toc.checksum.size as usize];
        reader.read_exact(&mut checksum_bytes[..])?;
        let checksum = Checksum::new(toc.checksum.algo, &checksum_bytes[..])?;
        if options.check_toc {
            let actual_checksum = checksum.algo().hash(&toc_bytes[..]);
            if checksum != actual_checksum {
                return Err(Error::other("toc checksum mismatch"));
            }
        }
        if options.verify {
            let (signature_bytes, mut certs) = match toc.signature {
                Some(signature) => {
                    reader.seek(SeekFrom::Start(heap_offset + signature.offset))?;
                    let mut signature_bytes = vec![0_u8; signature.size as usize];
                    reader.read_exact(&mut signature_bytes[..])?;
                    (signature_bytes, signature.key_info.data.certificates)
                }
                None => (Vec::new(), Vec::new()),
            };
            let mut signature: RsaSignature = signature_bytes[..]
                .try_into()
                .map_err(|_| Error::other("invalid signature"))?;
            let mut certificates = VecDeque::new();
            for cert in certs.iter_mut() {
                cert.data.retain(|ch| !ch.is_whitespace());
                let der = Base64::decode_vec(&cert.data).map_err(|_| ErrorKind::InvalidData)?;
                let certificate =
                    Certificate::from_der(&der).map_err(|_| ErrorKind::InvalidData)?;
                let rsa_public_key: RsaPublicKey = certificate
                    .tbs_certificate
                    .subject_public_key_info
                    .owned_to_ref()
                    .try_into()
                    .map_err(Error::other)?;
                let signature_algo: ChecksumAlgo = match certificate.signature_algorithm.oid {
                    RSA_SHA1_OID => ChecksumAlgo::Sha1,
                    RSA_SHA256_OID => ChecksumAlgo::Sha256,
                    _ => return Err(Error::other("unsupported signature algorithm")),
                };
                let rsa_signature: RsaSignature = certificate
                    .signature
                    .as_bytes()
                    .ok_or(ErrorKind::InvalidData)?
                    .try_into()
                    .map_err(|_| ErrorKind::InvalidData)?;
                let cert_data = certificate
                    .tbs_certificate
                    .to_der()
                    .map_err(|_| ErrorKind::InvalidData)?;
                certificates.push_back((
                    rsa_public_key,
                    cert_data,
                    signature_algo,
                    rsa_signature,
                    certificate,
                ));
            }
            let (
                rsa_public_key,
                mut cert_data,
                mut signature_algo,
                next_signature,
                mut certificate,
            ) = certificates
                .pop_front()
                .ok_or_else(|| Error::other("no certificates found"))?;
            let verifier = RsaVerifier::new(toc.checksum.algo, rsa_public_key)?;
            verifier.verify(&toc_bytes, &signature)?;
            signature = next_signature;
            let mut last_rsa_public_key = verifier.into_inner();
            while let Some((
                rsa_public_key,
                next_cert_data,
                next_signature_algo,
                next_signature,
                next_certificate,
            )) = certificates.pop_front()
            {
                let verifier = RsaVerifier::new(signature_algo, rsa_public_key)?;
                verifier.verify(&cert_data, &signature)?;
                cert_data = next_cert_data;
                signature = next_signature;
                signature_algo = next_signature_algo;
                certificate = next_certificate;
                last_rsa_public_key = verifier.into_inner();
            }
            // self-signed
            let verifier = RsaVerifier::new(signature_algo, last_rsa_public_key)?;
            verifier.verify(&cert_data, &signature)?;
            root_cert_verifier.verify(&certificate)?;
        }
        Ok(Self {
            files: toc.files,
            reader,
            heap_offset,
            preserve_mtime: options.preserve_mtime,
            preserve_owner: options.preserve_owner,
            check_files: options.check_files,
        })
    }
}

impl<R: Read + Seek, X> ExtendedArchive<R, X> {
    /// Get files.
    pub fn files(&self) -> &[xml::File<X>] {
        self.files.as_slice()
    }

    /// Get the number of files.
    pub fn num_entries(&self) -> usize {
        self.files.len()
    }

    /// Get file at index `i`.
    pub fn entry(&mut self, i: usize) -> Entry<R, X> {
        Entry { i, archive: self }
    }

    /// Extract the contents of the archive to `dest_dir`.
    pub fn extract<P: AsRef<Path>>(mut self, dest_dir: P) -> Result<(), Error> {
        use std::collections::hash_map::Entry::*;
        let dest_dir = dest_dir.as_ref();
        let mut dirs = Vec::new();
        // id -> path
        let mut file_paths = HashMap::new();
        let mut hard_links = Vec::new();
        // (dev, inode) -> id
        let mut inodes = HashMap::new();
        let preserve_mtime = self.preserve_mtime;
        let self_preserve_owner = self.preserve_owner;
        let c_preserve_mtime = |path: &CStr, file: &xml::File<X>| -> Result<(), Error> {
            if preserve_mtime {
                set_file_modified_time(path, file.mtime.0)?;
            }
            Ok(())
        };
        let preserve_owner = |path: &Path, file: &xml::File<X>| -> Result<(), Error> {
            if self_preserve_owner {
                lchown(path, Some(file.uid), Some(file.gid))?;
            }
            Ok(())
        };
        let c_preserve_owner = |path: &CStr, file: &xml::File<X>| -> Result<(), Error> {
            if self_preserve_owner {
                c_lchown(path, file.uid, file.gid)?;
            }
            Ok(())
        };
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
            match file_type {
                FileType::File => {
                    let mut file = File::create(&dest_file)?;
                    if let Some(mut reader) = entry.reader()? {
                        std::io::copy(&mut reader, &mut file)?;
                    }
                    if preserve_mtime {
                        file.set_modified(entry.file().mtime.0)?;
                    }
                    drop(file);
                    preserve_owner(&dest_file, entry.file())?;
                    let perms = Permissions::from_mode(entry.file().mode.into());
                    set_permissions(&dest_file, perms)?;
                }
                FileType::Directory => {
                    create_dir_all(&dest_file)?;
                    if preserve_mtime {
                        File::open(&dest_file)?.set_modified(entry.file().mtime.0)?;
                    }
                    preserve_owner(&dest_file, entry.file())?;
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
                    let target = entry
                        .file()
                        .link()
                        .ok_or(ErrorKind::InvalidData)?
                        .target
                        .as_path();
                    symlink(target, &dest_file)?;
                    let path = path_to_c_string(dest_file)?;
                    c_preserve_mtime(&path, entry.file())?;
                    c_preserve_owner(&path, entry.file())?;
                }
                FileType::Fifo => {
                    let path = path_to_c_string(dest_file)?;
                    let mode = entry.file().mode.into_inner();
                    mkfifo(&path, mode as _)?;
                    c_preserve_mtime(&path, entry.file())?;
                    c_preserve_owner(&path, entry.file())?;
                }
                #[allow(unused_unsafe)]
                FileType::CharacterSpecial | FileType::BlockSpecial => {
                    let path = path_to_c_string(dest_file)?;
                    let dev = entry.file().device().ok_or(ErrorKind::InvalidData)?;
                    let dev = unsafe { makedev(dev.major as _, dev.minor as _) };
                    let mode = entry.file().mode.into_inner();
                    mknod(&path, mode as _, dev as _)?;
                    c_preserve_mtime(&path, entry.file())?;
                    c_preserve_owner(&path, entry.file())?;
                }
                FileType::Socket => {
                    UnixDatagram::bind(&dest_file)?;
                    let path = path_to_c_string(dest_file)?;
                    c_preserve_mtime(&path, entry.file())?;
                    c_preserve_owner(&path, entry.file())?;
                }
            }
        }
        for (id, dest_file) in hard_links.into_iter() {
            let original = file_paths.get(&id).ok_or(ErrorKind::InvalidData)?;
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

#[inline]
fn seek_to_file<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    length: u64,
    archived_checksum: &Checksum,
    check_files: bool,
) -> Result<(), Error> {
    let mut file_bytes = vec![0_u8; length as usize];
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(&mut file_bytes[..])?;
    if check_files {
        let actual_checksum = archived_checksum.algo().hash(&file_bytes[..]);
        if archived_checksum != &actual_checksum {
            return Err(Error::other("file checksum mismatch"));
        }
    }
    reader.seek(SeekFrom::Start(offset))?;
    Ok(())
}

/// File entry that is currently being read.
pub struct Entry<'a, R: Read + Seek, X> {
    archive: &'a mut ExtendedArchive<R, X>,
    i: usize,
}

impl<R: Read + Seek, X> Entry<'_, R, X> {
    /// Get file reader.
    ///
    /// The reader is provided for every regular file.
    /// If the file is empty, the stream will not contain any bytes.
    /// For non-regular-file entries `Ok(None)` is returned.
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
                    self.archive.check_files,
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
                // The `FileData` may not be stored for empty files.
                let compression = Compression::None;
                Ok(Some(
                    compression.decoder(self.archive.reader.by_ref().take(0)),
                ))
            }
            // Not a regular file.
            None => Ok(None),
        }
    }

    /// Get file.
    pub fn file(&self) -> &xml::File<X> {
        &self.archive.files[self.i]
    }
}

const RSA_SHA1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
const RSA_SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::Once;
    use std::time::Duration;

    use arbtest::arbtest;
    use random_dir::DirBuilder;
    use rsa::pkcs1v15::SigningKey;
    use rsa::rand_core::OsRng;
    use rsa::signature::Keypair;
    use rsa::RsaPrivateKey;
    use tempfile::TempDir;
    use x509_cert::builder::Builder;
    use x509_cert::spki::EncodePublicKey;

    use super::*;
    use crate::BuilderOptions;
    use crate::NoSigner;
    use crate::RsaSigner;
    use crate::Signer;

    #[test]
    fn xar_unsigned_write_read() {
        test_xar_write_read(NoSigner, TrustAll, false, ChecksumAlgo::Sha256);
    }

    #[test]
    fn xar_signed_write_read() {
        use x509_cert::builder::{CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let signing_key = SigningKey::<sha1::Sha1>::new(private_key);
        let public_key_der = signing_key.verifying_key().to_public_key_der().unwrap();
        let serial_number = SerialNumber::from(0_u32);
        let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
        let profile = Profile::Root;
        let subject: Name = "CN=Zar,O=Zar,C=Zar".parse().unwrap();
        let subject_public_key_info =
            SubjectPublicKeyInfoOwned::try_from(public_key_der.as_bytes()).unwrap();
        let actual = subject_public_key_info.to_der().unwrap();
        let builder = CertificateBuilder::new(
            profile,
            serial_number,
            validity,
            subject,
            subject_public_key_info,
            &signing_key,
        )
        .unwrap();
        let cert = builder.build_with_rng::<RsaSignature>(&mut OsRng).unwrap();
        let expected = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .to_vec();
        assert_eq!(expected, actual);
        let verifier = TrustCert(cert.clone());
        let checksum_algo = ChecksumAlgo::Sha1;
        let signer = RsaSigner::with_sha1(signing_key, vec![cert]);
        test_xar_write_read(signer, verifier, true, checksum_algo);
    }

    fn test_xar_write_read<S: Signer, V: RootCertVerifier>(
        signer: S,
        root_cert_verifier: V,
        verify: bool,
        toc_checksum_algo: ChecksumAlgo,
    ) {
        do_not_truncate_assertions();
        let workdir = TempDir::new().unwrap();
        arbtest(|u| {
            let directory = DirBuilder::new().printable_names(true).create(u)?;
            let extra = u.arbitrary()?;
            let xar_path = workdir.path().join("test.xar");
            let mut xar = BuilderOptions::new()
                .toc_checksum_algo(toc_checksum_algo)
                .create(File::create(&xar_path).unwrap(), Some(&signer));
            xar.append_dir_all(
                directory.path(),
                Compression::Gzip,
                |_file: &xml::File<u64>, _: &Path, _: &Path| Ok(Some(extra)),
            )
            .unwrap();
            let expected_files = xar.files().to_vec();
            xar.finish().unwrap();
            let reader = File::open(&xar_path).unwrap();
            let mut xar_archive = ExtendedArchive::<std::fs::File, u64>::with_root_cert_verifier(
                reader,
                &root_cert_verifier,
                ArchiveOptions::new().verify(verify),
            )
            .unwrap();
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

    struct TrustCert(Certificate);

    impl RootCertVerifier for TrustCert {
        fn verify(&self, candidate: &Certificate) -> Result<(), Error> {
            if candidate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                == self
                    .0
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
            {
                return Ok(());
            }
            Err(Error::other("root certificate verification error"))
        }
    }

    #[derive(Default)]
    struct TrustAll;

    impl RootCertVerifier for TrustAll {
        fn verify(&self, _candidate: &Certificate) -> Result<(), Error> {
            Ok(())
        }
    }

    fn do_not_truncate_assertions() {
        NO_TRUNCATE.call_once(|| {
            std::env::set_var("SIMILAR_ASSERTS_MAX_STRING_LENGTH", "0");
        });
    }

    static NO_TRUNCATE: Once = Once::new();
}
