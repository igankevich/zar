use std::fs::create_dir_all;
use std::fs::remove_dir_all;
use std::process::Command;
use std::sync::Once;

use arbtest::arbtest;
use random_dir::list_dir_all;
use random_dir::DirBuilder;
use tempfile::TempDir;
use test_bin::get_test_bin;

#[test]
fn we_archive_they_extract() {
    archive_extract(|| get_test_bin("zar"), || Command::new("xar"));
}

#[test]
fn they_archive_we_extract() {
    archive_extract(|| Command::new("xar"), || get_test_bin("zar"));
}

fn archive_extract<F1, F2>(mut xar1: F1, mut xar2: F2)
where
    F1: FnMut() -> Command,
    F2: FnMut() -> Command,
{
    do_not_truncate_assertions();
    let workdir = TempDir::new().unwrap();
    let files_xar = workdir.path().join("files.xar");
    let unpack_dir = workdir.path().join("unpacked");
    arbtest(|u| {
        let compression = u.choose(&ALL_CODECS).unwrap();
        let toc_checksum_algo = u.choose(&ALL_CHECKSUM_ALGOS).unwrap();
        let file_checksum_algo = u.choose(&ALL_CHECKSUM_ALGOS).unwrap();
        remove_dir_all(&unpack_dir).ok();
        create_dir_all(&unpack_dir).unwrap();
        let directory = DirBuilder::new()
            .printable_names(true)
            .file_types([
                random_dir::FileType::Regular,
                random_dir::FileType::Directory,
                // On Linux `lchmod` is not supported.
                #[cfg(not(target_os = "linux"))]
                random_dir::FileType::Symlink,
                random_dir::FileType::Fifo,
                // Hard links are extracted as files.
                // Sockets don't work with MacOS's xar.
                // Character and block devices are hard to test on MacOS.
            ])
            .create(u)?;
        unsafe { libc::sync() };
        let mut xar1 = xar1();
        xar1.arg("--compression");
        xar1.arg(compression);
        xar1.arg("--toc-cksum");
        xar1.arg(toc_checksum_algo);
        xar1.arg("--file-cksum");
        xar1.arg(file_checksum_algo);
        xar1.arg("-cf");
        xar1.arg(&files_xar);
        xar1.arg(".");
        xar1.current_dir(directory.path());
        let status = xar1.status().unwrap();
        assert!(status.success());
        let mut xar2 = xar2();
        xar2.arg("-xf");
        xar2.arg(&files_xar);
        xar2.current_dir(&unpack_dir);
        let status = xar2.status().unwrap();
        assert!(status.success());
        unsafe { libc::sync() };
        let files1 = list_dir_all(directory.path()).unwrap();
        let files2 = list_dir_all(&unpack_dir).unwrap();
        #[cfg(target_os = "macos")]
        let (files1, files2) = {
            let mut files1 = files1;
            let mut files2 = files2;
            for (file1, file2) in files1.iter_mut().zip(files2.iter_mut()) {
                if file1.metadata.mtime != file2.metadata.mtime {
                    eprintln!(
                        "WARNING: wrong mtime: {} != {}",
                        file1.metadata.mtime, file1.metadata.mtime
                    );
                    file1.metadata.mtime = 0;
                    file2.metadata.mtime = 0;
                }
            }
            (files1, files2)
        };
        similar_asserts::assert_eq!(
            files1,
            files2,
            "compression = {compression:?}, \
            toc_checksum_algo = {toc_checksum_algo:?}, \
            file_checksum_algo = {file_checksum_algo:?}"
        );
        Ok(())
    });
}

#[cfg(target_os = "macos")]
const ALL_CODECS: [&str; 3] = ["none", "gzip", "bzip2"];
#[cfg(target_os = "linux")]
const ALL_CODECS: [&str; 4] = ["none", "gzip", "bzip2", "xz"];

#[cfg(target_os = "macos")]
const ALL_CHECKSUM_ALGOS: [&str; 3] = ["sha1", "sha256", "sha512"];

#[cfg(target_os = "linux")]
const ALL_CHECKSUM_ALGOS: [&str; 2] = ["md5", "sha1"];

fn do_not_truncate_assertions() {
    NO_TRUNCATE.call_once(|| {
        std::env::set_var("SIMILAR_ASSERTS_MAX_STRING_LENGTH", "0");
    });
}

static NO_TRUNCATE: Once = Once::new();
