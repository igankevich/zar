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
#[cfg_attr(miri, ignore)]
fn we_archive_they_extract() {
    archive_extract(|| get_test_bin("zar"), || Command::new("xar"));
}

#[test]
#[cfg_attr(miri, ignore)]
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
        remove_dir_all(&unpack_dir).ok();
        create_dir_all(&unpack_dir).unwrap();
        let directory = DirBuilder::new()
            .printable_names(true)
            .file_types([
                random_dir::FileType::Regular,
                random_dir::FileType::Directory,
                random_dir::FileType::Symlink,
                random_dir::FileType::HardLink,
                // Socket doesn't work with MacOS's xar.
                #[cfg(not(target_os = "macos"))]
                random_dir::FileType::Socket,
                random_dir::FileType::Fifo,
                // character and block devices are hard to test on macos
            ])
            .create(u)?;
        let mut xar1 = xar1();
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
        similar_asserts::assert_eq!(files1, files2);
        Ok(())
    });
}

fn do_not_truncate_assertions() {
    NO_TRUNCATE.call_once(|| {
        std::env::set_var("SIMILAR_ASSERTS_MAX_STRING_LENGTH", "0");
    });
}

static NO_TRUNCATE: Once = Once::new();
