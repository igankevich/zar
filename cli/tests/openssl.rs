use std::fs::create_dir_all;
use std::fs::remove_dir_all;
use std::fs::remove_file;
use std::process::Command;

use arbtest::arbtest;
use random_dir::DirBuilder;
use tempfile::TempDir;
use test_bin::get_test_bin;

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "`openssl` on MacOS doesn't support `-traditional`"
)]
fn sign_verify() {
    let workdir = TempDir::new().unwrap();
    let private_key_pem = workdir.path().join("private-key.pem");
    let cert_pem = workdir.path().join("cert.pem");
    let archive_xar = workdir.path().join("archive.xar");
    let unpack_dir = workdir.path().join("unpacked");
    // Generate PKCS1 PEM-encoded RSA key.
    assert!(Command::new("openssl")
        .arg("genrsa")
        .arg("-traditional")
        .arg("-out")
        .arg(&private_key_pem)
        .arg("2048")
        .status()
        .unwrap()
        .success());
    // Generate PKCS1 certificate.
    assert!(Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-sha1")
        .arg("-days")
        .arg("1")
        .arg("-noenc")
        .arg("-key")
        .arg(&private_key_pem)
        .arg("-out")
        .arg(&cert_pem)
        .arg("-subj")
        .arg("/CN=Zar")
        .status()
        .unwrap()
        .success());
    arbtest(|u| {
        remove_file(&archive_xar).ok();
        let directory = DirBuilder::new()
            .printable_names(true)
            .file_types([
                random_dir::FileType::Regular,
                random_dir::FileType::Directory,
            ])
            .create(u)?;
        remove_dir_all(&unpack_dir).ok();
        create_dir_all(&unpack_dir).unwrap();
        assert!(get_test_bin("zar")
            .arg("--sign")
            .arg(&private_key_pem)
            .arg("--cert")
            .arg(&cert_pem)
            .arg("-cf")
            .arg(&archive_xar)
            .arg(directory.path())
            .status()
            .unwrap()
            .success());
        assert!(get_test_bin("zar")
            .arg("--trust")
            .arg(&cert_pem)
            .arg("-xf")
            .arg(&archive_xar)
            .arg(&unpack_dir)
            .status()
            .unwrap()
            .success());
        Ok(())
    });
}
