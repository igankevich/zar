use std::fs::File;
use std::io::Error;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::from_utf8;
use std::str::FromStr;

use clap::Parser;
use clap::ValueEnum;
use x509_cert::der::Decode;
use x509_cert::Certificate;
use zar::rsa::pkcs1::DecodeRsaPrivateKey;

#[derive(Parser)]
#[clap(arg_required_else_help = true, about = "XAR archiver and extractor")]
struct Args {
    /// Create an archive.
    #[arg(short = 'c')]
    create: bool,

    /// Extract an archive.
    #[arg(short = 'x')]
    extract: bool,

    /// List an archive.
    #[arg(short = 't')]
    list: bool,

    /// Verbose output.
    #[arg(short = 'v')]
    verbose: bool,

    /// Extract to specified directory instead of the current directory.
    #[arg(short = 'C')]
    chdir: Option<PathBuf>,

    /// An archive.
    #[arg(short = 'f')]
    file_name: PathBuf,

    /// Use specified compression codec.
    #[arg(value_enum, long = "compression", value_name = "CODEC")]
    compression: Option<Compression>,

    /// Use LZMA compression.
    #[arg(short = 'a')]
    lzma: bool,

    /// Use BZIP2 compression.
    #[arg(short = 'j')]
    bzip2: bool,

    /// Use GZIP compression.
    #[arg(short = 'z')]
    gzip: bool,

    /// XML header checksum.
    #[arg(long = "toc-cksum", default_value = "sha1", value_name = "ALGO")]
    toc_checksum: ChecksumAlgo,

    /// File checksum.
    #[arg(long = "file-cksum", default_value = "sha1", value_name = "ALGO")]
    file_checksum: ChecksumAlgo,

    /// Path to a file with PKCS1 DER/PEM-encoded RSA private key.
    #[arg(long = "sign", value_name = "FILE")]
    signing_key_file: Option<PathBuf>,

    /// PKCS1 PEM/DER-encoded X509 certificate chain to include in the archive.
    ///
    /// The first certificate must correspond to the signing key.
    /// The argument can be repeated to include multiple invidvidual certificates.
    #[arg(long = "cert", value_name = "CERT")]
    certs: Vec<PathBuf>,

    /// DER-encoded X509 root certificates to verify the archive's certificate chain on reading.
    #[arg(long = "trust", value_name = "CERT")]
    trusted_certs: Vec<PathBuf>,

    /// Preserve files' last modification time.
    #[arg(long = "preserve-mtime", default_value = "true")]
    preserve_mtime: bool,

    /// Preserve files' owner.
    #[arg(long = "preserve-owner", action = clap::ArgAction::SetTrue)]
    preserve_owner: Option<bool>,

    /// Verify table of contents' checksum.
    #[arg(long = "check-toc", default_value = "true")]
    check_toc: bool,

    /// Verify files' checksums.
    #[arg(long = "check-files", default_value = "true")]
    check_files: bool,

    /// Files.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "FILE"
    )]
    paths: Vec<PathBuf>,
}

impl Args {
    fn command(&self) -> Result<Command, Error> {
        const T: bool = true;
        const F: bool = false;
        match (self.create, self.extract, self.list) {
            (T, F, F) => Ok(Command::Create),
            (F, T, F) => Ok(Command::Extract),
            (F, F, T) => Ok(Command::List),
            (F, F, F) => Err(Error::other("no command specified")),
            (..) => Err(Error::other("conflicting commands specified")),
        }
    }
    fn compression(&self) -> Result<Compression, Error> {
        use Compression::Bzip2;
        use Compression::Gzip;
        use Compression::Lzma;
        const T: bool = true;
        const F: bool = false;
        match (self.gzip, self.bzip2, self.lzma, self.compression) {
            (_, F, F, Some(Gzip)) => Ok(Gzip),
            (T, F, F, None) => Ok(Gzip),
            (F, _, F, Some(Bzip2)) => Ok(Bzip2),
            (F, T, F, None) => Ok(Bzip2),
            (F, F, _, Some(Lzma)) => Ok(Lzma),
            (F, F, T, None) => Ok(Lzma),
            (F, F, F, Some(c)) => Ok(c),
            (F, F, F, None) => Ok(Gzip),
            (..) => Err(Error::other("conflicting compression codecs specified")),
        }
    }
}

fn main() -> ExitCode {
    match do_main() {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn do_main() -> Result<ExitCode, Error> {
    let args = Args::parse();
    match args.command()? {
        Command::Create => create(args),
        Command::Extract => extract(args),
        Command::List => list(args),
    }
}

fn create(args: Args) -> Result<ExitCode, Error> {
    let compression: zar::Compression = args.compression()?.into();
    let file = File::create(&args.file_name)?;
    let toc_checksum_algo: zar::ChecksumAlgo = args.toc_checksum.into();
    let options = zar::BuilderOptions::new()
        .toc_checksum_algo(toc_checksum_algo)
        .file_checksum_algo(args.file_checksum.into());
    let mut builder = match args.signing_key_file {
        Some(ref signing_key_file) => {
            let signing_key_bytes = std::fs::read(signing_key_file)?;
            let private_key = if signing_key_bytes.get(0..4) == Some(b"----") {
                let s =
                    from_utf8(&signing_key_bytes).map_err(|_| Error::other("non-utf8 pem file"))?;
                zar::rsa::RsaPrivateKey::from_pkcs1_pem(s)
            } else {
                zar::rsa::RsaPrivateKey::from_pkcs1_der(&signing_key_bytes)
            }
            .map_err(Error::other)?;
            let mut certs = Vec::new();
            for cert_path in args.certs.iter() {
                certs.extend(read_cert_chain(cert_path)?);
            }
            let signer = zar::RsaSigner::new(toc_checksum_algo, private_key, certs)?;
            options.create(file, Some(signer))
        }
        None => options.create(file, None),
    };
    for path in args.paths.iter() {
        builder.append_dir_all(path, compression, zar::no_extra_contents)?;
    }
    builder.finish()?;
    Ok(ExitCode::SUCCESS)
}

fn extract(args: Args) -> Result<ExitCode, Error> {
    if args.paths.len() > 1 {
        return Err(Error::other("multiple output directories specified"));
    }
    let dest_dir = args
        .paths
        .first()
        .map(|x| x.as_path())
        .unwrap_or(Path::new("."));
    let file = File::open(&args.file_name)?;
    let (verifier, verify) = {
        let mut certs = Vec::new();
        for cert_path in args.trusted_certs.iter() {
            certs.extend(read_cert_chain(cert_path)?);
        }
        let verify = !certs.is_empty();
        (zar::TrustCerts::new(certs), verify)
    };
    let options = zar::ArchiveOptions::new()
        .check_toc(args.check_toc)
        .check_files(args.check_files)
        .preserve_mtime(args.preserve_mtime)
        .preserve_owner(args.preserve_owner.unwrap_or_else(can_chown))
        .verify(verify);
    let archive = zar::Archive::with_root_cert_verifier(file, &verifier, options)?;
    archive.extract(dest_dir)?;
    Ok(ExitCode::SUCCESS)
}

fn list(_args: Args) -> Result<ExitCode, Error> {
    Ok(ExitCode::SUCCESS)
}

enum Command {
    Create,
    Extract,
    List,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Compression {
    None,
    Gzip,
    Bzip2,
    Lzma,
    Xz,
}

impl FromStr for Compression {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Compression::None),
            "gzip" => Ok(Compression::Gzip),
            "bzip2" => Ok(Compression::Bzip2),
            "lzma" => Ok(Compression::Lzma),
            "xz" => Ok(Compression::Xz),
            _ => Err(Error::other("invalid compression")),
        }
    }
}

impl From<Compression> for zar::Compression {
    fn from(other: Compression) -> Self {
        match other {
            Compression::None => zar::Compression::None,
            Compression::Gzip => zar::Compression::Gzip,
            Compression::Bzip2 => zar::Compression::Bzip2,
            Compression::Lzma => panic!("lzma is not supported"),
            Compression::Xz => zar::Compression::Xz,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ChecksumAlgo {
    Md5,
    Sha1,
    #[default]
    Sha256,
    Sha512,
}

impl FromStr for ChecksumAlgo {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "md5" => Ok(ChecksumAlgo::Md5),
            "sha1" => Ok(ChecksumAlgo::Sha1),
            "sha256" => Ok(ChecksumAlgo::Sha256),
            "sha512" => Ok(ChecksumAlgo::Sha512),
            _ => Err(Error::other("invalid checksum algorithm")),
        }
    }
}

impl From<ChecksumAlgo> for zar::ChecksumAlgo {
    fn from(other: ChecksumAlgo) -> Self {
        match other {
            ChecksumAlgo::Md5 => zar::ChecksumAlgo::Md5,
            ChecksumAlgo::Sha1 => zar::ChecksumAlgo::Sha1,
            ChecksumAlgo::Sha256 => zar::ChecksumAlgo::Sha256,
            ChecksumAlgo::Sha512 => zar::ChecksumAlgo::Sha512,
        }
    }
}

#[cfg(target_os = "linux")]
fn can_chown() -> bool {
    use caps::*;
    has_cap(None, CapSet::Permitted, Capability::CAP_CHOWN).unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn can_chown() -> bool {
    libc::getuid() == 0
}

fn read_cert_chain(path: &Path) -> Result<Vec<Certificate>, Error> {
    let bytes = std::fs::read(path)?;
    if bytes.get(0..4) == Some(b"----") {
        Ok(Certificate::load_pem_chain(&bytes).map_err(Error::other)?)
    } else {
        Ok(vec![Certificate::from_der(&bytes).map_err(Error::other)?])
    }
}
