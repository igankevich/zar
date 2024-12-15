use std::fs::File;
use std::io::Error;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use clap::Parser;
use zar::DecodeRsaPrivateKey;
use zar::DecodeRsaPublicKey;

#[derive(Parser)]
#[clap(arg_required_else_help = true, about = "XAR archiver and unarchiver")]
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
    #[arg(value_enum, long = "compression")]
    compression: Option<Compression>,
    /// Use LZMA compression.
    #[arg(short = 'a')]
    lzma: bool,
    #[arg(short = 'j')]
    bzip2: bool,
    #[arg(short = 'z')]
    gzip: bool,
    /// XML header checksum.
    #[arg(long = "toc-cksum", default_value = "sha256")]
    toc_checksum: ChecksumAlgo,
    /// File checksum.
    #[arg(long = "file-cksum", default_value = "sha256")]
    file_checksum: ChecksumAlgo,
    /// Path to a file with DER-encoded RSA private key.
    #[arg(long = "sign")]
    signing_key_file: Option<PathBuf>,
    /// Path to a file with DER-encoded RSA public key.
    #[arg(long = "verify")]
    verifying_key_file: Option<PathBuf>,
    /// Preserve files' last modification time.
    #[arg(long = "preserve-mtime", default_value = "true")]
    preserve_mtime: bool,
    /// Preserve files' owner.
    #[arg(long = "preserve-owner")]
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
        use Compression::*;
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
    let options = zar::BuilderOptions::new()
        .toc_checksum_algo(args.toc_checksum.into())
        .file_checksum_algo(args.file_checksum.into());
    let mut builder = match args.signing_key_file {
        Some(ref signing_key_file) => {
            let private_key =
                zar::RsaPrivateKey::read_pkcs1_der_file(signing_key_file).map_err(Error::other)?;
            let signer = zar::RsaSigner::new(private_key);
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
    let verifier = match args.verifying_key_file {
        Some(ref verifying_key_file) => {
            let public_key =
                zar::RsaPublicKey::read_pkcs1_der_file(verifying_key_file).map_err(Error::other)?;
            let verifier = zar::RsaVerifier::new(public_key);
            Some(verifier)
        }
        None => None,
    };
    let options = zar::ArchiveOptions::new()
        .check_toc(args.check_toc)
        .check_files(args.check_files)
        .preserve_mtime(args.preserve_mtime)
        .preserve_owner(args.preserve_owner.unwrap_or_else(can_chown));
    let archive = zar::Archive::new(file, verifier.as_ref(), options)?;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Compression {
    No,
    Gzip,
    Bzip2,
    Lzma,
    Xz,
}

impl FromStr for Compression {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Compression::No),
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
            Compression::No => zar::Compression::None,
            Compression::Gzip => zar::Compression::Gzip,
            Compression::Bzip2 => zar::Compression::Bzip2,
            Compression::Lzma => panic!("lzma is not supported"),
            Compression::Xz => zar::Compression::Xz,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
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
