use std::fs::File;
use std::io::Error;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

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
    let file = File::create(&args.file_name)?;
    let mut builder = zar::Builder::new(file);
    for path in args.paths.iter() {
        builder.append_dir_all(path, zar::Compression::Gzip)?;
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
    let archive = zar::Archive::new(file)?;
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
