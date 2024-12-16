# zar

[![Crates.io Version](https://img.shields.io/crates/v/zar)](https://crates.io/crates/zar)
[![Docs](https://docs.rs/zar/badge.svg)](https://docs.rs/zar)
[![dependency status](https://deps.rs/repo/github/igankevich/zar/status.svg)](https://deps.rs/repo/github/igankevich/zar)

XAR archive reader/writer library that is fuzz-tested agains MacOS `xar`.
Supports signing and verifying archives.


## Installation

The easiest way to use `zar` is via command line interface.

```bash
cargo install zar-cli
```

## Usage


### As a command-line application

```bash
# archive tmp dir
zar -cf tmp.xar /tmp

# extract the archive
zar -xf tmp.xar /tmp/extracted

# archive tmp dir and sign the archive
openssl genrsa -traditional -out private-key.pem 2048
openssl req -x509 -sha1 -days 1 -noenc -key private-key.pem -out cert.pem -subj /CN=Zar
zar --sign private-key.pem --cert cert.pem -cf tmp.xar /tmp

# verify and extract the archive
zar --trust cert.pem -xf tmp.xar /tmp/extracted
```


### As a library

```rust
use std::fs::File;
use std::io::Error;

use zar::NoSigner;

fn create_archive() -> Result<(), Error> {
    let file = File::create("archive.xar")?;
    let mut builder = zar::UnsignedBuilder::new_unsigned(file);
    builder.append_dir_all("/tmp", zar::Compression::default(), zar::no_extra_contents)?;
    builder.finish()?;
    Ok(())
}

fn extract_archive() -> Result<(), Error> {
    let file = File::open("archive.xar")?;
    let mut archive = zar::Archive::new(file)?;
    for i in 0..archive.num_entries() {
        let mut entry = archive.entry(i);
        println!("{:?}", entry.file());
        if let Some(mut reader) = entry.reader()? {
            // read the entry...
        }
    }
    Ok(())
}
```
