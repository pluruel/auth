// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
//
// Generate an Ed25519 keypair for JWT signing. Writes
// `<dir>/jwt_private.pem` (PKCS8) and `<dir>/jwt_public.pem` (SPKI).
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let mut dir = PathBuf::from("keys");
    let mut force = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-d" | "--dir" => dir = PathBuf::from(args.next().expect("--dir needs a value")),
            "-f" | "--force" => force = true,
            "-h" | "--help" => {
                println!("usage: keygen [--dir <path>] [--force]");
                return Ok(());
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
    }

    let priv_path = dir.join("jwt_private.pem");
    let pub_path = dir.join("jwt_public.pem");

    if !force {
        if priv_path.exists() {
            anyhow::bail!(
                "{} already exists (pass --force to overwrite)",
                priv_path.display()
            );
        }
        if pub_path.exists() {
            anyhow::bail!(
                "{} already exists (pass --force to overwrite)",
                pub_path.display()
            );
        }
    }

    fs::create_dir_all(&dir)?;

    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();

    let priv_pem = signing.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let pub_pem = verifying.to_public_key_pem(LineEnding::LF)?;

    write_file(&priv_path, &priv_pem, 0o600)?;
    write_file(&pub_path, &pub_pem, 0o644)?;

    println!("wrote {}", priv_path.display());
    println!("wrote {}", pub_path.display());
    Ok(())
}

fn write_file(path: &PathBuf, contents: &str, mode: u32) -> anyhow::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}
