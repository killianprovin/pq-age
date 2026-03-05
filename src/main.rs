use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

mod crypto;
mod exchange;
mod kem;
mod keystore;

fn expand(path: PathBuf) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    path
}

#[derive(Parser)]
#[command(name = "pq-age", version, about = "Post-quantum file encryption")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    KeyGen,
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        /// Recipient key directory (default: own ~/.pq-age)
        #[arg(short, long)]
        recipient: Option<PathBuf>,
    },
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::KeyGen => {
            let dir = keystore::config_dir()?;
            keystore::generate_and_save(&dir)?;
            println!("Identity saved to {}", dir.display());
        }

        Commands::Encrypt { input, recipient } => {
            let input = expand(input);
            let dir = keystore::config_dir()?;
            let rec = recipient.map(expand).unwrap_or(dir);

            let x25519_pub = keystore::load_x25519_public(&rec)?;
            let mlkem_pub = keystore::load_mlkem_public(&rec)?;
            let (eph_x25519, mlkem_ct, sym_key) = exchange::encapsulate(&x25519_pub, &mlkem_pub);

            let output = input.with_extension("pq");
            let mut out = File::create(&output)?;
            out.write_all(&eph_x25519)?;
            out.write_all(&mlkem_ct)?;
            crypto::encrypt(File::open(&input)?, out, &sym_key)?;
            println!("Encrypted: {}", output.display());
        }

        Commands::Decrypt { input } => {
            let input = expand(input);
            let dir = keystore::config_dir()?;

            let mut f = File::open(&input)?;
            let mut eph_x25519 = [0u8; 32];
            let mut mlkem_ct = [0u8; kem::CT_SIZE];
            f.read_exact(&mut eph_x25519)?;
            f.read_exact(&mut mlkem_ct)?;

            let x25519_sk = keystore::load_x25519_secret(&dir)?;
            let mlkem_dk = keystore::load_mlkem_secret(&dir)?;
            let sym_key = exchange::decapsulate(&eph_x25519, &x25519_sk, &mlkem_ct, &mlkem_dk);

            let output = match input.extension().and_then(|e| e.to_str()) {
                Some("pq") => input.with_extension(""),
                _ => input.with_extension("dec"),
            };
            crypto::decrypt(f, File::create(&output)?, &sym_key)?;
            println!("Decrypted: {}", output.display());
        }
    }

    Ok(())
}