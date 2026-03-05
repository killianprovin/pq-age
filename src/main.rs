use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

mod crypto;
mod exchange;
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
        /// Recipient public key file (default: own identity.pub)
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
            let pub_path = recipient.map(expand).unwrap_or_else(|| dir.join("identity.pub"));
            let recipient_pub = keystore::load_public(&pub_path)?;

            let (eph_pub, sym_key) = exchange::encapsulate(&recipient_pub);

            let output = input.with_extension("pq");
            let mut out = File::create(&output)?;
            out.write_all(&eph_pub)?;
            crypto::encrypt(File::open(&input)?, out, &sym_key)?;
            println!("Encrypted: {}", output.display());
        }

        Commands::Decrypt { input } => {
            let input = expand(input);
            let secret = keystore::load_secret(&keystore::config_dir()?.join("identity.key"))?;

            let mut f = File::open(&input)?;
            let mut eph_pub = [0u8; 32];
            f.read_exact(&mut eph_pub)?;
            let sym_key = exchange::decapsulate(&eph_pub, &secret);

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