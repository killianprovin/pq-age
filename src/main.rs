use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs::File;
use std::path::PathBuf;

mod crypto;
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
            let path = keystore::config_dir()?.join("key.txt");
            keystore::generate_and_save(&path)?;
            println!("Key saved to {}", path.display());
        }

        Commands::Encrypt { input } => {
            let input = expand(input);
            let key = keystore::load(&keystore::config_dir()?.join("key.txt"))?;
            let output = input.with_extension("pq");
            crypto::encrypt(File::open(&input)?, File::create(&output)?, &key)?;
            println!("Encrypted: {}", output.display());
        }

        Commands::Decrypt { input } => {
            let input = expand(input);
            let key = keystore::load(&keystore::config_dir()?.join("key.txt"))?;
            let output = match input.extension().and_then(|e| e.to_str()) {
                Some("pq") => input.with_extension(""),
                _ => input.with_extension("dec"),
            };
            crypto::decrypt(File::open(&input)?, File::create(&output)?, &key)?;
            println!("Decrypted: {}", output.display());
        }
    }

    Ok(())
}