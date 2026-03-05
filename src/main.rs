use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pq-age", version = "0.1.0", about = "Post-Quantum file encryption tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    KeyGen,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::KeyGen => {
            let config_dir = get_config_path()?;
            ensure_directory(&config_dir)?;
            
            let key_path = config_dir.join("key.txt");
            save_new_key(&key_path)?;
            
            println!("Identity generated at: {:?}", key_path);
        }
    }

    Ok(())
}

fn get_config_path() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".pq-age"))
        .ok_or_else(|| anyhow!("Could not find home directory"))
}

fn ensure_directory(path: &PathBuf) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn save_new_key(path: &PathBuf) -> Result<()> {
    let key: [u8; 32] = rand::random();
    let encoded = general_purpose::STANDARD.encode(key);

    fs::write(path, encoded)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    
    Ok(())
}