use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::Aead, KeyInit};
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
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
    },
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

        Commands::Encrypt { input } => {
            let key_path = get_config_path()?.join("key.txt");
            let key_bytes = load_key(&key_path)?;
            
            encrypt_file(&input, &key_bytes)?;
            println!("File encrypted successfully: {:?}", input.with_extension("pq"));
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

fn load_key(path: &PathBuf) -> Result<Vec<u8>> {
    let content = fs::read_to_string(path)
        .context("Could not read key file. Run gen-key first.")?;
    
    general_purpose::STANDARD.decode(content.trim())
        .map_err(|e| anyhow!("Invalid base64 key: {}", e))
}

fn encrypt_file(input_path: &PathBuf, key_bytes: &[u8]) -> Result<()> {
    let data = fs::read(input_path).context("Failed to read input file")?;
    
    let cipher = ChaCha20Poly1305::new_from_slice(key_bytes)
        .map_err(|_| anyhow!("Invalid key length"))?;
    
    // Generate a random 12-byte nonce
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data.as_ref())
        .map_err(|_| anyhow!("Encryption failed"))?;

    // Combine nonce + ciphertext
    let mut output_data = nonce_bytes.to_vec();
    output_data.extend_from_slice(&ciphertext);

    let output_path = input_path.with_extension("pq");
    fs::write(output_path, output_data)?;

    Ok(())
}