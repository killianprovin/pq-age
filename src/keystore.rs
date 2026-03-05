use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::exchange;

pub fn config_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".pq-age"))
        .ok_or_else(|| anyhow!("Could not find home directory"))
}

pub fn generate_and_save(dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

    let (secret, public) = exchange::generate_keypair();

    let secret_path = dir.join("identity.key");
    fs::write(&secret_path, general_purpose::STANDARD.encode(secret.as_bytes()))?;
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))?;

    let pub_path = dir.join("identity.pub");
    fs::write(&pub_path, general_purpose::STANDARD.encode(public.as_bytes()))?;
    fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644))?;

    Ok(())
}

pub fn load_secret(path: &PathBuf) -> Result<[u8; 32]> {
    load_32(path, "private key")
}

pub fn load_public(path: &PathBuf) -> Result<[u8; 32]> {
    load_32(path, "public key")
}

fn load_32(path: &PathBuf, label: &str) -> Result<[u8; 32]> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Could not read {}. Run key-gen first.", label))?;
    let bytes = general_purpose::STANDARD
        .decode(content.trim())
        .map_err(|e| anyhow!("Invalid base64 {}: {}", label, e))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{} must be 32 bytes", label))
}