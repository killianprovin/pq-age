use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub fn config_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".pq-age"))
        .ok_or_else(|| anyhow!("Could not find home directory"))
}

pub fn generate_and_save(path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let key: [u8; 32] = rand::random();
    fs::write(path, general_purpose::STANDARD.encode(key))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn load(path: &PathBuf) -> Result<[u8; 32]> {
    let content = fs::read_to_string(path)
        .context("Could not read key file. Run key-gen first.")?;
    let bytes = general_purpose::STANDARD
        .decode(content.trim())
        .map_err(|e| anyhow!("Invalid key: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("Key must be 32 bytes"))
}
