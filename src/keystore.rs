use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::{exchange, kem};

pub fn config_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".pq-age"))
        .ok_or_else(|| anyhow!("Could not find home directory"))
}

pub fn generate_and_save(dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

    let (x25519_sk, x25519_pk) = exchange::generate_keypair();
    save(dir.join("identity.key"), x25519_sk.as_bytes(), 0o600)?;
    save(dir.join("identity.pub"), x25519_pk.as_bytes(), 0o644)?;

    let (mlkem_dk, mlkem_ek) = kem::generate_keypair();
    save(dir.join("mlkem.key"), &mlkem_dk, 0o600)?;
    save(dir.join("mlkem.pub"), &mlkem_ek, 0o644)?;

    Ok(())
}

pub fn load_x25519_secret(dir: &PathBuf) -> Result<[u8; 32]> {
    load_n(&dir.join("identity.key"), "X25519 private key")
}

pub fn load_x25519_public(dir: &PathBuf) -> Result<[u8; 32]> {
    load_n(&dir.join("identity.pub"), "X25519 public key")
}

pub fn load_mlkem_secret(dir: &PathBuf) -> Result<[u8; kem::DK_SIZE]> {
    load_n(&dir.join("mlkem.key"), "ML-KEM private key")
}

pub fn load_mlkem_public(dir: &PathBuf) -> Result<[u8; kem::EK_SIZE]> {
    load_n(&dir.join("mlkem.pub"), "ML-KEM public key")
}

fn save(path: PathBuf, bytes: &[u8], mode: u32) -> Result<()> {
    fs::write(&path, general_purpose::STANDARD.encode(bytes))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn load_n<const N: usize>(path: &PathBuf, label: &str) -> Result<[u8; N]> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Could not read {}. Run key-gen first.", label))?;
    let bytes = general_purpose::STANDARD
        .decode(content.trim())
        .map_err(|e| anyhow!("Invalid base64 {}: {}", label, e))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{} has wrong size", label))
}