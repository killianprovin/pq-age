use anyhow::{anyhow, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::identity::{Identity, Recipient};

pub fn config_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".pq-age"))
        .ok_or_else(|| anyhow!("Could not find home directory"))
}

pub fn recipients_dir(config: &Path) -> PathBuf {
    config.join("recipients")
}

fn identities_path(dir: &Path) -> PathBuf {
    dir.join("identities.txt")
}

pub fn generate_and_save(dir: &Path) -> Result<(Identity, Recipient)> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

    let (id, rec) = Identity::generate();

    let path = identities_path(dir);
    fs::write(&path, format!("{}\n", id.encode()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

    // Save own public key
    let pub_path = dir.join("recipient.pub");
    fs::write(&pub_path, format!("{}\n", rec.encode()))?;
    fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644))?;

    // Also add self to keyring as "self"
    let rdir = recipients_dir(dir);
    fs::create_dir_all(&rdir)?;
    fs::write(rdir.join("self.pub"), format!("{}\n", rec.encode()))?;

    Ok((id, rec))
}

pub fn load_identity(dir: &Path) -> Result<Identity> {
    let path = identities_path(dir);
    let content = fs::read_to_string(&path)
        .with_context(|| "Could not read identity. Run key-gen first.")?;
    let line = content
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow!("No identity found in {}", path.display()))?;
    Identity::decode(line)
}

pub fn load_recipient_file(path: &Path) -> Result<Recipient> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Could not read recipient from {}", path.display()))?;
    let line = content
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow!("No recipient found in {}", path.display()))?;
    Recipient::decode(line)
}

// ── Keyring (recipients/) ──────────────────────────────────────────

/// Resolve a recipient: either a name from the keyring or a file path.
pub fn resolve_recipient(config: &Path, name_or_path: &str) -> Result<Recipient> {
    // If it looks like a path (contains / or . or ~), load as file
    let p = Path::new(name_or_path);
    if p.is_absolute() || name_or_path.contains('/') || name_or_path.ends_with(".pub") {
        return load_recipient_file(p);
    }
    // Otherwise treat as a keyring name
    let path = recipients_dir(config).join(format!("{}.pub", name_or_path));
    if path.exists() {
        load_recipient_file(&path)
    } else {
        Err(anyhow!(
            "Unknown contact '{}'. Use `pq-age contacts add {}` first.",
            name_or_path,
            name_or_path
        ))
    }
}

/// Save a recipient to the keyring under the given name.
pub fn save_contact(config: &Path, name: &str, rec: &Recipient) -> Result<()> {
    let rdir = recipients_dir(config);
    fs::create_dir_all(&rdir)?;
    let path = rdir.join(format!("{}.pub", name));
    fs::write(&path, format!("{}\n", rec.encode()))?;
    Ok(())
}

/// Remove a contact from the keyring.
pub fn remove_contact(config: &Path, name: &str) -> Result<()> {
    let path = recipients_dir(config).join(format!("{}.pub", name));
    if !path.exists() {
        return Err(anyhow!("Contact '{}' not found", name));
    }
    fs::remove_file(&path)?;
    Ok(())
}

/// List all contacts: (name, recipient).
pub fn list_contacts(config: &Path) -> Result<Vec<(String, Recipient)>> {
    let rdir = recipients_dir(config);
    if !rdir.exists() {
        return Ok(vec![]);
    }
    let mut contacts = Vec::new();
    for entry in fs::read_dir(&rdir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("pub") {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
            match load_recipient_file(&path) {
                Ok(rec) => contacts.push((name, rec)),
                Err(e) => eprintln!("Warning: skipping {}: {}", path.display(), e),
            }
        }
    }
    contacts.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(contacts)
}

/// Find a contact by fingerprint prefix (returns name + recipient).
pub fn find_by_fingerprint(config: &Path, fp: &[u8; 32]) -> Result<Option<(String, Recipient)>> {
    let contacts = list_contacts(config)?;
    for (name, rec) in contacts {
        if rec.fingerprint() == *fp {
            return Ok(Some((name, rec)));
        }
    }
    Ok(None)
}