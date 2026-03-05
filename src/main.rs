use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;

mod crypto;
mod exchange;
mod identity;
mod kem;
mod keystore;
mod sign;

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
    /// Generate a new identity (private + public key)
    KeyGen,
    /// Encrypt a file for a recipient
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        /// Recipient: contact name or path to .pub file (default: self)
        #[arg(short, long)]
        recipient: Option<String>,
    },
    /// Decrypt a .pq file
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Manage known contacts (public keys)
    Contacts {
        #[command(subcommand)]
        action: ContactAction,
    },
}

#[derive(Subcommand)]
enum ContactAction {
    /// List all known contacts
    List,
    /// Add a contact (paste their public key)
    Add {
        /// Contact name (e.g. alice)
        name: String,
        /// Path to a .pub file (if omitted, reads from stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Show a contact's public key and fingerprint
    Show { name: String },
    /// Remove a contact
    Remove { name: String },
    /// Show your own public key
    #[command(name = "me")]
    Me,
}

/// File format (v1):
///   version(1) | eph_x25519(32) | mlkem_ct(1088) | sender_fp(32) |
///   ed25519_sig(64) | mldsa_sig(3309) | streaming_payload
const HEADER_UNSIGNED_SIZE: usize = 1 + 32 + kem::CT_SIZE + 32; // 1153

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::KeyGen => {
            let dir = keystore::config_dir()?;
            let (_id, rec) = keystore::generate_and_save(&dir)?;
            println!("Identity saved to {}", dir.display());
            println!("Fingerprint: {}", hex::encode(&rec.fingerprint()[..8]));
            println!(
                "\nYour public key (share it):\n{}\n",
                rec.encode()
            );
        }

        Commands::Encrypt { input, recipient } => {
            let input = expand(input);
            let dir = keystore::config_dir()?;

            // Load sender identity for signing
            let sender_id = keystore::load_identity(&dir)?;
            let sender_rec = sender_id.recipient();
            let sender_fp = sender_rec.fingerprint();

            // Resolve recipient: name, path, or default to self
            let rec = match recipient {
                Some(r) => keystore::resolve_recipient(&dir, &r)?,
                None => keystore::resolve_recipient(&dir, "self")?,
            };

            // Key exchange
            let (eph_x25519, mlkem_ct, sym_key) =
                exchange::encapsulate(&rec.x25519_pk, &rec.mlkem_ek);

            // Build unsigned header for signing
            let mut header = Vec::with_capacity(HEADER_UNSIGNED_SIZE);
            header.push(1u8); // version
            header.extend_from_slice(&eph_x25519);
            header.extend_from_slice(&mlkem_ct);
            header.extend_from_slice(&sender_fp);

            // Sign the header
            let sig = sign::sign(&sender_id.ed25519_seed, &sender_id.mldsa_seed, &header);

            // Write file
            let output = input.with_extension("pq");
            let mut out = File::create(&output)?;
            out.write_all(&header)?;
            out.write_all(&sig)?;
            crypto::encrypt(File::open(&input)?, out, &sym_key)?;

            println!("Encrypted: {}", output.display());
        }

        Commands::Decrypt { input } => {
            let input = expand(input);
            // If the user passed the original file, try the .pq version
            let input = if input.extension().and_then(|e| e.to_str()) != Some("pq") {
                let pq = input.with_extension("pq");
                if pq.exists() {
                    pq
                } else {
                    return Err(anyhow!(
                        "Expected a .pq file. Neither {:?} nor {:?} found.",
                        input.file_name().unwrap_or_default(),
                        pq.file_name().unwrap_or_default(),
                    ));
                }
            } else {
                input
            };
            let dir = keystore::config_dir()?;

            let mut f = File::open(&input)?;

            // Read header
            let mut header = vec![0u8; HEADER_UNSIGNED_SIZE];
            f.read_exact(&mut header)?;

            if header[0] != 1 {
                return Err(anyhow!("Unsupported file version {}", header[0]));
            }

            let eph_x25519: [u8; 32] = header[1..33].try_into().unwrap();
            let mlkem_ct: [u8; kem::CT_SIZE] = header[33..33 + kem::CT_SIZE].try_into().unwrap();
            let sender_fp: [u8; 32] =
                header[33 + kem::CT_SIZE..33 + kem::CT_SIZE + 32].try_into().unwrap();

            // Read signature
            let mut sig = vec![0u8; sign::COMBINED_SIG_SIZE];
            f.read_exact(&mut sig)?;

            // Auto-lookup sender in keyring
            let fp_hex = hex::encode(&sender_fp[..8]);
            match keystore::find_by_fingerprint(&dir, &sender_fp)? {
                Some((name, sender_rec)) => {
                    sign::verify(
                        &sender_rec.ed25519_pk,
                        &sender_rec.mldsa_vk,
                        &header,
                        &sig,
                    )?;
                    println!("Sender: {} ({})", name, fp_hex);
                    println!("Signature verified ✓");
                }
                None => {
                    println!(
                        "Warning: unknown sender (fingerprint: {})",
                        fp_hex
                    );
                    println!("  Use `pq-age contacts add <name>` to add them.");
                }
            }

            // Decapsulate
            let id = keystore::load_identity(&dir)?;
            let sym_key = exchange::decapsulate(
                &eph_x25519,
                &id.x25519_sk,
                &mlkem_ct,
                &id.mlkem_seed,
            );

            let output = match input.extension().and_then(|e| e.to_str()) {
                Some("pq") => input.with_extension(""),
                _ => input.with_extension("dec"),
            };
            crypto::decrypt(f, File::create(&output)?, &sym_key)?;
            println!("Decrypted: {}", output.display());
        }

        Commands::Contacts { action } => {
            let dir = keystore::config_dir()?;

            match action {
                ContactAction::List => {
                    let contacts = keystore::list_contacts(&dir)?;
                    if contacts.is_empty() {
                        println!("No contacts yet. Use `pq-age contacts add <name>`.");
                    } else {
                        println!("{:<16} {}", "NAME", "FINGERPRINT");
                        println!("{:<16} {}", "----", "-----------");
                        for (name, rec) in &contacts {
                            println!(
                                "{:<16} {}",
                                name,
                                hex::encode(&rec.fingerprint()[..8])
                            );
                        }
                        println!("\n{} contact(s)", contacts.len());
                    }
                }

                ContactAction::Add { name, file } => {
                    let pubkey_str = if let Some(path) = file {
                        std::fs::read_to_string(expand(path))?
                    } else {
                        println!("Paste the public key (pq-age-pub-1...):");
                        let mut line = String::new();
                        io::stdin().lock().read_line(&mut line)?;
                        line
                    };
                    let line = pubkey_str
                        .lines()
                        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
                        .ok_or_else(|| anyhow!("No public key found in input"))?;
                    let rec = identity::Recipient::decode(line)?;
                    let fp = hex::encode(&rec.fingerprint()[..8]);
                    keystore::save_contact(&dir, &name, &rec)?;
                    println!("Added contact '{}' (fingerprint: {})", name, fp);
                }

                ContactAction::Show { name } => {
                    let rec = keystore::resolve_recipient(&dir, &name)?;
                    let fp = hex::encode(&rec.fingerprint()[..8]);
                    println!("Contact: {}", name);
                    println!("Fingerprint: {}", fp);
                    println!("\n{}", rec.encode());
                }

                ContactAction::Remove { name } => {
                    keystore::remove_contact(&dir, &name)?;
                    println!("Removed contact '{}'", name);
                }

                ContactAction::Me => {
                    let id = keystore::load_identity(&dir)?;
                    let rec = id.recipient();
                    let fp = hex::encode(&rec.fingerprint()[..8]);
                    println!("Fingerprint: {}", fp);
                    println!("\n{}", rec.encode());
                }
            }
        }
    }

    Ok(())
}