use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};

use crate::{exchange, kem, sign};

const VERSION: u8 = 1;
const SECRET_PREFIX: &str = "PQ-AGE-SECRET-KEY-1";
const PUBLIC_PREFIX: &str = "pq-age-pub-1";
const CHECKSUM_LEN: usize = 4;

// Seed sizes (compact secret key representation)
const X25519_SK_SIZE: usize = 32;
const MLKEM_SEED_SIZE: usize = kem::DK_SIZE; // 64
const ED25519_SEED_SIZE: usize = 32;
const MLDSA_SEED_SIZE: usize = 32;
const SECRET_PAYLOAD: usize = 1 + X25519_SK_SIZE + MLKEM_SEED_SIZE + ED25519_SEED_SIZE + MLDSA_SEED_SIZE;

// Public key sizes
const X25519_PK_SIZE: usize = 32;
const MLKEM_EK_SIZE: usize = kem::EK_SIZE; // 1184
const ED25519_PK_SIZE: usize = 32;
pub const MLDSA_VK_SIZE: usize = sign::VK_SIZE; // 1952
const PUBLIC_PAYLOAD: usize = 1 + X25519_PK_SIZE + MLKEM_EK_SIZE + ED25519_PK_SIZE + MLDSA_VK_SIZE;

pub struct Identity {
    pub x25519_sk: [u8; 32],
    pub mlkem_seed: [u8; 64],
    pub ed25519_seed: [u8; 32],
    pub mldsa_seed: [u8; 32],
}

pub struct Recipient {
    pub x25519_pk: [u8; 32],
    pub mlkem_ek: [u8; 1184],
    pub ed25519_pk: [u8; 32],
    pub mldsa_vk: Vec<u8>, // 1952 bytes
}

impl Identity {
    pub fn generate() -> (Identity, Recipient) {
        let (x25519_sk, x25519_pk) = exchange::generate_keypair();
        let (mlkem_seed, mlkem_ek) = kem::generate_keypair();
        let (ed25519_seed, ed25519_pk) = sign::generate_ed25519();
        let (mldsa_seed, mldsa_vk) = sign::generate_mldsa();

        let id = Identity {
            x25519_sk: *x25519_sk.as_bytes(),
            mlkem_seed,
            ed25519_seed,
            mldsa_seed,
        };
        let rec = Recipient {
            x25519_pk: *x25519_pk.as_bytes(),
            mlkem_ek,
            ed25519_pk,
            mldsa_vk,
        };
        (id, rec)
    }

    pub fn recipient(&self) -> Recipient {
        let x25519_pk = *x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(self.x25519_sk),
        )
        .as_bytes();
        let mlkem_ek = kem::public_from_seed(&self.mlkem_seed);
        let ed25519_pk = sign::ed25519_pk_from_seed(&self.ed25519_seed);
        let mldsa_vk = sign::mldsa_vk_from_seed(&self.mldsa_seed);
        Recipient {
            x25519_pk,
            mlkem_ek,
            ed25519_pk,
            mldsa_vk,
        }
    }

    pub fn encode(&self) -> String {
        let mut buf = Vec::with_capacity(SECRET_PAYLOAD + CHECKSUM_LEN);
        buf.push(VERSION);
        buf.extend_from_slice(&self.x25519_sk);
        buf.extend_from_slice(&self.mlkem_seed);
        buf.extend_from_slice(&self.ed25519_seed);
        buf.extend_from_slice(&self.mldsa_seed);
        let cs = checksum(&buf);
        buf.extend_from_slice(&cs);
        format!("{}{}", SECRET_PREFIX, general_purpose::STANDARD_NO_PAD.encode(&buf))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        let data = s
            .strip_prefix(SECRET_PREFIX)
            .ok_or_else(|| anyhow!("Missing prefix {}", SECRET_PREFIX))?;
        let raw = general_purpose::STANDARD_NO_PAD
            .decode(data)
            .map_err(|e| anyhow!("Invalid base64: {}", e))?;

        if raw.len() != SECRET_PAYLOAD + CHECKSUM_LEN {
            return Err(anyhow!("Invalid secret key length"));
        }
        verify_checksum(&raw)?;

        let payload = &raw[..SECRET_PAYLOAD];
        if payload[0] != VERSION {
            return Err(anyhow!("Unsupported key version {}", payload[0]));
        }
        let mut off = 1;
        let x25519_sk: [u8; 32] = payload[off..off + 32].try_into().unwrap();
        off += 32;
        let mlkem_seed: [u8; 64] = payload[off..off + 64].try_into().unwrap();
        off += 64;
        let ed25519_seed: [u8; 32] = payload[off..off + 32].try_into().unwrap();
        off += 32;
        let mldsa_seed: [u8; 32] = payload[off..off + 32].try_into().unwrap();

        Ok(Identity {
            x25519_sk,
            mlkem_seed,
            ed25519_seed,
            mldsa_seed,
        })
    }
}

impl Recipient {
    pub fn encode(&self) -> String {
        let mut buf = Vec::with_capacity(PUBLIC_PAYLOAD + CHECKSUM_LEN);
        buf.push(VERSION);
        buf.extend_from_slice(&self.x25519_pk);
        buf.extend_from_slice(&self.mlkem_ek);
        buf.extend_from_slice(&self.ed25519_pk);
        buf.extend_from_slice(&self.mldsa_vk);
        let cs = checksum(&buf);
        buf.extend_from_slice(&cs);
        format!("{}{}", PUBLIC_PREFIX, general_purpose::STANDARD_NO_PAD.encode(&buf))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        let data = s
            .strip_prefix(PUBLIC_PREFIX)
            .ok_or_else(|| anyhow!("Missing prefix {}", PUBLIC_PREFIX))?;
        let raw = general_purpose::STANDARD_NO_PAD
            .decode(data)
            .map_err(|e| anyhow!("Invalid base64: {}", e))?;

        if raw.len() != PUBLIC_PAYLOAD + CHECKSUM_LEN {
            return Err(anyhow!("Invalid public key length"));
        }
        verify_checksum(&raw)?;

        let payload = &raw[..PUBLIC_PAYLOAD];
        if payload[0] != VERSION {
            return Err(anyhow!("Unsupported key version {}", payload[0]));
        }
        let mut off = 1;
        let x25519_pk: [u8; 32] = payload[off..off + 32].try_into().unwrap();
        off += 32;
        let mlkem_ek: [u8; 1184] = payload[off..off + 1184].try_into().unwrap();
        off += 1184;
        let ed25519_pk: [u8; 32] = payload[off..off + 32].try_into().unwrap();
        off += 32;
        let mldsa_vk = payload[off..off + MLDSA_VK_SIZE].to_vec();

        Ok(Recipient {
            x25519_pk,
            mlkem_ek,
            ed25519_pk,
            mldsa_vk,
        })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.x25519_pk);
        h.update(&self.mlkem_ek);
        h.update(&self.ed25519_pk);
        h.update(&self.mldsa_vk);
        h.finalize().into()
    }
}

fn checksum(data: &[u8]) -> [u8; CHECKSUM_LEN] {
    let h = Sha256::digest(data);
    h[..CHECKSUM_LEN].try_into().unwrap()
}

fn verify_checksum(raw: &[u8]) -> Result<()> {
    let (payload, cs) = raw.split_at(raw.len() - CHECKSUM_LEN);
    let expected = checksum(payload);
    if cs != expected {
        return Err(anyhow!("Checksum mismatch — corrupted key"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip() {
        let (id, rec) = Identity::generate();
        let id2 = Identity::decode(&id.encode()).unwrap();
        let rec2 = Recipient::decode(&rec.encode()).unwrap();

        assert_eq!(id.x25519_sk, id2.x25519_sk);
        assert_eq!(id.mlkem_seed, id2.mlkem_seed);
        assert_eq!(id.ed25519_seed, id2.ed25519_seed);
        assert_eq!(id.mldsa_seed, id2.mldsa_seed);

        assert_eq!(rec.x25519_pk, rec2.x25519_pk);
        assert_eq!(rec.mlkem_ek, rec2.mlkem_ek);
        assert_eq!(rec.ed25519_pk, rec2.ed25519_pk);
        assert_eq!(rec.mldsa_vk, rec2.mldsa_vk);
    }

    #[test]
    fn bad_checksum_rejected() {
        let (id, _) = Identity::generate();
        let mut s = id.encode();
        let len = s.len();
        s.replace_range(len - 2..len, "XX");
        assert!(Identity::decode(&s).is_err());
    }

    #[test]
    fn recipient_from_identity() {
        let (id, rec) = Identity::generate();
        let rec2 = id.recipient();
        assert_eq!(rec.fingerprint(), rec2.fingerprint());
    }
}
