use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const INFO: &[u8] = b"pq-age x25519 v1";

pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::from(rand::random::<[u8; 32]>());
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Encrypt side: generate ephemeral keypair, derive symmetric key.
/// Returns (ephemeral_pubkey_bytes, symmetric_key).
pub fn encapsulate(recipient_pub: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let (eph_secret, eph_public) = generate_keypair();
    let recipient = PublicKey::from(*recipient_pub);
    let shared = eph_secret.diffie_hellman(&recipient);
    let key = hkdf_derive(shared.as_bytes());
    (*eph_public.as_bytes(), key)
}

/// Decrypt side: recover symmetric key from ephemeral pubkey + our private key.
pub fn decapsulate(ephemeral_pub: &[u8; 32], our_secret: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*our_secret);
    let public = PublicKey::from(*ephemeral_pub);
    let shared = secret.diffie_hellman(&public);
    hkdf_derive(shared.as_bytes())
}

fn hkdf_derive(ikm: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut key = [0u8; 32];
    hk.expand(INFO, &mut key).expect("HKDF expand failed");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_roundtrip() {
        let (secret, public) = generate_keypair();
        let (eph_pub, enc_key) = encapsulate(public.as_bytes());
        let dec_key = decapsulate(&eph_pub, secret.as_bytes());
        assert_eq!(enc_key, dec_key);
    }
}
