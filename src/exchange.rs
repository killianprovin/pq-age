use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::kem;

const INFO: &[u8] = b"pq-age hybrid x25519+mlkem v1";

pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::from(rand::random::<[u8; 32]>());
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Returns (eph_x25519_pub, mlkem_ciphertext, symmetric_key).
pub fn encapsulate(
    x25519_pub: &[u8; 32],
    mlkem_pub: &[u8; kem::EK_SIZE],
) -> ([u8; 32], [u8; kem::CT_SIZE], [u8; 32]) {
    let (eph_secret, eph_public) = generate_keypair();
    let recipient = PublicKey::from(*x25519_pub);
    let x25519_ss = eph_secret.diffie_hellman(&recipient);

    let (mlkem_ct, mlkem_ss) = kem::encapsulate(mlkem_pub);

    let sym_key = hkdf_combine(x25519_ss.as_bytes(), &mlkem_ss);
    (*eph_public.as_bytes(), mlkem_ct, sym_key)
}

/// Recovers the symmetric key from both decapsulation inputs.
pub fn decapsulate(
    eph_x25519: &[u8; 32],
    x25519_secret: &[u8; 32],
    mlkem_ct: &[u8; kem::CT_SIZE],
    mlkem_dk: &[u8; kem::DK_SIZE],
) -> [u8; 32] {
    let secret = StaticSecret::from(*x25519_secret);
    let public = PublicKey::from(*eph_x25519);
    let x25519_ss = secret.diffie_hellman(&public);

    let mlkem_ss = kem::decapsulate(mlkem_dk, mlkem_ct);

    hkdf_combine(x25519_ss.as_bytes(), &mlkem_ss)
}

fn hkdf_combine(x25519_ss: &[u8], mlkem_ss: &[u8]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x25519_ss);
    ikm[32..].copy_from_slice(mlkem_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; 32];
    hk.expand(INFO, &mut key).expect("HKDF expand failed");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_roundtrip() {
        let (x25519_sk, x25519_pk) = generate_keypair();
        let (mlkem_dk, mlkem_ek) = kem::generate_keypair();

        let (eph_pub, mlkem_ct, enc_key) =
            encapsulate(x25519_pk.as_bytes(), &mlkem_ek);

        let dec_key = decapsulate(
            &eph_pub,
            x25519_sk.as_bytes(),
            &mlkem_ct,
            &mlkem_dk,
        );

        assert_eq!(enc_key, dec_key);
    }
}
