use anyhow::{anyhow, Result};
use ed25519_dalek::{
    Signature as Ed25519Sig, SigningKey as Ed25519Sk, VerifyingKey as Ed25519Vk,
    Signer as _,
};
use ml_dsa::{
    MlDsa65, Signature as MlDsaSig, SigningKey as MlDsaSk, VerifyingKey as MlDsaVk,
    signature::Verifier as _,
};

pub const VK_SIZE: usize = 1952;
pub const ED25519_SIG_SIZE: usize = 64;
pub const MLDSA_SIG_SIZE: usize = 3309;
pub const COMBINED_SIG_SIZE: usize = ED25519_SIG_SIZE + MLDSA_SIG_SIZE;

pub fn generate_ed25519() -> ([u8; 32], [u8; 32]) {
    let seed: [u8; 32] = rand::random();
    let sk = Ed25519Sk::from_bytes(&seed);
    let pk = Ed25519Vk::from(&sk);
    (seed, pk.to_bytes())
}

pub fn generate_mldsa() -> ([u8; 32], Vec<u8>) {
    let seed: [u8; 32] = rand::random();
    let sk = MlDsaSk::<MlDsa65>::from_seed(&seed.into());
    let vk = sk.verifying_key();
    let vk_enc = vk.encode();
    let vk_bytes: &[u8] = vk_enc.as_ref();
    (seed, vk_bytes.to_vec())
}

pub fn ed25519_pk_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    Ed25519Vk::from(&Ed25519Sk::from_bytes(seed)).to_bytes()
}

pub fn mldsa_vk_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let sk = MlDsaSk::<MlDsa65>::from_seed(&(*seed).into());
    let vk_enc = sk.verifying_key().encode();
    let s: &[u8] = vk_enc.as_ref();
    s.to_vec()
}

/// Sign data with both Ed25519 and ML-DSA-65.
/// Returns [ed25519_sig(64) | mldsa_sig(3309)] = 3373 bytes.
pub fn sign(ed25519_seed: &[u8; 32], mldsa_seed: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let ed_sk = Ed25519Sk::from_bytes(ed25519_seed);
    let ed_sig: Ed25519Sig = ed_sk.sign(data);

    let ml_sk = MlDsaSk::<MlDsa65>::from_seed(&(*mldsa_seed).into());
    let ml_sig: MlDsaSig<MlDsa65> = ml_sk.sign_deterministic(data, &[]).unwrap();
    let ml_sig_enc = ml_sig.encode();
    let ml_bytes: &[u8] = ml_sig_enc.as_ref();

    let mut out = Vec::with_capacity(COMBINED_SIG_SIZE);
    out.extend_from_slice(&ed_sig.to_bytes());
    out.extend_from_slice(ml_bytes);
    out
}

/// Verify both Ed25519 and ML-DSA-65 signatures.
pub fn verify(
    ed25519_pk: &[u8; 32],
    mldsa_vk: &[u8],
    data: &[u8],
    combined_sig: &[u8],
) -> Result<()> {
    if combined_sig.len() != COMBINED_SIG_SIZE {
        return Err(anyhow!("Invalid signature length"));
    }

    let ed_sig_bytes: [u8; 64] = combined_sig[..ED25519_SIG_SIZE].try_into().unwrap();
    let ed_sig = Ed25519Sig::from_bytes(&ed_sig_bytes);
    let ed_vk = Ed25519Vk::from_bytes(ed25519_pk)
        .map_err(|_| anyhow!("Invalid Ed25519 public key"))?;
    ed_vk
        .verify_strict(&data, &ed_sig)
        .map_err(|_| anyhow!("Ed25519 signature verification failed"))?;

    let ml_sig_bytes = &combined_sig[ED25519_SIG_SIZE..];
    let ml_sig = MlDsaSig::<MlDsa65>::decode(ml_sig_bytes.try_into().map_err(|_| anyhow!("Invalid ML-DSA sig size"))?)
        .ok_or_else(|| anyhow!("Invalid ML-DSA signature"))?;
    let ml_vk_arr = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(mldsa_vk)
        .map_err(|_| anyhow!("Invalid ML-DSA VK size"))?;
    let ml_vk = MlDsaVk::<MlDsa65>::decode(&ml_vk_arr);
    ml_vk
        .verify(data, &ml_sig)
        .map_err(|_| anyhow!("ML-DSA signature verification failed"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (ed_seed, ed_pk) = generate_ed25519();
        let (ml_seed, ml_vk) = generate_mldsa();
        let msg = b"authenticate this header";
        let sig = sign(&ed_seed, &ml_seed, msg);
        verify(&ed_pk, &ml_vk, msg, &sig).unwrap();
    }

    #[test]
    fn wrong_data_fails() {
        let (ed_seed, ed_pk) = generate_ed25519();
        let (ml_seed, ml_vk) = generate_mldsa();
        let sig = sign(&ed_seed, &ml_seed, b"original");
        assert!(verify(&ed_pk, &ml_vk, b"tampered", &sig).is_err());
    }
}
