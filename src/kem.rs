use ml_kem::{
    Ciphertext, DecapsulationKey, EncapsulationKey, Key, MlKem768, Seed,
    kem::{Decapsulate, Encapsulate, KeyExport},
};

pub const EK_SIZE: usize = 1184;
pub const DK_SIZE: usize = 64;
pub const CT_SIZE: usize = 1088;
pub const SS_SIZE: usize = 32;

pub fn generate_keypair() -> ([u8; DK_SIZE], [u8; EK_SIZE]) {
    let dk_seed: [u8; DK_SIZE] = rand::random();
    let seed = Seed::try_from(&dk_seed[..]).unwrap();
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    let ek = dk.encapsulation_key().clone();
    let ek_arr = ek.to_bytes();
    let ek_slice: &[u8] = ek_arr.as_ref();
    let ek_bytes: [u8; EK_SIZE] = ek_slice.try_into().unwrap();
    (dk_seed, ek_bytes)
}

pub fn encapsulate(ek_bytes: &[u8; EK_SIZE]) -> ([u8; CT_SIZE], [u8; SS_SIZE]) {
    let ek_key = Key::<EncapsulationKey<MlKem768>>::try_from(&ek_bytes[..]).unwrap();
    let ek = EncapsulationKey::<MlKem768>::new(&ek_key).unwrap();
    let (ct, ss) = ek.encapsulate_with_rng(&mut rand::rng());
    let ct_slice: &[u8] = ct.as_ref();
    let ss_slice: &[u8] = ss.as_ref();
    (ct_slice.try_into().unwrap(), ss_slice.try_into().unwrap())
}

pub fn decapsulate(dk_bytes: &[u8; DK_SIZE], ct: &[u8; CT_SIZE]) -> [u8; SS_SIZE] {
    let seed = Seed::try_from(&dk_bytes[..]).unwrap();
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    let ct_typed = Ciphertext::<MlKem768>::try_from(&ct[..]).unwrap();
    let ss = dk.decapsulate(&ct_typed);
    let ss_slice: &[u8] = ss.as_ref();
    ss_slice.try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let (dk, ek) = generate_keypair();
        let (ct, ss1) = encapsulate(&ek);
        let ss2 = decapsulate(&dk, &ct);
        assert_eq!(ss1, ss2);
    }
}
