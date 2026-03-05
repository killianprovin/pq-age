use anyhow::{anyhow, Result};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use std::io::{BufWriter, Read, Write};

const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const NONCE_PREFIX: usize = 8;

fn make_nonce(base: &[u8; NONCE_PREFIX], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..NONCE_PREFIX].copy_from_slice(base);
    nonce[NONCE_PREFIX..].copy_from_slice(&index.to_le_bytes());
    nonce
}

fn fill_buf<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

pub fn encrypt<R: Read, W: Write>(mut r: R, w: W, key: &[u8; 32]) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let base: [u8; NONCE_PREFIX] = rand::random();
    let mut w = BufWriter::new(w);

    w.write_all(&base)?;

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut index: u32 = 0;

    loop {
        let n = fill_buf(&mut r, &mut buf)?;
        if n == 0 {
            break;
        }
        let nonce = make_nonce(&base, index);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), &buf[..n])
            .map_err(|_| anyhow!("Encryption failed"))?;
        w.write_all(&ct)?;
        index += 1;
    }

    w.flush()?;
    Ok(())
}

pub fn decrypt<R: Read, W: Write>(mut r: R, w: W, key: &[u8; 32]) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut base = [0u8; NONCE_PREFIX];
    r.read_exact(&mut base)?;

    let mut w = BufWriter::new(w);
    let mut buf = vec![0u8; CHUNK_SIZE + TAG_SIZE];
    let mut index: u32 = 0;

    loop {
        let n = fill_buf(&mut r, &mut buf)?;
        if n == 0 {
            break;
        }
        let nonce = make_nonce(&base, index);
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce), &buf[..n])
            .map_err(|_| anyhow!("Decryption failed (wrong key or corrupted data)"))?;
        w.write_all(&pt)?;
        index += 1;
    }

    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip(data: &[u8]) {
        let key: [u8; 32] = rand::random();
        let mut ct = Vec::new();
        encrypt(Cursor::new(data), &mut ct, &key).unwrap();
        let mut pt = Vec::new();
        decrypt(Cursor::new(&ct), &mut pt, &key).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn small() {
        roundtrip(b"hello, world!");
    }

    #[test]
    fn multi_chunk() {
        // 3 chunks worth of data
        let data: Vec<u8> = (0..CHUNK_SIZE * 2 + 1000).map(|i| (i % 256) as u8).collect();
        roundtrip(&data);
    }

    #[test]
    fn wrong_key_fails() {
        let key: [u8; 32] = rand::random();
        let wrong: [u8; 32] = rand::random();
        let mut ct = Vec::new();
        encrypt(Cursor::new(b"secret"), &mut ct, &key).unwrap();
        let mut out = Vec::new();
        assert!(decrypt(Cursor::new(&ct), &mut out, &wrong).is_err());
    }
}
