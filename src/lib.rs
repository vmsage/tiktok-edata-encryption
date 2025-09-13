use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::RngCore;
use base64::{engine::general_purpose, Engine as _};

pub const FLAG_LEN: usize = 1;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = FLAG_LEN + KEY_LEN + NONCE_LEN;

pub fn edata_encrypt(
    plaintext: &str,
    key: Option<[u8; KEY_LEN]>,
    nonce: Option<[u8; NONCE_LEN]>,
    flag: u8,
) -> String {
    if flag.to_le_bytes().len() != 1 {
        panic!("flag must be exactly one byte");
    }

    let mut rng = rand::thread_rng();

    let key = key.unwrap_or_else(|| {
        let mut k = [0u8; KEY_LEN];
        rng.fill_bytes(&mut k);
        k
    });

    let nonce = nonce.unwrap_or_else(|| {
        let mut n = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut n);
        n
    });

    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    let mut ciphertext = plaintext.as_bytes().to_vec();
    cipher.apply_keystream(&mut ciphertext);

    let mut raw = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    raw.push(flag);
    raw.extend_from_slice(&key);
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&ciphertext);

    general_purpose::STANDARD.encode(raw)
}

pub fn edata_decrypt(edata_b64: &str) -> String {
    let raw = general_purpose::STANDARD
        .decode(edata_b64)
        .expect("invalid base64");

    if raw.len() <= HEADER_LEN {
        panic!("edata too short to contain key/nonce/payload");
    }

    let _flag = raw[0]; // not used in decrypt but kept for symmetry
    let key: [u8; KEY_LEN] = raw[FLAG_LEN..FLAG_LEN + KEY_LEN]
        .try_into()
        .unwrap();
    let nonce: [u8; NONCE_LEN] = raw[FLAG_LEN + KEY_LEN..HEADER_LEN]
        .try_into()
        .unwrap();
    let ciphertext = &raw[HEADER_LEN..];

    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    let mut plaintext_bytes = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext_bytes);

    String::from_utf8(plaintext_bytes).expect("invalid utf-8")
}