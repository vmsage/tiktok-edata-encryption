use edata::{edata_encrypt, edata_decrypt};

fn main() {
    // currently its constant 0x01 flag in tiktok (can change in future)
    let enc = edata_encrypt("hello world", None, None, 0x01);
    println!("Encrypted: {}", enc);

    let dec = edata_decrypt(&enc);
    println!("Decrypted: {}", dec);
}