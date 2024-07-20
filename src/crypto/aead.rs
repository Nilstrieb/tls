//! Symmetric AEAD-based record encryption.
//! <https://datatracker.ietf.org/doc/html/rfc8446#section-5.2>

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, KeyInit,
};

use crate::proto;

use super::{keys, TlsInnerPlaintext};

pub type AeadKey = aes_gcm::Key<Aes128Gcm>;
pub type Nonce = aes_gcm::Nonce<<Aes128Gcm as aes_gcm::AeadCore>::NonceSize>;

fn decrypt(key: &AeadKey, ciphertext: &[u8], nonce: &Nonce, additional_data: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new(key);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: additional_data,
            },
        )
        .unwrap()
}

pub fn decrypt_ciphertext(
    encrypted_record: &[u8],
    secret: &[u8],
    nonce: Nonce,
) -> TlsInnerPlaintext {
    // <https://datatracker.ietf.org/doc/html/rfc8446#section-7.3>
    let key = keys::hkdf_expand_label::<sha2::Sha256>(secret, b"key", &[], 128/8);

    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&key[0..(128 / 8)]);

    // TLS v1.2 0x03, 0x03
    let mut additional_data = [proto::TLSPlaintext::APPLICATION_DATA, 0x03, 0x03, 0, 0];
    let ciphertext_len = encrypted_record.as_ref().len() as u16;
    additional_data[3..].copy_from_slice(&ciphertext_len.to_be_bytes());

    let result = decrypt(key, encrypted_record, &nonce, &additional_data);

    TlsInnerPlaintext {
        content: result,
        content_type: 0,
        padding_len: 0,
    }
}
