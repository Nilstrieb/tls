//! Module for encrypting `TLSPlaintext` records.

use crate::proto;

use ring::aead;

struct TlsCiphertext {
    encrypted_record: Vec<u8>,
}

pub struct AeadKey {
    key: aead::LessSafeKey,
}

impl AeadKey {
    fn new(algorithm: proto::CipherSuite, key_bytes: &[u8]) -> Self {
        Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(proto_algo_to_ring(algorithm), key_bytes).expect("invalid key"),
            ),
        }
    }
}

fn proto_algo_to_ring(algo: proto::CipherSuite) -> &'static aead::Algorithm {
    match algo {
        proto::CipherSuite::TLS_AES_128_GCM_SHA256 => &aead::AES_128_GCM,
        proto::CipherSuite::TLS_AES_256_GCM_SHA384 => &aead::AES_256_GCM,
        proto::CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => &aead::CHACHA20_POLY1305,
        proto::CipherSuite::TLS_AES_128_CCM_SHA256 => todo!("TLS_AES_128_CCM_SHA256"),
        proto::CipherSuite::TLS_AES_128_CCM_8_SHA256 => todo!("TLS_AES_128_CCM_8_SHA256"),
    }
}

fn encrypt(key: AeadKey, message: &[u8], seq: u8) -> Vec<u8> {
    let total_len =  message.len() + key.key.algorithm().tag_len();
    let mut ciphertext_payload = Vec::with_capacity(total_len);
    ciphertext_payload.extend_from_slice(message);
    
    // FIXME: dont use zero obviously
    let nonce = aead::Nonce::assume_unique_for_key([0; aead::NONCE_LEN]);
    // FIXME: fill out the AAD properly
    let aad = aead::Aad::from([0; 5]);
    key.key.seal_in_place_append_tag(nonce, aad, &mut ciphertext_payload).unwrap();

    ciphertext_payload
}
