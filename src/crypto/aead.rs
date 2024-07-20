use ring::aead::Nonce;

use crate::proto;

use super::{keys, TlsCiphertext, TlsInnerPlaintext};



pub struct AeadKey {
    key: ring::aead::LessSafeKey,
}

impl AeadKey {
    fn new(algorithm: proto::CipherSuite, key_bytes: &[u8]) -> Self {
        Self {
            key: ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(proto_algo_to_ring(algorithm), key_bytes)
                    .expect("invalid key"),
            ),
        }
    }
}


fn proto_algo_to_ring(algo: proto::CipherSuite) -> &'static ring::aead::Algorithm {
    match algo {
        proto::CipherSuite::TLS_AES_128_GCM_SHA256 => &ring::aead::AES_128_GCM,
        proto::CipherSuite::TLS_AES_256_GCM_SHA384 => &ring::aead::AES_256_GCM,
        proto::CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => &ring::aead::CHACHA20_POLY1305,
        proto::CipherSuite::TLS_AES_128_CCM_SHA256 => todo!("TLS_AES_128_CCM_SHA256"),
        proto::CipherSuite::TLS_AES_128_CCM_8_SHA256 => todo!("TLS_AES_128_CCM_8_SHA256"),
    }
}

fn encrypt(key: AeadKey, message: &[u8], seq: u8, nonce: Nonce) -> Vec<u8> {
    let total_len = message.len() + key.key.algorithm().tag_len();
    let mut ciphertext_payload = Vec::with_capacity(total_len);
    ciphertext_payload.extend_from_slice(message);

    // FIXME: fill out the AAD properly
    let aad = ring::aead::Aad::from([0; 5]);
    key.key
        .seal_in_place_append_tag(nonce, aad, &mut ciphertext_payload)
        .unwrap();

    ciphertext_payload
}

fn decrypt(key: AeadKey, msg: &mut [u8], nonce: ring::aead::Nonce) {
    // FIXME: fill out the AAD properly
    let aad = ring::aead::Aad::from([0; 5]);
    key.key.open_in_place(nonce, aad, msg);
}

impl TlsCiphertext {
    pub fn decrypt(mut self, secret: &[u8], nonce: Nonce) -> TlsInnerPlaintext {
        let key = keys::hkdf_expand_label::<sha2::Sha256>(secret, b"key", &[]);
        let iv = keys::hkdf_expand_label::<sha2::Sha256>(secret, b"iv", &[]);

        let key = AeadKey::new(proto::CipherSuite::TLS_AES_128_GCM_SHA256, secret);

        decrypt(key, &mut self.encrypted_record, nonce);

        TlsInnerPlaintext {
            content: self.encrypted_record,
            content_type: 0,
            padding_len: 0,
        }
    }
}
