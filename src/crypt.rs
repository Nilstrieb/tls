//! Module for encrypting `TLSPlaintext` records.

use crate::proto::{
    self,
    ser_de::{proto_enum, proto_struct, Value},
};

use ring::aead::{self, Nonce};

pub struct TlsCiphertext {
    /// The encrypted [`TlsInnerPlaintext`] record.
    pub encrypted_record: Vec<u8>,
}
impl From<Vec<u8>> for TlsCiphertext {
    fn from(value: Vec<u8>) -> Self {
        TlsCiphertext {
            encrypted_record: value,
        }
    }
}

pub fn compute_keys(shared_secret: SharedSecret) {
    let hkdf_expand_label = |secret: &[u8], label: &[u8], context: &[u8], length| {
        proto_struct! {
            #[derive(Debug)]
            pub struct HkdfLabel {
                pub length: u16,
                pub label: proto::ser_de::List<u8,u8>,
                pub context: proto::ser_de::List<u8,u8>,
            }
        }
        let mut hkdf_label = Vec::new();
        HkdfLabel {
            length,
            label: {
                let mut v = b"tls13 ".to_vec();
                v.extend_from_slice(label);
                v.into()
            },
            context: context.to_vec().into(),
        }
        .write(&mut hkdf_label)
        .unwrap();

        // TODO: use correct algo, the cipher suite hash algorithm!
        let mut okm = [0u8; 42];
        hkdf::Hkdf::<sha2::Sha256>::new(None, secret).expand(&hkdf_label, &mut okm)
    };

    let derive_secret = |secret: &[u8], label: &[u8], messages: ()| {
        hkdf_expand_label(secret, label, &[], 16) // todo: fix length
    };
}

pub struct AeadKey {
    key: aead::LessSafeKey,
}

impl AeadKey {
    fn new(algorithm: proto::CipherSuite, key_bytes: &[u8]) -> Self {
        Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(proto_algo_to_ring(algorithm), key_bytes)
                    .expect("invalid key"),
            ),
        }
    }
}

mod seq {
    use std::cell::Cell;

    use ring::aead::{self, Nonce};

    /// The sequence ID generator.
    /// There is a separate one maintained for reading and writing.
    pub struct SeqIdGen {
        next: Cell<u64>,
    }
    impl SeqIdGen {
        pub fn new() -> SeqIdGen {
            SeqIdGen { next: Cell::new(0) }
        }
        pub fn next(&self) -> SeqId {
            let next = self.next.get();
            self.next.set(next.checked_add(1).unwrap());
            SeqId(next)
        }
    }
    // Don't implement `Clone` to ensure every seq id is only used once.
    pub struct SeqId(u64);
    impl SeqId {
        pub fn to_nonce(self) -> Nonce {
            let mut nonce = [0; aead::NONCE_LEN];
            nonce[4..].copy_from_slice(&self.0.to_be_bytes());
            Nonce::assume_unique_for_key(nonce)
        }
    }
}
pub use seq::{SeqId, SeqIdGen};
use x25519_dalek::SharedSecret;

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
    let total_len = message.len() + key.key.algorithm().tag_len();
    let mut ciphertext_payload = Vec::with_capacity(total_len);
    ciphertext_payload.extend_from_slice(message);

    // FIXME: dont use zero obviously
    let nonce = aead::Nonce::assume_unique_for_key([0; aead::NONCE_LEN]);
    // FIXME: fill out the AAD properly
    let aad = aead::Aad::from([0; 5]);
    key.key
        .seal_in_place_append_tag(nonce, aad, &mut ciphertext_payload)
        .unwrap();

    ciphertext_payload
}

pub struct TlsInnerPlaintext {
    /// The `TLSPlaintext.fragment`` value
    pub content: Vec<u8>,
    /// The `TLSPlaintext.type` value
    pub content_type: u8,
    pub padding_len: u16,
}

impl TlsCiphertext {
    pub fn decrypt(&self, key: AeadKey, nonce: Nonce) -> TlsInnerPlaintext {
        todo!()
    }
}
