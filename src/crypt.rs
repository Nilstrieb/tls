//! Module for encrypting `TLSPlaintext` records.

use crate::proto::{
    self,
    ser_de::{proto_enum, proto_struct, Value},
    Handshake,
};
use hkdf::{hmac::Hmac, HmacImpl};
use ring::aead::{self, Nonce};
pub use seq::{SeqId, SeqIdGen};
use sha2::{
    digest::{
        core_api::{self, CoreProxy},
        generic_array::ArrayLength,
        typenum::Unsigned,
        OutputSizeUser,
    },
    Digest,
};
use x25519_dalek::SharedSecret;

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

trait TlsHasher: OutputSizeUser {
    const ZEROED: &'static [u8];
    fn expand(ikm: &[u8], label: &[u8], okm: &mut [u8]) -> Result<(), hkdf::InvalidLength>;
    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8>;
}
macro_rules! impl_hkdf_hasher {
    () => {
        const ZEROED: &'static [u8] =
            &[0; <<Self as OutputSizeUser>::OutputSize as Unsigned>::USIZE];
        fn expand(ikm: &[u8], label: &[u8], okm: &mut [u8]) -> Result<(), hkdf::InvalidLength> {
            hkdf::Hkdf::<Self>::new(None, ikm).expand(&label, okm)
        }
        fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
            hkdf::Hkdf::<Self>::extract(Some(&[]), &[])
                .0
                .as_slice()
                .to_vec()
        }
    };
}
impl TlsHasher for sha2::Sha256 {
    impl_hkdf_hasher!();
}
impl TlsHasher for sha2::Sha384 {
    impl_hkdf_hasher!();
}

// Key Schedule
// https://datatracker.ietf.org/doc/html/rfc8446#section-7.1

// The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm
fn hkdf_expand_label<H: TlsHasher>(secret: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    proto_struct! {
        #[derive(Debug)]
        pub struct HkdfLabel {
            pub length: u16,
            pub label: proto::ser_de::List<u8, u8>,
            pub context: proto::ser_de::List<u8, u8>,
        }
    }
    let mut hkdf_label = Vec::new();
    HkdfLabel {
        // Hash.length is its output length in bytes
        length: <H as OutputSizeUser>::output_size().try_into().unwrap(),
        label: {
            let mut v = b"tls13 ".to_vec();
            v.extend_from_slice(label);
            v.into()
        },
        context: context.to_vec().into(),
    }
    .write(&mut hkdf_label)
    .unwrap();

    let mut okm = [0u8; 128];
    H::expand(secret, &hkdf_label, &mut okm).unwrap();
    okm[..<H as OutputSizeUser>::output_size()].to_vec()
}

/// Messages is the concatenation of the indicated handshake messages,
/// including the handshake message type and length fields, but not
/// including record layer headers.
fn derive_secret<H: TlsHasher>(secret: &[u8], label: &[u8], messages_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label::<H>(secret, label, messages_hash)
}

pub struct CryptoProvider {
    zeroed_of_hash_size: &'static [u8],
    hkdf_extract: fn(salt: &[u8], ikm: &[u8]) -> Vec<u8>,
    derive_secret: fn(secret: &[u8], label: &[u8], messages_hash: &[u8]) -> Vec<u8>,
}
impl CryptoProvider {
    fn new<H: TlsHasher>() -> Self {
        CryptoProvider {
            zeroed_of_hash_size: H::ZEROED,
            hkdf_extract: H::extract,
            derive_secret: derive_secret::<H>,
        }
    }
}

pub struct TranscriptHash {
    state: sha2::Sha256,
}
impl TranscriptHash {
    pub fn new() -> Self {
        Self {
            state: sha2::Sha256::new(),
        }
    }
    pub fn handshake(&mut self, handshake: &Handshake) {
        let mut buf = Vec::new();
        handshake.write(&mut buf);
        self.state.update(&buf);
    }
    pub fn get_current(&self) -> Vec<u8> {
        self.state.clone().finalize().to_vec()
    }
}

/**
```text
           0
             |
             v
   PSK ->  HKDF-Extract = Early Secret
             |
             +-----> Derive-Secret(., "ext binder" | "res binder", "")
             |                     = binder_key
             |
             +-----> Derive-Secret(., "c e traffic", ClientHello)
             |                     = client_early_traffic_secret
             |
             +-----> Derive-Secret(., "e exp master", ClientHello)
             |                     = early_exporter_master_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
   (EC)DHE -> HKDF-Extract = Handshake Secret
             |
             +-----> Derive-Secret(., "c hs traffic",
             |                     ClientHello...ServerHello)
             |                     = client_handshake_traffic_secret
             |
             +-----> Derive-Secret(., "s hs traffic",
             |                     ClientHello...ServerHello)
             |                     = server_handshake_traffic_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
   0 -> HKDF-Extract = Master Secret
             |
             +-----> Derive-Secret(., "c ap traffic",
             |                     ClientHello...server Finished)
             |                     = client_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "s ap traffic",
             |                     ClientHello...server Finished)
             |                     = server_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "exp master",
             |                     ClientHello...server Finished)
             |                     = exporter_master_secret
             |
             +-----> Derive-Secret(., "res master",
                                   ClientHello...client Finished)
                                   = resumption_master_secret
```
*/

pub struct KeysAfterServerHello {
    provider: CryptoProvider,
    handhske_secret: Vec<u8>,
    pub client_handshake_traffic_secret: Vec<u8>,
    pub server_handshake_traffic_secret: Vec<u8>,
    master_secret: Vec<u8>,
}

impl KeysAfterServerHello {
    pub fn compute(
        shared_secret: SharedSecret,
        algo: proto::CipherSuite,
        transcript: &TranscriptHash,
    ) -> Self {
        let provider = match algo {
            proto::CipherSuite::TLS_AES_128_GCM_SHA256 => CryptoProvider::new::<sha2::Sha256>(),
            proto::CipherSuite::TLS_AES_256_GCM_SHA384 => {
                todo!("anyhting but SHA256")
                // CryptoProvider::new::<sha2::Sha384>()
            }
            proto::CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => {
                CryptoProvider::new::<sha2::Sha256>()
            }
            proto::CipherSuite::TLS_AES_128_CCM_SHA256 => CryptoProvider::new::<sha2::Sha256>(),
            proto::CipherSuite::TLS_AES_128_CCM_8_SHA256 => CryptoProvider::new::<sha2::Sha256>(),
        };

        let early_secret =
            (provider.hkdf_extract)(&provider.zeroed_of_hash_size, &provider.zeroed_of_hash_size);

        let handhske_secret = (provider.hkdf_extract)(
            &(provider.derive_secret)(&early_secret, b"derived", &transcript.get_current()),
            shared_secret.as_bytes(),
        );

        let client_handshake_traffic_secret =
            (provider.derive_secret)(&handhske_secret, b"c hs traffic", &transcript.get_current());

        let server_handshake_traffic_secret =
            (provider.derive_secret)(&handhske_secret, b"s hs traffic", &transcript.get_current());

        let master_secret = (provider.hkdf_extract)(
            &(provider.derive_secret)(
                &handhske_secret,
                b"derived",
                &sha2::Sha256::new().finalize(),
            ),
            &provider.zeroed_of_hash_size,
        );

        Self {
            provider,
            handhske_secret,
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            master_secret,
        }
    }

    fn after_handshake(self, transcript: &TranscriptHash) {
        let client_application_traffic_secret_0 = (self.provider.derive_secret)(
            &self.master_secret,
            b"c ap traffic",
            &transcript.get_current(),
        );
        let server_application_traffic_secret_0 = (self.provider.derive_secret)(
            &self.master_secret,
            b"s ap traffic",
            &transcript.get_current(),
        );
        todo!()
    }
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

fn proto_algo_to_ring(algo: proto::CipherSuite) -> &'static aead::Algorithm {
    match algo {
        proto::CipherSuite::TLS_AES_128_GCM_SHA256 => &aead::AES_128_GCM,
        proto::CipherSuite::TLS_AES_256_GCM_SHA384 => &aead::AES_256_GCM,
        proto::CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => &aead::CHACHA20_POLY1305,
        proto::CipherSuite::TLS_AES_128_CCM_SHA256 => todo!("TLS_AES_128_CCM_SHA256"),
        proto::CipherSuite::TLS_AES_128_CCM_8_SHA256 => todo!("TLS_AES_128_CCM_8_SHA256"),
    }
}

fn encrypt(key: AeadKey, message: &[u8], seq: u8, nonce: Nonce) -> Vec<u8> {
    let total_len = message.len() + key.key.algorithm().tag_len();
    let mut ciphertext_payload = Vec::with_capacity(total_len);
    ciphertext_payload.extend_from_slice(message);

    // FIXME: fill out the AAD properly
    let aad = aead::Aad::from([0; 5]);
    key.key
        .seal_in_place_append_tag(nonce, aad, &mut ciphertext_payload)
        .unwrap();

    ciphertext_payload
}

fn decrypt(key: AeadKey, msg: &mut [u8], nonce: Nonce) {
    // FIXME: fill out the AAD properly
    let aad = aead::Aad::from([0; 5]);
    key.key.open_in_place(nonce, aad, msg);
}

pub struct TlsInnerPlaintext {
    /// The `TLSPlaintext.fragment`` value
    pub content: Vec<u8>,
    /// The `TLSPlaintext.type` value
    pub content_type: u8,
    pub padding_len: u16,
}

impl TlsCiphertext {
    pub fn decrypt(mut self, secret: &[u8], nonce: Nonce) -> TlsInnerPlaintext {
        let key = hkdf_expand_label::<sha2::Sha256>(secret, b"key", &[]);
        let iv = hkdf_expand_label::<sha2::Sha256>(secret, b"iv", &[]);

        let key = AeadKey::new(proto::CipherSuite::TLS_AES_128_GCM_SHA256, secret);

        decrypt(key, &mut self.encrypted_record, nonce);

        TlsInnerPlaintext {
            content: self.encrypted_record,
            content_type: 0,
            padding_len: 0,
        }
    }
}
