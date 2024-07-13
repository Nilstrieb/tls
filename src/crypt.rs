//! Module for encrypting `TLSPlaintext` records.

use crate::proto::{
    self,
    ser_de::{proto_enum, proto_struct, Value},
};
use hkdf::{hmac::Hmac, HmacImpl};
use ring::aead::{self, Nonce};
pub use seq::{SeqId, SeqIdGen};
use sha2::digest::{
    core_api::{self, CoreProxy},
    generic_array::ArrayLength,
    typenum::Unsigned,
    OutputSizeUser,
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

trait HkdfHasher: OutputSizeUser {
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
impl HkdfHasher for sha2::Sha256 {
    impl_hkdf_hasher!();
}
impl HkdfHasher for sha2::Sha384 {
    impl_hkdf_hasher!();
}

// Key Schedule
// https://datatracker.ietf.org/doc/html/rfc8446#section-7.1

// The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm
fn hkdf_expand_label<H: HkdfHasher>(secret: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
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
        length: H::output_size().try_into().unwrap(),
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
    okm[..H::output_size()].to_vec()
}

/// Messages is the concatenation of the indicated handshake messages,
/// including the handshake message type and length fields, but not
/// including record layer headers.
fn derive_secret<H: HkdfHasher>(secret: &[u8], label: &[u8], messages: ()) -> Vec<u8> {
    hkdf_expand_label::<H>(secret, label, &[])
}

pub struct CryptoProvider {
    zeroed_of_hash_size: &'static [u8],
    hkdf_extract: fn(salt: &[u8], ikm: &[u8]) -> Vec<u8>,
    derive_secret: fn(secret: &[u8], label: &[u8], messages: ()) -> Vec<u8>,
}
impl CryptoProvider {
    fn new<H: HkdfHasher>() -> Self {
        CryptoProvider {
            zeroed_of_hash_size: H::ZEROED,
            hkdf_extract: H::extract,
            derive_secret: derive_secret::<H>,
        }
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
pub fn compute_keys(shared_secret: SharedSecret, algo: proto::CipherSuite) {
    let provider = match algo {
        proto::CipherSuite::TLS_AES_128_GCM_SHA256 => CryptoProvider::new::<sha2::Sha256>(),
        proto::CipherSuite::TLS_AES_256_GCM_SHA384 => CryptoProvider::new::<sha2::Sha384>(),
        proto::CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => CryptoProvider::new::<sha2::Sha256>(),
        proto::CipherSuite::TLS_AES_128_CCM_SHA256 => CryptoProvider::new::<sha2::Sha256>(),
        proto::CipherSuite::TLS_AES_128_CCM_8_SHA256 => CryptoProvider::new::<sha2::Sha256>(),
    };

    let early_secret =
        (provider.hkdf_extract)(&provider.zeroed_of_hash_size, &provider.zeroed_of_hash_size);

    let handhske_secret = (provider.hkdf_extract)(
        &(provider.derive_secret)(&early_secret, b"derived", (/*empty*/)),
        shared_secret.as_bytes(),
    );

    let client_handshake_traffic_secret = (provider.derive_secret)(
        &handhske_secret,
        b"c hs traffic",
        (/*clienthello..serverhello*/),
    );

    let server_handshake_traffic_secret = (provider.derive_secret)(
        &handhske_secret,
        b"s hs traffic",
        (/*clienthello..serverhello*/),
    );

    let master_secret = (provider.hkdf_extract)(
        &(provider.derive_secret)(&handhske_secret, b"derived", (/*empty*/)),
        &provider.zeroed_of_hash_size,
    );

    let client_application_traffic_secret_0 = (provider.derive_secret)(
        &master_secret,
        b"c ap traffic",
        (/*clienthello..server finished*/),
    );
    let server_application_traffic_secret_0 = (provider.derive_secret)(
        &master_secret,
        b"s ap traffic",
        (/*clienthello..server finished*/),
    );


    dbg!("keys");
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
