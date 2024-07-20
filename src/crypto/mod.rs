//! Cryptographic operations.

pub mod aead;
pub mod keys;

use crate::proto::{
    self,
    ser_de::{proto_enum, proto_struct, Value},
    Handshake,
};
use hkdf::{hmac::Hmac, HmacImpl};
use ring::aead::Nonce;
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
            derive_secret: keys::derive_secret::<H>,
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

pub struct TlsInnerPlaintext {
    /// The `TLSPlaintext.fragment`` value
    pub content: Vec<u8>,
    /// The `TLSPlaintext.type` value
    pub content_type: u8,
    pub padding_len: u16,
}
