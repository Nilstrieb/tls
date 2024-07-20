use sha2::Digest;
use x25519_dalek::SharedSecret;

use crate::proto::{self, ser_de::Value};

use super::{CryptoProvider, TlsHasher};

// Key Schedule
// https://datatracker.ietf.org/doc/html/rfc8446#section-7.1

// The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm
pub(super) fn hkdf_expand_label<H: TlsHasher>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    proto::ser_de::proto_struct! {
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
        length: length.try_into().unwrap(),
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
    okm[..length].to_vec()
}

/// Messages is the concatenation of the indicated handshake messages,
/// including the handshake message type and length fields, but not
/// including record layer headers.
pub(super) fn derive_secret<H: TlsHasher>(
    secret: &[u8],
    label: &[u8],
    messages_hash: &[u8],
) -> Vec<u8> {
    hkdf_expand_label::<H>(secret, label, messages_hash, H::output_size())
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
    pub fn handshake(&mut self, handshake: &proto::Handshake) {
        let mut buf = Vec::new();
        proto::ser_de::Value::write(handshake, &mut buf).unwrap();
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
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            master_secret,
        }
    }

    #[allow(dead_code)]
    fn after_handshake(self, transcript: &TranscriptHash) {
        let _client_application_traffic_secret_0 = (self.provider.derive_secret)(
            &self.master_secret,
            b"c ap traffic",
            &transcript.get_current(),
        );
        let _server_application_traffic_secret_0 = (self.provider.derive_secret)(
            &self.master_secret,
            b"s ap traffic",
            &transcript.get_current(),
        );
        todo!()
    }
}
