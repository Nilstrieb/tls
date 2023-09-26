mod crypt;
pub mod proto;

use std::{
    fmt::Debug,
    io::{self, Read, Write},
};

use crate::proto::TLSPlaintext;

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct ClientConnection<W> {
    _w: W,
}

impl<W: Read + Write> ClientConnection<W> {
    pub fn establish(w: W, host: &str) -> Result<Self> {
        let _setup = ClientSetupConnection::establish(w, host)?;

        todo!()
    }
}

struct ClientSetupConnection<W> {
    _w: W,
}

macro_rules! unexpected_message {
    ($($tt:tt)*) => {
        Err(ErrorKind::UnexpectedMessage(format!($($tt)*)).into())
    };
}

impl<W: Read + Write> ClientSetupConnection<W> {
    fn establish(mut stream: W, host: &str) -> Result<Self> {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = x25519_dalek::PublicKey::from(&secret);

        let legacy_session_id = rand::random::<[u8; 32]>();
        let cipher_suites = vec![proto::CipherSuite::TLS_AES_128_GCM_SHA256];

        let handshake = proto::Handshake::ClientHello {
            legacy_version: proto::LEGACY_TLSV12,
            random: rand::random(),
            legacy_session_id: legacy_session_id.to_vec().into(),
            cipher_suites: cipher_suites.clone().into(),
            legacy_compressions_methods: vec![0].into(),
            extensions: vec![
                proto::ExtensionCH::ServerName {
                    server_name: vec![proto::ServerName::HostName {
                        host_name: host.as_bytes().to_vec().into(),
                    }]
                    .into(),
                },
                proto::ExtensionCH::ECPointFormat {
                    formats: vec![proto::ECPointFormat::Uncompressed].into(),
                },
                proto::ExtensionCH::SupportedGroups {
                    groups: vec![proto::NamedGroup::X25519].into(),
                },
                proto::ExtensionCH::KeyShare {
                    entries: vec![proto::KeyShareEntry::X25519 {
                        len: public.as_bytes().len().try_into().unwrap(),
                        key_exchange: *public.as_bytes(),
                    }]
                    .into(),
                },
                proto::ExtensionCH::SignatureAlgorithms {
                    supported_signature_algorithms: vec![
                        proto::SignatureScheme::ED25519,
                        proto::SignatureScheme::ED448,
                        proto::SignatureScheme::ECDSA_SECP256R1_SHA256,
                        proto::SignatureScheme::ECDSA_SECP384R1_SHA384,
                        proto::SignatureScheme::ECDSA_SECP521R1_SHA512,
                        proto::SignatureScheme::RSA_PSS_PSS_SHA256,
                        proto::SignatureScheme::RSA_PSS_PSS_SHA384,
                        proto::SignatureScheme::RSA_PSS_PSS_SHA512,
                        proto::SignatureScheme::RSA_PSS_RSAE_SHA256,
                        proto::SignatureScheme::RSA_PSS_RSAE_SHA384,
                        proto::SignatureScheme::RSA_PSS_RSAE_SHA512,
                    ]
                    .into(),
                },
                proto::ExtensionCH::SupportedVersions {
                    versions: vec![proto::TLSV13].into(),
                },
            ]
            .into(),
        };
        let plaintext = proto::TLSPlaintext::Handshake { handshake };
        plaintext.write(&mut stream)?;
        stream.flush()?;

        let out = proto::TLSPlaintext::read(&mut stream)?;
        dbg!(&out);

        let proto::TLSPlaintext::Handshake {
            handshake:
                proto::Handshake::ServerHello {
                    legacy_version,
                    random,
                    legacy_session_id_echo,
                    cipher_suite,
                    legacy_compression_method,
                    extensions,
                },
        } = out
        else {
            return Err(
                ErrorKind::UnexpectedMessage(format!("expected ServerHello, got {out:?}")).into(),
            );
        };

        if random.is_hello_retry_request() {
            return Err(ErrorKind::HelloRetryRequest.into());
        }

        if legacy_version != proto::LEGACY_TLSV12 {
            return unexpected_message!(
                "unexpected TLS version in legacy_version field: {legacy_version:x?}"
            );
        }

        if legacy_session_id_echo.as_ref() != legacy_session_id {
            return unexpected_message!(
                "server did not echo the legacy_session_id: {legacy_session_id_echo:?}"
            );
        }

        if !cipher_suites.contains(&cipher_suite) {
            return unexpected_message!(
                "cipher suite from server not sent in client hello: {cipher_suite:?}"
            );
        }

        if legacy_compression_method != 0 {
            return unexpected_message!(
                "legacy compression method MUST be zero: {legacy_compression_method}"
            );
        }

        let mut supported_versions = false;
        let mut server_key = None;

        for ext in extensions.as_ref() {
            match ext {
                proto::ExtensionSH::PreSharedKey => todo!(),
                proto::ExtensionSH::SupportedVersions { selected_version } => {
                    if *selected_version != proto::TLSV13 {
                        return unexpected_message!("server returned non-TLS 1.3 version: {selected_version}");
                    }
                    supported_versions = true;
                },
                proto::ExtensionSH::Cookie { .. } => todo!(),
                proto::ExtensionSH::KeyShare { key_share } => {
                    let entry = key_share.unwrap_server_hello();
                    match entry {
                        proto::KeyShareEntry::X25519 { len, key_exchange } => {
                            if *len != 32 {
                                return unexpected_message!("key length for X25519 key share must be 32: {len}");
                            }
                            server_key = Some(key_exchange);
                        },
                    }
                },
            }
        }

        if !supported_versions {
            return unexpected_message!("server did not send supported_versions extension");
        }

        let Some(server_key) = server_key else {
            return unexpected_message!("server did not send its key");
        };
        let server_key = x25519_dalek::PublicKey::from(*server_key);
        let dh_shared_secret = secret.diffie_hellman(&server_key);

        println!("we have established a shared secret. dont leak it!! anywhere here is it: {:x?}", dh_shared_secret.as_bytes());

        dbg!(proto::TLSPlaintext::read(&mut stream))?;

        todo!()
    }
}

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
}

#[derive(Debug)]
pub enum ErrorKind {
    InvalidFrame(Box<dyn Debug>),
    HelloRetryRequest,
    UnexpectedMessage(String),
    Io(io::Error),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        panic!("error: {value}");
        Self {
            kind: ErrorKind::Io(value),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(value: ErrorKind) -> Self {
        panic!("error:{value:?}");
        Self { kind: value }
    }
}

#[derive(Debug)]
pub struct LoggingWriter<W>(pub W);

impl<W: io::Write> io::Write for LoggingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.0.write(buf);
        if let Ok(len) = len {
            eprintln!(" bytes: {:02x?}", &buf[..len]);
        }
        len
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<R: Read> io::Read for LoggingWriter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.0.read(buf);
        if let Ok(len) = len {
            eprintln!("read bytes: {:02x?}", &buf[..len]);
        }
        len
    }
}
