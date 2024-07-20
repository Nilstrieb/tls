#![allow(unused)]

mod crypt;
pub mod proto;

use std::{
    cell::RefCell,
    fmt::Debug,
    io::{self, Read, Write},
};

use crypt::{KeysAfterServerHello, TranscriptHash};
use proto::{ser_de::Value, CipherSuite};

use crate::proto::TLSPlaintext;

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct ClientConnection<W> {
    _w: W,
}

impl<W: Read + Write> ClientConnection<W> {
    pub fn establish(w: W, host: &str) -> Result<Self> {
        let mut setup = ClientSetupConnection {
            stream: StreamState::new(w),
        };
        let _setup = setup.establish(host)?;

        todo!()
    }
}

struct ClientSetupConnection<W> {
    stream: StreamState<W>,
}

mod stream_state {
    use std::io::{Read, Write};

    use crate::crypt::{SeqId, SeqIdGen};
    use crate::proto::{self, TLSPlaintext};
    use crate::Result;

    pub struct StreamState<W> {
        stream: W,
        read_seq_id: SeqIdGen,
        write_seq_id: SeqIdGen,
    }
    impl<W: Write + Read> StreamState<W> {
        pub fn new(stream: W) -> Self {
            Self {
                stream,
                read_seq_id: SeqIdGen::new(),
                write_seq_id: SeqIdGen::new(),
            }
        }
        pub fn write_flush_record(&mut self, plaintext: TLSPlaintext) -> Result<()> {
            self.write_record(plaintext)?;
            self.stream.flush()?;
            Ok(())
        }

        pub fn write_record(&mut self, plaintext: TLSPlaintext) -> Result<SeqId> {
            plaintext.write(&mut self.stream)?;
            Ok(self.write_seq_id.next())
        }

        pub fn read_record(&mut self) -> Result<(TLSPlaintext, SeqId)> {
            let seq_id = self.read_seq_id.next();
            let frame = proto::TLSPlaintext::read(&mut self.stream)?;
            Ok((frame, seq_id))
        }
    }
}
use stream_state::StreamState;

macro_rules! unexpected_message {
    ($($tt:tt)*) => {
        Err(ErrorKind::UnexpectedMessage(format!($($tt)*)).into())
    };
}

/**
https://datatracker.ietf.org/doc/html/rfc8446#appendix-A.1

```text
                              START <----+
               Send ClientHello |        | Recv HelloRetryRequest
          [K_send = early data] |        |
                                v        |
           /                 WAIT_SH ----+
           |                    | Recv ServerHello
           |                    | K_recv = handshake
       Can |                    V
      send |                 WAIT_EE
     early |                    | Recv EncryptedExtensions
      data |           +--------+--------+
           |     Using |                 | Using certificate
           |       PSK |                 v
           |           |            WAIT_CERT_CR
           |           |        Recv |       | Recv CertificateRequest
           |           | Certificate |       v
           |           |             |    WAIT_CERT
           |           |             |       | Recv Certificate
           |           |             v       v
           |           |              WAIT_CV
           |           |                 | Recv CertificateVerify
           |           +> WAIT_FINISHED <+
           |                  | Recv Finished
           \                  | [Send EndOfEarlyData]
                              | K_send = handshake
                              | [Send Certificate [+ CertificateVerify]]
    Can send                  | Send Finished
    app data   -->            | K_send = K_recv = application
    after here                v
                          CONNECTED
```
*/
enum ConnectState {
    Start,
    WaitServerHello {
        legacy_session_id: [u8; 32],
        secret: RefCell<Option<x25519_dalek::EphemeralSecret>>,
        cipher_suites: Vec<CipherSuite>,
        transcript: RefCell<TranscriptHash>,
    },
    WaitEncryptedExtensions {
        keys: RefCell<Option<KeysAfterServerHello>>,
    },
    WaitCertificateRequest,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
}

impl<W: Read + Write> ClientSetupConnection<W> {
    fn establish(&mut self, host: &str) -> Result<Self> {
        let mut state = ConnectState::Start;

        loop {
            let next_state = match &state {
                ConnectState::Start => {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-2
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

                    let mut transcript = TranscriptHash::new();
                    transcript.handshake(&handshake);

                    let plaintext = proto::TLSPlaintext::Handshake { handshake };
                    self.stream.write_flush_record(plaintext)?;
                    ConnectState::WaitServerHello {
                        legacy_session_id,
                        secret: RefCell::new(Some(secret)),
                        cipher_suites,
                        transcript: RefCell::new(transcript),
                    }
                }
                ConnectState::WaitServerHello {
                    legacy_session_id,
                    secret,
                    cipher_suites,
                    transcript,
                } => {
                    let (frame, seq_id) = self.stream.read_record()?;
                    if frame.should_drop() {
                        continue;
                    }
                    let proto::TLSPlaintext::Handshake {
                        handshake:
                            handshake @ proto::Handshake::ServerHello {
                                legacy_version,
                                random,
                                legacy_session_id_echo,
                                cipher_suite,
                                legacy_compression_method,
                                extensions,
                            },
                    } = &frame
                    else {
                        return unexpected_message!("expected ServerHello, got {frame:?}");
                    };

                    if random.is_hello_retry_request() {
                        return Err(ErrorKind::HelloRetryRequest.into());
                    }

                    if *legacy_version != proto::LEGACY_TLSV12 {
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

                    if *legacy_compression_method != 0 {
                        return unexpected_message!(
                            "legacy compression method MUST be zero: {legacy_compression_method}"
                        );
                    }

                    transcript.borrow_mut().handshake(&handshake);

                    let mut supported_versions = false;
                    let mut server_key = None;

                    for ext in extensions.as_ref() {
                        match ext {
                            proto::ExtensionSH::PreSharedKey => todo!(),
                            proto::ExtensionSH::SupportedVersions { selected_version } => {
                                if *selected_version != proto::TLSV13 {
                                    return unexpected_message!(
                                        "server returned non-TLS 1.3 version: {selected_version}"
                                    );
                                }
                                supported_versions = true;
                            }
                            proto::ExtensionSH::Cookie { .. } => todo!(),
                            proto::ExtensionSH::KeyShare { key_share } => {
                                let entry = key_share.unwrap_server_hello();
                                match entry {
                                    proto::KeyShareEntry::X25519 { len, key_exchange } => {
                                        if *len != 32 {
                                            return unexpected_message!(
                                                "key length for X25519 key share must be 32: {len}"
                                            );
                                        }
                                        server_key = Some(key_exchange);
                                    }
                                }
                            }
                        }
                    }

                    if !supported_versions {
                        return unexpected_message!(
                            "server did not send supported_versions extension"
                        );
                    }

                    let Some(server_key) = server_key else {
                        return unexpected_message!("server did not send its key");
                    };
                    let server_key = x25519_dalek::PublicKey::from(*server_key);
                    let dh_shared_secret = secret
                        .borrow_mut()
                        .take()
                        .unwrap()
                        .diffie_hellman(&server_key);

                    println!(
                        "we have established a shared secret. dont leak it!! anyways here is it: {:x?}",
                        dh_shared_secret.as_bytes()
                    );

                    let keys = crypt::KeysAfterServerHello::compute(
                        dh_shared_secret,
                        *cipher_suite,
                        &transcript.borrow(),
                    );

                    ConnectState::WaitEncryptedExtensions {
                        keys: RefCell::new(Some(keys)),
                    }
                }
                ConnectState::WaitEncryptedExtensions { keys } => {
                    let (frame, seq_id) = self.stream.read_record()?;
                    if frame.should_drop() {
                        continue;
                    }
                    let proto::TLSPlaintext::ApplicationData { data } = frame else {
                        return unexpected_message!("expected ApplicationData, got {frame:?}");
                    };
                    // Encrypted with server_handshake_traffic_secret
                    crypt::TlsCiphertext::from(data).decrypt(
                        &keys
                            .borrow()
                            .as_ref()
                            .unwrap()
                            .server_handshake_traffic_secret,
                        seq_id.to_nonce(),
                    );

                    todo!()
                }
                ConnectState::WaitCertificateRequest => todo!(),
                ConnectState::WaitCertificate => todo!(),
                ConnectState::WaitCertificateVerify => todo!(),
                ConnectState::WaitFinished => todo!(),
                ConnectState::Connected => todo!(),
            };
            state = next_state;
        }
    }
}

impl TLSPlaintext {
    fn should_drop(&self) -> bool {
        match self {
            TLSPlaintext::ChangeCipherSpec { data: body } if body.as_ref() == &[0x01] => true,
            _ => false,
        }
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
        //Self {
        //    kind: ErrorKind::Io(value),
        //}
    }
}

impl From<ErrorKind> for Error {
    fn from(value: ErrorKind) -> Self {
        panic!("error:{value:?}");
        //Self { kind: value }
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

pub trait LoggingWriterExt: Sized {
    fn log(self) -> LoggingWriter<Self> {
        LoggingWriter(self)
    }
}
impl<W: io::Write> LoggingWriterExt for W {}
