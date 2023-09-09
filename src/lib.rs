pub mod proto;

use std::{
    fmt::Debug,
    io::{self, BufWriter, Read, Write},
    net::{TcpStream, ToSocketAddrs},
};

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct ClientConnection {}

impl ClientConnection {
    pub fn establish(host: &str, port: u16) -> Result<Self> {
        let _setup = ClientSetupConnection::establish(host, port)?;

        todo!()
    }
}

struct ClientSetupConnection {}

impl ClientSetupConnection {
    fn establish(host: &str, port: u16) -> Result<Self> {
        let mut stream = BufWriter::new(LoggingWriter(TcpStream::connect((host, port))?));
        let handshake = proto::Handshake::ClientHello {
            legacy_version: proto::LEGACY_TLSV12,
            random: rand::random(),
            legacy_session_id: [(); 32].map(|()| rand::random()).to_vec().into(),
            cipher_suites: vec![proto::CipherSuite::TlsAes128GcmSha256].into(),
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
                    groups: vec![
                        proto::NamedGroup::X25519,
                    ].into(),
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

        let out = proto::TLSPlaintext::read(stream.get_mut())?;
        dbg!(out);

        // let res: proto::TLSPlaintext = proto::Value::read(&mut stream.get_mut())?;
        // dbg!(res);

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
    Io(io::Error),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self {
            kind: ErrorKind::Io(value),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(value: ErrorKind) -> Self {
        Self { kind: value }
    }
}

#[derive(Debug)]
struct LoggingWriter<W>(W);

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
