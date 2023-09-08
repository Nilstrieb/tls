pub mod proto;

use std::{
    fmt::Debug,
    io::{self, BufWriter, Read, Write},
    net::{TcpStream, ToSocketAddrs},
};

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct ClientConnection {}

impl ClientConnection {
    pub fn establish(host: impl ToSocketAddrs) -> Result<Self> {
        let _setup = ClientSetupConnection::establish(host)?;

        todo!()
    }
}

struct ClientSetupConnection {}

impl ClientSetupConnection {
    fn establish(host: impl ToSocketAddrs) -> Result<Self> {
        let mut stream = BufWriter::new(LoggingWriter(TcpStream::connect(host)?));
        let handshake = proto::Handshake::ClientHello {
            legacy_version: proto::LEGACY_VERSION,
            random: rand::random(),
            legacy_session_id: 0,
            cipher_suites: vec![proto::CipherSuite::TlsAes128GcmSha256].into(),
            legacy_compressions_methods: 0,
            extensions: vec![proto::ExtensionCH::SupportedVersions {
                versions: vec![proto::TLSV3].into(),
            }]
            .into(),
        };
        let plaintext = proto::TLSPlaintext::Handshake {
            handshake,
        };
        plaintext.write(&mut stream)?;
        stream.flush()?;

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
    InvalidHandshake(Box<dyn Debug>),
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
            eprintln!("wrote bytes: {:x?}", &buf[..len]);
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
            eprintln!("read bytes: {:x?}", &buf[..len]);
        }
        len
    }
}
