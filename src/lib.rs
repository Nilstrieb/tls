pub mod proto;

use std::{
    io::{self, Read},
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
        let mut stream = TcpStream::connect(host)?;
        let handshake = proto::Handshake::ClientHello {
            legacy_version: proto::LEGACY_VERSION,
            random: rand::random(),
            legacy_session_id: 0,
            cipher_suites: [0; 2],
            legacy_compressions_methods: 0,
            extensions: 0,
        };
        proto::write_handshake(&mut stream, handshake)?;

        let res = proto::read_handshake(&mut stream)?;
        dbg!(res);

        todo!()
    }
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

#[derive(Debug)]
pub enum ErrorKind {
    InvalidHandshake(u8),
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
