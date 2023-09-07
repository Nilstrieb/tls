use std::io::{self, Read, Write};

use byteorder::{BigEndian as B, ReadBytesExt, WriteBytesExt};

use crate::ErrorKind;

// https://datatracker.ietf.org/doc/html/rfc8446#section-4
macro_rules! handshake {
    ($(#[$meta:meta])* pub enum Handshake {
        $(
            $KindName:ident {
                $(
                    $field_name:ident : $field_ty:ty,
                )*
            } = $discriminant:expr,
        )*
    }) => {
        $(#[$meta])*
        pub enum Handshake {
            $(
                $KindName {
                    $(
                        $field_name: $field_ty,
                    )*
                },
            )*
        }

        impl Handshake {
            fn write(self, w: &mut impl Write) -> io::Result<()> {
                match self {
                    $(
                        Self::$KindName {
                            $( $field_name, )*
                        } => {
                            $(
                                Value::write($field_name, &mut *w)?;
                            )*
                            Ok(())
                        }
                    )*
                }
            }

            fn read(r: &mut impl Read) -> crate::Result<Self> {
                let kind = r.read_u8()?;
                match kind {
                    $(
                        $discriminant => {
                            let ( $( $field_name ),* ) = ($( { discard!($field_name); Value::read(&mut *r)? } ),*);

                            Ok(Self::$KindName {
                                $(
                                    $field_name,
                                )*
                            })
                        },
                    )*

                    _ => Err(ErrorKind::InvalidHandshake(kind).into()),
                }
            }
        }
    };
}

handshake! {
    #[derive(Debug, Clone, Copy)]
    pub enum Handshake {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        ClientHello {
            legacy_version: u16,
            random: [u8; 32],
            legacy_session_id: u8,
            cipher_suites: [u8; 2],
            legacy_compressions_methods: u8,
            extensions: u16,
        } = 1,
        ServerHello {} = 2,
        NewSessionTicket {} = 4,
        EndOfEarlyData {} = 5,
        EncryptedExtensions {} = 8,
        Certificate {} = 11,
        CertificateRequest {} = 13,
        CertificateVerify {} = 15,
        Finished {} = 20,
        KeyUpdate {} = 24,
        MessageHash {} = 254,
    }
}

pub const LEGACY_VERSION: u16 = 0x0303; // TLS v1.2

pub fn write_handshake<W: Write>(w: &mut W, handshake: Handshake) -> io::Result<()> {
    handshake.write(w)
}

pub fn read_handshake<R: Read>(r: &mut R) -> crate::Result<Handshake> {
    Handshake::read(r)
}

trait Value: Sized + Copy {
    fn write<W: io::Write>(self, w: W) -> io::Result<()>;
    fn read<R: io::Read>(r: R) -> io::Result<Self>;
}

impl<V: Value, const N: usize> Value for [V; N] {
    fn write<W: io::Write>(self, mut w: W) -> io::Result<()> {
        self.into_iter().map(|v| Value::write(v, &mut w)).collect()
    }
    fn read<R: io::Read>(mut r: R) -> io::Result<Self> {
        // ugly :(
        let mut values = [None; N];
        for i in 0..N {
            let value = V::read(&mut r)?;
            values[i] = Some(value);
        }
        Ok(values.map(Option::unwrap))
    }
}

impl Value for u8 {
    fn write<W: io::Write>(self, mut w: W) -> io::Result<()> {
        w.write_u8(self)
    }
    fn read<R: io::Read>(mut r: R) -> io::Result<Self> {
        r.read_u8()
    }
}

impl Value for u16 {
    fn write<W: io::Write>(self, mut w: W) -> io::Result<()> {
        w.write_u16::<B>(self)
    }
    fn read<R: io::Read>(mut r: R) -> io::Result<Self> {
        r.read_u16::<B>()
    }
}

macro_rules! discard {
    ($($tt:tt)*) => {};
}
use discard;
