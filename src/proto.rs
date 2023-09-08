use std::{
    fmt::Debug,
    io::{self, Read, Write},
    marker::PhantomData,
};

use byteorder::{BigEndian as B, ReadBytesExt, WriteBytesExt};

use crate::ErrorKind;

// https://datatracker.ietf.org/doc/html/rfc8446#section-4
proto_enum! {
    #[derive(Debug, Clone)]
    pub enum Handshake: u8 {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        ClientHello {
            legacy_version: u16,
            random: [u8; 32],
            legacy_session_id: u8,
            cipher_suites: List<CipherSuite, u16>,
            legacy_compressions_methods: u8,
            extensions: List<Extension, u16>,
        } = 1,
        ServerHello {
            legacy_version: u16,
            random: [u8; 32],
            legacy_session_id_echo: u8,
            cipher_suite: CipherSuite,
            legacy_compression_method: u8,
            extensions: List<Extension, u16>,
        } = 2,
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

proto_enum! {
    #[derive(Debug, Clone, Copy)]
    pub enum CipherSuite: [u8; 2] {
        TlsAes128GcmSha256 = [0x13, 0x01],
        TlsAes256GcmSha384 = [0x13, 0x02],
        TlsChacha20Poly1305Sha256 = [0x13, 0x03],
        TlsAes128CcmSha256 = [0x13, 0x04],
        TlsAes128Ccm8Sha256 = [0x13, 0x05],
    }
}

pub type Extension = (ExtensionType, List<u8, u16>);

proto_enum! {
    #[derive(Debug, Clone, Copy)]
    pub enum ExtensionType: u16 {
        ServerName = 0,
        MaxFragmentLength = 1,
        StatusRequest = 5,
        SupportedGroups = 10,
        SignatureAlgorithms = 13,
        UseSrtp = 14,
        Heartbeat = 15,
        ApplicationLayerProtocolNegotiation = 16,
        SignedCertificateTimestamp = 18,
        ClientCertificateType = 19,
        ServerCertificateType = 20,
        Padding = 21,
        PreSharedKey = 41,
        EarlyData = 42,
        SupportedVersions = 43,
        Cookie = 44,
        PskKeyExchangeModes = 45,
        CertificateAuthorities = 47,
        OidFilters = 48,
        PostHandshakeAuth = 49,
        SignatureAlgorithmsCert = 50,
        KeyShare = 51,
    }
}

macro_rules! proto_enum {
    ($(#[$meta:meta])* pub enum $name:ident: $discr_ty:ty {
        $(
            $KindName:ident $({
                $(
                    $field_name:ident : $field_ty:ty,
                )*
            })? = $discriminant:expr,
        )*
    }) => {
        $(#[$meta])*
        pub enum $name {
            $(
                $KindName $({
                    $(
                        $field_name: $field_ty,
                    )*
                })?,
            )*
        }

        impl Value for $name {
            fn write<W: Write>(&self, mut w: &mut W) -> io::Result<()> {
                mod discr_consts {
                    $(
                        #[allow(non_upper_case_globals)]
                        pub(super) const $KindName: $discr_ty = $discriminant;
                    )*
                }

                match self {
                    $(
                        Self::$KindName $( {
                            $( $field_name, )*
                        } )? => {
                            Value::write(&discr_consts::$KindName, &mut w)?;
                            $($(
                                Value::write($field_name, &mut w)?;
                            )*)?
                            Ok(())
                        }
                    )*
                }
            }

            fn read<R: Read>(r: &mut R) -> crate::Result<Self> {
                mod discr_consts {
                    $(
                        #[allow(non_upper_case_globals)]
                        pub(super) const $KindName: $discr_ty = $discriminant;
                    )*
                }

                let kind: $discr_ty = Value::read(r)?;
                match kind {
                    $(
                        discr_consts::$KindName => {
                            $(let ( $( $field_name ),* ) = ($( { discard!($field_name); Value::read(r)? } ),*);)?

                            Ok(Self::$KindName $({
                                $(
                                    $field_name,
                                )*
                            })*)
                        },
                    )*

                    _ => Err(ErrorKind::InvalidHandshake(Box::new(kind)).into()),
                }
            }
        }
    };
}
use proto_enum;

#[derive(Clone)]
pub struct List<T, Len>(Vec<T>, PhantomData<Len>);

impl<T, Len: Value> From<Vec<T>> for List<T, Len> {
    fn from(value: Vec<T>) -> Self {
        Self(value, PhantomData)
    }
}

impl<T: Debug, Len> Debug for List<T, Len> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl<T: Value, Len: Value + Into<usize> + TryFrom<usize>> Value for List<T, Len> {
    fn read<R: Read>(r: &mut R) -> crate::Result<Self> {
        let len: usize = Len::read(r)?.into();
        let mut v = Vec::with_capacity(len.max(1000));
        for _ in 0..len {
            v.push(T::read(r)?);
        }
        Ok(Self(v, PhantomData))
    }
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        Len::write(
            &self
                .0
                .len()
                .try_into()
                .unwrap_or_else(|_| panic!("list is too large for domain: {}", self.0.len())),
            w,
        )
    }
}

pub fn write_handshake<W: Write>(w: &mut W, handshake: Handshake) -> io::Result<()> {
    handshake.write(w)
}

pub fn read_handshake<R: Read>(r: &mut R) -> crate::Result<Handshake> {
    Handshake::read(r)
}

pub trait Value: Sized + std::fmt::Debug {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()>;
    fn read<R: Read>(r: &mut R) -> crate::Result<Self>;
}

impl<V: Value, const N: usize> Value for [V; N] {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.iter().try_for_each(|v| Value::write(v, w))
    }
    fn read<R: Read>(r: &mut R) -> crate::Result<Self> {
        // ugly :(
        let mut values = Vec::with_capacity(N);
        for _ in 0..N {
            let value = V::read(r)?;
            values.push(value);
        }
        Ok(values.try_into().unwrap())
    }
}

impl Value for u8 {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_u8(*self)
    }
    fn read<R: Read>(r: &mut R) -> crate::Result<Self> {
        r.read_u8().map_err(Into::into)
    }
}

impl Value for u16 {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_u16::<B>(*self)
    }
    fn read<R: Read>(r: &mut R) -> crate::Result<Self> {
        r.read_u16::<B>().map_err(Into::into)
    }
}

impl<T: Value, U: Value> Value for (T, U) {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        T::write(&self.0, w)?;
        T::write(&self.0, w)?;
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> crate::Result<Self> {
        Ok((T::read(r)?, U::read(r)?))
    }
}

macro_rules! discard {
    ($($tt:tt)*) => {};
}
use discard;
