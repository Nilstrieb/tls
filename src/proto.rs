pub mod ser_de;

use std::{
    fmt::Debug,
    io::{self, Read, Write},
};

use crate::ErrorKind;

use self::ser_de::{proto_enum, proto_struct, u24, FrameReader, List, Todo, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TLSPlaintext {
    Invalid {
        legacy_version: ProtocolVersion,
        fragment: List<u8, u16>,
    },
    /// This only exists for compatibility and must be sent immediately before the second flight. 
    /// If this is received with the single byte value `0x01`, then it should just be dropped.
    ChangeCipherSpec,
    Alert {
        alert: Alert,
    },
    Handshake {
        handshake: Handshake,
    },
    ApplicationData,
}

impl TLSPlaintext {
    const INVALID: u8 = 0;
    const CHANGE_CIPHER_SPEC: u8 = 20;
    const ALERT: u8 = 21;
    const HANDSHAKE: u8 = 22;
    const APPLICATION_DATA: u8 = 23;

    pub fn write(&self, w: &mut impl Write) -> io::Result<()> {
        match self {
            TLSPlaintext::Invalid { .. } => todo!(),
            TLSPlaintext::ChangeCipherSpec => todo!(),
            TLSPlaintext::Alert { .. } => todo!(),
            TLSPlaintext::Handshake { handshake } => {
                Self::HANDSHAKE.write(w)?;
                // MUST be set to 0x0303 for all records
                // generated by a TLS 1.3 implementation other than an initial
                // ClientHello (i.e., one not generated after a HelloRetryRequest),
                // where it MAY also be 0x0301 for compatibility purposes.
                if matches!(handshake, Handshake::ClientHello { .. }) {
                    LEGACY_TLSV10.write(w)?;
                } else {
                    LEGACY_TLSV12.write(w)?;
                }
                let len: u16 = handshake.byte_size().try_into().unwrap();
                len.write(w)?;
                handshake.write(w)?;
                Ok(())
            }
            TLSPlaintext::ApplicationData => todo!(),
        }
    }

    pub fn read(r: &mut impl Read) -> crate::Result<Self> {
        let r = &mut FrameReader::new(r);
        let discr = u8::read(r)?;
        let _legacy_version = ProtocolVersion::read(r)?;
        let _len = u16::read(r)?;
        match discr {
            Self::INVALID => todo!(),
            Self::CHANGE_CIPHER_SPEC => todo!(),
            Self::ALERT => {
                let alert = Alert::read(r)?;
                Ok(Self::Alert { alert })
            }
            Self::HANDSHAKE => {
                let handshake = Handshake::read(r)?;
                Ok(TLSPlaintext::Handshake { handshake })
            }
            Self::APPLICATION_DATA => todo!(),
            _ => {
                return Err(crate::ErrorKind::InvalidFrame(Box::new(format!(
                    "Invalid record discriminant: {discr}"
                )))
                .into())
            }
        }
    }
}

pub type ProtocolVersion = u16;
pub type Random = [u8; 32];

// https://datatracker.ietf.org/doc/html/rfc8446#section-4
proto_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Handshake: u8, (length: u24) {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        ClientHello {
            legacy_version: ProtocolVersion,
            random: Random,
            legacy_session_id: LegacySessionId,
            cipher_suites: List<CipherSuite, u16>,
            legacy_compressions_methods: List<u8, u8>,
            extensions: List<ExtensionCH, u16>,
        } = 1,
        ServerHello {
            legacy_version: ProtocolVersion,
            random: ServerHelloRandom,
            legacy_session_id_echo: LegacySessionId,
            cipher_suite: CipherSuite,
            legacy_compression_method: u8,
            extensions: List<ExtensionSH, u16>,
        } = 2,
        NewSessionTicket {} = 4,
        EndOfEarlyData {} = 5,
        EncryptedExtensions {
            extensions: List<ExtensionEE, u16>,
        } = 8,
        Certificate {} = 11,
        CertificateRequest {} = 13,
        CertificateVerify {} = 15,
        Finished {} = 20,
        KeyUpdate {} = 24,
        MessageHash {} = 254,
    }
}

pub const HELLO_RETRY_REQUEST: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

pub const LEGACY_TLSV10: ProtocolVersion = 0x0301;
pub const LEGACY_TLSV12: ProtocolVersion = 0x0303;
pub const TLSV13: ProtocolVersion = 0x0304;

type LegacySessionId = List<u8, u8>;

proto_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(non_camel_case_types)]
    pub enum CipherSuite: [u8; 2] {
        TLS_AES_128_GCM_SHA256 = [0x13, 0x01],
        TLS_AES_256_GCM_SHA384 = [0x13, 0x02],
        TLS_CHACHA20_POLY1305_SHA256 = [0x13, 0x03],
        TLS_AES_128_CCM_SHA256 = [0x13, 0x04],
        TLS_AES_128_CCM_8_SHA256 = [0x13, 0x05],
    }
}

proto_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ExtensionCH: u16, (length: u16) {
        ServerName {
            server_name: ServerNameList,
        } = 0,
        MaxFragmentLength { todo: Todo, } = 1,
        StatusRequest { todo: Todo, } = 5,
        SupportedGroups {
            groups: NamedGroupList,
        } = 10,
        ECPointFormat {
            formats: ECPointFormatList,
        } = 11,
        SignatureAlgorithms {
            supported_signature_algorithms: List<SignatureScheme, u16>,
        } = 13,
        UseSrtp { todo: Todo, } = 14,
        Heartbeat { todo: Todo, } = 15,
        ApplicationLayerProtocolNegotiation { todo: Todo, } = 16,
        SignedCertificateTimestamp { todo: Todo, } = 18,
        ClientCertificateType { todo: Todo, } = 19,
        ServerCertificateType { todo: Todo, } = 20,
        Padding { todo: Todo, } = 21,
        PreSharedKey { todo: Todo, } = 41,
        EarlyData { todo: Todo, } = 42,
        SupportedVersions {
            versions: List<ProtocolVersion, u8>,
        } = 43,
        Cookie{ todo: Todo, } = 44,
        PskKeyExchangeModes { todo: Todo, } = 45,
        CertificateAuthorities { todo: Todo, } = 47,
        PostHandshakeAuth { todo: Todo, } = 49,
        SignatureAlgorithmsCert{ todo: Todo, } = 50,
        KeyShare {
            entries: List<KeyShareEntry, u16>,
        } = 51,
    }
}

proto_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ExtensionSH: u16, (length: u16) {
        PreSharedKey = 41,
        SupportedVersions {
            selected_version: ProtocolVersion,
        } = 43,
        Cookie { todo: Todo, } = 44,
        KeyShare {
            key_share: ServerHelloKeyshare,
        } = 51,
    }
}

proto_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ExtensionEE: u16, (length: u16) {
        ServerName {
            server_name: ServerNameList,
        } = 0,
        MaxFragmentLength { todo: Todo, } = 1,
        SupportedGroups {
            groups: NamedGroupList,
        } = 10,
        UseSrtp { todo: Todo, } = 14,
        Heartbeat { todo: Todo, } = 15,
        ApplicationLayerProtocolNegotiation { todo: Todo, } = 16,
        ClientCertificateType { todo: Todo, } = 19,
        ServerCertificateType { todo: Todo, } = 20,
        EarlyData { todo: Todo, } = 42,
    }
}


proto_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ServerName: u8 {
        HostName {
            host_name: HostName,
        } = 0,
    }
}

type HostName = List<u8, u16>;
type ServerNameList = List<ServerName, u16>;

proto_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ECPointFormat: u8 {
        Uncompressed = 0,
    }
}
type ECPointFormatList = List<ECPointFormat, u8>;

proto_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum KeyShareEntry: super::NamedGroup {
        X25519 {
            len: u16,
            key_exchange: [u8; 32],
        } = super::NamedGroup::X25519,
    }
}

proto_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(non_camel_case_types)]
    pub enum NamedGroup: u16 {
        /* Elliptic Curve Groups (ECDHE) */
        SECP256R1 = 0x0017,
        SECP384R1 = 0x0018,
        SECP521R1 = 0x0019,
        X25519 = 0x001D,
        X448 = 0x001E,

        /* Finite Field Groups (DHE) */
        FFDHE2048 = 0x0100,
        FFDHE3072 = 0x0101,
        FFDHE4096 = 0x0102,
        FFDHE6144 = 0x0103,
        FFDHE8192 = 0x0104,
    }
}
type NamedGroupList = List<NamedGroup, u16>;

proto_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(non_camel_case_types)]
    pub enum SignatureScheme: u32 {
        /* RSASSA-PKCS1-v1_5 algorithms */
        RSA_PKCS1_SHA256 = 0x0401,
        RSA_PKCS1_SHA384 = 0x0501,
        RSA_PKCS1_SHA512 = 0x0601,

        /* ECDSA algorithms */
        ECDSA_SECP256R1_SHA256 = 0x0403,
        ECDSA_SECP384R1_SHA384 = 0x0503,
        ECDSA_SECP521R1_SHA512 = 0x0603,

        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        RSA_PSS_RSAE_SHA256 = 0x0804,
        RSA_PSS_RSAE_SHA384 = 0x0805,
        RSA_PSS_RSAE_SHA512 = 0x0806,

        /* EdDSA algorithms */
        ED25519 = 0x0807,
        ED448 = 0x0808,

        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        RSA_PSS_PSS_SHA256 = 0x0809,
        RSA_PSS_PSS_SHA384 = 0x080a,
        RSA_PSS_PSS_SHA512 = 0x080b,

        /* Legacy algorithms */
        RSA_PKCS1_SHA1 = 0x0201,
        ECDSA_SHA1 = 0x0203,
    }
}

proto_struct! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Alert {
        pub level: AlertLevel,
        pub description: AlertDescription,
    }
}

proto_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AlertLevel: u8 {
        Warning = 1,
        Fatal = 2,
    }
}

proto_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AlertDescription: u8 {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        RecordOverflow = 22,
        HandshakeFailure = 40,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknown = 46,
        IllegalParameter = 47,
        UnknownCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        InappropriateFallback = 86,
        UserCanceled = 90,
        MissingExtension = 109,
        UnsupportedExtension = 110,
        UnrecognizedName = 112,
        BadCertificateStatusResponse = 113,
        UnknownPskIdentity = 115,
        CertificateRequired = 116,
        NoApplicationProtocol = 120,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHelloRandom(Random);

impl Value for ServerHelloRandom {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.0.write(w)
    }

    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self> {
        let random = Random::read(r)?;
        if random == HELLO_RETRY_REQUEST {
            r.is_hello_retry_request = true;
        }
        Ok(Self(random))
    }

    fn byte_size(&self) -> usize {
        self.0.byte_size()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerHelloKeyshare {
    HelloRetryRequest(NamedGroup),
    ServerHello(KeyShareEntry),
}

impl ServerHelloKeyshare {
    pub fn unwrap_server_hello(&self) -> &KeyShareEntry {
        match self {
            Self::HelloRetryRequest(_) => panic!("unexpected hello retry request, expected server hello"),
            Self::ServerHello(entry) => entry,
        }
    }
}

impl Value for ServerHelloKeyshare {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Self::HelloRetryRequest(group) => group.write(w),
            Self::ServerHello(entry) => entry.write(w),
        }
    }

    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self> {
        if r.is_hello_retry_request {
            NamedGroup::read(r).map(Self::HelloRetryRequest)
        } else {
            KeyShareEntry::read(r).map(Self::ServerHello)
        }
    }

    fn byte_size(&self) -> usize {
        match self {
            Self::HelloRetryRequest(group) => group.byte_size(),
            Self::ServerHello(entry) => entry.byte_size(),
        }
    }
}

impl ServerHelloRandom {
    pub fn is_hello_retry_request(&self) -> bool {
        self.0 == HELLO_RETRY_REQUEST
    }
}

#[cfg(test)]
mod tests;
