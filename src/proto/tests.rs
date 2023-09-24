use super::*;

#[test]
fn parse_hello_retry_request() {
    #[rustfmt::skip]
    let mut bytes: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x58, 0x02, 0x00, 0x00, 0x54, 0x03, 0x03, 0xcf, 0x21, 0xad, 0x74, 0xe5,
        0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a,
        0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c, 0x20, 0xdd, 0x0f, 0x25, 0x0a,
        0xf0, 0xa6, 0xd9, 0xb0, 0x1c, 0x28, 0x2f, 0x55, 0xcb, 0xab, 0x07, 0x94, 0x2e, 0xb3, 0x98, 0x96,
        0x32, 0x81, 0xad, 0x8d, 0x24, 0x72, 0x52, 0x2a, 0x45, 0x26, 0x10, 0xa2, 0x13, 0x01, 0x00, 0x00,
        0x0c, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00, 0x1d,
    ];

    let handshake = TLSPlaintext::read(&mut bytes).unwrap();
    assert_eq!(
        handshake,
        TLSPlaintext::Handshake {
            handshake: Handshake::ServerHello {
                legacy_version: LEGACY_TLSV12,
                random: ServerHelloRandom(HELLO_RETRY_REQUEST),
                legacy_session_id_echo:
                    b"\xdd\x0f\x25\x0a\xf0\xa6\xd9\xb0\x1c\x28\x2f\x55\xcb\xab\x07\x94\
                    \x2e\xb3\x98\x96\x32\x81\xad\x8d\x24\x72\x52\x2a\x45\x26\x10\xa2"
                        .to_vec()
                        .into(),
                cipher_suite: CipherSuite::TlsAes128GcmSha256,
                legacy_compression_method: 0,
                extensions: vec![
                    ExtensionSH::SupportedVersions {
                        selected_version: TLSV13
                    },
                    ExtensionSH::KeyShare {
                        key_share: ServerHelloKeyshare::HelloRetryRequest(NamedGroup::X25519)
                    }
                ]
                .into()
            }
        }
    );
}

#[test]
fn parse_server_hello() {
    let mut bytes: &[u8] = b"\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03\x15\x2a\x7b\x01\xaa\
    \x65\xde\x1f\xe0\x87\x52\x73\xd6\x7d\xd4\x8c\xc8\xf1\x9d\x55\x09\
    \x4c\xbd\xa2\xb0\xc9\x77\xa2\x4b\x81\xed\x63\x20\x05\xc1\x7d\x07\
    \x34\x68\xaf\xd5\xfc\x7f\x1c\x0c\x07\xd7\x14\x9e\x2b\x66\x87\x44\
    \x02\xbb\xf7\xb7\x1d\x6a\x29\xaf\x93\xaf\xe2\x02\x13\x01\x00\x00\
    \x2e\x00\x33\x00\x24\x00\x1d\x00\x20\x8e\xbc\x32\x53\xd7\x4d\xf9\
    \x4a\xb8\x04\x03\xda\xfe\xbf\xf5\xab\x6f\x8f\x65\x2a\x1d\x70\xde\
    \xe7\xaf\x93\x82\x59\x70\xac\x75\x4d\x00\x2b\x00\x02\x03\x04";

    let handshake = TLSPlaintext::read(&mut bytes).unwrap();

    assert_eq!(
        handshake,
        TLSPlaintext::Handshake {
            handshake: Handshake::ServerHello {
                legacy_version: LEGACY_TLSV12,
                random: ServerHelloRandom(
                    *b"\x15\x2a\x7b\x01\xaa\x65\xde\x1f\xe0\x87\x52\x73\xd6\x7d\xd4\x8c\
                    \xc8\xf1\x9d\x55\x09\x4c\xbd\xa2\xb0\xc9\x77\xa2\x4b\x81\xed\x63"
                ),
                legacy_session_id_echo:
                    b"\x05\xc1\x7d\x07\x34\x68\xaf\xd5\xfc\x7f\x1c\x0c\x07\xd7\x14\x9e\
                    \x2b\x66\x87\x44\x02\xbb\xf7\xb7\x1d\x6a\x29\xaf\x93\xaf\xe2\x02"
                        .to_vec()
                        .into(),
                cipher_suite: CipherSuite::TlsAes128GcmSha256,
                legacy_compression_method: 0,
                extensions: vec![
                    ExtensionSH::KeyShare {
                        key_share: ServerHelloKeyshare::ServerHello(KeyShareEntry::X25519 {
                            len: 32,
                            key_exchange:
                                *b"\x8e\xbc\x32\x53\xd7\x4d\xf9\x4a\xb8\x04\x03\xda\xfe\xbf\xf5\xab\
                                \x6f\x8f\x65\x2a\x1d\x70\xde\xe7\xaf\x93\x82\x59\x70\xac\x75\x4d"
                        })
                    },
                    ExtensionSH::SupportedVersions {
                        selected_version: TLSV13
                    },
                ]
                .into()
            }
        }
    );
}
