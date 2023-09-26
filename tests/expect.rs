#![allow(dead_code)]

use std::io::{Read, Write};

struct ExpectServer {
    expect: Vec<Expect>,
}

impl ExpectServer {
    fn new(expect: Vec<Expect>) -> Self {
        ExpectServer { expect }
    }
}

impl Read for ExpectServer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(Expect::Server(server)) = self.expect.first_mut() else {
            panic!("Reading from server, but client input is expected");
        };

        let len = std::cmp::min(buf.len(), server.len());
        buf[..len].copy_from_slice(&mut server[..len]);
        server.rotate_left(len);
        server.truncate(server.len() - len);
        if server.is_empty() {
            self.expect.remove(0);
        }
        Ok(len)
    }
}

impl Write for ExpectServer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(Expect::Client(client)) = self.expect.first_mut() else {
            panic!("Writing as client, but should read instead");
        };

        let to_write = client
            .get(..buf.len())
            .expect("writing more bytes than expected");
        assert_eq!(to_write, buf);
        client.rotate_left(buf.len());
        client.truncate(client.len() - buf.len());
        if client.is_empty() {
            self.expect.remove(0);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

enum Expect {
    Server(Vec<u8>),
    Client(Vec<u8>),
}

#[test]
#[ignore]
fn connect() {
    let mut expect = ExpectServer::new(vec![
        Expect::Client(vec![0]), // TODO: do this
    ]);

    tls::ClientConnection::establish(&mut expect, "example.com").unwrap();
}
