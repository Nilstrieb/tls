use std::net::TcpStream;

// An example program that makes a shitty HTTP/1.1 request.
fn main() {
    let conn = TcpStream::connect(("noratrieb.dev", 443))
        .unwrap()
        //.log()
        ;
    tls::ClientConnection::establish(conn, "noratrieb.dev").unwrap();
}
