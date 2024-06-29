use std::net::TcpStream;

// An example program that makes a shitty HTTP/1.1 request.
fn main() {
    let conn = tls::LoggingWriter(TcpStream::connect(("vps1.nilstrieb.dev", 443)).unwrap());
    tls::ClientConnection::establish(conn, "vps1.nilstrieb.dev").unwrap();
}
