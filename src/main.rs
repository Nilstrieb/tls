// An example program that makes a shitty HTTP/1.1 request.
fn main() {
    tls::ClientConnection::establish("google.com", 443).unwrap();
}
