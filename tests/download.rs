//! Downloads through the sandboxed download worker from a local HTTP server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use skladiste::http::{RootCerts, Url};
use skladiste::worker::Workers;

fn workers() -> Workers {
    Workers::new(env!("CARGO_BIN_EXE_skl"))
}

fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// Serve canned responses on a local port, by request path, on one thread.
/// Returns the base URL.
fn serve() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut conn = conn.unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            let path = request_line.split(' ').nth(1).unwrap();
            let big = content(3 << 20);
            let response = match path {
                "/big.zst" => {
                    let mut r = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nLast-Modified: Mon, 16 Nov 2026 08:00:00 GMT\r\n\r\n",
                        big.len()
                    )
                    .into_bytes();
                    r.extend_from_slice(&big);
                    r
                }
                "/chunked.zst" => {
                    let mut r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                    for piece in big.chunks(100_000) {
                        r.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                        r.extend_from_slice(piece);
                        r.extend_from_slice(b"\r\n");
                    }
                    r.extend_from_slice(b"0\r\n\r\n");
                    r
                }
                "/evil" => "HTTP/1.1 302 Found\r\nLocation: \u{9b}2Jgotcha\r\n\r\n"
                    .as_bytes()
                    .to_vec(),
                _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            };
            // The client may close early (e.g. size limit exceeded).
            let _ = conn.write_all(&response);
        }
    });
    format!("http://{addr}")
}

fn download(url: &str, max_size: u64) -> anyhow::Result<Vec<u8>> {
    download_with(&workers(), url, max_size)
}

fn download_with(workers: &Workers, url: &str, max_size: u64) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let d = workers.download(&Url::parse(url)?, &mut out, max_size)?;
    assert_eq!(d.size, out.len() as u64);
    Ok(out)
}

/// Test certificates for 127.0.0.1, signed by a test CA (`ca.pem`).
const CA: &[u8] = include_bytes!("tls/ca.pem");
const SERVER_CERT: &[u8] = include_bytes!("tls/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("tls/server.key");

/// Serve `body` over TLS with the test certificate to each connection.
/// Returns the base URL.
fn serve_tls(body: &'static [u8]) -> String {
    let certs = CertificateDer::pem_slice_iter(SERVER_CERT)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp.unwrap());
            // Fails when the client rejects the certificate.
            let _ = serve_one(&mut tls, body);
        }
    });
    format!("https://{addr}")
}

/// Read a request head and respond with `body`.
fn serve_one(conn: &mut (impl Read + Write), body: &[u8]) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut *conn);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
    }
    write!(
        conn,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    conn.write_all(body)?;
    conn.flush()
}

#[test]
fn https_with_custom_roots() {
    let base = serve_tls(b"secret");
    let url = format!("{base}/x");
    let mut custom = workers();
    custom.set_root_certs(RootCerts::from_pem(CA).unwrap());
    assert_eq!(download_with(&custom, &url, u64::MAX).unwrap(), b"secret");

    // The test CA isn't among the built-in roots.
    let err = format!("{:#}", download(&url, u64::MAX).unwrap_err());
    assert!(err.contains("UnknownIssuer"), "{err}");

    // Nor is the server's certificate a root.
    let mut wrong = workers();
    wrong.set_root_certs(RootCerts::from_pem(SERVER_CERT).unwrap());
    let err = format!("{:#}", download_with(&wrong, &url, u64::MAX).unwrap_err());
    assert!(err.contains("UnknownIssuer"), "{err}");
}

#[test]
fn custom_roots_apply_only_to_https() {
    let base = serve();
    let mut custom = workers();
    custom.set_root_certs(RootCerts::from_pem(CA).unwrap());
    let body = download_with(&custom, &format!("{base}/big.zst"), u64::MAX).unwrap();
    assert!(body == content(3 << 20));
}

#[test]
fn bad_root_certs() {
    let err = format!("{:#}", RootCerts::from_pem(b"").unwrap_err());
    assert!(err.contains("no certificates"), "{err}");
    let err = format!("{:#}", RootCerts::from_pem(SERVER_KEY).unwrap_err());
    assert!(err.contains("no certificates"), "{err}");
    let garbage = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let both = [CA, garbage].concat();
    let err = format!("{:#}", RootCerts::from_pem(&both).unwrap_err());
    assert!(err.contains("certificate 2"), "{err}");
}

#[test]
fn downloads_body() {
    let base = serve();
    let expected = content(3 << 20);
    assert!(download(&format!("{base}/big.zst"), u64::MAX).unwrap() == expected);
    assert!(download(&format!("{base}/chunked.zst"), u64::MAX).unwrap() == expected);

    let url = Url::parse(&format!("{base}/big.zst")).unwrap();
    let d = workers()
        .download(&url, &mut std::io::sink(), u64::MAX)
        .unwrap();
    assert_eq!(
        d.last_modified.as_deref(),
        Some("Mon, 16 Nov 2026 08:00:00 GMT")
    );
    let url = Url::parse(&format!("{base}/chunked.zst")).unwrap();
    let d = workers()
        .download(&url, &mut std::io::sink(), u64::MAX)
        .unwrap();
    assert_eq!(d.last_modified, None);
}

#[test]
fn download_errors() {
    let base = serve();
    let err = download(&format!("{base}/missing.zst"), u64::MAX).unwrap_err();
    assert!(format!("{err:#}").contains("404 Not Found"), "{err:#}");

    let err = download(&format!("{base}/big.zst"), 1000).unwrap_err();
    assert!(format!("{err:#}").contains("larger than 1000"), "{err:#}");

    // Text from the server (here a redirect target) can't send escape
    // sequences to the terminal.
    let err = format!(
        "{:#}",
        download(&format!("{base}/evil"), u64::MAX).unwrap_err()
    );
    assert!(err.contains("redirect to \\u{9b}2Jgotcha"), "{err}");
    assert!(!err.contains('\u{9b}'));

    // Nothing listens on port 1.
    let err = download("http://127.0.0.1:1/x", u64::MAX).unwrap_err();
    assert!(
        format!("{err:#}").contains("connecting to 127.0.0.1:1"),
        "{err:#}"
    );
}
