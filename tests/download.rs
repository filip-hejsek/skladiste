//! Downloads through the sandboxed download worker from a local HTTP server.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use skladiste::http::Url;
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
                    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", big.len())
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
    let mut out = Vec::new();
    let size = workers().download(&Url::parse(url)?, &mut out, max_size)?;
    assert_eq!(size, out.len() as u64);
    Ok(out)
}

#[test]
fn downloads_body() {
    let base = serve();
    let expected = content(3 << 20);
    assert!(download(&format!("{base}/big.zst"), u64::MAX).unwrap() == expected);
    assert!(download(&format!("{base}/chunked.zst"), u64::MAX).unwrap() == expected);
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
