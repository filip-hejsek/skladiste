//! Downloads through the sandboxed download worker from local HTTP servers.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use skladiste::http::{RootCerts, Url};
use skladiste::worker::{Request, Sink, Workers};

fn workers() -> Workers {
    let mut workers = Workers::new(env!("CARGO_BIN_EXE_skl"));
    // Tests of connections that get nothing shouldn't take seconds.
    workers.set_retry_delay(Duration::from_millis(10));
    workers
}

fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// A request that a test server got.
#[derive(Clone, Debug, PartialEq)]
struct Req {
    /// The connection it came over, counting from 0.
    conn: usize,
    path: String,
    range: Option<String>,
    if_range: Option<String>,
}

/// What a test server does with a request.
enum Reply {
    /// Send this and wait for the next request.
    Keep(Vec<u8>),
    /// Send this and close the connection.
    Close(Vec<u8>),
}

struct Server {
    /// `http://127.0.0.1:PORT`.
    base: String,
    requests: Arc<Mutex<Vec<Req>>>,
    connections: Arc<AtomicUsize>,
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn requests(&self) -> Vec<Req> {
        self.requests.lock().unwrap().clone()
    }

    /// The paths requested, with the connection each came over.
    fn paths(&self) -> Vec<(usize, String)> {
        let requests = self.requests();
        requests.into_iter().map(|r| (r.conn, r.path)).collect()
    }

    /// The number of connections accepted.
    fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }
}

/// Serve HTTP on a local port, with keep-alive: `handler` says what to
/// send for each request.
fn serve(handler: impl Fn(&Req) -> Reply + Send + Sync + 'static) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = Server {
        base: format!("http://{}", listener.local_addr().unwrap()),
        requests: Arc::default(),
        connections: Arc::default(),
    };
    let (requests, connections) = (server.requests.clone(), server.connections.clone());
    let handler = Arc::new(handler);
    std::thread::spawn(move || {
        for (conn, stream) in listener.incoming().enumerate() {
            let mut stream = stream.unwrap();
            connections.fetch_add(1, Ordering::Relaxed);
            let (handler, requests) = (handler.clone(), requests.clone());
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                while let Some(req) = read_request(&mut reader, conn) {
                    requests.lock().unwrap().push(req.clone());
                    // The client may close early (e.g. size limit exceeded).
                    match handler(&req) {
                        Reply::Keep(bytes) if stream.write_all(&bytes).is_ok() => {}
                        Reply::Keep(_) => break,
                        Reply::Close(bytes) => {
                            let _ = stream.write_all(&bytes);
                            break;
                        }
                    }
                }
            });
        }
    });
    server
}

/// Read a request head; `None` when the client closed the connection.
fn read_request(reader: &mut impl BufRead, conn: usize) -> Option<Req> {
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return None;
    }
    let mut req = Req {
        conn,
        path: line.split(' ').nth(1)?.to_owned(),
        range: None,
        if_range: None,
    };
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return None;
        }
        let Some((name, value)) = line.trim_end().split_once(": ") else {
            return Some(req);
        };
        match name.to_ascii_lowercase().as_str() {
            "range" => req.range = Some(value.to_owned()),
            "if-range" => req.if_range = Some(value.to_owned()),
            _ => {}
        }
    }
}

/// A response with `headers` (lines) and a `Content-Length` for `body`.
fn response(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut r = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for header in headers {
        r += &format!("{header}\r\n");
    }
    r += "\r\n";
    let mut r = r.into_bytes();
    r.extend_from_slice(body);
    r
}

fn ok(body: &[u8]) -> Reply {
    Reply::Keep(response("200 OK", &[], body))
}

/// The rest of `body` from the offset that `req` asks for, if it does.
fn rest(req: &Req, headers: &[&str], body: &[u8]) -> Option<Vec<u8>> {
    let offset: usize = req
        .range
        .as_deref()?
        .strip_prefix("bytes=")?
        .strip_suffix('-')?
        .parse()
        .ok()?;
    let range = format!(
        "Content-Range: bytes {offset}-{}/{}",
        body.len() - 1,
        body.len()
    );
    let headers = [headers, &[&range]].concat();
    Some(response("206 Partial Content", &headers, &body[offset..]))
}

/// A response that the server gives up on after `sent` bytes of the body.
fn cut(mut response: Vec<u8>, body: &[u8], sent: usize) -> Reply {
    response.truncate(response.len() - (body.len() - sent));
    Reply::Close(response)
}

/// A server of canned responses, by path.
fn serve_files() -> Server {
    serve(|req| {
        let big = content(3 << 20);
        Reply::Keep(match req.path.as_str() {
            "/big.zst" => response(
                "200 OK",
                &[
                    "Last-Modified: Mon, 16 Nov 2026 08:00:00 GMT",
                    "ETag: \"6919-abc\"",
                ],
                &big,
            ),
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
            path => match path.strip_prefix("/small/") {
                Some(name) => response("200 OK", &[], name.as_bytes()),
                None => response("404 Not Found", &[], b""),
            },
        })
    })
}

fn download(url: &str, max_size: u64) -> anyhow::Result<Vec<u8>> {
    download_with(&workers(), url, max_size)
}

fn download_with(workers: &Workers, url: &str, max_size: u64) -> anyhow::Result<Vec<u8>> {
    let (out, d) = workers.download(&Url::parse(url)?, Vec::new(), max_size)?;
    assert_eq!(d.size, out.len() as u64);
    Ok(out)
}

/// Keeps a download, and counts how often it started again.
#[derive(Debug, Default)]
struct Body {
    data: Vec<u8>,
    restarts: usize,
}

impl Sink for Body {
    fn write(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.data.extend_from_slice(data);
        Ok(())
    }

    fn restart(&mut self) -> anyhow::Result<()> {
        self.data.clear();
        self.restarts += 1;
        Ok(())
    }
}

/// Download `urls` with [`Workers::download_all`]; returns each body, in
/// their order.
fn download_all(urls: &[String], restart_if_changed: bool) -> anyhow::Result<Vec<Body>> {
    let requests = urls
        .iter()
        .map(|url| Request {
            url: Url::parse(url).unwrap(),
            max_size: u64::MAX,
            restart_if_changed,
            sink: Body::default(),
        })
        .collect();
    let bodies: Vec<Mutex<Option<Body>>> = urls.iter().map(|_| Mutex::default()).collect();
    let failed = AtomicBool::new(false);
    let jobs = NonZeroUsize::new(4).unwrap();
    workers().download_all(requests, jobs, &failed, |i, body, d| {
        assert_eq!(d.size, body.data.len() as u64);
        assert!(bodies[i].lock().unwrap().replace(body).is_none());
        Ok(())
    })?;
    assert!(!failed.into_inner());
    Ok(bodies
        .into_iter()
        .map(|body| body.into_inner().unwrap().expect("a download is missing"))
        .collect())
}

/// Download one file with [`download_all`].
fn download_one(url: String, restart_if_changed: bool) -> anyhow::Result<Body> {
    Ok(download_all(&[url], restart_if_changed)?.pop().unwrap())
}

/// Test certificates for 127.0.0.1, signed by a test CA (`ca.pem`).
const CA: &[u8] = include_bytes!("tls/ca.pem");
const SERVER_CERT: &[u8] = include_bytes!("tls/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("tls/server.key");

/// Serve `body` over TLS with the test certificate, for every request.
/// Returns the base URL and the number of connections accepted.
fn serve_tls(body: &'static [u8]) -> (String, Arc<AtomicUsize>) {
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
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = connections.clone();
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            accepted.fetch_add(1, Ordering::Relaxed);
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp.unwrap());
            // Fails when the client rejects the certificate, or is done.
            while serve_one(&mut tls, body).is_ok() {}
        }
    });
    (format!("https://{addr}"), connections)
}

/// Read a request head and respond with `body`.
fn serve_one(conn: &mut (impl Read + Write), body: &[u8]) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut *conn);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if line == "\r\n" {
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
    let (base, connections) = serve_tls(b"secret");
    let url = format!("{base}/x");
    let mut custom = workers();
    custom.set_root_certs(RootCerts::from_pem(CA).unwrap());
    assert_eq!(download_with(&custom, &url, u64::MAX).unwrap(), b"secret");

    // Several files over one TLS connection.
    let requests = (0..3)
        .map(|i| Request {
            url: Url::parse(&format!("{base}/{i}")).unwrap(),
            max_size: u64::MAX,
            restart_if_changed: true,
            sink: Vec::new(),
        })
        .collect();
    let done = AtomicUsize::new(0);
    let before = connections.load(Ordering::Relaxed);
    custom
        .download_all(
            requests,
            NonZeroUsize::MIN,
            &AtomicBool::new(false),
            |_, body, _| {
                assert_eq!(body, b"secret");
                done.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(done.into_inner(), 3);
    assert_eq!(connections.load(Ordering::Relaxed) - before, 1);

    // The test CA isn't among the built-in roots.
    let err = format!("{:#}", download(&url, u64::MAX).unwrap_err());
    assert!(err.contains("UnknownIssuer"), "{err}");

    // Nor is the server's certificate a root.
    let mut wrong = workers();
    wrong.set_root_certs(RootCerts::from_pem(SERVER_CERT).unwrap());
    let before = connections.load(Ordering::Relaxed);
    let err = format!("{:#}", download_with(&wrong, &url, u64::MAX).unwrap_err());
    assert!(err.contains("UnknownIssuer"), "{err}");
    // A certificate that doesn't verify isn't tried again.
    assert_eq!(connections.load(Ordering::Relaxed) - before, 1);
}

#[test]
fn custom_roots_apply_only_to_https() {
    let server = serve_files();
    let mut custom = workers();
    custom.set_root_certs(RootCerts::from_pem(CA).unwrap());
    let body = download_with(&custom, &server.url("/big.zst"), u64::MAX).unwrap();
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
    let server = serve_files();
    let expected = content(3 << 20);
    assert!(download(&server.url("/big.zst"), u64::MAX).unwrap() == expected);
    assert!(download(&server.url("/chunked.zst"), u64::MAX).unwrap() == expected);
    // A file of exactly the largest size allowed.
    assert!(download(&server.url("/big.zst"), 3 << 20).unwrap() == expected);
    assert!(download(&server.url("/chunked.zst"), 3 << 20).unwrap() == expected);

    let url = Url::parse(&server.url("/big.zst")).unwrap();
    let (_, d) = workers().download(&url, Vec::new(), u64::MAX).unwrap();
    assert_eq!(
        d.last_modified.as_deref(),
        Some("Mon, 16 Nov 2026 08:00:00 GMT")
    );
    assert_eq!(d.etag.as_deref(), Some("\"6919-abc\""));
    let url = Url::parse(&server.url("/chunked.zst")).unwrap();
    let (_, d) = workers().download(&url, Vec::new(), u64::MAX).unwrap();
    assert_eq!((d.last_modified, d.etag), (None, None));
}

#[test]
fn download_errors() {
    let server = serve_files();
    let err = download(&server.url("/missing.zst"), u64::MAX).unwrap_err();
    assert!(format!("{err:#}").contains("404 Not Found"), "{err:#}");
    assert!(format!("{err:#}").contains("/missing.zst"), "{err:#}");

    // Larger than allowed, by its length or as it turns out.
    for path in ["/big.zst", "/chunked.zst"] {
        let err = download(&server.url(path), 1000).unwrap_err();
        assert!(format!("{err:#}").contains("larger than 1000"), "{err:#}");
    }

    // Text from the server (here a redirect target) can't send escape
    // sequences to the terminal.
    let err = format!(
        "{:#}",
        download(&server.url("/evil"), u64::MAX).unwrap_err()
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

#[test]
fn one_connection_for_many_files() {
    let server = serve_files();
    let names: Vec<String> = (0..20).map(|i| format!("file-{i}")).collect();
    let mut urls: Vec<String> = names
        .iter()
        .map(|name| server.url(&format!("/small/{name}")))
        .collect();
    urls.insert(7, server.url("/chunked.zst"));
    let bodies = download_all(&urls, false).unwrap();
    assert!(bodies[7].data == content(3 << 20));
    let small: Vec<&[u8]> = bodies.iter().map(|b| &b.data[..]).collect();
    assert_eq!(
        small[..7],
        names[..7].iter().map(|n| n.as_bytes()).collect::<Vec<_>>()
    );
    assert_eq!(
        small[8..],
        names[7..].iter().map(|n| n.as_bytes()).collect::<Vec<_>>()
    );
    assert!(bodies.iter().all(|b| b.restarts == 0));

    // In the order given, over the one connection.
    assert_eq!(server.connections(), 1);
    let expected: Vec<(usize, String)> = urls
        .iter()
        .map(|url| (0, url.strip_prefix(&server.base).unwrap().to_owned()))
        .collect();
    assert_eq!(server.paths(), expected);
}

#[test]
fn several_servers() {
    let servers = [serve_files(), serve_files(), serve_files()];
    let urls: Vec<String> = (0..12)
        .map(|i| servers[i % 3].url(&format!("/small/{i}")))
        .collect();
    let bodies = download_all(&urls, false).unwrap();
    for (i, body) in bodies.iter().enumerate() {
        assert_eq!(body.data, i.to_string().as_bytes());
    }
    for server in &servers {
        assert_eq!(server.connections(), 1);
        assert_eq!(server.requests().len(), 4);
    }
}

#[test]
fn reconnects_when_the_server_closes() {
    // The server closes after every response, with and without saying so.
    for header in [&[][..], &["Connection: close"]] {
        let server =
            serve(move |req| Reply::Close(response("200 OK", header, req.path.as_bytes())));
        let urls: Vec<String> = (0..4).map(|i| server.url(&format!("/{i}"))).collect();
        let bodies = download_all(&urls, false).unwrap();
        for (i, body) in bodies.iter().enumerate() {
            assert_eq!(body.data, format!("/{i}").as_bytes());
        }
        assert_eq!(server.connections(), 4);
    }
}

#[test]
fn continues_after_a_broken_connection() {
    let headers = ["ETag: \"v1\""];
    let server = serve(move |req| {
        let big = content(3 << 20);
        match rest(req, &headers, &big) {
            // The second time the connection breaks further on.
            Some(rest) if req.conn == 1 => cut(rest, &big, 2 << 20),
            Some(rest) => Reply::Keep(rest),
            None => cut(response("200 OK", &headers, &big), &big, 1 << 20),
        }
    });
    let body = download_one(server.url("/big"), false).unwrap();
    assert!(body.data == content(3 << 20));
    assert_eq!(body.restarts, 0);
    let got: Vec<_> = server
        .requests()
        .into_iter()
        .map(|r| (r.conn, r.range, r.if_range))
        .collect();
    let v1 = || Some("\"v1\"".to_owned());
    assert_eq!(
        got,
        [
            (0, None, None),
            (1, Some("bytes=1048576-".to_owned()), v1()),
            (2, Some("bytes=2097152-".to_owned()), v1()),
        ]
    );
}

#[test]
fn starts_again_without_a_validator() {
    // A weak entity tag doesn't say that the file is the same.
    for headers in [&[][..], &["ETag: W/\"v1\""]] {
        let server = serve(move |req| {
            let big = content(1 << 20);
            let whole = response("200 OK", headers, &big);
            match req.conn {
                0 => cut(whole, &big, 500_000),
                _ => Reply::Keep(whole),
            }
        });
        let body = download_one(server.url("/big"), false).unwrap();
        assert!(body.data == content(1 << 20));
        assert_eq!(body.restarts, 1);
        let ranges: Vec<_> = server.requests().into_iter().map(|r| r.range).collect();
        assert_eq!(ranges, [None, None]);
    }
}

/// A server whose file changes after the first connection, which breaks.
fn serve_changing(new: &'static [u8]) -> Server {
    serve(move |req| {
        let old = content(1 << 20);
        if req.conn == 0 {
            return cut(response("200 OK", &["ETag: \"v1\""], &old), &old, 500_000);
        }
        assert_eq!(req.if_range.as_deref(), Some("\"v1\""));
        assert_eq!(req.range.as_deref(), Some("bytes=500000-"));
        Reply::Keep(response("200 OK", &["ETag: \"v2\""], new))
    })
}

#[test]
fn changed_file() {
    // The new version is taken from the beginning, over the connection
    // that found it.
    let server = serve_changing(b"new content");
    let body = download_one(server.url("/f"), true).unwrap();
    assert_eq!(body.data, b"new content");
    assert_eq!(body.restarts, 1);
    assert_eq!(server.connections(), 2);

    // Or not at all.
    let server = serve_changing(b"new content");
    let err = format!("{:#}", download_one(server.url("/f"), false).unwrap_err());
    assert!(err.contains("the file changed on the server"), "{err}");
    assert!(err.contains("200 OK"), "{err}");
    assert_eq!(server.connections(), 2);
}

/// A server that has less of its file after the first connection, which
/// breaks, than it sent.
fn serve_shrinking() -> Server {
    serve(|req| {
        let big = content(1 << 20);
        match (req.conn, &req.range) {
            (0, _) => cut(response("200 OK", &["ETag: \"v1\""], &big), &big, 500_000),
            (_, Some(_)) => Reply::Keep(response("416 Range Not Satisfiable", &[], b"")),
            (_, None) => ok(b"short"),
        }
    })
}

#[test]
fn range_not_served() {
    // The file is fetched again from the beginning, whether another
    // version is wanted or not: the server didn't say that it has one.
    for restart_if_changed in [true, false] {
        let server = serve_shrinking();
        let body = download_one(server.url("/f"), restart_if_changed).unwrap();
        assert_eq!(body.data, b"short");
        assert_eq!(body.restarts, 1);
        let ranges: Vec<_> = server
            .requests()
            .into_iter()
            .map(|r| (r.conn, r.range.is_some()))
            .collect();
        assert_eq!(ranges, [(0, false), (1, true), (2, false)]);
    }
}

#[test]
fn gives_up_without_progress() {
    // Connections that get no response at all.
    let server = serve(|_| Reply::Close(Vec::new()));
    let err = format!("{:#}", download_one(server.url("/f"), true).unwrap_err());
    assert!(err.contains("closed before the response"), "{err}");
    assert!(err.contains("giving up"), "{err}");
    assert!(err.contains("/f"), "{err}");
    assert_eq!(server.connections(), 3);

    // Getting as far as before isn't progress.
    let server = serve(|_| {
        let big = content(1 << 20);
        cut(response("200 OK", &[], &big), &big, 500_000)
    });
    let err = format!("{:#}", download_one(server.url("/f"), true).unwrap_err());
    assert!(err.contains("after 500000 of 1048576 bytes"), "{err}");
    assert_eq!(server.connections(), 4);

    // Nor is a file that is cut off where it was continued.
    let server = serve(|req| {
        let big = content(1 << 20);
        match rest(req, &["ETag: \"v1\""], &big) {
            Some(rest) => cut(rest, &big, 500_000),
            None => cut(response("200 OK", &["ETag: \"v1\""], &big), &big, 500_000),
        }
    });
    let err = format!("{:#}", download_one(server.url("/f"), true).unwrap_err());
    assert!(err.contains("after 0 of 548576 bytes"), "{err}");
    assert_eq!(server.connections(), 4);

    // Connections that get somewhere don't count, but don't make up for
    // those that don't either.
    let server = serve(|req| match req.conn {
        1 | 3 | 5 => Reply::Close(Vec::new()),
        _ => Reply::Close(response("200 OK", &[], req.path.as_bytes())),
    });
    let urls: Vec<String> = (0..9).map(|i| server.url(&format!("/{i}"))).collect();
    let err = format!("{:#}", download_all(&urls, true).unwrap_err());
    assert!(err.contains("giving up"), "{err}");
    assert!(err.contains("/3"), "{err}");
    assert_eq!(server.connections(), 6);
}

#[test]
fn stops_after_a_failure() {
    // Something else failed before: nothing is downloaded.
    let server = serve_files();
    let request = |path: &str| Request {
        url: Url::parse(&server.url(path)).unwrap(),
        max_size: u64::MAX,
        restart_if_changed: true,
        sink: Vec::new(),
    };
    let failed = AtomicBool::new(true);
    workers()
        .download_all(
            vec![request("/small/a")],
            NonZeroUsize::MIN,
            &failed,
            |_, _, _| panic!("downloaded after a failure"),
        )
        .unwrap();
    assert_eq!(server.connections(), 0);

    // A failure of what is done with a download fails the stage, which
    // starts nothing more.
    let failed = AtomicBool::new(false);
    let requests = (0..10).map(|i| request(&format!("/small/{i}"))).collect();
    let done = AtomicUsize::new(0);
    let err = workers()
        .download_all(requests, NonZeroUsize::MIN, &failed, |i, _, _| {
            done.fetch_add(1, Ordering::Relaxed);
            anyhow::ensure!(i != 2, "file {i} is no good");
            Ok(())
        })
        .unwrap_err();
    assert_eq!(err.to_string(), "file 2 is no good");
    assert!(failed.into_inner());
    assert_eq!(done.into_inner(), 3);
    // The worker had the next file at hand.
    let requests = server.requests().len();
    assert!((3..=4).contains(&requests), "{requests}");

    // A file that fails ends the downloads from its server.
    let urls = ["/small/a", "/missing", "/small/b", "/small/c", "/small/d"];
    let urls: Vec<String> = urls.iter().map(|path| server.url(path)).collect();
    let err = format!("{:#}", download_all(&urls, true).unwrap_err());
    assert!(err.contains("/missing: server responded 404"), "{err}");
}
