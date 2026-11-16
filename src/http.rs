//! Downloading files over HTTP(S): one GET request per connection.
//!
//! The supervisor parses the URL ([`Url`]) and opens the TCP connection
//! ([`connect`]); the download worker speaks TLS and HTTP over it (`get`),
//! so it needs no network access, DNS or files of its own and can reach no
//! other host. Redirects are not followed. Server certificates are checked
//! against [`RootCerts`].

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::CertificateDer;

/// Longest response head (status line and headers) accepted.
const MAX_HEAD: u64 = 64 << 10;
const MAX_HEADERS: usize = 100;
/// Longest chunk-size or trailer line of a chunked body accepted.
const MAX_LINE: u64 = 4 << 10;
const MAX_URL: usize = 8 << 10;
const BUF_SIZE: usize = 64 << 10;

/// An `http` or `https` URL, restricted to what downloads need: no user
/// info, a host name or IP address, and a path of printable ASCII
/// characters (already percent-encoded where needed). A fragment is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub tls: bool,
    /// Host name or IP address (IPv6 without brackets).
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

impl Url {
    /// Whether `s` looks like a URL rather than a file path.
    pub fn is_url(s: &str) -> bool {
        let s = s.as_bytes();
        let has_prefix =
            |p: &str| s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p.as_bytes());
        has_prefix("http://") || has_prefix("https://")
    }

    pub fn parse(s: &str) -> Result<Url> {
        Self::parse_inner(s).with_context(|| format!("invalid URL {s:?}"))
    }

    fn parse_inner(s: &str) -> Result<Url> {
        ensure!(s.len() <= MAX_URL, "longer than {MAX_URL} bytes");
        ensure!(
            s.bytes().all(|b| b.is_ascii_graphic()),
            "only printable ASCII characters are allowed (percent-encode others)"
        );
        let (scheme, rest) = s.split_once("://").context("no scheme")?;
        let tls = match scheme.to_ascii_lowercase().as_str() {
            "https" => true,
            "http" => false,
            _ => bail!("unsupported scheme {scheme:?} (only http and https)"),
        };
        let rest = rest.split_once('#').map_or(rest, |(r, _)| r);
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        ensure!(!authority.contains('@'), "user info is not supported");
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (addr, after) = v6.split_once(']').context("unclosed [")?;
            addr.parse::<Ipv6Addr>().context("bad IPv6 address")?;
            (addr, after)
        } else {
            let end = authority.find(':').unwrap_or(authority.len());
            let (host, after) = authority.split_at(end);
            ensure!(!host.is_empty(), "no host");
            ensure!(
                host.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'),
                "bad host name {host:?}"
            );
            (host, after)
        };
        let port = match port {
            "" => {
                if tls {
                    443
                } else {
                    80
                }
            }
            p => {
                let p = p.strip_prefix(':').context("junk after host")?;
                ensure!(p.bytes().all(|b| b.is_ascii_digit()), "bad port {p:?}");
                match p.parse() {
                    Ok(0) | Err(_) => bail!("bad port {p:?}"),
                    Ok(p) => p,
                }
            }
        };
        Ok(Url {
            tls,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    /// The last segment of the path, without the query; may be empty.
    pub fn file_name(&self) -> &str {
        let path = self.path.split_once('?').map_or(&*self.path, |(p, _)| p);
        path.rsplit('/').next().unwrap_or("")
    }

    /// This URL with `suffix` appended to the path (before the query).
    pub fn with_suffix(&self, suffix: &str) -> Url {
        let mut url = self.clone();
        url.path = match self.path.split_once('?') {
            Some((p, q)) => format!("{p}{suffix}?{q}"),
            None => format!("{}{suffix}", self.path),
        };
        url
    }

    fn default_port(&self) -> u16 {
        if self.tls { 443 } else { 80 }
    }

    /// Host and port as in the `Host` header.
    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.tls { "https" } else { "http" };
        write!(f, "{scheme}://{}{}", self.authority(), self.path)
    }
}

/// Open a TCP connection to `url`'s host, trying each of its addresses.
/// Reads and writes on the returned socket time out after `timeout`
/// (`SO_RCVTIMEO`, `SO_SNDTIMEO`), also in a process it is passed to.
pub fn connect(url: &Url, timeout: Duration) -> Result<TcpStream> {
    let addrs: Vec<_> = match url.host.parse::<IpAddr>() {
        Ok(ip) => vec![(ip, url.port).into()],
        Err(_) => (url.host.as_str(), url.port)
            .to_socket_addrs()
            .with_context(|| format!("resolving {}", url.host))?
            .collect(),
    };
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(stream);
            }
            Err(e) => {
                last_err = Some(anyhow::Error::new(e).context(format!("connecting to {addr}")))
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("{} has no addresses", url.host)))
}

/// The root certificates that TLS server certificates must chain to: by
/// default the Mozilla roots compiled into skl (`webpki-roots`), or
/// certificates given by the user instead.
#[derive(Clone, Debug, Default)]
pub struct RootCerts {
    /// `None` for the built-in roots. Each certificate was checked to be
    /// usable as a trust anchor.
    custom: Option<Vec<CertificateDer<'static>>>,
}

impl RootCerts {
    /// Root certificates from a PEM file, such as a CA bundle
    /// (`/etc/ssl/certs/ca-certificates.crt`), used instead of the built-in
    /// ones. Sections other than `CERTIFICATE` are ignored. There must be
    /// at least one certificate, and each must be usable as a trust anchor.
    pub fn from_pem(pem: &[u8]) -> Result<RootCerts> {
        use rustls::pki_types::pem::PemObject;
        let certs = CertificateDer::pem_slice_iter(pem)
            .enumerate()
            .map(|(i, cert)| cert.with_context(|| format!("reading certificate {}", i + 1)))
            .collect::<Result<Vec<_>>>()?;
        ensure!(!certs.is_empty(), "no certificates found");
        Self::from_der(certs)
    }

    /// Root certificates in DER, used instead of the built-in ones.
    pub(crate) fn from_der(certs: Vec<CertificateDer<'static>>) -> Result<RootCerts> {
        let roots = RootCerts {
            custom: Some(certs),
        };
        roots.store()?;
        Ok(roots)
    }

    /// The certificates given instead of the built-in ones, if any.
    pub(crate) fn custom(&self) -> Option<&[CertificateDer<'static>]> {
        self.custom.as_deref()
    }

    fn store(&self) -> Result<rustls::RootCertStore> {
        let Some(certs) = &self.custom else {
            return Ok(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            });
        };
        let mut store = rustls::RootCertStore::empty();
        for (i, cert) in certs.iter().enumerate() {
            store
                .add(cert.clone())
                .with_context(|| format!("certificate {} is not a usable root", i + 1))?;
        }
        Ok(store)
    }
}

/// What a response said besides its body.
#[derive(Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Response {
    /// The `Last-Modified` header, as sent.
    pub last_modified: Option<String>,
    /// The `ETag` header, as sent (with its quotes and any `W/`).
    pub etag: Option<String>,
}

/// Request `url` over `stream`, an open connection to its host, using TLS
/// for `https` with server certificates checked against `roots`, and pass
/// the body of a `200 OK` response to `body` in pieces. Any other status
/// is an error, including redirects.
pub(crate) fn get(
    stream: impl Read + Write,
    url: &Url,
    roots: &RootCerts,
    body: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> Result<Response> {
    if !url.tls {
        return request(stream, url, body);
    }
    let roots = roots.store()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(url.host.clone())?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name)?;
    request(rustls::StreamOwned::new(conn, stream), url, body)
}

fn request(
    mut stream: impl Read + Write,
    url: &Url,
    body: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> Result<Response> {
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: skl/{}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        url.path,
        url.authority(),
        env!("CARGO_PKG_VERSION"),
    );
    stream
        .write_all(req.as_bytes())
        .and_then(|()| stream.flush())
        .context("sending request")?;
    let mut r = BufReader::with_capacity(BUF_SIZE, stream);
    let (framing, response) = read_head(&mut r)?;
    match framing {
        Framing::Chunked => copy_chunked(&mut r, body),
        Framing::Length(len) => {
            let n = copy(&mut (&mut r).take(len), body)?;
            ensure!(n == len, "connection closed after {n} of {len} bytes");
            Ok(())
        }
        Framing::Close => copy(&mut r, body).map(|_| ()),
    }
    .context("reading response body")?;
    Ok(response)
}

/// How the end of the body is marked.
#[derive(Debug, PartialEq)]
enum Framing {
    Chunked,
    Length(u64),
    /// The server closes the connection.
    Close,
}

/// Read the status line and headers; succeeds only for `200 OK`.
fn read_head(r: &mut impl BufRead) -> Result<(Framing, Response)> {
    let mut head = Vec::new();
    loop {
        let start = head.len();
        let left = MAX_HEAD - start as u64;
        ensure!(left > 0, "response head longer than {MAX_HEAD} bytes");
        let n = r
            .take(left)
            .read_until(b'\n', &mut head)
            .context("reading response")?;
        ensure!(n > 0, "connection closed before the response was complete");
        ensure!(
            head.ends_with(b"\n"),
            "response head longer than {MAX_HEAD} bytes"
        );
        // An empty line ends the head (not before the status line).
        if start > 0 && matches!(&head[start..], b"\r\n" | b"\n") {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp.parse(&head).context("invalid response")?;
    ensure!(status.is_complete(), "invalid response");
    let code = resp.code.unwrap_or(0);
    let header = |name: &'static str| {
        resp.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).trim().to_owned())
    };
    if code != 200 {
        let reason = resp.reason.unwrap_or("");
        let mut msg = format!("server responded {code} {reason}");
        if (300..400).contains(&code)
            && let Some(location) = header("location").next()
        {
            msg += &format!(" (redirect to {location}, which is not followed)");
        }
        bail!(msg);
    }
    if let Some(enc) = header("content-encoding").find(|e| !e.eq_ignore_ascii_case("identity")) {
        bail!("unsupported content encoding {enc:?}");
    }
    let response = Response {
        last_modified: header("last-modified").next(),
        etag: header("etag").next(),
    };
    let te: Vec<String> = header("transfer-encoding").collect();
    if !te.is_empty() {
        ensure!(
            te.len() == 1 && te[0].eq_ignore_ascii_case("chunked"),
            "unsupported transfer encoding {:?}",
            te.join(", ")
        );
        return Ok((Framing::Chunked, response));
    }
    let mut length = None;
    for value in header("content-length") {
        ensure!(
            !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
            "bad content length {value:?}"
        );
        let n: u64 = value.parse().context("bad content length")?;
        ensure!(length.is_none_or(|l| l == n), "conflicting content lengths");
        length = Some(n);
    }
    Ok((length.map_or(Framing::Close, Framing::Length), response))
}

/// Copy everything from `r` to `body`; returns the number of bytes.
fn copy(r: &mut impl Read, body: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> Result<u64> {
    let mut buf = vec![0; BUF_SIZE];
    let mut total = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(describe_io(e).into()),
        };
        body(&buf[..n])?;
        total += n as u64;
    }
}

fn describe_io(e: io::Error) -> io::Error {
    // SO_RCVTIMEO makes a read fail with EAGAIN.
    if e.kind() == io::ErrorKind::WouldBlock {
        io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for the server")
    } else {
        e
    }
}

/// One line of a chunked body, without the line ending.
fn read_line(r: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    r.take(MAX_LINE)
        .read_until(b'\n', &mut line)
        .map_err(describe_io)?;
    ensure!(line.ends_with(b"\n"), "bad chunked encoding");
    line.pop();
    if line.ends_with(b"\r") {
        line.pop();
    }
    Ok(line)
}

fn copy_chunked(r: &mut impl BufRead, body: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> Result<()> {
    loop {
        let line = read_line(r)?;
        // Chunk extensions after `;` are ignored.
        let size = line.split(|&b| b == b';').next().unwrap_or_default();
        let size = size.trim_ascii();
        ensure!(
            !size.is_empty() && size.len() <= 16 && size.iter().all(u8::is_ascii_hexdigit),
            "bad chunk size"
        );
        let size = u64::from_str_radix(std::str::from_utf8(size)?, 16)?;
        if size == 0 {
            // Trailer fields, ignored, up to an empty line.
            while !read_line(r)?.is_empty() {}
            return Ok(());
        }
        let n = copy(&mut r.take(size), body)?;
        ensure!(n == size, "connection closed in the middle of a chunk");
        ensure!(read_line(r)?.is_empty(), "bad chunked encoding");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls() {
        let u =
            Url::parse("https://Mirror.Example.org/core/os/x86_64/bash-5.3-1-x86_64.pkg.tar.zst")
                .unwrap();
        assert_eq!(
            u,
            Url {
                tls: true,
                host: "mirror.example.org".into(),
                port: 443,
                path: "/core/os/x86_64/bash-5.3-1-x86_64.pkg.tar.zst".into(),
            }
        );
        assert_eq!(u.file_name(), "bash-5.3-1-x86_64.pkg.tar.zst");
        assert_eq!(
            u.to_string(),
            "https://mirror.example.org/core/os/x86_64/bash-5.3-1-x86_64.pkg.tar.zst"
        );

        let u = Url::parse("http://[::1]:8080/a/b.zst?x=1#frag").unwrap();
        assert_eq!(
            (u.tls, &*u.host, u.port, &*u.path),
            (false, "::1", 8080, "/a/b.zst?x=1")
        );
        assert_eq!(u.file_name(), "b.zst");
        assert_eq!(u.with_suffix(".sig").path, "/a/b.zst.sig?x=1");
        assert_eq!(u.to_string(), "http://[::1]:8080/a/b.zst?x=1");

        let u = Url::parse("HTTP://host:80").unwrap();
        assert_eq!(
            (&*u.path, u.file_name(), u.authority()),
            ("/", "", "host".into())
        );

        for bad in [
            "ftp://host/x",
            "https://",
            "https:///x",
            "https://user@host/x",
            "https://host:0/x",
            "https://host:99999/x",
            "https://host:+1/x",
            "https://host:/x",
            "https://ho_st/x",
            "https://[::1/x",
            "https://[nope]/x",
            "https://host/a b",
            "https://host/\u{e9}",
            "https://host/a\nb",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
        assert!(Url::is_url("HTTPS://x") && Url::is_url("http://x"));
        assert!(!Url::is_url("./https://x") && !Url::is_url("http:/x"));
    }

    /// Run a plain HTTP request against a canned response.
    fn fetch(response: &[u8]) -> Result<Vec<u8>> {
        fetch_response(response).map(|(body, _)| body)
    }

    fn fetch_response(response: &[u8]) -> Result<(Vec<u8>, Response)> {
        struct Fake<'a> {
            input: &'a [u8],
            sent: Vec<u8>,
        }
        impl Read for Fake<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.input.read(buf)
            }
        }
        impl Write for Fake<'_> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.sent.write(buf)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut stream = Fake {
            input: response,
            sent: Vec::new(),
        };
        let url = Url::parse("http://example.org:8080/x/y.zst").unwrap();
        let mut out = Vec::new();
        let r = request(&mut stream, &url, &mut |d| {
            out.extend_from_slice(d);
            Ok(())
        });
        let sent = String::from_utf8(stream.sent).unwrap();
        assert!(
            sent.starts_with("GET /x/y.zst HTTP/1.1\r\nHost: example.org:8080\r\n"),
            "{sent}"
        );
        assert!(sent.ends_with("\r\n\r\n"));
        r.map(|r| (out, r))
    }

    fn err(response: &[u8]) -> String {
        format!("{:#}", fetch(response).unwrap_err())
    }

    #[test]
    fn content_length() {
        let body = fetch(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA").unwrap();
        assert_eq!(body, b"hello");
        assert!(err(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhello").contains("after 5 of 9"));
        assert!(
            err(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello")
                .contains("conflicting")
        );
        assert!(err(b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\nhello").contains("bad content"));
    }

    #[test]
    fn validators() {
        let resp = b"HTTP/1.1 200 OK\r\nLast-Modified:  Mon, 16 Nov 2026 08:00:00 GMT \r\n\
            etag: W/\"6919-abc\"\r\n\r\nx";
        let (_, r) = fetch_response(resp).unwrap();
        assert_eq!(
            r.last_modified.as_deref(),
            Some("Mon, 16 Nov 2026 08:00:00 GMT")
        );
        assert_eq!(r.etag.as_deref(), Some("W/\"6919-abc\""));
        let (_, r) = fetch_response(b"HTTP/1.1 200 OK\r\n\r\nx").unwrap();
        assert_eq!(r, Response::default());
    }

    #[test]
    fn until_close() {
        let body = fetch(b"HTTP/1.0 200 OK\nServer: x\n\nall of it").unwrap();
        assert_eq!(body, b"all of it");
    }

    #[test]
    fn chunked() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\nContent-Length: 1\r\n\r\n\
            5;ext=1\r\nhello\r\n1\r\n \r\nA\r\n0123456789\r\n0\r\nTrailer: x\r\n\r\njunk";
        assert_eq!(fetch(resp).unwrap(), b"hello 0123456789");
        let truncated = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        assert!(err(truncated).contains("middle of a chunk"));
        let bad_size =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n";
        assert!(err(bad_size).contains("bad chunk size"));
        let no_crlf =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloX\r\n0\r\n\r\n";
        assert!(err(no_crlf).contains("bad chunked"));
        let gzip = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        assert!(err(gzip).contains("unsupported transfer encoding"));
    }

    #[test]
    fn errors() {
        assert!(err(b"HTTP/1.1 404 Not Found\r\n\r\n").contains("404 Not Found"));
        let e = err(b"HTTP/1.1 301 Moved\r\nLocation: https://other/y\r\n\r\n");
        assert!(e.contains("redirect to https://other/y"), "{e}");
        assert!(err(b"HTTP/1.1 200 OK\r\n").contains("closed before"));
        assert!(err(b"garbage\r\n\r\n").contains("invalid response"));
        assert!(err(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n").contains("encoding"));
        let mut huge = b"HTTP/1.1 200 OK\r\n".to_vec();
        huge.resize(MAX_HEAD as usize + 10, b'a');
        assert!(err(&huge).contains("longer than"));
    }
}
