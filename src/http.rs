//! Downloading files over HTTP(S): `GET` requests, one after another, over
//! a connection that is kept open between them.
//!
//! The supervisor parses URLs ([`Url`]) and opens the TCP connection to
//! their [`Origin`] ([`connect`]); a download worker speaks TLS and HTTP
//! over it (`Connection`), so it needs no network access, DNS or files of
//! its own and can reach no other host. A file can be continued after its
//! connection broke ([`Resume`]). Redirects are not followed. Server
//! certificates are checked against [`RootCerts`].

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

/// Longest response head (status line and headers) accepted.
const MAX_HEAD: u64 = 64 << 10;
const MAX_HEADERS: usize = 100;
/// Longest chunk-size or trailer line of a chunked body accepted.
const MAX_LINE: u64 = 4 << 10;
const MAX_URL: usize = 8 << 10;
const BUF_SIZE: usize = 64 << 10;
/// Longest validator ([`Start::validator`]) offered for continuing a file.
pub(crate) const MAX_VALIDATOR: usize = 256;

/// What a connection is made to: a scheme, a host and a port. Files of
/// one origin are downloaded over one connection, by one worker.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin {
    pub tls: bool,
    /// Host name or IP address (IPv6 without brackets).
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// Parse an origin as [`Origin`]'s `Display` writes it
    /// (`https://host:port`).
    pub fn parse(s: &str) -> Result<Origin> {
        let url = Url::parse(s)?;
        ensure!(url.path == "/", "{s:?} has a path");
        Ok(url.origin)
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

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.tls { "https" } else { "http" };
        write!(f, "{scheme}://{}", self.authority())
    }
}

/// An `http` or `https` URL, restricted to what downloads need: no user
/// info, a host name or IP address, and a path of printable ASCII
/// characters (already percent-encoded where needed). A fragment is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub origin: Origin,
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
            origin: Origin {
                tls,
                host: host.to_ascii_lowercase(),
                port,
            },
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
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.origin, self.path)
    }
}

/// Open a TCP connection to `origin`'s host, trying each of its addresses.
/// Reads and writes on the returned socket time out after `timeout`
/// (`SO_RCVTIMEO`, `SO_SNDTIMEO`), also in a process it is passed to.
pub fn connect(origin: &Origin, timeout: Duration) -> Result<TcpStream> {
    let addrs: Vec<_> = match origin.host.parse::<IpAddr>() {
        Ok(ip) => vec![(ip, origin.port).into()],
        Err(_) => (origin.host.as_str(), origin.port)
            .to_socket_addrs()
            .with_context(|| format!("resolving {}", origin.host))?
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
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("{} has no addresses", origin.host)))
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

/// A request to continue a file whose first `offset` bytes were received
/// before the connection broke.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resume {
    /// Number of bytes received so far.
    pub offset: u64,
    /// The validator of the response those bytes came from
    /// ([`Start::validator`]), sent in `If-Range`: the server continues
    /// the file only if it still has that version of it.
    pub validator: String,
    /// The length of the file, if that response gave it.
    pub length: Option<u64>,
}

/// The head of a response whose body follows.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Start {
    /// Whether the body continues the file at the offset asked for
    /// (`206`). Otherwise it is the file from its beginning, also where a
    /// continuation was asked for.
    pub continued: bool,
    /// The length of the whole file, if the response gives it.
    pub length: Option<u64>,
    /// A value for `If-Range` that a later request can continue this file
    /// with, if the response has a strong one: an `ETag` that isn't weak,
    /// or else a `Last-Modified` at least a second older than `Date`.
    pub validator: Option<String>,
    /// The `Last-Modified` header, as sent.
    pub last_modified: Option<String>,
    /// The `ETag` header, as sent (with its quotes and any `W/`).
    pub etag: Option<String>,
}

/// How a request ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum End {
    /// The body is complete.
    Done,
    /// The connection ended (it was closed or reset, or timed out) before
    /// the response was complete, for the reason given. What arrived of
    /// the body is good, and the request can be made again on a new
    /// connection.
    Closed(String),
    /// The server neither continued the file as asked nor sent the whole
    /// of it: it doesn't serve the range, or what it serves doesn't fit.
    /// The file can be requested again from the beginning.
    Unresumable(String),
    /// The request failed for good, e.g. with `404 Not Found`.
    Failed(String),
}

/// A piece of a response, as it arrives.
pub(crate) enum Event<'a> {
    /// The head, before any of the body.
    Start(&'a Start),
    /// More of the body.
    Data(&'a [u8]),
}

/// Why an exchange stopped where the response can't be completed.
enum Broken {
    /// The connection ended.
    Closed(String),
    /// The server sent something that can't be used.
    Failed(String),
    /// The receiver of the response failed.
    Output(io::Error),
}

type Exchange<T> = std::result::Result<T, Broken>;

trait Stream: Read + Write {}

impl<T: Read + Write> Stream for T {}

/// A connection to an origin, for one request after another.
pub(crate) struct Connection<'a> {
    stream: BufReader<Box<dyn Stream + 'a>>,
    /// The `Host` header.
    host: String,
    /// Whether another request can be made.
    open: bool,
}

impl<'a> Connection<'a> {
    /// Use `stream`, an open connection to `origin`'s host, with TLS for
    /// `https`: server certificates are checked against `roots`. Nothing
    /// is sent before the first request.
    pub(crate) fn new(
        stream: impl Read + Write + 'a,
        origin: &Origin,
        roots: &RootCerts,
    ) -> Result<Connection<'a>> {
        let stream: Box<dyn Stream + 'a> = if origin.tls {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots.store()?)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let name = rustls::pki_types::ServerName::try_from(origin.host.clone())?;
            let conn = rustls::ClientConnection::new(Arc::new(config), name)?;
            Box::new(rustls::StreamOwned::new(conn, stream))
        } else {
            Box::new(stream)
        };
        Ok(Connection {
            stream: BufReader::with_capacity(BUF_SIZE, stream),
            host: origin.authority(),
            open: true,
        })
    }

    /// Whether another request can be made: the last response was
    /// complete and the server keeps the connection open, as far as it
    /// said. It can still have closed it since.
    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    /// Request `path` and pass the head and the body of a `200 OK`
    /// response to `out` as they arrive. With `resume`, ask for the rest
    /// of a file; if the server sends the whole file instead (it has
    /// another version of it now), take that if `restart`, else the
    /// request fails. Any other status is a failure, including redirects.
    ///
    /// Fails only if `out` does; what goes wrong with the connection or
    /// the response is in the returned [`End`].
    pub(crate) fn get(
        &mut self,
        path: &str,
        resume: Option<&Resume>,
        restart: bool,
        out: &mut dyn FnMut(Event) -> io::Result<()>,
    ) -> io::Result<End> {
        // Until the response turns out complete.
        self.open = false;
        match self.exchange(path, resume, restart, out) {
            Ok(end) => Ok(end),
            Err(Broken::Closed(reason)) => Ok(End::Closed(reason)),
            Err(Broken::Failed(reason)) => Ok(End::Failed(reason)),
            Err(Broken::Output(e)) => Err(e),
        }
    }

    fn exchange(
        &mut self,
        path: &str,
        resume: Option<&Resume>,
        restart: bool,
        out: &mut dyn FnMut(Event) -> io::Result<()>,
    ) -> Exchange<End> {
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: skl/{}\r\nAccept-Encoding: identity\r\n",
            self.host,
            env!("CARGO_PKG_VERSION"),
        );
        if let Some(resume) = resume {
            request += &format!(
                "Range: bytes={}-\r\nIf-Range: {}\r\n",
                resume.offset, resume.validator
            );
        }
        request += "\r\n";
        let stream = self.stream.get_mut();
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|e| net_error("sending request", e))?;

        let head = read_head(&mut self.stream)?;
        let mut persistent = head.persistent;
        let status = format!("server responded {} {}", head.code, head.reason);
        // The body isn't read after these, so the connection ends here.
        let (start, framing, range) = match (head.code, resume) {
            (200, Some(_)) if !restart => {
                return Ok(End::Failed(format!(
                    "the file changed on the server while it was downloaded, or the server \
                     can't continue downloads ({status} to a request for the rest of the file)"
                )));
            }
            (200, _) => {
                head.check_encoding()?;
                let framing = head.framing()?;
                let length = match framing {
                    Framing::Length(n) => Some(n),
                    _ => None,
                };
                (head.start(false, length), framing, None)
            }
            (206, Some(resume)) => {
                head.check_encoding()?;
                let (count, total) = match head.range(resume) {
                    Ok(range) => range,
                    Err(why) => return Ok(End::Unresumable(why)),
                };
                // The body ends where the range does, however it is framed.
                let framing = match head.framing()? {
                    Framing::Length(n) if n != count => {
                        return Ok(End::Unresumable(format!(
                            "the range has {count} bytes, but the content length is {n}"
                        )));
                    }
                    Framing::Length(_) => Framing::Length(count),
                    Framing::Chunked => Framing::Chunked,
                    Framing::Close => {
                        persistent = false;
                        Framing::Length(count)
                    }
                };
                (head.start(true, total), framing, Some(count))
            }
            (416, Some(_)) => return Ok(End::Unresumable(status)),
            // Sent by some servers when they close a connection that was
            // idle, which then meets the next request.
            (408, _) => return Err(Broken::Closed(status)),
            (code, _) => {
                let mut msg = status;
                if (300..400).contains(&code)
                    && let Some(location) = head.get("location")
                {
                    msg += &format!(" (redirect to {location}, which is not followed)");
                }
                return Ok(End::Failed(msg));
            }
        };
        out(Event::Start(&start)).map_err(Broken::Output)?;

        let mut received: u64 = 0;
        let mut body = |data: &[u8]| {
            received += data.len() as u64;
            out(Event::Data(data))
        };
        match framing {
            Framing::Chunked => copy_chunked(&mut self.stream, &mut body)?,
            Framing::Length(len) => {
                let n = copy(&mut (&mut self.stream).take(len), &mut body)?;
                if n != len {
                    return Err(Broken::Closed(format!(
                        "connection closed after {n} of {len} bytes"
                    )));
                }
            }
            Framing::Close => {
                copy(&mut self.stream, &mut body)?;
            }
        }
        if let Some(count) = range
            && received != count
        {
            return Err(Broken::Failed(format!(
                "the range has {count} bytes, but the server sent {received}"
            )));
        }
        // Bytes after the response aren't an answer to anything.
        self.open = persistent && framing != Framing::Close && self.stream.buffer().is_empty();
        Ok(End::Done)
    }
}

/// An error of the connection. rustls reports TLS failures (a certificate
/// that doesn't verify, an alert) as I/O errors wrapping its own; after
/// those, a new connection would fail the same way.
fn net_error(doing: &str, e: io::Error) -> Broken {
    if e.get_ref().is_some_and(|inner| inner.is::<rustls::Error>()) {
        Broken::Failed(format!("{doing}: {e}"))
    } else if e.kind() == io::ErrorKind::WouldBlock {
        // SO_RCVTIMEO and SO_SNDTIMEO make reads and writes fail with EAGAIN.
        Broken::Closed(format!("{doing}: timed out waiting for the server"))
    } else {
        Broken::Closed(format!("{doing}: {e}"))
    }
}

/// How the end of the body is marked.
#[derive(Debug, PartialEq)]
enum Framing {
    Chunked,
    Length(u64),
    /// The server closes the connection.
    Close,
}

/// The status line and headers of a response.
struct Head {
    code: u16,
    reason: String,
    /// Whether the server keeps the connection open after the response:
    /// HTTP/1.1 without `Connection: close`.
    persistent: bool,
    /// Names in lower case, values trimmed.
    headers: Vec<(String, String)>,
}

impl Head {
    /// The values of all headers `name` (in lower case).
    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn get(&self, name: &str) -> Option<&str> {
        let (_, value) = self.headers.iter().find(|(n, _)| n == name)?;
        Some(value)
    }

    fn check_encoding(&self) -> Exchange<()> {
        match self
            .all("content-encoding")
            .find(|e| !e.eq_ignore_ascii_case("identity"))
        {
            Some(enc) => Err(Broken::Failed(format!(
                "unsupported content encoding {enc:?}"
            ))),
            None => Ok(()),
        }
    }

    fn framing(&self) -> Exchange<Framing> {
        let te: Vec<&str> = self.all("transfer-encoding").collect();
        if !te.is_empty() {
            if te.len() == 1 && te[0].eq_ignore_ascii_case("chunked") {
                return Ok(Framing::Chunked);
            }
            return Err(Broken::Failed(format!(
                "unsupported transfer encoding {:?}",
                te.join(", ")
            )));
        }
        let mut length = None;
        for value in self.all("content-length") {
            let n = parse_number(value)
                .ok_or_else(|| Broken::Failed(format!("bad content length {value:?}")))?;
            if length.is_some_and(|l| l != n) {
                return Err(Broken::Failed("conflicting content lengths".to_owned()));
            }
            length = Some(n);
        }
        Ok(length.map_or(Framing::Close, Framing::Length))
    }

    /// Check that a `206` response continues the file as `resume` asked:
    /// from its offset to the end, of a file as long as the first
    /// response said. Returns the number of bytes in the body and the
    /// length of the whole file, if known.
    fn range(&self, resume: &Resume) -> std::result::Result<(u64, Option<u64>), String> {
        let value = self.get("content-range").ok_or("no content range")?;
        let parse = || {
            let (range, total) = value.strip_prefix("bytes ")?.split_once('/')?;
            let (first, last) = range.split_once('-')?;
            let total = match total.trim() {
                "*" => None,
                total => Some(parse_number(total)?),
            };
            let (first, last) = (parse_number(first.trim())?, parse_number(last.trim())?);
            let end = last.checked_add(1).filter(|&end| end > first)?;
            Some((first, end, total))
        };
        let (first, end, total) = parse().ok_or(format!("bad content range {value:?}"))?;
        if first != resume.offset {
            return Err(format!(
                "content range {value:?} doesn't start at byte {}",
                resume.offset
            ));
        }
        if total.is_some_and(|t| t != end) || resume.length.is_some_and(|l| l != end) {
            return Err(match resume.length {
                Some(length) => {
                    format!("content range {value:?} doesn't end a file of {length} bytes")
                }
                None => format!("content range {value:?} doesn't end the file"),
            });
        }
        Ok((end - first, total.or(resume.length)))
    }

    /// A value for `If-Range` that only this version of the file has.
    fn validator(&self) -> Option<String> {
        let usable = |v: &str| {
            v.len() <= MAX_VALIDATOR && v.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
        };
        // With an entity tag, the date isn't used, also if the tag is weak
        // (`W/"…"`): the server says that versions can't be told apart.
        if let Some(etag) = self.get("etag") {
            let strong = etag.len() >= 2 && etag.starts_with('"') && etag.ends_with('"');
            return (strong && usable(etag)).then(|| etag.to_owned());
        }
        // A file changed twice within a second keeps its date. A response
        // sent a second or more after the date doesn't have this problem.
        let modified = self.get("last-modified")?;
        let age = parse_http_date(self.get("date")?)? - parse_http_date(modified)?;
        (age >= 1 && usable(modified)).then(|| modified.to_owned())
    }

    fn start(&self, continued: bool, length: Option<u64>) -> Start {
        Start {
            continued,
            length,
            validator: self.validator(),
            last_modified: self.get("last-modified").map(str::to_owned),
            etag: self.get("etag").map(str::to_owned),
        }
    }
}

/// A number written with digits only.
fn parse_number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Seconds since 1970 of an HTTP date in the preferred format
/// (`Sun, 06 Nov 1994 08:49:37 GMT`). The obsolete formats aren't read.
fn parse_http_date(s: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let number = |s: &str, digits: usize| -> Option<i64> {
        (s.len() == digits)
            .then(|| parse_number(s))
            .flatten()?
            .try_into()
            .ok()
    };
    let mut parts = s.split(' ');
    parts.next()?.strip_suffix(',')?;
    let day = number(parts.next()?, 2)?;
    let month_name = parts.next()?;
    let month = MONTHS.iter().position(|m| *m == month_name)? as i64 + 1;
    let year = number(parts.next()?, 4)?;
    let mut time = parts.next()?.split(':');
    let (hour, minute, second) = (
        number(time.next()?, 2)?,
        number(time.next()?, 2)?,
        number(time.next()?, 2)?,
    );
    if time.next().is_some() || parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Days since 1970-01-01 from the civil date (Howard Hinnant's
    // algorithm), with years starting in March.
    let year = if month <= 2 { year - 1 } else { year };
    let (era, year_of_era) = (year.div_euclid(400), year.rem_euclid(400));
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

/// Read the status line and headers.
fn read_head(r: &mut impl BufRead) -> Exchange<Head> {
    let mut head = Vec::new();
    loop {
        let start = head.len();
        let left = MAX_HEAD - start as u64;
        let n = r
            .take(left)
            .read_until(b'\n', &mut head)
            .map_err(|e| net_error("reading response", e))?;
        if n == 0 || !head.ends_with(b"\n") {
            return Err(if n as u64 == left {
                Broken::Failed(format!("response head longer than {MAX_HEAD} bytes"))
            } else if head.is_empty() {
                Broken::Closed("connection closed before the response".to_owned())
            } else {
                Broken::Closed("connection closed before the response was complete".to_owned())
            });
        }
        // An empty line ends the head (not before the status line).
        if start > 0 && matches!(&head[start..], b"\r\n" | b"\n") {
            break;
        }
    }
    let invalid = || Broken::Failed("invalid response".to_owned());
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp.parse(&head).map_err(|_| invalid())?;
    if !status.is_complete() {
        return Err(invalid());
    }
    let headers: Vec<(String, String)> = resp
        .headers
        .iter()
        .map(|h| {
            let value = String::from_utf8_lossy(h.value).trim().to_owned();
            (h.name.to_ascii_lowercase(), value)
        })
        .collect();
    let mut head = Head {
        code: resp.code.unwrap_or(0),
        reason: resp.reason.unwrap_or("").to_owned(),
        persistent: false,
        headers,
    };
    let close = head
        .all("connection")
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("close"));
    head.persistent = resp.version == Some(1) && !close;
    Ok(head)
}

/// Copy everything from `r` to `body`; returns the number of bytes.
fn copy(r: &mut impl Read, body: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> Exchange<u64> {
    let mut buf = vec![0; BUF_SIZE];
    let mut total = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(net_error("reading response body", e)),
        };
        body(&buf[..n]).map_err(Broken::Output)?;
        total += n as u64;
    }
}

/// One line of a chunked body, without the line ending.
fn read_line(r: &mut impl BufRead) -> Exchange<Vec<u8>> {
    let mut line = Vec::new();
    let n = r
        .take(MAX_LINE)
        .read_until(b'\n', &mut line)
        .map_err(|e| net_error("reading response body", e))?;
    if !line.ends_with(b"\n") {
        return Err(if n as u64 == MAX_LINE {
            bad_chunked()
        } else {
            Broken::Closed("connection closed in the middle of a chunked body".to_owned())
        });
    }
    line.pop();
    if line.ends_with(b"\r") {
        line.pop();
    }
    Ok(line)
}

fn bad_chunked() -> Broken {
    Broken::Failed("bad chunked encoding".to_owned())
}

fn copy_chunked(
    r: &mut impl BufRead,
    body: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> Exchange<()> {
    loop {
        let line = read_line(r)?;
        // Chunk extensions after `;` are ignored.
        let size = line.split(|&b| b == b';').next().unwrap_or_default();
        let size = std::str::from_utf8(size.trim_ascii())
            .ok()
            .filter(|s| !s.is_empty() && s.len() <= 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or_else(|| Broken::Failed("bad chunk size".to_owned()))?;
        if size == 0 {
            // Trailer fields, ignored, up to an empty line.
            while !read_line(r)?.is_empty() {}
            return Ok(());
        }
        let n = copy(&mut r.take(size), body)?;
        if n != size {
            return Err(Broken::Closed(
                "connection closed in the middle of a chunk".to_owned(),
            ));
        }
        if !read_line(r)?.is_empty() {
            return Err(bad_chunked());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[test]
    fn parse_urls() {
        let u =
            Url::parse("https://Mirror.Example.org/core/os/x86_64/bash-5.3-1-x86_64.pkg.tar.zst")
                .unwrap();
        assert_eq!(
            u,
            Url {
                origin: Origin {
                    tls: true,
                    host: "mirror.example.org".into(),
                    port: 443,
                },
                path: "/core/os/x86_64/bash-5.3-1-x86_64.pkg.tar.zst".into(),
            }
        );
        assert_eq!(u.file_name(), "bash-5.3-1-x86_64.pkg.tar.zst");
        assert_eq!(
            u.to_string(),
            "https://mirror.example.org/core/os/x86_64/bash-5.3-1-x86_64.pkg.tar.zst"
        );
        assert_eq!(u.origin.to_string(), "https://mirror.example.org");

        let u = Url::parse("http://[::1]:8080/a/b.zst?x=1#frag").unwrap();
        let o = &u.origin;
        assert_eq!(
            (o.tls, &*o.host, o.port, &*u.path),
            (false, "::1", 8080, "/a/b.zst?x=1")
        );
        assert_eq!(u.file_name(), "b.zst");
        assert_eq!(u.with_suffix(".sig").path, "/a/b.zst.sig?x=1");
        assert_eq!(u.to_string(), "http://[::1]:8080/a/b.zst?x=1");
        assert_eq!(Origin::parse(&o.to_string()).unwrap(), *o);
        assert!(Origin::parse("http://[::1]:8080/a").is_err());

        let u = Url::parse("HTTP://host:80").unwrap();
        assert_eq!(
            (&*u.path, u.file_name(), u.origin.authority()),
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

    /// A server that answers each request with the next of its responses
    /// and closes the connection after the last.
    struct Fake {
        responses: VecDeque<Vec<u8>>,
        /// What is left of the response to the last request.
        response: VecDeque<u8>,
        sent: Vec<u8>,
    }

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.response.read(buf)
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sent.extend_from_slice(buf);
            if self.sent.ends_with(b"\r\n\r\n") {
                self.response
                    .extend(self.responses.pop_front().unwrap_or_default());
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// What one request got: the head, if any, the body and the end.
    type Got = (Option<Start>, Vec<u8>, End);

    /// One request to make: a path, and what [`Connection::get`] takes.
    type Request<'a> = (&'a str, Option<Resume>, bool);

    /// Make `requests` over one connection to a server with `responses`,
    /// as long as the connection stays open. Also returns what was sent.
    fn exchange(requests: &[Request], responses: &[&[u8]]) -> (Vec<Got>, String) {
        let mut fake = Fake {
            responses: responses.iter().map(|r| r.to_vec()).collect(),
            response: VecDeque::new(),
            sent: Vec::new(),
        };
        let origin = Origin::parse("http://example.org:8080").unwrap();
        let mut conn = Connection::new(&mut fake, &origin, &RootCerts::default()).unwrap();
        let mut got = Vec::new();
        for (path, resume, restart) in requests {
            if !conn.is_open() {
                break;
            }
            let (mut start, mut body) = (None, Vec::new());
            let end = conn
                .get(path, resume.as_ref(), *restart, &mut |event| {
                    match event {
                        Event::Start(s) => {
                            assert!(start.is_none() && body.is_empty());
                            start = Some(s.clone());
                        }
                        Event::Data(data) => {
                            assert!(start.is_some());
                            body.extend_from_slice(data);
                        }
                    }
                    Ok(())
                })
                .unwrap();
            got.push((start, body, end));
        }
        drop(conn);
        (got, String::from_utf8(fake.sent).unwrap())
    }

    /// Request a file from a server with `response`.
    fn fetch(response: &[u8]) -> Got {
        let (mut got, sent) = exchange(&[("/x/y.zst", None, false)], &[response]);
        assert_eq!(
            sent.split_once("User-Agent").unwrap().0,
            "GET /x/y.zst HTTP/1.1\r\nHost: example.org:8080\r\n"
        );
        assert!(sent.ends_with("identity\r\n\r\n"), "{sent}");
        got.pop().unwrap()
    }

    /// The body of a complete response.
    fn body(response: &[u8]) -> Vec<u8> {
        let (_, body, end) = fetch(response);
        assert_eq!(end, End::Done);
        body
    }

    /// The reason a request for `response` failed for good.
    fn failure(response: &[u8]) -> String {
        match fetch(response).2 {
            End::Failed(reason) => reason,
            end => panic!("{end:?}"),
        }
    }

    /// The reason a connection ended before `response` was complete.
    fn closed(response: &[u8]) -> String {
        match fetch(response).2 {
            End::Closed(reason) => reason,
            end => panic!("{end:?}"),
        }
    }

    #[test]
    fn content_length() {
        assert_eq!(
            body(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA"),
            b"hello"
        );
        let (start, body, end) = fetch(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhello");
        assert_eq!(start.unwrap().length, Some(9));
        assert_eq!(body, b"hello");
        assert_eq!(
            end,
            End::Closed("connection closed after 5 of 9 bytes".into())
        );
        assert!(
            failure(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello")
                .contains("conflicting")
        );
        assert!(
            failure(b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\nhello").contains("bad content")
        );
    }

    #[test]
    fn validators() {
        let start = |headers: &str| {
            let response = format!("HTTP/1.1 200 OK\r\n{headers}Content-Length: 1\r\n\r\nx");
            fetch(response.as_bytes()).0.unwrap()
        };
        let date = "Date: Mon, 16 Nov 2026 08:00:01 GMT\r\n";
        let modified = "Last-Modified:  Mon, 16 Nov 2026 08:00:00 GMT \r\n";

        // A strong entity tag; the date isn't needed.
        let s = start(&format!("{modified}etag: \"6919-abc\"\r\n"));
        assert_eq!(
            s.last_modified.as_deref(),
            Some("Mon, 16 Nov 2026 08:00:00 GMT")
        );
        assert_eq!(s.etag.as_deref(), Some("\"6919-abc\""));
        assert_eq!(s.validator.as_deref(), Some("\"6919-abc\""));
        assert!(!s.continued);

        // A weak one isn't used, nor the date next to it.
        let s = start(&format!("{date}{modified}ETag: W/\"6919-abc\"\r\n"));
        assert_eq!(s.etag.as_deref(), Some("W/\"6919-abc\""));
        assert_eq!(s.validator, None);
        for bad in [
            "6919",
            "\"",
            "\"a\tb\"",
            &format!("\"{}\"", "a".repeat(300)),
        ] {
            assert_eq!(start(&format!("ETag: {bad}\r\n")).validator, None, "{bad}");
        }

        // A date at least a second before the response's.
        let s = start(&format!("{date}{modified}"));
        assert_eq!(
            s.validator.as_deref(),
            Some("Mon, 16 Nov 2026 08:00:00 GMT")
        );
        let same = "Date: Mon, 16 Nov 2026 08:00:00 GMT\r\n";
        assert_eq!(start(&format!("{same}{modified}")).validator, None);
        assert_eq!(start(modified).validator, None);
        let old = "Last-Modified: Monday, 16-Nov-26 08:00:00 GMT\r\n";
        assert_eq!(start(&format!("{date}{old}")).validator, None);

        assert_eq!(
            start(""),
            Start {
                length: Some(1),
                ..Start::default()
            }
        );
    }

    #[test]
    fn http_dates() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Sun, 22 Nov 2026 08:41:38 GMT"),
            Some(1_795_336_898)
        );
        assert_eq!(
            parse_http_date("Tue, 29 Feb 2000 00:00:00 GMT"),
            Some(951_782_400)
        );
        for bad in [
            "",
            "Sun, 22 Nov 2026 08:41:38",
            "Sun, 22 Nov 2026 08:41:38 UTC",
            "Sun, 22 Nov 2026 08:41 GMT",
            "Sun, 2 Nov 2026 08:41:38 GMT",
            "Sun, 22 nov 2026 08:41:38 GMT",
            "Sun 22 Nov 2026 08:41:38 GMT",
            "Sun, 22 Nov 2026 24:00:00 GMT",
            "Sun, 22 Nov 2026 08:41:38 GMT+1",
            "Sunday, 22-Nov-26 08:41:38 GMT",
            "Sun Nov 22 08:41:38 2026",
        ] {
            assert_eq!(parse_http_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn until_close() {
        assert_eq!(
            body(b"HTTP/1.0 200 OK\nServer: x\n\nall of it"),
            b"all of it"
        );
        let (start, ..) = fetch(b"HTTP/1.1 200 OK\r\n\r\nall of it");
        assert_eq!(start.unwrap().length, None);
    }

    #[test]
    fn chunked() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\nContent-Length: 1\r\n\r\n\
            5;ext=1\r\nhello\r\n1\r\n \r\nA\r\n0123456789\r\n0\r\nTrailer: x\r\n\r\njunk";
        let (start, body, end) = fetch(resp);
        assert_eq!((start.unwrap().length, end), (None, End::Done));
        assert_eq!(body, b"hello 0123456789");
        let truncated = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        assert!(closed(truncated).contains("middle of a chunk"));
        let no_end = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(closed(no_end).contains("middle of a chunked body"));
        let bad_size =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n";
        assert!(failure(bad_size).contains("bad chunk size"));
        let no_crlf =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloX\r\n0\r\n\r\n";
        assert!(failure(no_crlf).contains("bad chunked"));
        let gzip = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        assert!(failure(gzip).contains("unsupported transfer encoding"));
    }

    #[test]
    fn errors() {
        assert!(failure(b"HTTP/1.1 404 Not Found\r\n\r\n").contains("404 Not Found"));
        let e = failure(b"HTTP/1.1 301 Moved\r\nLocation: https://other/y\r\n\r\n");
        assert!(e.contains("redirect to https://other/y"), "{e}");
        assert!(failure(b"HTTP/1.1 206 Partial Content\r\n\r\n").contains("206"));
        assert!(failure(b"HTTP/1.1 416 Range Not Satisfiable\r\n\r\n").contains("416"));
        assert_eq!(closed(b""), "connection closed before the response");
        assert!(closed(b"HTTP/1.1 408 Request Timeout\r\n\r\n").contains("408 Request Timeout"));
        assert!(closed(b"HTTP/1.1 200 OK\r\n").contains("closed before the response was"));
        assert!(closed(b"HTTP/1.1 200 OK\r\nServer").contains("closed before the response was"));
        assert!(failure(b"garbage\r\n\r\n").contains("invalid response"));
        assert!(failure(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n").contains("encoding"));
        let mut huge = b"HTTP/1.1 200 OK\r\n".to_vec();
        huge.resize(MAX_HEAD as usize + 10, b'a');
        assert!(failure(&huge).contains("longer than"));
    }

    #[test]
    fn several_requests() {
        let ok = |body: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        };
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ntwo\r\n0\r\n\r\n";
        let requests = [
            ("/1", None, false),
            ("/2", None, false),
            ("/3", None, false),
        ];
        let (got, sent) = exchange(&requests, &[&ok("one"), chunked, &ok("three")]);
        let bodies: Vec<&[u8]> = got.iter().map(|(_, body, _)| &body[..]).collect();
        assert_eq!(bodies, [&b"one"[..], b"two", b"three"]);
        assert!(got.iter().all(|(_, _, end)| *end == End::Done));
        let paths: Vec<&str> = sent.matches("GET /").collect();
        assert_eq!(paths.len(), 3, "{sent}");
        assert!(!sent.contains("Connection:"), "{sent}");

        // The server closed the connection in the meantime.
        let (got, _) = exchange(&requests, &[&ok("one")]);
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[1],
            (
                None,
                vec![],
                End::Closed("connection closed before the response".into())
            )
        );

        // No request follows a response that ends the connection.
        let close =
            b"HTTP/1.1 200 OK\r\nConnection: Keep-Alive, Close\r\nContent-Length: 3\r\n\r\none";
        let old = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\none";
        let until_close = b"HTTP/1.1 200 OK\r\n\r\none";
        let extra = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\noneHTTP/1.1 200 OK\r\n";
        let failed = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\none";
        for last in [&close[..], old, until_close, extra, failed, partial] {
            let (got, sent) = exchange(&requests, &[last, &ok("two")]);
            assert_eq!(got.len(), 1, "{}", String::from_utf8_lossy(last));
            assert_eq!(sent.matches("GET /").count(), 1);
        }
    }

    #[test]
    fn continuing() {
        let resume = |length| Resume {
            offset: 3,
            validator: "\"v1\"".into(),
            length,
        };
        let get = |length, restart, response: &[u8]| {
            let requests = [("/f", Some(resume(length)), restart), ("/g", None, false)];
            let (mut got, sent) = exchange(&requests, &[response, b""]);
            assert!(
                sent.contains("\r\nRange: bytes=3-\r\nIf-Range: \"v1\"\r\n\r\n"),
                "{sent}"
            );
            // Whether the connection took a second request.
            let open = got.len() == 2;
            (got.swap_remove(0), open)
        };
        let unresumable = |length, response: &[u8]| match get(length, true, response) {
            ((None, body, End::Unresumable(reason)), false) if body.is_empty() => reason,
            got => panic!("{got:?}"),
        };

        // The rest of the file.
        let rest = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 3-8/9\r\n\
            Content-Length: 6\r\nETag: \"v1\"\r\n\r\nlo you";
        for length in [Some(9), None] {
            let ((start, body, end), open) = get(length, false, rest);
            assert_eq!(
                start.unwrap(),
                Start {
                    continued: true,
                    length: Some(9),
                    validator: Some("\"v1\"".into()),
                    last_modified: None,
                    etag: Some("\"v1\"".into()),
                }
            );
            assert_eq!((&body[..], end, open), (&b"lo you"[..], End::Done, true));
        }
        // The length of the file can be left out, and the body chunked or
        // without a length of its own.
        let unknown =
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 3-8/*\r\n\r\nlo youEXTRA";
        let ((start, body, end), _) = get(Some(9), false, unknown);
        assert_eq!(start.unwrap().length, Some(9));
        assert_eq!((&body[..], end), (&b"lo you"[..], End::Done));
        let ((start, ..), _) = get(None, false, unknown);
        assert_eq!(start.unwrap().length, None);
        let chunked = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 3-8/9\r\n\
            Transfer-Encoding: chunked\r\n\r\n6\r\nlo you\r\n0\r\n\r\n";
        let ((_, body, end), open) = get(Some(9), false, chunked);
        assert_eq!((&body[..], end, open), (&b"lo you"[..], End::Done, true));
        let short = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 3-8/9\r\n\
            Transfer-Encoding: chunked\r\n\r\n2\r\nlo\r\n0\r\n\r\n";
        let ((_, _, end), open) = get(Some(9), false, short);
        assert!(matches!(end, End::Failed(_)) && !open, "{end:?}");
        // Cut off again.
        let ((start, body, end), _) = get(Some(9), false, &rest[..rest.len() - 2]);
        assert!(start.unwrap().continued);
        assert_eq!(
            (&body[..], end),
            (
                &b"lo y"[..],
                End::Closed("connection closed after 4 of 6 bytes".into())
            )
        );

        // Not the rest of the file as it was.
        for (length, range) in [
            (Some(9), "bytes 3-8/10"),
            (Some(9), "bytes 3-7/9"),
            (Some(9), "bytes 3-7/8"),
            (Some(9), "bytes 3-7/*"),
            (None, "bytes 3-7/9"),
            (None, "bytes 2-8/9"),
            (None, "bytes 4-8/9"),
            (None, "bytes 3-2/3"),
            (None, "bytes 3-/9"),
            (None, "bytes */9"),
            (None, "3-8/9"),
        ] {
            let response =
                format!("HTTP/1.1 206 Partial Content\r\nContent-Range: {range}\r\n\r\n");
            let reason = unresumable(length, response.as_bytes());
            assert!(reason.contains("content range"), "{range}: {reason}");
        }
        assert!(unresumable(None, b"HTTP/1.1 206 Partial Content\r\n\r\n").contains("no content"));
        let lengths = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 3-8/9\r\n\
            Content-Length: 5\r\n\r\nlo yo";
        assert!(unresumable(None, lengths).contains("content length is 5"));
        let gone = b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */2\r\n\r\n";
        assert!(unresumable(None, gone).contains("416"));

        // The whole file: taken from the beginning, or not at all.
        let whole = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"v2\"\r\n\r\nother";
        let ((start, body, end), open) = get(Some(9), true, whole);
        let start = start.unwrap();
        assert!(!start.continued);
        assert_eq!(
            (start.length, start.validator.as_deref()),
            (Some(5), Some("\"v2\""))
        );
        assert_eq!((&body[..], end, open), (&b"other"[..], End::Done, true));
        match get(Some(9), false, whole) {
            ((None, body, End::Failed(reason)), false) if body.is_empty() => {
                assert!(
                    reason.contains("the file changed on the server"),
                    "{reason}"
                );
            }
            got => panic!("{got:?}"),
        }
    }
}
