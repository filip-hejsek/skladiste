//! Downloads, and the worker that does them: [`download_all`] runs one
//! worker per origin.
//!
//! A download worker serves one origin (scheme, host and port) over one
//! connection, which the supervisor opened: fd 0 is that TCP connection,
//! fd 1 a socket to the supervisor, and the origin is an argument. With
//! a second argument `custom-roots`, the supervisor first sends the root
//! certificates on the socket (a `CERT` frame each, in DER, then an empty
//! `DONE`); otherwise the worker uses the built-in ones. No filesystem
//! access, no ioctls, and no other host can be reached.
//!
//! The worker handles a queue: the supervisor sends `ITEM`s (a path each,
//! what continues a file that an earlier connection began, and the
//! version the file is wanted only if it isn't) and the worker answers
//! each, in order, with `START` (what the response head says), the body
//! in `CHUNK`s and `END` (how the request ended: [`http::End`]); for a
//! file that didn't change, only `END`. It makes one request at a time over the connection,
//! which is kept open in between. Each direction of the socket flows one
//! way, and the worker never asks the supervisor for anything.
//!
//! A worker lives as long as its connection: when the server closes it,
//! or after a response that ends it, the worker says so in the `END` of
//! the request under way, if there is one, and exits after a final empty
//! `DONE`, as it does when its input ends. The supervisor connects again
//! and starts a new worker for the files that got no result, continuing
//! the one that was cut off.

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::num::NonZeroUsize;
use std::os::fd::FromRawFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::CertificateDer;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::http::{self, Connection, End, Event, Origin, Resume, RootCerts, Start, Url};
use crate::jobs::{both, par_map_iter};
use crate::sandbox::{self, Policy};
use crate::worker::{
    self, Args, BUF_SIZE, CHUNK, DONE, ERROR, Kind, MAX_CHUNK, MAX_ERROR, NO_CAPS, WorkerError,
    Workers, read_error, read_header, read_payload, sanitize, write_frame,
};

const CERT: u8 = 5;
const ITEM: u8 = 6;
const START: u8 = 7;
const END: u8 = 8;

/// Largest root certificate the worker accepts.
const MAX_CERT: usize = 64 << 10;
/// Largest `ITEM` the worker accepts (a URL is at most 8 KiB).
const MAX_ITEM: usize = 16 << 10;
/// Largest `START` or `END` the supervisor accepts.
const MAX_MESSAGE: usize = MAX_ERROR;

/// Address space limit of the worker (TLS and a few buffers).
const MAX_MEMORY: u64 = 256 << 20;

/// Timeout for connecting, and for each read and write once connected.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Files a worker has been sent and not yet answered, at most. With two,
/// the worker has the next file at hand when it finishes one, so there is
/// no round trip per file, and both always fit in the socket's buffer, so
/// sending them never blocks.
const WINDOW: usize = 2;

/// Connections to an origin that may end without progress before the
/// origin is given up.
const MAX_STRIKES: u32 = 3;

/// Longest `Last-Modified` value kept from a worker.
const MAX_LAST_MODIFIED: usize = 100;
/// The worker; see the module documentation.
pub(crate) const DOWNLOAD_WORKER: Kind = Kind {
    name: "download",
    dirs: &[],
    caps: NO_CAPS,
    main: worker,
};

/// Longest `ETag` value kept from a worker.
const MAX_ETAG: usize = 256;

/// One request to a worker.
#[derive(Serialize, Deserialize)]
struct Item {
    /// Path and query.
    path: String,
    /// To continue a file instead of fetching it from the beginning.
    resume: Option<Resume>,
    /// If the server sends the whole file where the rest was asked for
    /// (it has another version of it now): take that from the beginning
    /// instead of failing the request.
    restart: bool,
    /// A validator: ask for the file only if the server has another
    /// version.
    unless: Option<String>,
}

/// Where the body of a download goes.
pub trait Sink: Send {
    /// More of the body.
    fn write(&mut self, data: &[u8]) -> Result<()>;

    /// The download starts again from the beginning: drop what was
    /// written.
    fn restart(&mut self) -> Result<()>;
}

impl Sink for Vec<u8> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.extend_from_slice(data);
        Ok(())
    }

    fn restart(&mut self) -> Result<()> {
        self.clear();
        Ok(())
    }
}

/// A file to download.
pub struct Request<S> {
    pub url: Url,
    /// The download fails if the file is larger.
    pub max_size: u64,
    /// What to do when the file is to be continued after its connection
    /// broke, and the server has another version of it by then: download
    /// that one from the beginning, or fail. Failing suits a file whose
    /// content is known beforehand (e.g. by a hash), as another version
    /// can't be the one wanted.
    pub restart_if_changed: bool,
    /// The validator of a version of the file that the caller has
    /// ([`Downloaded::validator`] of an earlier download): if the server
    /// still has that version, the download ends without a body, as
    /// [`Downloaded::not_modified`].
    pub unless: Option<String>,
    pub sink: S,
}

/// A finished download.
#[derive(Debug)]
pub struct Downloaded {
    /// Size of the body, counted by the supervisor.
    pub size: u64,
    /// The server's `Last-Modified` header, if it sent one, with control
    /// characters escaped. Untrusted: for information only.
    pub last_modified: Option<String>,
    /// The server's `ETag` header, likewise.
    pub etag: Option<String>,
    /// A value that only this version of the file has, if the server gave
    /// one (see [`http::Start::validator`]), for [`Request::unless`]: at
    /// most 256 printable ASCII characters. Untrusted like the headers it
    /// comes from.
    pub validator: Option<String>,
    /// The server still has the version [`Request::unless`] named, so
    /// there is no body, and nothing else here applies.
    pub not_modified: bool,
}

/// A file being downloaded, on the supervisor's side.
struct Job<S> {
    /// Position among the requests.
    index: usize,
    url: Url,
    max_size: u64,
    restart_if_changed: bool,
    unless: Option<String>,
    sink: S,
    /// Bytes of the file in the sink.
    received: u64,
    /// The most bytes any connection brought the file to. Only more than
    /// that is progress, so starting again from the beginning isn't.
    most: u64,
    /// From the response that started the file in the sink: its length,
    /// what continues it, and headers to report.
    length: Option<u64>,
    validator: Option<String>,
    last_modified: Option<String>,
    etag: Option<String>,
    /// Whether the request sent last asked for the rest of the file.
    resuming: bool,
    /// Whether the request sent last asked for the file only if it
    /// changed.
    conditional: bool,
    /// Whether the worker has started the body for that request.
    started: bool,
}

impl<S: Sink> Job<S> {
    fn new(index: usize, request: Request<S>) -> Self {
        Job {
            index,
            url: request.url,
            max_size: request.max_size,
            restart_if_changed: request.restart_if_changed,
            unless: request.unless,
            sink: request.sink,
            received: 0,
            most: 0,
            length: None,
            validator: None,
            last_modified: None,
            etag: None,
            resuming: false,
            conditional: false,
            started: false,
        }
    }

    /// The next request for this file: for the rest of it, if there is
    /// something to continue with, else for the file only if it isn't the
    /// version the caller has, as long as no other version was started.
    fn item(&mut self) -> Item {
        let resume = match &self.validator {
            Some(validator) if self.received > 0 => Some(Resume {
                offset: self.received,
                validator: validator.clone(),
                length: self.length,
            }),
            _ => None,
        };
        let unless = self.unless.clone().filter(|_| self.most == 0);
        self.resuming = resume.is_some();
        self.conditional = unless.is_some();
        self.started = false;
        Item {
            path: self.url.path.clone(),
            resume,
            restart: self.restart_if_changed,
            unless,
        }
    }

    /// The worker starts a body.
    fn start(&mut self, start: Start) -> Result<()> {
        ensure!(!self.started, "worker started a file twice");
        self.started = true;
        if start.continued {
            ensure!(
                self.resuming,
                "worker continued a file that it was to fetch from the beginning"
            );
            return Ok(());
        }
        // From the beginning: the first request, one that had nothing to
        // continue with, or the server has another version now.
        if self.received > 0 {
            self.sink.restart().context("starting the file again")?;
            self.received = 0;
        }
        if let Some(length) = start.length {
            ensure!(
                length <= self.max_size,
                "file is larger than {} bytes",
                self.max_size
            );
        }
        // The validator goes into a request head later.
        if let Some(v) = &start.validator {
            ensure!(http::is_validator(v), "worker sent a bad validator");
        }
        let keep = |value: Option<String>, max| {
            value
                .filter(|v| v.len() <= max)
                .map(|v| sanitize(&v, false))
        };
        self.length = start.length;
        self.validator = start.validator;
        self.last_modified = keep(start.last_modified, MAX_LAST_MODIFIED);
        self.etag = keep(start.etag, MAX_ETAG);
        Ok(())
    }

    /// More of the body. Returns whether the file got further than ever
    /// before.
    fn data(&mut self, data: &[u8]) -> Result<bool> {
        ensure!(self.started, "worker sent data outside of a file");
        self.received += data.len() as u64;
        ensure!(
            self.received <= self.max_size,
            "file is larger than {} bytes",
            self.max_size
        );
        self.sink.write(data).context("writing download")?;
        let progress = self.received > self.most;
        self.most = self.most.max(self.received);
        Ok(progress)
    }

    /// The body is complete.
    fn finish(self) -> Result<(usize, S, Downloaded)> {
        ensure!(self.started, "worker ended a file that it didn't start");
        if let Some(length) = self.length {
            ensure!(
                self.received == length,
                "worker sent {} bytes of a file of {length}",
                self.received
            );
        }
        let downloaded = Downloaded {
            size: self.received,
            last_modified: self.last_modified,
            etag: self.etag,
            validator: self.validator,
            not_modified: false,
        };
        Ok((self.index, self.sink, downloaded))
    }

    /// The server still has the version the caller has.
    fn not_modified(self) -> Result<(usize, S, Downloaded)> {
        ensure!(
            self.conditional && !self.started,
            "worker said that a file didn't change where it wasn't asked"
        );
        let downloaded = Downloaded {
            size: 0,
            last_modified: None,
            etag: None,
            validator: None,
            not_modified: true,
        };
        Ok((self.index, self.sink, downloaded))
    }
}

/// How a worker's connection ended, short of an error.
enum Ended {
    /// Every file is done.
    Finished,
    /// Something failed elsewhere, so nothing more is downloaded.
    Stopped,
    /// The connection is over and files are left: whether it got
    /// anywhere, and why it ended.
    Closed { progress: bool, reason: String },
}

/// Context of an error after which the worker has exited or is about to,
/// so that its exit status and what it wrote to stderr can explain the
/// error. After any other error the worker is killed.
#[derive(Debug)]
struct Gone;

impl fmt::Display for Gone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reading from worker")
    }
}

fn gone(e: io::Error) -> anyhow::Error {
    anyhow::Error::new(e).context(Gone)
}

/// Download `requests` in workers, and call `done` with each one's
/// index, sink and result when it is complete.
///
/// Files of one origin (scheme, host and port) are downloaded one
/// after another, in the order given, over one connection, by one
/// worker; up to `jobs` origins at once. The connections are opened
/// here and handed to the workers, which have no network access of
/// their own. When a connection ends before its files are done, a new
/// one continues, also in the middle of a file where the server
/// allows; an origin whose connections keep ending without progress
/// is given up. Redirects are not followed.
///
/// `done` runs on the thread that serves the file's origin, which
/// downloads nothing meanwhile.
///
/// `failed` is shared with whatever else works on the same task: once
/// it is set, here or elsewhere, no more downloads start, and the
/// ones under way are finished. This returns an error only for
/// failures of its own.
pub fn download_all<S: Sink>(
    workers: &Workers,
    requests: Vec<Request<S>>,
    jobs: NonZeroUsize,
    failed: &AtomicBool,
    done: impl Fn(usize, S, Downloaded) -> Result<()> + Sync,
) -> Result<()> {
    let mut origins: Vec<(Origin, VecDeque<Job<S>>)> = Vec::new();
    for (index, request) in requests.into_iter().enumerate() {
        // It goes into a request head.
        if let Some(v) = &request.unless {
            ensure!(
                http::is_validator(v),
                "downloading {}: bad validator {v:?}",
                request.url
            );
        }
        let origin = &request.url.origin;
        let queue = match origins.iter().position(|(o, _)| o == origin) {
            Some(i) => &mut origins[i].1,
            None => {
                origins.push((origin.clone(), VecDeque::new()));
                &mut origins.last_mut().unwrap().1
            }
        };
        queue.push_back(Job::new(index, request));
    }
    par_map_iter(origins.into_iter(), jobs, failed, |(origin, queue)| {
        download_from(workers, &origin, queue, failed, &done)
    })?;
    Ok(())
}

/// Download `url` in a worker into `sink`, failing if it is longer
/// than `max_size`. See [`download_all`].
pub fn download<S: Sink>(
    workers: &Workers,
    url: &Url,
    sink: S,
    max_size: u64,
) -> Result<(S, Downloaded)> {
    let request = Request {
        url: url.clone(),
        max_size,
        restart_if_changed: true,
        unless: None,
        sink,
    };
    let result = Mutex::new(None);
    let failed = AtomicBool::new(false);
    download_all(
        workers,
        vec![request],
        NonZeroUsize::MIN,
        &failed,
        |_, sink, downloaded| {
            *result.lock().unwrap() = Some((sink, downloaded));
            Ok(())
        },
    )?;
    let result = result.into_inner().unwrap();
    result.with_context(|| format!("downloading {url} didn't finish"))
}

/// Download the files in `queue`, all from `origin`, in order: over
/// one connection, and over further ones while they make progress.
fn download_from<S: Sink>(
    workers: &Workers,
    origin: &Origin,
    mut queue: VecDeque<Job<S>>,
    failed: &AtomicBool,
    done: &impl Fn(usize, S, Downloaded) -> Result<()>,
) -> Result<()> {
    let mut strikes = 0;
    while !failed.load(Ordering::Relaxed) {
        match connection(workers, origin, &mut queue, failed, done)? {
            Ended::Finished | Ended::Stopped => break,
            Ended::Closed { progress: true, .. } => {}
            Ended::Closed {
                progress: false,
                reason,
            } => {
                // Not reset by the connections that get somewhere
                // in between.
                strikes += 1;
                if strikes == MAX_STRIKES {
                    let url = &queue.front().context("no file is left")?.url;
                    bail!(
                        "downloading {url}: {reason} (giving up on {origin} \
                         after {MAX_STRIKES} connections that got nothing)"
                    );
                }
                std::thread::sleep(workers.retry_delay() * (1 << (strikes - 1)));
            }
        }
    }
    Ok(())
}

/// Open a connection to `origin` and run a worker on it for the files
/// in `queue`, until they are done or the connection ends. Files left
/// are back in `queue` then.
fn connection<S: Sink>(
    workers: &Workers,
    origin: &Origin,
    queue: &mut VecDeque<Job<S>>,
    failed: &AtomicBool,
    done: &impl Fn(usize, S, Downloaded) -> Result<()>,
) -> Result<Ended> {
    let first = queue.front().context("no file to download")?;
    let conn =
        http::connect(origin, TIMEOUT).with_context(|| format!("downloading {}", first.url))?;
    let (ours, theirs) = worker::stream_socket()?;
    let custom = workers.root_certs().custom().filter(|_| origin.tls);
    let name = origin.to_string();
    let mut args = vec![&*name];
    if custom.is_some() {
        args.push("custom-roots");
    }
    let worker = workers.spawn(&DOWNLOAD_WORKER, conn.into(), theirs, &[], &args)?;
    let sock = File::from(ours);
    // The worker reads all certificates before it writes anything but
    // an error, which then explains a failure to send them.
    let sent = custom.map_or(Ok(()), |certs| send_certs(&sock, certs));
    let mut window = VecDeque::new();
    let result = serve(&sock, queue, &mut window, failed, done).and_then(|ended| {
        sent?;
        Ok(ended)
    });
    // Files that got no result are requested again, in their order.
    while let Some(job) = window.pop_back() {
        queue.push_front(job);
    }
    match result {
        // Dropped, which kills it: it may be in the middle of a file.
        Ok(Ended::Stopped) => Ok(Ended::Stopped),
        Ok(ended) => worker.finish(Ok(ended)),
        Err(e) if e.is::<Gone>() || e.is::<WorkerError>() => worker
            .finish(Err(e))
            .with_context(|| format!("downloading from {origin}")),
        Err(e) => Err(e),
    }
}

/// Supervisor side of a download worker: send it the files in `queue`,
/// keeping at most [`WINDOW`] of them in `window`, unanswered, and handle
/// what it sends back, until the files are done, the worker's connection
/// ends or `failed` says to stop. Files that got no result stay in
/// `window`.
///
/// This thread is the only one that deals with the worker: it blocks
/// reading the worker's output, and may block in `done`, which stalls the
/// worker in turn. Sending never blocks.
fn serve<S: Sink>(
    sock: &File,
    queue: &mut VecDeque<Job<S>>,
    window: &mut VecDeque<Job<S>>,
    failed: &AtomicBool,
    done: &impl Fn(usize, S, Downloaded) -> Result<()>,
) -> Result<Ended> {
    let mut output = BufReader::with_capacity(BUF_SIZE, sock);
    let mut input = sock;
    let mut buf = Vec::new();
    // Whether this connection completed a file or got further with one.
    let mut progress = false;
    let mut reason = None;
    // Whether the worker takes more files.
    let mut open = true;
    // Results beyond the files sent are a reason to kill the worker.
    let unasked = "worker sent a result for a file that it wasn't sent";
    loop {
        let stopping = failed.load(Ordering::Relaxed);
        // A download under way is finished and kept even then.
        if stopping && !window.front().is_some_and(|job| job.started) {
            return Ok(Ended::Stopped);
        }
        while open && !stopping && window.len() < WINDOW {
            let Some(mut job) = queue.pop_front() else {
                break;
            };
            let item = serde_json::to_vec(&job.item())?;
            // Fails if the worker has exited; what it sent explains why.
            open = write_frame(&mut input, ITEM, &item).is_ok();
            window.push_back(job);
        }
        if window.is_empty() {
            break;
        }
        let (tag, len) = read_header(&mut output).map_err(gone)?;
        let downloading = |job: &Job<S>| format!("downloading {}", job.url);
        match tag {
            START => {
                let start: Start = message(&mut output, len)?;
                let job = window.front_mut().context(unasked)?;
                job.start(start).with_context(|| downloading(job))?;
            }
            CHUNK if len <= MAX_CHUNK => {
                buf.resize(len, 0);
                output.read_exact(&mut buf).map_err(gone)?;
                let job = window.front_mut().context(unasked)?;
                progress |= job.data(&buf).with_context(|| downloading(job))?;
            }
            END => {
                let end: End = message(&mut output, len)?;
                let mut job = window.pop_front().context(unasked)?;
                // Reasons can contain text from the server.
                let context = downloading(&job);
                match end {
                    End::Done => {
                        let (index, sink, downloaded) = job.finish().context(context)?;
                        done(index, sink, downloaded)?;
                        progress = true;
                    }
                    End::NotModified => {
                        let (index, sink, downloaded) = job.not_modified().context(context)?;
                        done(index, sink, downloaded)?;
                        progress = true;
                    }
                    End::Closed(why) => {
                        // The worker exits now. The file is continued
                        // over the next connection.
                        reason = Some(sanitize(&why, false));
                        open = false;
                        job.started = false;
                        window.push_front(job);
                    }
                    End::Unresumable(why) => {
                        ensure!(
                            job.resuming,
                            "{context}: worker couldn't continue a file that it wasn't to continue"
                        );
                        // Fetched again from the beginning, after the
                        // file that the worker has already.
                        job.validator = None;
                        reason = Some(sanitize(&why, false));
                        queue.push_front(job);
                    }
                    End::Failed(why) => bail!("{context}: {}", sanitize(&why, false)),
                }
            }
            DONE if len == 0 => {
                // The worker's connection is over, with files left.
                ensure!(
                    !window.front().is_some_and(|job| job.started),
                    "worker stopped in the middle of a file"
                );
                return Ok(Ended::Closed {
                    progress,
                    reason: reason.unwrap_or_else(|| "the connection ended".to_owned()),
                });
            }
            ERROR => return Err(read_error(&mut output, len)),
            _ => bail!("unexpected message {tag} ({len} bytes) from worker"),
        }
    }
    // Nothing is left: the worker exits when its input ends.
    rustix::net::shutdown(sock, rustix::net::Shutdown::Write).context("shutting down socket")?;
    match read_header(&mut output).map_err(gone)? {
        (DONE, 0) => Ok(Ended::Finished),
        (ERROR, len) => Err(read_error(&mut output, len)),
        (tag, len) => bail!("unexpected message {tag} ({len} bytes) from worker"),
    }
}

/// Read a `START` or `END` of `len` bytes.
fn message<T: DeserializeOwned>(mut r: impl Read, len: usize) -> Result<T> {
    ensure!(
        len <= MAX_MESSAGE,
        "worker sent a message of {len} bytes (limit {MAX_MESSAGE})"
    );
    let mut payload = vec![0; len];
    r.read_exact(&mut payload).map_err(gone)?;
    serde_json::from_slice(&payload).context("parsing message from worker")
}

/// Send root certificates to a worker.
fn send_certs(sock: &File, certs: &[CertificateDer]) -> Result<()> {
    let mut w = BufWriter::new(sock);
    for cert in certs {
        ensure!(
            cert.len() <= MAX_CERT,
            "root certificate of {} bytes is too large (limit {MAX_CERT})",
            cert.len()
        );
        write_frame(&mut w, CERT, cert)?;
    }
    write_frame(&mut w, DONE, &[])?;
    w.flush().context("sending root certificates to worker")
}

/// Worker side of [`send_certs`].
fn receive_certs(mut input: impl Read) -> Result<RootCerts> {
    let mut certs = Vec::new();
    loop {
        match read_header(&mut input).context("reading root certificates")? {
            (CERT, len) => certs.push(read_payload(&mut input, len, MAX_CERT)?.into()),
            (DONE, 0) => return RootCerts::from_der(certs),
            (tag, len) => bail!("unexpected message {tag} ({len} bytes) from supervisor"),
        }
    }
}

/// The worker: the origin that fd 0 is connected to is its argument; with
/// a second argument `custom-roots`, the root certificates come first on
/// the socket, fd 1.
fn worker(args: Args) -> Result<Vec<u8>> {
    let (origin, custom_roots) = match &args.extra[..] {
        [origin] => (origin, false),
        [origin, roots] if roots == "custom-roots" => (origin, true),
        _ => bail!("unexpected arguments {:?}", args.extra),
    };
    let origin = Origin::parse(origin)?;
    let out = args.out;
    // SAFETY: the supervisor passes the connection as fd 0.
    let net = unsafe { File::from_raw_fd(0) };
    // Items come over the socket that results go to. The fd is duplicated
    // here because confined, the worker can't do that any more.
    let input = out.get_ref().try_clone().context("duplicating socket")?;
    let policy = Policy {
        max_memory: Some(MAX_MEMORY),
        ..Policy::default()
    };
    sandbox::confine(args.layers, &policy)?;
    // One reader for all input, so nothing is lost in a buffer.
    let mut input = BufReader::new(input);
    let roots = if custom_roots {
        receive_certs(&mut input)?
    } else {
        RootCerts::default()
    };
    let mut conn = Connection::new(net, &origin, &roots)?;
    while conn.is_open() {
        let item: Item = match read_header(&mut input) {
            Ok((ITEM, len)) => serde_json::from_slice(&read_payload(&mut input, len, MAX_ITEM)?)
                .context("parsing item")?,
            Ok((tag, len)) => bail!("unexpected message {tag} ({len} bytes) from supervisor"),
            // The supervisor has no more files.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("reading from supervisor"),
        };
        let end = conn
            .get(
                &item.path,
                item.resume.as_ref(),
                item.restart,
                item.unless.as_deref(),
                &mut |event| match event {
                    Event::Start(start) => write_frame(out, START, &serde_json::to_vec(start)?),
                    Event::Data(data) => write_frame(out, CHUNK, data),
                },
            )
            .context("sending to supervisor")?;
        write_frame(out, END, &serde_json::to_vec(&end)?)?;
        // The supervisor acts on the end of a file (and reads the head of
        // a short one) while the next request is under way.
        out.flush().context("sending to supervisor")?;
    }
    Ok(Vec::new())
}

/// Downloads that wait for a job, at most; the download stage waits when
/// there are more. Each can keep a file open.
const MAX_WAITING: usize = 64;

/// Download `requests`, and meanwhile run `job` on up to `jobs` threads:
/// on what `downloaded` makes of each finished download (if anything),
/// and on the items in `ready`, in their order. Returns the results of
/// `job` in no particular order.
///
/// Downloads go one after another per server, in the order of `requests`
/// (see [`download_all`]). `downloaded` is called with the index
/// of the request, on the thread that downloads from its server, so the
/// next download from there waits for it. Finished downloads are taken
/// before items of `ready`, so that the download stage isn't held up.
///
/// Once something fails, no new downloads or jobs start; those under way
/// finish.
pub fn fetch_and_run<S: Sink, T: Send, R: Send>(
    workers: &Workers,
    jobs: NonZeroUsize,
    ready: Vec<T>,
    requests: Vec<Request<S>>,
    downloaded: impl Fn(usize, S, Downloaded) -> Result<Option<T>> + Sync,
    job: impl Fn(T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    let failed = &AtomicBool::new(false);
    let downloaded = &downloaded;
    let (tx, rx) = sync_channel(MAX_WAITING);
    let feed = Feed {
        downloads: rx,
        ready: ready.into_iter(),
    };
    let (downloads, results) = std::thread::scope(|s| {
        // Owns the sender, so the jobs end when the downloads have.
        let stage = s.spawn(move || {
            download_all(workers, requests, jobs, failed, |i, sink, download| {
                if let Some(item) = downloaded(i, sink, download)? {
                    // Fails only once the jobs have stopped for a failure.
                    let _ = tx.send(item);
                }
                Ok(())
            })
        });
        let results = par_map_iter(feed, jobs, failed, job);
        let downloads = stage
            .join()
            .unwrap_or_else(|p| std::panic::resume_unwind(p));
        (downloads, results)
    });
    Ok(both(downloads, results)?.1)
}

/// What the jobs of [`fetch_and_run`] work on.
struct Feed<T> {
    downloads: Receiver<T>,
    ready: std::vec::IntoIter<T>,
}

impl<T> Iterator for Feed<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if let Ok(item) = self.downloads.try_recv() {
            return Some(item);
        }
        self.ready.next().or_else(|| self.downloads.recv().ok())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::ensure;

    use super::*;

    #[test]
    fn downloads_come_before_ready_items() {
        let (tx, rx) = sync_channel(4);
        let mut feed = Feed {
            downloads: rx,
            ready: vec![1, 2].into_iter(),
        };
        tx.send(10).unwrap();
        assert_eq!(feed.next(), Some(10));
        assert_eq!(feed.next(), Some(1));
        tx.send(11).unwrap();
        assert_eq!(feed.next(), Some(11));
        assert_eq!(feed.next(), Some(2));
        // Nothing is ready: waits for the downloads, until they end.
        tx.send(12).unwrap();
        drop(tx);
        assert_eq!(feed.next(), Some(12));
        assert_eq!(feed.next(), None);
    }

    #[test]
    fn jobs_without_downloads() {
        // No worker is started without requests.
        let workers = Workers::new("/nonexistent");
        let jobs = NonZeroUsize::new(3).unwrap();
        let run = |fail: Option<u32>| {
            let requests: Vec<Request<Vec<u8>>> = Vec::new();
            fetch_and_run(
                &workers,
                jobs,
                (0..20).collect(),
                requests,
                |_, _, _| Ok(None),
                |n: u32| {
                    ensure!(Some(n) != fail, "job {n} failed");
                    Ok(n * 2)
                },
            )
        };
        let mut results = run(None).unwrap();
        results.sort();
        assert_eq!(results, (0..20).map(|n| n * 2).collect::<Vec<_>>());
        assert_eq!(run(Some(7)).unwrap_err().to_string(), "job 7 failed");
    }
}
