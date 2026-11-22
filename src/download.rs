//! Downloads, and the worker that does them: [`download_all`] runs one
//! worker per origin, and moves files between mirrors.
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
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::CertificateDer;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::http::{self, End, Origin, Resume, Start, Url};
use crate::jobs::{both, par_map_iter};
use crate::worker::{
    self, BUF_SIZE, CHUNK, DONE, ERROR, MAX_CHUNK, MAX_ERROR, WorkerError, Workers, read_error,
    read_header, sanitize, write_frame,
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

/// Timeout for connecting, and for each read and write once connected.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Files a worker has been sent and not yet answered, at most. With two,
/// the worker has the next file at hand when it finishes one, so there is
/// no round trip per file, and both always fit in the socket's buffer, so
/// sending them never blocks.
const WINDOW: usize = 2;

/// Mirrors of a file that it may be downloaded from at once, at most:
/// the first ones among its URLs that neither failed it nor were given
/// up. More of them share the files of a repo, but each takes a
/// connection and a worker.
pub const MIRRORS_AT_ONCE: usize = 2;

/// Connections to an origin that may end without progress before the
/// origin is given up.
const MAX_STRIKES: u32 = 3;

/// Longest `Last-Modified` value kept from a worker.
const MAX_LAST_MODIFIED: usize = 100;

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
    /// Where the file is, in order of preference: mirrors that have the
    /// same file. At least one.
    pub urls: Vec<Url>,
    /// The download fails if the file is larger.
    pub max_size: u64,
    /// What to do when the file is to be continued after its connection
    /// broke, and the server has another version of it by then: download
    /// that one from the beginning, or fail. Failing suits a file whose
    /// content is known beforehand (e.g. by a hash), as another version
    /// can't be the one wanted.
    pub restart_if_changed: bool,
    /// A version of the file that the caller has: if the file is
    /// requested from that URL and the server there still has that
    /// version, the download ends without a body, as
    /// [`Downloaded::not_modified`].
    pub unless: Option<Unless>,
    pub sink: S,
}

/// A version of a file at a URL, for [`Request::unless`]. A validator
/// means something only to the server that gave it, so the file is asked
/// for only if it changed only where it is downloaded from that URL.
#[derive(Debug, Clone)]
pub struct Unless {
    /// One of the request's URLs.
    pub url: Url,
    /// [`Downloaded::validator`] of an earlier download from there.
    pub validator: String,
}

/// A finished download.
#[derive(Debug)]
pub struct Downloaded {
    /// Where it came from: one of the request's URLs.
    pub url: Url,
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
    /// The file on each of its mirrors, in order of preference: the
    /// mirror (an index into [`Stage::mirrors`]) and the URL there.
    urls: Vec<(usize, Url)>,
    /// The mirror it is downloaded from now: an index into `urls`.
    at: usize,
    /// Mirrors that failed the file for good, and why.
    failures: Vec<(usize, anyhow::Error)>,
    max_size: u64,
    restart_if_changed: bool,
    unless: Option<Unless>,
    sink: S,
    /// Bytes of the file in the sink.
    received: u64,
    /// The most bytes any connection to this mirror brought the file to.
    /// Only more than that is progress, so starting again from the
    /// beginning isn't.
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
    fn new(index: usize, request: Request<S>, urls: Vec<(usize, Url)>) -> Self {
        Job {
            index,
            urls,
            at: 0,
            failures: Vec::new(),
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

    /// The file's URL on the mirror it is downloaded from.
    fn url(&self) -> &Url {
        &self.urls[self.at].1
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
        let unless = self
            .unless
            .as_ref()
            .filter(|u| self.most == 0 && u.url == *self.url())
            .map(|u| u.validator.clone());
        self.resuming = resume.is_some();
        self.conditional = unless.is_some();
        self.started = false;
        Item {
            path: self.url().path.clone(),
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
        // continue with, the server has another version now, or the file
        // comes from another mirror.
        if self.received > 0 {
            self.sink.restart().context("starting the file again")?;
            self.received = 0;
        }
        if let Some(length) = start.length
            && length > self.max_size
        {
            return Err(TooLarge(self.max_size).into());
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
    /// before on this mirror.
    fn data(&mut self, data: &[u8]) -> Result<bool> {
        ensure!(self.started, "worker sent data outside of a file");
        self.received += data.len() as u64;
        if self.received > self.max_size {
            return Err(TooLarge(self.max_size).into());
        }
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
            url: self.url().clone(),
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
            url: self.url().clone(),
            size: 0,
            last_modified: None,
            etag: None,
            validator: None,
            not_modified: true,
        };
        Ok((self.index, self.sink, downloaded))
    }

    /// Positions in `urls` of the mirrors that may take the file now: the
    /// first [`MIRRORS_AT_ONCE`] that neither failed it nor were given up.
    fn eligible<'a>(&'a self, mirrors: &'a [Mirror]) -> impl Iterator<Item = usize> + 'a {
        (0..self.urls.len())
            .filter(|&at| {
                let m = self.urls[at].0;
                !mirrors[m].given_up && !self.failures.iter().any(|&(f, _)| f == m)
            })
            .take(MIRRORS_AT_ONCE)
    }

    /// Download the file from the mirror at `at` in `urls` from now on.
    /// What continues it on one mirror doesn't on another, so there it
    /// starts again, and only getting further than on that mirror before
    /// is progress.
    fn move_to(&mut self, at: usize) {
        if self.urls[at].0 != self.urls[self.at].0 {
            self.validator = None;
            self.most = 0;
        }
        self.at = at;
    }
}

/// A file is larger than allowed. The mirror is given up: what it serves
/// isn't the file asked for.
#[derive(Debug)]
struct TooLarge(u64);

impl fmt::Display for TooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "file is larger than {} bytes", self.0)
    }
}

impl std::error::Error for TooLarge {}

/// An origin that files are downloaded from: a mirror, or the only
/// server of a file.
struct Mirror {
    origin: Origin,
    /// Whether a thread serves it now.
    running: bool,
    /// Connections that ended without progress, in this run. Not reset by
    /// connections that get somewhere in between.
    strikes: u32,
    /// Whether it was given up: no file is downloaded from it any more.
    given_up: bool,
    /// Why, until a file that no mirror is left for takes it for its
    /// error.
    why: Option<anyhow::Error>,
}

/// The download stage's state, shared by its threads.
struct Stage<S> {
    /// Files that no thread has, by their position among the requests.
    pool: Vec<Job<S>>,
    mirrors: Vec<Mirror>,
    /// Threads serving a mirror.
    running: usize,
    /// The first failure of the stage itself.
    error: Option<anyhow::Error>,
}

impl<S: Sink> Stage<S> {
    /// The first file in the pool that `mirror` may take, moved to it.
    fn take(&mut self, mirror: usize) -> Option<Job<S>> {
        let (i, at) = self.pool.iter().enumerate().find_map(|(i, job)| {
            let at = job
                .eligible(&self.mirrors)
                .find(|&at| job.urls[at].0 == mirror)?;
            Some((i, at))
        })?;
        let mut job = self.pool.remove(i);
        job.move_to(at);
        Some(job)
    }

    /// Return a file to the pool, in its place.
    fn put_back(&mut self, job: Job<S>) {
        let i = self.pool.partition_point(|j| j.index < job.index);
        self.pool.insert(i, job);
    }

    /// Return a file that its mirror failed for good, for `why`.
    fn failed_on_mirror(&mut self, mut job: Job<S>, why: anyhow::Error) {
        let mirror = job.urls[job.at].0;
        if job
            .eligible(&self.mirrors)
            .any(|at| job.urls[at].0 != mirror)
        {
            warn(&format!("{why:#} (trying another mirror)"));
        }
        job.failures.push((mirror, why));
        self.put_back(job);
    }

    /// Give up `mirror` for `why`. Its files go to other mirrors, if they
    /// have any left.
    fn give_up(&mut self, mirror: usize, why: anyhow::Error) {
        self.mirrors[mirror].given_up = true;
        let elsewhere = self.pool.iter().any(|job| {
            job.urls.iter().any(|&(m, _)| m == mirror)
                && job.eligible(&self.mirrors).next().is_some()
        });
        if elsewhere {
            warn(&format!("{why:#} (trying other mirrors)"));
        }
        self.mirrors[mirror].why = Some(why);
    }

    /// Fail the stage with `e`, unless it has failed already.
    fn fail(&mut self, e: anyhow::Error, failed: &AtomicBool) {
        self.error.get_or_insert(e);
        failed.store(true, Ordering::Relaxed);
    }

    /// The error for a file in the pool that no mirror is left for, if
    /// there is one: why its mirrors failed it.
    fn stranded(&mut self) -> Option<anyhow::Error> {
        let i = self
            .pool
            .iter()
            .position(|job| job.eligible(&self.mirrors).next().is_none())?;
        let job = &mut self.pool[i];
        let mut causes = Vec::new();
        for &(m, _) in &job.urls {
            if let Some(k) = job.failures.iter().position(|&(f, _)| f == m) {
                causes.push(job.failures.swap_remove(k).1);
            } else if let Some(why) = self.mirrors[m].why.take() {
                causes.push(why);
            }
        }
        let url = job.urls[0].1.clone();
        Some(match causes.len() {
            0 => anyhow::anyhow!("downloading {url}: no mirror is left"),
            1 => causes.pop().unwrap(),
            _ => {
                let causes: Vec<String> = causes.iter().map(|e| format!("{e:#}")).collect();
                anyhow::anyhow!(
                    "downloading {}: every mirror failed: {}",
                    url.file_name(),
                    causes.join("; ")
                )
            }
        })
    }

    /// Mirrors that files in the pool may go to and that have no thread,
    /// in the order of the files that want them.
    fn wanted(&self) -> Vec<usize> {
        let mut wanted = Vec::new();
        for job in &self.pool {
            for at in job.eligible(&self.mirrors) {
                let m = job.urls[at].0;
                if !self.mirrors[m].running && !wanted.contains(&m) {
                    wanted.push(m);
                }
            }
        }
        wanted
    }
}

/// [`Stage`] with what its threads wait on.
struct Shared<S> {
    stage: Mutex<Stage<S>>,
    /// Signalled when a thread ends or returns a file to the pool.
    changed: Condvar,
}

impl<S> Shared<S> {
    fn lock(&self) -> MutexGuard<'_, Stage<S>> {
        // A thread that panicked is joined later, which resumes the panic.
        self.stage.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Print a warning about the downloads.
fn warn(message: &str) {
    // Not eprintln!, which panics if writing fails.
    let _ = writeln!(io::stderr().lock(), "warning: {message}");
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
    /// The mirror is to be given up, for this reason: it couldn't be
    /// reached, served something that isn't the file, or its worker
    /// failed.
    GaveUp(anyhow::Error),
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
/// Each origin (scheme, host and port) has one worker at a time, with
/// one connection, over which it downloads files one after another;
/// up to `jobs` origins at once. A file goes to the first mirror among
/// its URLs that is free, of the first [`MIRRORS_AT_ONCE`] that haven't
/// failed it, in the order of `requests`: so the mirrors of a repo
/// share its files, and a file that fails on one (e.g. `404`) goes to
/// the next. The connections are opened here and handed to the
/// workers, which have no network access of their own. When a
/// connection ends before its files are done, a new one continues,
/// also in the middle of a file where the server allows. A mirror is
/// given up when it can't be reached, when its connections keep ending
/// without progress, when it serves more than a file may have, or when
/// its worker fails; its files go to the other mirrors. This fails
/// when a file has no mirror left. Redirects are not followed.
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
    let mut mirrors: Vec<Mirror> = Vec::new();
    let mut pool = Vec::new();
    for (index, request) in requests.into_iter().enumerate() {
        ensure!(!request.urls.is_empty(), "a download has no URL");
        // It goes into a request head.
        if let Some(Unless { url, validator }) = &request.unless {
            ensure!(
                http::is_validator(validator),
                "downloading {url}: bad validator {validator:?}"
            );
        }
        let mut urls = Vec::new();
        for url in &request.urls {
            let m = match mirrors.iter().position(|m| m.origin == url.origin) {
                Some(m) => m,
                None => {
                    mirrors.push(Mirror {
                        origin: url.origin.clone(),
                        running: false,
                        strikes: 0,
                        given_up: false,
                        why: None,
                    });
                    mirrors.len() - 1
                }
            };
            urls.push((m, url.clone()));
        }
        pool.push(Job::new(index, request, urls));
    }
    let shared = Shared {
        stage: Mutex::new(Stage {
            pool,
            mirrors,
            running: 0,
            error: None,
        }),
        changed: Condvar::new(),
    };
    let (shared, done) = (&shared, &done);
    std::thread::scope(|s| {
        let mut stage = shared.lock();
        loop {
            let stopping = failed.load(Ordering::Relaxed);
            if !stopping {
                if let Some(e) = stage.stranded() {
                    stage.fail(e, failed);
                    continue;
                }
                for m in stage.wanted() {
                    if stage.running == jobs.get() {
                        break;
                    }
                    stage.mirrors[m].running = true;
                    stage.running += 1;
                    s.spawn(move || run_mirror(workers, shared, m, failed, done));
                }
            }
            if stage.running == 0 && (stopping || stage.pool.is_empty()) {
                break;
            }
            stage = shared
                .changed
                .wait(stage)
                .unwrap_or_else(PoisonError::into_inner);
        }
    });
    let error = shared.lock().error.take();
    error.map_or(Ok(()), Err)
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
        urls: vec![url.clone()],
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

/// The thread that serves `mirror` (an index into [`Stage::mirrors`]):
/// see [`serve_mirror`]. When it ends, the files it has go back to the
/// pool, and the mirror is given up if it is to be.
fn run_mirror<S: Sink>(
    workers: &Workers,
    shared: &Shared<S>,
    mirror: usize,
    failed: &AtomicBool,
    done: &impl Fn(usize, S, Downloaded) -> Result<()>,
) {
    let mut mine = VecDeque::new();
    let exit = std::panic::catch_unwind(AssertUnwindSafe(|| {
        serve_mirror(workers, shared, mirror, &mut mine, failed, done)
    }));
    let mut stage = shared.lock();
    for job in mine {
        stage.put_back(job);
    }
    stage.mirrors[mirror].running = false;
    stage.running -= 1;
    let panic = match exit {
        Ok(Ok(None)) => None,
        Ok(Ok(Some(why))) => {
            stage.give_up(mirror, why);
            None
        }
        Ok(Err(e)) => {
            stage.fail(e, failed);
            None
        }
        Err(panic) => {
            failed.store(true, Ordering::Relaxed);
            Some(panic)
        }
    };
    drop(stage);
    shared.changed.notify_all();
    if let Some(panic) = panic {
        std::panic::resume_unwind(panic);
    }
}

/// Download files from `mirror` in order, over one connection and over
/// further ones while they make progress: those in `mine`, and then
/// those it may take from the pool. Returns when there are none, or with
/// the reason to give the mirror up. Files that are left stay in `mine`.
fn serve_mirror<S: Sink>(
    workers: &Workers,
    shared: &Shared<S>,
    mirror: usize,
    mine: &mut VecDeque<Job<S>>,
    failed: &AtomicBool,
    done: &impl Fn(usize, S, Downloaded) -> Result<()>,
) -> Result<Option<anyhow::Error>> {
    let origin = shared.lock().mirrors[mirror].origin.clone();
    while !failed.load(Ordering::Relaxed) {
        // A connection is opened only for a file.
        if mine.is_empty() {
            match shared.lock().take(mirror) {
                Some(job) => mine.push_back(job),
                None => break,
            }
        }
        match connection(workers, &origin, shared, mirror, mine, failed, done)? {
            Ended::Finished | Ended::Stopped => break,
            Ended::Closed { progress: true, .. } => {}
            Ended::Closed {
                progress: false,
                reason,
            } => {
                let strikes = {
                    let mut stage = shared.lock();
                    stage.mirrors[mirror].strikes += 1;
                    stage.mirrors[mirror].strikes
                };
                if strikes == MAX_STRIKES {
                    let url = mine.front().context("no file is left")?.url();
                    return Ok(Some(anyhow::anyhow!(
                        "downloading {url}: {reason} (giving up on {origin} \
                         after {MAX_STRIKES} connections that got nothing)"
                    )));
                }
                std::thread::sleep(workers.retry_delay() * (1 << (strikes - 1)));
            }
            Ended::GaveUp(why) => return Ok(Some(why)),
        }
    }
    Ok(None)
}

/// Open a connection to `origin` (`mirror`) and run a worker on it for
/// the files in `mine`, and those it takes from the pool, until there
/// are none or the connection ends. Files left are in `mine` then.
fn connection<S: Sink>(
    workers: &Workers,
    origin: &Origin,
    shared: &Shared<S>,
    mirror: usize,
    mine: &mut VecDeque<Job<S>>,
    failed: &AtomicBool,
    done: &impl Fn(usize, S, Downloaded) -> Result<()>,
) -> Result<Ended> {
    let first = mine.front().context("no file to download")?;
    let conn = match http::connect(origin, TIMEOUT) {
        Ok(conn) => conn,
        Err(e) => {
            let e = e.context(format!("downloading {}", first.url()));
            return Ok(Ended::GaveUp(e));
        }
    };
    let (ours, theirs) = worker::stream_socket()?;
    let custom = workers.root_certs().custom().filter(|_| origin.tls);
    let name = origin.to_string();
    let mut args = vec![&*name];
    if custom.is_some() {
        args.push("custom-roots");
    }
    let worker = workers.spawn(&download_worker::KIND, conn.into(), theirs, &[], &args)?;
    let sock = File::from(ours);
    // The worker reads all certificates before it writes anything but
    // an error, which then explains a failure to send them.
    let sent = custom.map_or(Ok(()), |certs| send_certs(&sock, certs));
    let mut window = VecDeque::new();
    let result = serve(&sock, shared, mirror, mine, &mut window, failed, done).and_then(|ended| {
        sent?;
        Ok(ended)
    });
    // Files that got no result are requested again, in their order.
    while let Some(job) = window.pop_back() {
        mine.push_front(job);
    }
    let result = match result {
        // Dropped, which kills it: it may be in the middle of a file.
        Ok(Ended::Stopped) => return Ok(Ended::Stopped),
        Ok(ended) => worker.finish(Ok(ended)),
        Err(e) if e.is::<Gone>() || e.is::<WorkerError>() => worker
            .finish(Err(e))
            .with_context(|| format!("downloading from {origin}")),
        // The worker is killed.
        Err(e) if e.is::<TooLarge>() => return Ok(Ended::GaveUp(e)),
        Err(e) => return Err(e),
    };
    // What the worker did, or how it exited, is up to its server.
    Ok(result.unwrap_or_else(Ended::GaveUp))
}

/// Supervisor side of a download worker: send it the files in `mine` and
/// then those that `mirror` may take from the pool, keeping at most
/// [`WINDOW`] of them in `window`, unanswered, and handle what it sends
/// back, until there are no files left, the worker's connection ends or
/// `failed` says to stop. Files that got no result stay in `window`; one
/// that the server can't continue goes to the front of `mine`, and one
/// that it fails for good back to the pool, for other mirrors.
///
/// This thread is the only one that deals with the worker: it blocks
/// reading the worker's output, and may block in `done`, which stalls the
/// worker in turn. Sending never blocks.
fn serve<S: Sink>(
    sock: &File,
    shared: &Shared<S>,
    mirror: usize,
    mine: &mut VecDeque<Job<S>>,
    window: &mut VecDeque<Job<S>>,
    failed: &AtomicBool,
    done: &impl Fn(usize, S, Downloaded) -> Result<()>,
) -> Result<Ended> {
    let mut output = BufReader::with_capacity(BUF_SIZE, sock);
    let mut input = sock;
    let mut buf = Vec::new();
    // Whether this connection completed a file, got further with one, or
    // got a final answer for one.
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
            let Some(mut job) = mine.pop_front().or_else(|| shared.lock().take(mirror)) else {
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
        let downloading = |job: &Job<S>| format!("downloading {}", job.url());
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
                        mine.push_front(job);
                    }
                    End::Failed(why) => {
                        // Each file fails at most once per mirror, so
                        // this can't go on and on.
                        let why = anyhow::anyhow!("{context}: {}", sanitize(&why, false));
                        shared.lock().failed_on_mirror(job, why);
                        shared.changed.notify_all();
                        progress = true;
                    }
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

pub(crate) mod download_worker {
    //! The worker's side (see [`KIND`]).

    use std::fs::File;
    use std::io::{self, BufReader, Read, Write};
    use std::os::fd::FromRawFd;

    use anyhow::{Context, Result, bail};

    use super::{CERT, END, ITEM, Item, MAX_CERT, MAX_ITEM, START};
    use crate::http::{Connection, Event, Origin, RootCerts};
    use crate::sandbox::{self, Policy};
    use crate::worker::{Args, CHUNK, DONE, Kind, NO_CAPS, read_header, read_payload, write_frame};

    /// Address space limit of the worker (TLS and a few buffers).
    const MAX_MEMORY: u64 = 256 << 20;

    /// The worker; see the documentation of [`super`].
    pub(crate) const KIND: Kind = Kind {
        name: "download",
        dirs: &[],
        caps: NO_CAPS,
        main,
    };

    /// Worker side of [`super::send_certs`].
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
    fn main(args: Args) -> Result<Vec<u8>> {
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
                Ok((ITEM, len)) => {
                    serde_json::from_slice(&read_payload(&mut input, len, MAX_ITEM)?)
                        .context("parsing item")?
                }
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
