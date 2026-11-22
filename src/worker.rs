//! Worker processes: parts of skl that run apart from the supervisor (the
//! `skl` process), each confined to the access it needs.
//!
//! The supervisor starts a worker by executing the `skl` binary with the
//! hidden [`SUBCOMMAND`] under bubblewrap (`src/bwrap.rs`), handing it
//! only the fds and directories it needs. A fresh exec is single-threaded
//! and inherits no memory. The worker closes any other inherited fds and
//! confines itself (Landlock and seccomp) before reading its input. Both
//! ends are the same binary, so the protocol needs no stability.
//!
//! Messages are frames: a tag byte, a little-endian `u32` length and the
//! payload. A worker ends by writing one `DONE` frame (its JSON result) or
//! one `ERROR` frame (a message) to fd 1. Workers write fd 1 through a
//! buffer, so many small messages cost one system call.
//!
//! Each kind of worker is a `Kind`, defined next to the code it runs
//! (e.g. the Arch package import in [`crate::arch`]), whose documentation
//! says what the worker gets and what it sends. `KINDS` here lists them, and
//! a worker can run only as one of those. The supervisor's side of each is a
//! function there that takes [`Workers`].
//!
//! Directories (`Kind::dirs`) are passed as paths inside the worker's mount
//! namespace, or as inherited fd numbers when it runs without namespaces.
//! Other arguments of a worker come last, after `--`.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::marker::PhantomData;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, ExitStatus};
use std::sync::{Mutex, mpsc};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};

use crate::bwrap::{self, Mount, Namespaces};
use crate::download::Parallel;
use crate::http::RootCerts;
use crate::manifest::{BlobId, Content};
use crate::sandbox::Layers;
use crate::store::{BlobSink, Store};
use crate::{arch, diff, download, fds, install};

/// First argument that makes `skl` run as a worker. `main` must check for
/// it before doing anything else.
pub const SUBCOMMAND: &str = "__worker";

/// Every kind of worker there is.
const KINDS: &[&Kind] = &[
    &arch::import_worker::KIND,
    &arch::repo::read_db_worker::KIND,
    &arch::verify::verify_worker::KIND,
    &download::download_worker::KIND,
    &diff::diff_worker::KIND,
    &install::install_worker::KIND,
];

pub(crate) const BEGIN: u8 = 1;
pub(crate) const CHUNK: u8 = 2;
pub(crate) const DONE: u8 = 3;
pub(crate) const ERROR: u8 = 4;

/// Chunk size the worker sends; the supervisor accepts up to [`MAX_CHUNK`].
const CHUNK_SIZE: usize = 64 << 10;
pub(crate) const MAX_CHUNK: usize = 1 << 20;
const MAX_DONE: usize = 256 << 20;
pub(crate) const MAX_ERROR: usize = 64 << 10;
/// Buffer size for writing and reading messages. Chunks at least this
/// large bypass the buffer.
pub(crate) const BUF_SIZE: usize = CHUNK_SIZE;

/// Delay before a download's next connection after the first one that got
/// nothing; see [`Workers::set_retry_delay`].
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// A kind of worker: how the supervisor starts it, and the code it runs.
pub(crate) struct Kind {
    /// The worker's name: its argument after [`SUBCOMMAND`], and what its
    /// messages are prefixed with.
    pub(crate) name: &'static str,
    /// Directories the worker gets, in order (see [`Workers::spawn`]).
    pub(crate) dirs: &'static [Dir],
    pub(crate) caps: Caps,
    /// The worker's code, after `main` has closed inherited fds other than
    /// stdio and the directories. It must confine itself (with
    /// [`crate::sandbox::confine`]) before it reads any input. It returns
    /// the payload of `DONE`; an error is sent as `ERROR`.
    pub(crate) main: fn(Args) -> Result<Vec<u8>>,
}

/// A directory a worker gets, bound in its mount namespace.
pub(crate) struct Dir {
    /// Absolute path inside the mount namespace.
    pub(crate) path: &'static str,
    pub(crate) writable: bool,
}

/// What a worker's [`Kind::main`] gets.
pub(crate) struct Args<'a> {
    /// The sandboxing layers to confine itself with.
    pub(crate) layers: Layers,
    /// The directories of [`Kind::dirs`], one each, in order.
    pub(crate) dirs: Vec<OwnedFd>,
    /// The arguments after `--`.
    pub(crate) extra: Vec<String>,
    /// fd 1, buffered; `DONE` or `ERROR` is written to it after `main`.
    pub(crate) out: &'a mut BufWriter<File>,
}

impl Args<'_> {
    /// The directories, which are as many as [`Kind::dirs`] says.
    pub(crate) fn dirs<const N: usize>(&mut self) -> Result<[OwnedFd; N]> {
        <[OwnedFd; N]>::try_from(std::mem::take(&mut self.dirs))
            .map_err(|d| anyhow::anyhow!("expected {N} directories, got {}", d.len()))
    }

    /// Fail if there are arguments after `--`.
    pub(crate) fn no_extra(&self) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "unexpected arguments {:?}",
            self.extra
        );
        Ok(())
    }
}

/// Capabilities a worker keeps; see [`Namespaces`].
#[derive(Clone, Copy)]
pub(crate) struct Caps {
    /// [`Namespaces::root_caps`]
    pub(crate) root: Option<&'static [&'static str]>,
    /// [`Namespaces::userns_caps`]
    pub(crate) userns: &'static [&'static str],
}

/// A worker that runs in a new user namespace without capabilities.
pub(crate) const NO_CAPS: Caps = Caps {
    root: None,
    userns: &[],
};

/// Statistics about an import, counted by the supervisor.
#[derive(Debug, Default)]
pub struct ImportStats {
    pub files: u64,
    pub new_blobs: u64,
    pub new_bytes: u64,
}

/// Starts worker processes.
pub struct Workers {
    exe: PathBuf,
    layers: Layers,
    roots: RootCerts,
    retry_delay: Duration,
    downloads: Parallel,
}

impl Workers {
    /// `exe` is the `skl` binary to run workers with; the `skl` command uses
    /// `/proc/self/exe`. All sandboxing layers are on.
    pub fn new(exe: impl Into<PathBuf>) -> Self {
        Workers {
            exe: exe.into(),
            layers: Layers::default(),
            roots: RootCerts::default(),
            retry_delay: RETRY_DELAY,
            downloads: Parallel::default(),
        }
    }

    /// How many downloads run at once, and where ([`Parallel::default`]
    /// by default).
    pub fn set_downloads(&mut self, downloads: Parallel) {
        self.downloads = downloads;
    }

    /// Check TLS server certificates of downloads against `roots` (the
    /// built-in ones by default).
    pub fn set_root_certs(&mut self, roots: RootCerts) {
        self.roots = roots;
    }

    /// How long a download waits before it connects to a server again
    /// after a connection that got nothing (one second by default). The
    /// wait doubles with each such connection to the same server.
    pub fn set_retry_delay(&mut self, delay: Duration) {
        self.retry_delay = delay;
    }

    /// Run workers without new namespaces (and without bubblewrap).
    #[cfg(feature = "insecure")]
    pub fn disable_namespaces(&mut self) {
        self.layers.namespaces = false;
    }

    /// Run workers without Landlock, e.g. where an outer container blocks it.
    #[cfg(feature = "insecure")]
    pub fn disable_landlock(&mut self) {
        self.layers.landlock = false;
    }

    /// Run workers without seccomp filters.
    #[cfg(feature = "insecure")]
    pub fn disable_seccomp(&mut self) {
        self.layers.seccomp = false;
    }

    /// The root certificates downloads check servers against.
    pub(crate) fn root_certs(&self) -> &RootCerts {
        &self.roots
    }

    /// See [`Workers::set_retry_delay`].
    pub(crate) fn retry_delay(&self) -> Duration {
        self.retry_delay
    }

    /// See [`Workers::set_downloads`].
    pub(crate) fn downloads(&self) -> Parallel {
        self.downloads
    }

    /// Start a worker of `kind` with `stdin` and `stdout` as fds 0 and 1,
    /// and `dirs`, one for each of [`Kind::dirs`], bound in its mount
    /// namespace, their paths passed as arguments. Without namespaces, the
    /// fds of `dirs` are inherited under their current numbers instead, and
    /// the numbers passed. `args` are passed last, after `--`.
    /// Stderr is a pipe; see [`Worker::finish`].
    ///
    /// The worker dies with this thread, so it stays on it; see
    /// [`Workers::with_spawner`] for workers that threads share.
    pub(crate) fn spawn(
        &self,
        kind: &'static Kind,
        stdin: OwnedFd,
        stdout: OwnedFd,
        dirs: &[BorrowedFd],
        args: &[&str],
    ) -> Result<Worker> {
        self.start(kind, stdin, stdout, dirs, args)
    }

    /// Run `f` with a [`Spawner`], which starts workers on a thread of its
    /// own that lives until `f` has returned, so the workers can move
    /// between threads. They can't outlive `f`.
    ///
    /// Workers die with the thread that started them (bubblewrap's
    /// `--die-with-parent`, which sets `PR_SET_PDEATHSIG`): a worker started
    /// by a thread that ends before the worker is done is killed.
    pub(crate) fn with_spawner<T>(
        &self,
        f: impl for<'s> FnOnce(&'s Spawner<'s>) -> Result<T>,
    ) -> Result<T> {
        std::thread::scope(|scope| {
            let (requests, received) = mpsc::channel::<SpawnRequest>();
            std::thread::Builder::new()
                .name("worker-spawner".into())
                .spawn_scoped(scope, move || {
                    for r in received {
                        let _ = r
                            .reply
                            .send(self.start(r.kind, r.stdin, r.stdout, &[], &[]));
                    }
                })
                .context("starting thread")?;
            // Dropping the spawner when `f` is done ends the thread.
            f(&Spawner {
                requests: Mutex::new(requests),
                _scope: PhantomData,
            })
        })
    }

    /// See [`Workers::spawn`]; `T` says on which threads the worker may be.
    fn start<T>(
        &self,
        kind: &'static Kind,
        stdin: OwnedFd,
        stdout: OwnedFd,
        dirs: &[BorrowedFd],
        args: &[&str],
    ) -> Result<Worker<T>> {
        ensure!(
            dirs.len() == kind.dirs.len(),
            "{} worker needs {} directories",
            kind.name,
            kind.dirs.len()
        );
        let dirs: Vec<Mount> = (kind.dirs.iter().zip(dirs))
            .map(|(dir, &fd)| Mount {
                fd,
                dest: dir.path,
                writable: dir.writable,
            })
            .collect();
        let caps = kind.caps;
        let kind = kind.name;
        let exe_fd: OwnedFd;
        let (mut cmd, raw) = if self.layers.namespaces {
            let bwrap = bwrap::find()?;
            use rustix::fs::{Mode, OFlags};
            exe_fd = rustix::fs::open(&self.exe, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
                .with_context(|| format!("opening {}", self.exe.display()))?;
            let ns = Namespaces {
                mounts: &dirs,
                root_caps: caps.root,
                userns_caps: caps.userns,
            };
            let (mut cmd, raw) = bwrap::command(&bwrap, exe_fd.as_fd(), &ns)?;
            cmd.arg(SUBCOMMAND).arg(kind);
            cmd.args(dirs.iter().map(|d| d.dest));
            (cmd, raw)
        } else {
            let mut cmd = Command::new(&self.exe);
            cmd.arg(SUBCOMMAND).arg(kind);
            let raw: Vec<RawFd> = dirs.iter().map(|d| d.fd.as_raw_fd()).collect();
            for fd in &raw {
                cmd.arg(fd.to_string());
            }
            (cmd, raw)
        };
        if !self.layers.landlock {
            cmd.arg("--no-landlock");
        }
        if !self.layers.seccomp {
            cmd.arg("--no-seccomp");
        }
        cmd.arg("--").args(args);
        // Non-blocking on the worker's side: if the pipe fills up, further
        // output is lost instead of blocking a worker while the supervisor
        // waits for it on another fd. The worker can't change this, as
        // seccomp allows `fcntl` only with `F_GETFD`.
        use rustix::pipe::{PipeFlags, pipe_with};
        let (stderr_r, stderr_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
        rustix::fs::fcntl_setfl(&stderr_w, rustix::fs::OFlags::NONBLOCK)
            .context("making pipe non-blocking")?;
        cmd.env_clear()
            .current_dir("/")
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr_w);
        fds::inherit(&mut cmd, raw);
        let child = cmd
            .spawn()
            .with_context(|| format!("starting {kind} worker ({})", self.exe.display()))?;
        Ok(Worker {
            kind,
            child: Some(child),
            stderr: File::from(stderr_r),
            _thread: PhantomData,
        })
    }
}

/// Starts workers on a thread of its own; see [`Workers::with_spawner`].
/// `'s` is the scope in which its workers live.
pub(crate) struct Spawner<'s> {
    requests: Mutex<mpsc::Sender<SpawnRequest>>,
    _scope: PhantomData<fn(&'s ()) -> &'s ()>,
}

struct SpawnRequest {
    kind: &'static Kind,
    stdin: OwnedFd,
    stdout: OwnedFd,
    /// Gets the worker, which lives during the spawner's scope; only the
    /// spawner's thread makes `Shared<'static>` workers, and
    /// [`Spawner::spawn`] narrows that.
    reply: mpsc::SyncSender<Result<Worker<Shared<'static>>>>,
}

impl<'s> Spawner<'s> {
    /// Start a worker of `kind`, which takes no directories or arguments
    /// (see [`Workers::spawn`]).
    pub(crate) fn spawn(
        &self,
        kind: &'static Kind,
        stdin: OwnedFd,
        stdout: OwnedFd,
    ) -> Result<Worker<Shared<'s>>> {
        let gone = || anyhow::anyhow!("the thread that starts workers is gone");
        let (reply, worker) = mpsc::sync_channel(1);
        let request = SpawnRequest {
            kind,
            stdin,
            stdout,
            reply,
        };
        self.requests
            .lock()
            .unwrap()
            .send(request)
            .map_err(|_| gone())?;
        worker.recv().map_err(|_| gone())?
    }
}

/// A [`Worker`] that must stay on the thread that started it, as it dies
/// with that thread.
pub(crate) struct ThreadBound(PhantomData<*const ()>);

/// A [`Worker`] that a [`Spawner`]'s thread started, which lives during `'s`.
pub(crate) struct Shared<'s>(PhantomData<&'s ()>);

/// A running worker; killed if dropped before [`Worker::finish`]. `T` is
/// [`ThreadBound`] or [`Shared`].
pub(crate) struct Worker<T = ThreadBound> {
    kind: &'static str,
    child: Option<Child>,
    stderr: File,
    _thread: PhantomData<T>,
}

impl<T> Worker<T> {
    /// Wait for the worker to exit and combine its exit status with the
    /// result received from it. An error the worker reported explains a
    /// failure best; otherwise an abnormal exit explains a broken connection.
    ///
    /// Then prints what the worker wrote to stderr (e.g. a panic message):
    /// control characters escaped and each line prefixed with the worker's
    /// name, so it can't pass for the supervisor's output or control the
    /// terminal. Only what fit in the pipe is kept.
    pub(crate) fn finish<R>(mut self, result: Result<R>) -> Result<R> {
        let status = self.child.take().unwrap().wait();
        let status = status.with_context(|| format!("waiting for {} worker", self.kind))?;
        // The worker has exited, so this can't block: no one else has the
        // pipe's write end.
        let mut output = Vec::new();
        match self.stderr.read_to_end(&mut output) {
            Ok(_) => print_worker_output(self.kind, &output),
            Err(e) => eprintln!("warning: reading {} worker's stderr: {e}", self.kind),
        }
        match result {
            Err(e) if e.is::<WorkerError>() => Err(e),
            _ if !status.success() => {
                let err = anyhow::anyhow!("{} worker {}", self.kind, describe(status));
                match result {
                    Ok(_) => Err(err),
                    Err(e) => Err(err.context(format!("{e:#}"))),
                }
            }
            r => r,
        }
    }
}

impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Print a worker's output as one block, so output from workers finishing
/// at the same time doesn't interleave.
fn print_worker_output(kind: &str, output: &[u8]) {
    let mut stderr = io::stderr().lock();
    for line in sanitize(&String::from_utf8_lossy(output), true).lines() {
        let _ = writeln!(stderr, "{kind} worker: {line}");
    }
}

/// Escape control characters, other than newline and tab if `lines`.
pub(crate) fn sanitize(s: &str, lines: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() && !(lines && (c == '\n' || c == '\t')) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

fn describe(status: ExitStatus) -> String {
    // bwrap exits with 128 + the signal that killed the worker. Workers
    // and bwrap itself exit with small codes.
    let signal = status
        .signal()
        .or_else(|| status.code().filter(|&c| c > 128).map(|c| c - 128));
    match signal {
        Some(libc::SIGSYS) => {
            "was killed by SIGSYS (it made a system call its seccomp filter doesn't allow)"
                .to_owned()
        }
        Some(libc::SIGABRT) => {
            "aborted (e.g. out of memory: workers have a fixed memory limit)".to_owned()
        }
        Some(sig) => format!("was killed by signal {sig}"),
        None => format!("failed ({status})"),
    }
}

/// An error message a worker sent.
#[derive(Debug)]
pub(crate) struct WorkerError(String);

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WorkerError {}

pub(crate) fn write_frame(w: &mut impl Write, tag: u8, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(io::Error::other)?;
    let mut header = [tag, 0, 0, 0, 0];
    header[1..].copy_from_slice(&len.to_le_bytes());
    w.write_all(&header)?;
    w.write_all(payload)
}

pub(crate) fn read_header(mut r: impl Read) -> io::Result<(u8, usize)> {
    let mut h = [0u8; 5];
    r.read_exact(&mut h)?;
    let len = u32::from_le_bytes([h[1], h[2], h[3], h[4]]);
    Ok((h[0], len as usize))
}

pub(crate) fn read_payload(mut r: impl Read, len: usize, max: usize) -> Result<Vec<u8>> {
    if len > max {
        bail!("worker sent a message of {len} bytes (limit {max})");
    }
    let mut payload = vec![0; len];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

/// Read an error message, escaping control characters: it may contain
/// text from untrusted input, such as a server's reason phrase.
pub(crate) fn read_error(r: impl Read, len: usize) -> anyhow::Error {
    match read_payload(r, len, MAX_ERROR) {
        Ok(msg) => WorkerError(sanitize(&String::from_utf8_lossy(&msg), false)).into(),
        Err(e) => e.context("reading error message from worker"),
    }
}

/// Read a worker's final `DONE` or `ERROR` frame.
pub(crate) fn read_result(mut r: impl Read) -> Result<Vec<u8>> {
    let (tag, len) = read_header(&mut r).context("reading result from worker")?;
    match tag {
        DONE => read_payload(r, len, MAX_DONE),
        ERROR => Err(read_error(r, len)),
        _ => bail!("unexpected message {tag} from worker"),
    }
}

pub(crate) fn send_json(fd: OwnedFd, value: &(impl serde::Serialize + ?Sized)) -> Result<()> {
    let mut w = BufWriter::new(File::from(fd));
    serde_json::to_writer(&mut w, value)?;
    w.flush().context("sending to worker")
}

/// A pair of connected stream sockets: the supervisor's end, the worker's.
pub(crate) fn stream_socket() -> Result<(OwnedFd, OwnedFd)> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
    socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .context("creating socket")
}

/// The supervisor's end of a socket that only the worker writes to (any
/// input for the worker was sent before).
pub(crate) fn receiver(ours: OwnedFd) -> Result<BufReader<File>> {
    // Nothing more is sent to the worker.
    rustix::net::shutdown(&ours, rustix::net::Shutdown::Write).context("shutting down socket")?;
    Ok(BufReader::with_capacity(BUF_SIZE, File::from(ours)))
}

/// Supervisor side of a [`RemoteSink`]: add the blobs a worker streams
/// to `store` until its `DONE`. Returns
/// the content of each blob in the order received, the payload of
/// `DONE`, and statistics.
pub(crate) fn receive_blobs(
    store: &Store,
    conn: &mut BufReader<File>,
) -> Result<(Vec<Content>, Vec<u8>, ImportStats)> {
    let mut stats = ImportStats::default();
    // Content of each blob, in the order received.
    let mut blobs: Vec<Content> = Vec::new();
    loop {
        let (tag, len) = read_header(&mut *conn).context("reading from worker")?;
        match tag {
            BEGIN if len == 8 => {
                let mut size = [0u8; 8];
                conn.read_exact(&mut size).context("reading from worker")?;
                let mut reader = BlobReader {
                    conn: &mut *conn,
                    left: u64::from_le_bytes(size),
                    remaining: 0,
                    error: None,
                };
                let added = store.add_blob(&mut reader);
                if let Some(e) = reader.error {
                    return Err(e.into());
                }
                let added = added?;
                stats.files += 1;
                if added.new {
                    stats.new_blobs += 1;
                    stats.new_bytes += added.size;
                }
                blobs.push(Content {
                    hash: added.hash,
                    size: added.size,
                });
            }
            DONE => {
                let json = read_payload(&mut *conn, len, MAX_DONE)?;
                return Ok((blobs, json, stats));
            }
            ERROR => return Err(read_error(conn, len)),
            _ => bail!("unexpected message {tag} from worker"),
        }
    }
}

/// Reads one blob's content from `CHUNK` frames, up to its size.
struct BlobReader<'a> {
    conn: &'a mut BufReader<File>,
    /// Bytes of the blob not yet read.
    left: u64,
    /// Bytes left in the current chunk.
    remaining: usize,
    /// An error the worker reported instead of finishing the blob.
    error: Option<WorkerError>,
}

impl Read for BlobReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.remaining == 0 {
            if self.left == 0 {
                return Ok(0);
            }
            let (tag, len) = read_header(&mut *self.conn)?;
            match tag {
                CHUNK if len <= MAX_CHUNK && len as u64 <= self.left => {
                    self.remaining = len;
                    self.left -= len as u64;
                }
                ERROR => {
                    let e = read_error(&mut *self.conn, len);
                    let msg = format!("{e:#}");
                    self.error = Some(WorkerError(msg.clone()));
                    return Err(io::Error::other(msg));
                }
                CHUNK => {
                    return Err(io::Error::other(format!(
                        "worker sent a chunk of {len} bytes where at most {} were left",
                        self.left.min(MAX_CHUNK as u64)
                    )));
                }
                _ => {
                    return Err(io::Error::other(format!(
                        "unexpected message {tag} from worker"
                    )));
                }
            }
        }
        let n = buf.len().min(self.remaining);
        self.conn.read_exact(&mut buf[..n])?;
        self.remaining -= n;
        Ok(n)
    }
}

/// Entry point of a worker process; `args` are the arguments after
/// [`SUBCOMMAND`].
pub fn main(args: impl Iterator<Item = OsString>) -> ExitCode {
    // SAFETY: the supervisor always passes fd 1; nothing else uses it.
    let mut out = BufWriter::with_capacity(BUF_SIZE, unsafe { File::from_raw_fd(1) });
    // The last message goes through the same buffer as any earlier ones, so
    // it can't overtake them.
    let (tag, payload, code) = match run(args, &mut out) {
        Ok(json) => (DONE, json, ExitCode::SUCCESS),
        Err(e) => (ERROR, format!("{e:#}").into_bytes(), ExitCode::FAILURE),
    };
    if let Err(e) = write_frame(&mut out, tag, &payload).and_then(|()| out.flush()) {
        // Not eprintln!, which panics if the stderr pipe is full.
        let _ = writeln!(io::stderr(), "sending result: {e}");
        return ExitCode::FAILURE;
    }
    code
}

fn run(args: impl Iterator<Item = OsString>, out: &mut BufWriter<File>) -> Result<Vec<u8>> {
    let mut args = args.map(|a| {
        a.into_string()
            .map_err(|a| anyhow::anyhow!("bad argument {a:?}"))
    });
    let kind = args.next().context("missing worker kind")??;
    let mut layers = Layers::default();
    // Directories: absolute paths, or inherited fd numbers.
    let mut dirs: Vec<Result<String, RawFd>> = Vec::new();
    let mut extra = Vec::new();
    while let Some(arg) = args.next() {
        match arg?.as_str() {
            "--" => {
                extra = args.collect::<Result<_>>()?;
                break;
            }
            "--no-landlock" => layers.landlock = insecure_option()?,
            "--no-seccomp" => layers.seccomp = insecure_option()?,
            path if path.starts_with('/') => dirs.push(Ok(path.to_owned())),
            fd => {
                let fd: RawFd = fd.parse().with_context(|| format!("bad fd {fd:?}"))?;
                anyhow::ensure!(fd > 2, "bad fd {fd}");
                dirs.push(Err(fd));
            }
        }
    }
    let inherited: Vec<RawFd> = dirs.iter().filter_map(|d| d.clone().err()).collect();
    // Landlock and seccomp don't restrict fds that are already open, so a
    // stray inherited one could bypass the sandbox.
    fds::close_other(&inherited)?;
    let dirs = dirs
        .into_iter()
        .map(|dir| match dir {
            Ok(path) => {
                use rustix::fs::{Mode, OFlags};
                let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                rustix::fs::open(&path, flags, Mode::empty())
                    .with_context(|| format!("opening {path}"))
            }
            // SAFETY: these fds were inherited from the supervisor for this
            // worker, and closing the others above makes them the only owners.
            Err(fd) => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
        })
        .collect::<Result<Vec<OwnedFd>>>()?;
    let kind = KINDS
        .iter()
        .find(|k| k.name == kind)
        .with_context(|| format!("unknown worker {kind:?}"))?;
    ensure!(
        dirs.len() == kind.dirs.len(),
        "{} worker needs {} directories",
        kind.name,
        kind.dirs.len()
    );
    (kind.main)(Args {
        layers,
        dirs,
        extra,
        out,
    })
}

/// Value of a layer that an option turns off, if this build allows it.
fn insecure_option() -> Result<bool> {
    if cfg!(feature = "insecure") {
        Ok(false)
    } else {
        bail!("this build of skl can't turn off sandboxing (needs the `insecure` feature)")
    }
}

/// Worker side of streaming blobs: sends contents to the supervisor
/// (`BEGIN` with the size, then `CHUNK`s with exactly that many bytes), which
/// stores and hashes them as they arrive ([`receive_blobs`]). Results
/// refer to blobs by their position in the stream ([`BlobId`]), and the
/// supervisor fills in the hashes, so a compromised worker can't put content
/// under the wrong hash.
pub(crate) struct RemoteSink<'a> {
    conn: &'a mut BufWriter<File>,
    buf: Vec<u8>,
    /// Id of the next blob.
    next: u64,
}

impl<'a> RemoteSink<'a> {
    pub(crate) fn new(conn: &'a mut BufWriter<File>) -> Self {
        RemoteSink {
            conn,
            buf: vec![0; CHUNK_SIZE],
            next: 0,
        }
    }
}

impl BlobSink for RemoteSink<'_> {
    fn add_blob(&mut self, size: u64, content: &mut dyn Read) -> Result<BlobId> {
        write_frame(self.conn, BEGIN, &size.to_le_bytes())?;
        let mut left = size;
        loop {
            let n = match content.read(&mut self.buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            left = left
                .checked_sub(n as u64)
                .context("content is longer than its size")?;
            write_frame(self.conn, CHUNK, &self.buf[..n])?;
        }
        anyhow::ensure!(left == 0, "content is shorter than its size");
        let id = BlobId { blob: self.next };
        self.next += 1;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_escapes_control_characters() {
        assert_eq!(
            sanitize("a\tb\n\x1b[2Jc\rd\u{9b}e é", true),
            "a\tb\n\\u{1b}[2Jc\\rd\\u{9b}e é"
        );
        assert_eq!(sanitize("a\tb\nc", false), "a\\tb\\nc");
    }
}
