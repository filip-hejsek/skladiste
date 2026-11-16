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
//! - `import-arch`: fd 0 is the package archive, fd 1 a socket. The worker
//!   parses the archive with [`arch::import`] and streams each file's content
//!   (`BEGIN` with the size, then `CHUNK`s with exactly that many bytes). Data
//!   flows only from the worker: it never waits for the supervisor, which
//!   stores and hashes the objects as they arrive. The manifest in `DONE`
//!   refers to objects by their position in the stream ([`ObjectId`]), and
//!   the supervisor fills in the hashes, so a compromised parser can't put
//!   content under the wrong hash. No filesystem access, no ioctls.
//! - `download`: fd 0 is a TCP connection the supervisor opened to the
//!   URL's host (passed as an argument), fd 1 a socket. With a second
//!   argument `custom-roots`, the supervisor first sends the root
//!   certificates on fd 1 (a `CERT` frame each, in DER, then an empty
//!   `DONE`); otherwise the worker uses the built-in ones. The worker sends
//!   the request (over TLS for `https`) and streams the response body in
//!   `CHUNK`s, ending with `DONE` with the response's headers of interest
//!   ([`http::Response`]). It can't reach any other host, and the
//!   supervisor writes the file. No filesystem access, no ioctls.
//! - `read-arch-db`: fd 0 is an Arch repo database, fd 1 a pipe. The
//!   worker reads it with [`arch::repo::read_db`] and sends the entries in
//!   `DONE`; the supervisor validates them. No filesystem access, no
//!   ioctls.
//! - `install`: fd 0 is the plan (JSON entries), fd 1 a pipe for the result,
//!   and the store directory and image root are bound at `/store`
//!   (read-only) and `/image` in the worker's mount namespace. The worker
//!   installs the files with read access to the store and write access to
//!   the image.
//!
//! Directories are passed as paths inside the worker's mount namespace, or
//! as inherited fd numbers when it runs without namespaces. Other arguments
//! of a worker come last, after `--`.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, ExitStatus};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use landlock::AccessFs;

use crate::arch;
use crate::bwrap::{self, Mount, Namespaces};
use crate::http::{self, RootCerts, Url};
use crate::install::{self, Report};
use crate::manifest::{Content, Entry, ObjectId, Package};
use crate::sandbox::{self, Layers, Policy};
use crate::store::{ObjectSink, Store};

/// First argument that makes `skl` run as a worker. `main` must check for
/// it before doing anything else.
pub const SUBCOMMAND: &str = "__worker";

const BEGIN: u8 = 1;
const CHUNK: u8 = 2;
const DONE: u8 = 3;
const ERROR: u8 = 4;
const CERT: u8 = 5;

/// Chunk size the worker sends; the supervisor accepts up to [`MAX_CHUNK`].
const CHUNK_SIZE: usize = 64 << 10;
const MAX_CHUNK: usize = 1 << 20;
const MAX_DONE: usize = 256 << 20;
const MAX_ERROR: usize = 64 << 10;
/// Largest root certificate the download worker accepts.
const MAX_CERT: usize = 64 << 10;
/// Buffer size for writing and reading messages. Chunks at least this
/// large bypass the buffer.
const BUF_SIZE: usize = CHUNK_SIZE;

/// Address space limit of the import worker. Real packages need tens of
/// MiB; zstd's default limit on the decoding window is 128 MiB, and very
/// large packages have manifests of tens of MiB.
const IMPORT_MAX_MEMORY: u64 = 1 << 30;
/// Address space limit of the install worker, which holds the whole plan
/// (about 40 MiB were enough for an image of 17,000 entries).
const INSTALL_MAX_MEMORY: u64 = 4 << 30;
/// Address space limit of the download worker (TLS and a few buffers).
const DOWNLOAD_MAX_MEMORY: u64 = 256 << 20;

/// Timeout for connecting, and for each read and write once connected.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Capabilities the install worker keeps when skl runs as root: to set
/// owners, then modes (including setuid and setgid bits), times and xattrs
/// (including `security.capability`) of entries it no longer owns, and to
/// create entries in directories whose permissions don't allow it.
const INSTALL_CAPS: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_SETFCAP",
];

/// Longest `Last-Modified` value kept from a download worker.
const MAX_LAST_MODIFIED: usize = 100;
/// Longest `ETag` value kept from a download worker.
const MAX_ETAG: usize = 256;

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
}

/// Statistics about an import, counted by the supervisor.
#[derive(Debug, Default)]
pub struct ImportStats {
    pub files: u64,
    pub new_objects: u64,
    pub new_bytes: u64,
}

/// Starts worker processes.
pub struct Workers {
    exe: PathBuf,
    layers: Layers,
    roots: RootCerts,
}

impl Workers {
    /// `exe` is the `skl` binary to run workers with; the `skl` command uses
    /// `/proc/self/exe`. All sandboxing layers are on.
    pub fn new(exe: impl Into<PathBuf>) -> Self {
        Workers {
            exe: exe.into(),
            layers: Layers::default(),
            roots: RootCerts::default(),
        }
    }

    /// Check TLS server certificates of downloads against `roots` (the
    /// built-in ones by default).
    pub fn set_root_certs(&mut self, roots: RootCerts) {
        self.roots = roots;
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

    /// Parse an Arch package archive in a worker, adding its file contents
    /// to `store`. The returned manifest is checked but not saved.
    pub fn import_arch(&self, store: &Store, archive: File) -> Result<(Package, ImportStats)> {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .context("creating socket")?;
        let worker = self.spawn("import-arch", archive.into(), theirs, &[], None, &[])?;
        let mut conn = receiver(ours)?;
        let result = receive_import(store, &mut conn);
        drop(conn);
        worker.finish(result)
    }

    /// Read an Arch repo database in a worker, and validate the entries.
    pub fn read_arch_db(&self, db: File) -> Result<Vec<arch::repo::DbEntry>> {
        use rustix::pipe::{PipeFlags, pipe_with};
        let (result_r, result_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
        let worker = self.spawn("read-arch-db", db.into(), result_w, &[], None, &[])?;
        let result = read_result(&mut BufReader::new(File::from(result_r))).and_then(|json| {
            let entries: Vec<arch::repo::DbEntry> =
                serde_json::from_slice(&json).context("parsing result from worker")?;
            arch::repo::validate(&entries)?;
            Ok(entries)
        });
        worker.finish(result)
    }

    /// Download `url` in a worker and write the body to `dest`, failing
    /// if it is longer than `max_size`. The connection is opened here and
    /// handed to the worker, which has no network access of its own.
    /// Redirects are not followed.
    pub fn download(&self, url: &Url, dest: &mut dyn Write, max_size: u64) -> Result<Downloaded> {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
        let conn = http::connect(url, DOWNLOAD_TIMEOUT)?;
        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .context("creating socket")?;
        let custom = self.roots.custom().filter(|_| url.tls);
        let url = url.to_string();
        let mut args = vec![&*url];
        if custom.is_some() {
            args.push("custom-roots");
        }
        let worker = self.spawn("download", conn.into(), theirs, &[], None, &args)?;
        let ours = File::from(ours);
        // The worker reads all certificates before it writes anything but
        // an error, which then explains a failure to send them.
        let sent = custom.map_or(Ok(()), |certs| send_certs(&ours, certs));
        let mut conn = receiver(ours.into())?;
        let result = receive_download(&mut conn, dest, max_size).and_then(|size| {
            sent?;
            Ok(size)
        });
        drop(conn);
        worker.finish(result)
    }

    /// Run [`install::populate`] in a worker that can read only the store
    /// and write only beneath `root`. The store is bound read-only, so the
    /// worker can't change metadata of its files either (Landlock doesn't
    /// restrict that).
    pub(crate) fn install(&self, store: &Store, plan: &[&Entry], root: &OwnedFd) -> Result<Report> {
        use rustix::pipe::{PipeFlags, pipe_with};
        let (plan_r, plan_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
        let (result_r, result_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
        let dirs = [
            Mount {
                fd: store.dir(),
                dest: "/store",
                writable: false,
            },
            Mount {
                fd: root.as_fd(),
                dest: "/image",
                writable: true,
            },
        ];
        let worker = self.spawn("install", plan_r, result_w, &dirs, Some(INSTALL_CAPS), &[])?;
        // The worker reads the whole plan before it writes a result, unless
        // it fails; then its error message explains the broken pipe.
        let sent = send_json(plan_w, plan);
        let result = read_result(&mut File::from(result_r)).and_then(|json| {
            sent?;
            Ok(serde_json::from_slice(&json)?)
        });
        worker.finish(result)
    }

    /// Start worker `kind` with `stdin` and `stdout` as fds 0 and 1, and
    /// `dirs` bound in its mount namespace, their paths passed as arguments.
    /// Without namespaces, the fds of `dirs` are inherited under their
    /// current numbers instead, and the numbers passed. `root_caps`: see
    /// [`Namespaces::root_caps`]. `args` are passed last, after `--`.
    /// Stderr is a pipe; see [`Worker::finish`].
    fn spawn(
        &self,
        kind: &'static str,
        stdin: OwnedFd,
        stdout: OwnedFd,
        dirs: &[Mount],
        root_caps: Option<&[&str]>,
        args: &[&str],
    ) -> Result<Worker> {
        let exe_fd: OwnedFd;
        let (mut cmd, raw) = if self.layers.namespaces {
            let bwrap = bwrap::find()?;
            use rustix::fs::{Mode, OFlags};
            exe_fd = rustix::fs::open(&self.exe, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
                .with_context(|| format!("opening {}", self.exe.display()))?;
            let ns = Namespaces {
                mounts: dirs,
                root_caps,
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
        // SAFETY: fcntl is async-signal-safe, and only the child's fd table
        // is changed.
        unsafe {
            cmd.pre_exec(move || {
                for &fd in &raw {
                    rustix::io::fcntl_setfd(
                        BorrowedFd::borrow_raw(fd),
                        rustix::io::FdFlags::empty(),
                    )?;
                }
                Ok(())
            });
        }
        let child = cmd
            .spawn()
            .with_context(|| format!("starting {kind} worker ({})", self.exe.display()))?;
        Ok(Worker {
            kind,
            child: Some(child),
            stderr: File::from(stderr_r),
        })
    }
}

/// A running worker; killed if dropped before [`Worker::finish`].
struct Worker {
    kind: &'static str,
    child: Option<Child>,
    stderr: File,
}

impl Worker {
    /// Wait for the worker to exit and combine its exit status with the
    /// result received from it. An error the worker reported explains a
    /// failure best; otherwise an abnormal exit explains a broken connection.
    ///
    /// Then prints what the worker wrote to stderr (e.g. a panic message):
    /// control characters escaped and each line prefixed with the worker's
    /// name, so it can't pass for the supervisor's output or control the
    /// terminal. Only what fit in the pipe is kept.
    fn finish<T>(mut self, result: Result<T>) -> Result<T> {
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

impl Drop for Worker {
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
fn sanitize(s: &str, lines: bool) -> String {
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
struct WorkerError(String);

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WorkerError {}

fn write_frame(w: &mut impl Write, tag: u8, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(io::Error::other)?;
    let mut header = [tag, 0, 0, 0, 0];
    header[1..].copy_from_slice(&len.to_le_bytes());
    w.write_all(&header)?;
    w.write_all(payload)
}

fn read_header(mut r: impl Read) -> io::Result<(u8, usize)> {
    let mut h = [0u8; 5];
    r.read_exact(&mut h)?;
    let len = u32::from_le_bytes([h[1], h[2], h[3], h[4]]);
    Ok((h[0], len as usize))
}

fn read_payload(mut r: impl Read, len: usize, max: usize) -> Result<Vec<u8>> {
    if len > max {
        bail!("worker sent a message of {len} bytes (limit {max})");
    }
    let mut payload = vec![0; len];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

/// Read an error message, escaping control characters: it may contain
/// text from untrusted input, such as a server's reason phrase.
fn read_error(r: impl Read, len: usize) -> anyhow::Error {
    match read_payload(r, len, MAX_ERROR) {
        Ok(msg) => WorkerError(sanitize(&String::from_utf8_lossy(&msg), false)).into(),
        Err(e) => e.context("reading error message from worker"),
    }
}

/// Read a worker's final `DONE` or `ERROR` frame.
fn read_result(mut r: impl Read) -> Result<Vec<u8>> {
    let (tag, len) = read_header(&mut r).context("reading result from worker")?;
    match tag {
        DONE => read_payload(r, len, MAX_DONE),
        ERROR => Err(read_error(r, len)),
        _ => bail!("unexpected message {tag} from worker"),
    }
}

fn send_json(fd: OwnedFd, value: &(impl serde::Serialize + ?Sized)) -> Result<()> {
    let mut w = BufWriter::new(File::from(fd));
    serde_json::to_writer(&mut w, value)?;
    w.flush().context("sending to worker")
}

/// Send root certificates to a download worker.
fn send_certs(conn: &File, certs: &[rustls::pki_types::CertificateDer]) -> Result<()> {
    let mut w = BufWriter::new(conn);
    for cert in certs {
        anyhow::ensure!(
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
fn receive_certs(conn: &File) -> Result<RootCerts> {
    let mut r = BufReader::new(conn);
    let mut certs = Vec::new();
    loop {
        match read_header(&mut r).context("reading root certificates")? {
            (CERT, len) => certs.push(read_payload(&mut r, len, MAX_CERT)?.into()),
            (DONE, 0) => return RootCerts::from_der(certs),
            (tag, len) => bail!("unexpected message {tag} ({len} bytes) from supervisor"),
        }
    }
}

/// The supervisor's end of a socket that only the worker writes to (any
/// input for the worker was sent before).
fn receiver(ours: OwnedFd) -> Result<BufReader<File>> {
    // Nothing more is sent to the worker.
    rustix::net::shutdown(&ours, rustix::net::Shutdown::Write).context("shutting down socket")?;
    Ok(BufReader::with_capacity(BUF_SIZE, File::from(ours)))
}

/// Supervisor side of `download`.
fn receive_download(
    conn: &mut BufReader<File>,
    dest: &mut dyn Write,
    max_size: u64,
) -> Result<Downloaded> {
    let mut total: u64 = 0;
    let mut buf = Vec::new();
    loop {
        let (tag, len) = read_header(&mut *conn).context("reading from worker")?;
        match tag {
            CHUNK if len <= MAX_CHUNK => {
                total += len as u64;
                if total > max_size {
                    bail!("file is larger than {max_size} bytes");
                }
                buf.resize(len, 0);
                conn.read_exact(&mut buf).context("reading from worker")?;
                dest.write_all(&buf).context("writing download")?;
            }
            DONE => {
                let json = read_payload(&mut *conn, len, MAX_ERROR)?;
                let response: http::Response =
                    serde_json::from_slice(&json).context("parsing result from worker")?;
                let keep = |value: Option<String>, max| {
                    value
                        .filter(|v| v.len() <= max)
                        .map(|v| sanitize(&v, false))
                };
                return Ok(Downloaded {
                    size: total,
                    last_modified: keep(response.last_modified, MAX_LAST_MODIFIED),
                    etag: keep(response.etag, MAX_ETAG),
                });
            }
            ERROR => return Err(read_error(conn, len)),
            _ => bail!("unexpected message {tag} ({len} bytes) from worker"),
        }
    }
}

/// Supervisor side of `import-arch`.
fn receive_import(store: &Store, conn: &mut BufReader<File>) -> Result<(Package, ImportStats)> {
    let mut stats = ImportStats::default();
    // Content of each object, in the order received.
    let mut objects: Vec<Content> = Vec::new();
    loop {
        let (tag, len) = read_header(&mut *conn).context("reading from worker")?;
        match tag {
            BEGIN if len == 8 => {
                let mut size = [0u8; 8];
                conn.read_exact(&mut size).context("reading from worker")?;
                let mut reader = ObjectReader {
                    conn: &mut *conn,
                    left: u64::from_le_bytes(size),
                    remaining: 0,
                    error: None,
                };
                let added = store.add_object(&mut reader);
                if let Some(e) = reader.error {
                    return Err(e.into());
                }
                let added = added?;
                stats.files += 1;
                if added.new {
                    stats.new_objects += 1;
                    stats.new_bytes += added.size;
                }
                objects.push(Content {
                    hash: added.hash,
                    size: added.size,
                });
            }
            DONE => {
                let json = read_payload(&mut *conn, len, MAX_DONE)?;
                let pkg: Package<ObjectId> =
                    serde_json::from_slice(&json).context("parsing manifest from worker")?;
                let pkg = pkg.resolve(&objects)?;
                pkg.validate()?;
                return Ok((pkg, stats));
            }
            ERROR => return Err(read_error(conn, len)),
            _ => bail!("unexpected message {tag} from worker"),
        }
    }
}

/// Reads one object's content from `CHUNK` frames, up to its size.
struct ObjectReader<'a> {
    conn: &'a mut BufReader<File>,
    /// Bytes of the object not yet read.
    left: u64,
    /// Bytes left in the current chunk.
    remaining: usize,
    /// An error the worker reported instead of finishing the object.
    error: Option<WorkerError>,
}

impl Read for ObjectReader<'_> {
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
    close_other_fds(&inherited)?;
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
    match (kind.as_str(), &extra[..]) {
        ("import-arch", []) if dirs.is_empty() => import_worker(layers, out),
        ("download", [url]) if dirs.is_empty() => download_worker(layers, url, false, out),
        ("download", [url, roots]) if dirs.is_empty() && roots == "custom-roots" => {
            download_worker(layers, url, true, out)
        }
        ("read-arch-db", []) if dirs.is_empty() => read_db_worker(layers),
        ("install", []) => {
            let [store, root] = <[OwnedFd; 2]>::try_from(dirs)
                .map_err(|_| anyhow::anyhow!("install worker needs two directories"))?;
            install_worker(layers, store, root)
        }
        (kind, _) => bail!("unknown worker {kind:?} or wrong arguments or directories"),
    }
}

/// Value of a layer that an option turns off, if this build allows it.
fn insecure_option() -> Result<bool> {
    if cfg!(feature = "insecure") {
        Ok(false)
    } else {
        bail!("this build of skl can't turn off sandboxing (needs the `insecure` feature)")
    }
}

/// Close every fd except stdio and `keep`. Landlock and seccomp don't
/// restrict fds that are already open, so a stray inherited one could
/// bypass the sandbox.
fn close_other_fds(keep: &[RawFd]) -> Result<()> {
    let close = |first: u32, last: u32| {
        // SAFETY: no Rust object owns these fds yet.
        let r = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) };
        if r != 0 {
            return Err(io::Error::last_os_error()).context("closing inherited fds");
        }
        Ok(())
    };
    let mut keep: Vec<u32> = keep.iter().map(|&fd| fd as u32).collect();
    keep.sort_unstable();
    let mut first = 3;
    for fd in keep {
        if fd > first {
            close(first, fd - 1)?;
        }
        first = fd + 1;
    }
    close(first, u32::MAX)
}

fn import_worker(layers: Layers, out: &mut BufWriter<File>) -> Result<Vec<u8>> {
    // SAFETY: the supervisor passes the archive as fd 0.
    let archive = unsafe { File::from_raw_fd(0) };
    let policy = Policy {
        max_memory: Some(IMPORT_MAX_MEMORY),
        ..Policy::default()
    };
    sandbox::confine(layers, &policy)?;
    let sink = RemoteSink {
        conn: out,
        buf: vec![0; CHUNK_SIZE],
        next: 0,
    };
    let pkg = arch::import(archive, sink)?;
    Ok(serde_json::to_vec(&pkg)?)
}

fn read_db_worker(layers: Layers) -> Result<Vec<u8>> {
    // SAFETY: the supervisor passes the database as fd 0.
    let db = unsafe { File::from_raw_fd(0) };
    let policy = Policy {
        max_memory: Some(IMPORT_MAX_MEMORY),
        ..Policy::default()
    };
    sandbox::confine(layers, &policy)?;
    Ok(serde_json::to_vec(&arch::repo::read_db(db)?)?)
}

/// Worker side of `import-arch`: sends contents to the supervisor.
struct RemoteSink<'a> {
    conn: &'a mut BufWriter<File>,
    buf: Vec<u8>,
    /// Id of the next object.
    next: u64,
}

impl ObjectSink for RemoteSink<'_> {
    fn add_object(&mut self, size: u64, content: &mut dyn Read) -> Result<ObjectId> {
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
        let id = ObjectId { object: self.next };
        self.next += 1;
        Ok(id)
    }
}

/// `custom_roots`: read the root certificates from fd 1 first.
fn download_worker(
    layers: Layers,
    url: &str,
    custom_roots: bool,
    out: &mut BufWriter<File>,
) -> Result<Vec<u8>> {
    let url = Url::parse(url)?;
    // SAFETY: the supervisor passes the connection as fd 0.
    let conn = unsafe { File::from_raw_fd(0) };
    let policy = Policy {
        max_memory: Some(DOWNLOAD_MAX_MEMORY),
        ..Policy::default()
    };
    sandbox::confine(layers, &policy)?;
    let roots = if custom_roots {
        receive_certs(out.get_ref())?
    } else {
        RootCerts::default()
    };
    let response = http::get(conn, &url, &roots, &mut |data| {
        write_frame(out, CHUNK, data)
    })?;
    Ok(serde_json::to_vec(&response)?)
}

/// System calls the installer makes besides [`sandbox`]'s basic set.
const INSTALL_SYSCALLS: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_mkdirat,
    libc::SYS_symlinkat,
    libc::SYS_linkat,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_fchmod,
    libc::SYS_fsetxattr,
    libc::SYS_utimensat,
];

fn install_worker(layers: Layers, store: OwnedFd, root: OwnedFd) -> Result<Vec<u8>> {
    let store = Store::from_dir(store);
    let image = AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSym
        | AccessFs::Refer;
    let policy = Policy {
        paths: vec![
            (store.dir(), AccessFs::ReadFile.into()),
            (root.as_fd(), image),
        ],
        syscalls: INSTALL_SYSCALLS,
        // Landlock doesn't restrict ioctls on regular files, and btrfs has
        // ioctls such as subvolume creation that work on any fd.
        ioctls: &[libc::FICLONE],
        max_memory: Some(INSTALL_MAX_MEMORY),
    };
    sandbox::confine(layers, &policy)?;
    // SAFETY: the supervisor passes the plan as fd 0.
    let plan = BufReader::new(unsafe { File::from_raw_fd(0) });
    let entries: Vec<Entry> = serde_json::from_reader(plan).context("reading plan")?;
    let report = install::populate(&store, entries.iter().collect(), root)?;
    Ok(serde_json::to_vec(&report)?)
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
