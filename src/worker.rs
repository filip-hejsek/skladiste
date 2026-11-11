//! Worker processes: parts of skl that run apart from the supervisor (the
//! `skl` process), each confined to the access it needs.
//!
//! The supervisor starts a worker by executing the `skl` binary with the
//! hidden [`SUBCOMMAND`], handing it only the fds it needs. A fresh exec is
//! single-threaded and inherits no memory. The worker closes any other
//! inherited fds and confines itself (Landlock and seccomp) before reading
//! its input. Both ends are the same binary, so the protocol needs no
//! stability.
//!
//! Messages are frames: a tag byte, a little-endian `u32` length and the
//! payload. A worker ends by writing one `DONE` frame (its JSON result) or
//! one `ERROR` frame (a message) to fd 1.
//!
//! - `import-arch`: fd 0 is the package archive, fd 1 a socket. The worker
//!   parses the archive with [`arch::import`] and streams each file's content
//!   (`BEGIN`, `CHUNK`…, `END`). The supervisor stores and hashes it and
//!   replies with the hash, so a compromised parser can't put content under
//!   the wrong hash. No filesystem access, no ioctls.
//! - `install`: fd 0 is the plan (JSON entries), fd 1 a pipe for the result,
//!   and the store directory and image root are passed as two more fds. The
//!   worker installs the files with read access to the store and
//!   write access to the image.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, ExitStatus};

use anyhow::{Context, Result, bail};
use landlock::AccessFs;

use crate::arch;
use crate::install::{self, Report};
use crate::manifest::{Entry, EntryKind, Hash, Package};
use crate::sandbox::{self, Layers, Policy};
use crate::store::{Added, ObjectSink, Store};

/// First argument that makes `skl` run as a worker. `main` must check for
/// it before doing anything else.
pub const SUBCOMMAND: &str = "__worker";

const BEGIN: u8 = 1;
const CHUNK: u8 = 2;
const END: u8 = 3;
const DONE: u8 = 4;
const ERROR: u8 = 5;

/// Chunk size the worker sends; the supervisor accepts up to [`MAX_CHUNK`].
const CHUNK_SIZE: usize = 64 << 10;
const MAX_CHUNK: usize = 1 << 20;
const MAX_DONE: usize = 256 << 20;
const MAX_ERROR: usize = 64 << 10;
/// Reply to an object: hash, size (`u64` LE), and whether it was new.
const REPLY_LEN: usize = 32 + 8 + 1;

/// Address space limit of the import worker. Real packages need tens of
/// MiB; zstd's default limit on the decoding window is 128 MiB, and very
/// large packages have manifests of tens of MiB.
const IMPORT_MAX_MEMORY: u64 = 1 << 30;
/// Address space limit of the install worker, which holds the whole plan
/// (about 40 MiB were enough for an image of 17,000 entries).
const INSTALL_MAX_MEMORY: u64 = 4 << 30;

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
}

impl Workers {
    /// `exe` is the `skl` binary to run workers with; the `skl` command uses
    /// `/proc/self/exe`. All sandboxing layers are on.
    pub fn new(exe: impl Into<PathBuf>) -> Self {
        Workers {
            exe: exe.into(),
            layers: Layers::default(),
        }
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
        let worker = self.spawn("import-arch", archive.into(), theirs, &[])?;
        let mut conn = File::from(ours);
        let result = receive_import(store, &mut conn);
        drop(conn);
        worker.finish(result)
    }

    /// Run [`install::populate`] in a worker that can read only the store
    /// and write only beneath `root`.
    pub(crate) fn install(&self, store: &Store, plan: &[&Entry], root: &OwnedFd) -> Result<Report> {
        use rustix::pipe::{PipeFlags, pipe_with};
        let (plan_r, plan_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
        let (result_r, result_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
        let worker = self.spawn("install", plan_r, result_w, &[store.dir(), root.as_fd()])?;
        // The worker reads the whole plan before it writes a result, unless
        // it fails; then its error message explains the broken pipe.
        let sent = send_json(plan_w, plan);
        let result = read_result(&mut File::from(result_r)).and_then(|json| {
            sent?;
            Ok(serde_json::from_slice(&json)?)
        });
        worker.finish(result)
    }

    /// Start worker `kind` with `stdin` and `stdout` as fds 0 and 1. `extra`
    /// fds are inherited under their current numbers, which are passed as
    /// arguments. Stderr is a pipe; see [`Worker::finish`].
    fn spawn(
        &self,
        kind: &'static str,
        stdin: OwnedFd,
        stdout: OwnedFd,
        extra: &[BorrowedFd],
    ) -> Result<Worker> {
        let mut cmd = Command::new(&self.exe);
        cmd.arg(SUBCOMMAND).arg(kind);
        let raw: Vec<RawFd> = extra.iter().map(|fd| fd.as_raw_fd()).collect();
        for fd in &raw {
            cmd.arg(fd.to_string());
        }
        if !self.layers.landlock {
            cmd.arg("--no-landlock");
        }
        if !self.layers.seccomp {
            cmd.arg("--no-seccomp");
        }
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
    for line in sanitize(&String::from_utf8_lossy(output)).lines() {
        let _ = writeln!(stderr, "{kind} worker: {line}");
    }
}

/// Escape control characters other than newline and tab.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() && c != '\n' && c != '\t' {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

fn describe(status: ExitStatus) -> String {
    match status.signal() {
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

fn write_frame(mut w: impl Write, tag: u8, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(io::Error::other)?;
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(tag);
    frame.extend(len.to_le_bytes());
    frame.extend(payload);
    w.write_all(&frame)
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

fn read_error(r: impl Read, len: usize) -> anyhow::Error {
    match read_payload(r, len, MAX_ERROR) {
        Ok(msg) => WorkerError(String::from_utf8_lossy(&msg).into_owned()).into(),
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

/// Supervisor side of `import-arch`.
fn receive_import(store: &Store, conn: &mut File) -> Result<(Package, ImportStats)> {
    let mut stats = ImportStats::default();
    // Objects added during this import, with their sizes.
    let mut objects: HashMap<Hash, u64> = HashMap::new();
    loop {
        let (tag, len) = read_header(&mut *conn).context("reading from worker")?;
        match tag {
            BEGIN if len == 0 => {
                let mut reader = ObjectReader {
                    conn: &mut *conn,
                    remaining: 0,
                    done: false,
                    error: None,
                };
                let added = store.add_object(&mut reader);
                if let Some(e) = reader.error {
                    return Err(e.into());
                }
                let added = added?;
                anyhow::ensure!(reader.done, "worker sent no end of object");
                stats.files += 1;
                if added.new {
                    stats.new_objects += 1;
                    stats.new_bytes += added.size;
                }
                objects.insert(added.hash, added.size);
                let mut reply = [0u8; REPLY_LEN];
                reply[..32].copy_from_slice(&added.hash.0);
                reply[32..40].copy_from_slice(&added.size.to_le_bytes());
                reply[40] = added.new.into();
                conn.write_all(&reply).context("replying to worker")?;
            }
            DONE => {
                let json = read_payload(&mut *conn, len, MAX_DONE)?;
                let pkg: Package =
                    serde_json::from_slice(&json).context("parsing manifest from worker")?;
                check_manifest(&pkg, &objects)?;
                return Ok((pkg, stats));
            }
            ERROR => return Err(read_error(conn, len)),
            _ => bail!("unexpected message {tag} from worker"),
        }
    }
}

/// Check a manifest from a worker: its invariants, and that every file
/// refers to an object stored during this import, with the right size.
fn check_manifest(pkg: &Package, objects: &HashMap<Hash, u64>) -> Result<()> {
    pkg.validate()?;
    for entry in &pkg.entries {
        if let EntryKind::File { hash, size } = &entry.kind {
            anyhow::ensure!(
                objects.get(hash) == Some(size),
                "/{}: content {hash} of size {size} was not received from the worker",
                entry.path
            );
        }
    }
    Ok(())
}

/// Reads one object's content from `CHUNK` frames until `END`.
struct ObjectReader<'a> {
    conn: &'a mut File,
    /// Bytes left in the current chunk.
    remaining: usize,
    done: bool,
    /// An error the worker reported instead of finishing the object.
    error: Option<WorkerError>,
}

impl Read for ObjectReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.remaining == 0 {
            if self.done {
                return Ok(0);
            }
            let (tag, len) = read_header(&mut *self.conn)?;
            match tag {
                CHUNK if len <= MAX_CHUNK => self.remaining = len,
                END if len == 0 => self.done = true,
                ERROR => {
                    let e = read_error(&mut *self.conn, len);
                    let msg = format!("{e:#}");
                    self.error = Some(WorkerError(msg.clone()));
                    return Err(io::Error::other(msg));
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
    let out = unsafe { File::from_raw_fd(1) };
    let (tag, payload, code) = match run(args, &out) {
        Ok(json) => (DONE, json, ExitCode::SUCCESS),
        Err(e) => (ERROR, format!("{e:#}").into_bytes(), ExitCode::FAILURE),
    };
    if let Err(e) = write_frame(&out, tag, &payload) {
        // Not eprintln!, which panics if the stderr pipe is full.
        let _ = writeln!(io::stderr(), "sending result: {e}");
        return ExitCode::FAILURE;
    }
    code
}

fn run(args: impl Iterator<Item = OsString>, out: &File) -> Result<Vec<u8>> {
    let mut args = args.map(|a| {
        a.into_string()
            .map_err(|a| anyhow::anyhow!("bad argument {a:?}"))
    });
    let kind = args.next().context("missing worker kind")??;
    let mut layers = Layers::default();
    let mut fds = Vec::new();
    for arg in args {
        match arg?.as_str() {
            "--no-landlock" => layers.landlock = insecure_option()?,
            "--no-seccomp" => layers.seccomp = insecure_option()?,
            fd => {
                let fd: RawFd = fd.parse().with_context(|| format!("bad fd {fd:?}"))?;
                anyhow::ensure!(fd > 2, "bad fd {fd}");
                fds.push(fd);
            }
        }
    }
    close_other_fds(&fds)?;
    // SAFETY: these fds were inherited from the supervisor for this worker,
    // and closing the others above makes them the only owners.
    let fds: Vec<OwnedFd> = fds
        .into_iter()
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .collect();
    match kind.as_str() {
        "import-arch" if fds.is_empty() => import_worker(layers, out),
        "install" => {
            let [store, root] = <[OwnedFd; 2]>::try_from(fds)
                .map_err(|_| anyhow::anyhow!("install worker needs two fds"))?;
            install_worker(layers, store, root)
        }
        kind => bail!("unknown worker {kind:?} or wrong number of fds"),
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

fn import_worker(layers: Layers, out: &File) -> Result<Vec<u8>> {
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
    };
    let pkg = arch::import(archive, sink)?;
    Ok(serde_json::to_vec(&pkg)?)
}

/// Worker side of `import-arch`: sends contents to the supervisor.
struct RemoteSink<'a> {
    conn: &'a File,
    buf: Vec<u8>,
}

impl ObjectSink for RemoteSink<'_> {
    fn add_object(&mut self, content: &mut dyn Read) -> Result<Added> {
        write_frame(self.conn, BEGIN, &[])?;
        loop {
            let n = match content.read(&mut self.buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            write_frame(self.conn, CHUNK, &self.buf[..n])?;
        }
        write_frame(self.conn, END, &[])?;
        let mut reply = [0u8; REPLY_LEN];
        (&mut &*self.conn)
            .read_exact(&mut reply)
            .context("reading reply from supervisor")?;
        Ok(Added {
            hash: Hash(reply[..32].try_into().unwrap()),
            size: u64::from_le_bytes(reply[32..40].try_into().unwrap()),
            new: reply[40] != 0,
        })
    }
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
            sanitize("a\tb\n\x1b[2Jc\rd\u{9b}e é"),
            "a\tb\n\\u{1b}[2Jc\\rd\\u{9b}e é"
        );
    }
}
