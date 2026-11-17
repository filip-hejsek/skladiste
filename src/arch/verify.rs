//! The signature verification worker, and the pool of them that checks
//! package signatures for the supervisor.
//!
//! A worker checks Arch package signatures with
//! [`Keyring`]: fd 0 is a `SOCK_SEQPACKET` socket for its
//! input, fd 1 a pipe for its results. Each input message is a tag byte and
//! a payload, with fds attached (`SCM_RIGHTS`):
//!
//! - `KEYRING`, the first message, has no payload and the three keyring
//!   files (certificates, master keys, revoked keys) attached. The worker
//!   loads them and answers `READY`, or fails with `ERROR`.
//! - Then any number of `ITEM`s: the detached signature as payload, and the
//!   archive attached. The worker answers each with `GOOD` or `BAD` (with
//!   the reason), in order, and exits after a final empty `DONE` when its
//!   input ends.
//!
//! The supervisor gives the worker its own read-only open file of each file
//! (see `reopen_read_only`), so the worker can't change an archive after
//! it was checked, and its reads don't move the supervisor's file offset.
//! No filesystem access, no ioctls.
//!
//! The verdict can't be checked: a compromised worker can accept anything.
//! What the worker protects is the host, from a parser exploit with
//! `skl`'s privileges. Each worker keeps the keyring loaded (about 30 ms)
//! and its certification checks cached, so it serves a whole run.

use std::fs::File;
use std::io::{self, BufReader, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::{Condvar, Mutex};

use anyhow::{Context, Result, bail, ensure};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use crate::arch::signature::{Keyring, MAX_SIGNATURE_SIZE};
use crate::sandbox::{self, Policy};
use crate::worker::{
    Args, DONE, ERROR, Kind, MAX_ERROR, NO_CAPS, Shared, Spawner, Worker, Workers, read_error,
    read_header, read_payload, read_result, sanitize, write_frame,
};

const KEYRING: u8 = 1;
const ITEM: u8 = 2;
const READY: u8 = 5;
const GOOD: u8 = 6;
const BAD: u8 = 7;

/// Address space limit of the worker: the keyring (the Arch keyring is
/// 1.8 MB) and a buffer.
const MAX_MEMORY: u64 = 256 << 20;

/// System calls the worker makes besides [`sandbox`]'s basic set.
const SYSCALLS: &[i64] = &[libc::SYS_recvmsg];

/// The worker; see the module documentation.
pub(crate) const VERIFY_WORKER: Kind = Kind {
    name: "verify-arch",
    dirs: &[],
    caps: NO_CAPS,
    main: worker,
};

/// The files of an Arch keyring, as in `/usr/share/pacman/keyrings/`.
pub struct KeyringFiles {
    /// OpenPGP certificates (`archlinux.gpg`).
    pub certs: File,
    /// Master key fingerprints (`archlinux-trusted`).
    pub trusted: File,
    /// Revoked key fingerprints (`archlinux-revoked`).
    pub revoked: File,
}

/// Checks package signatures in workers; see the module documentation and
/// [`with_verifier`]. Calls from several threads are served by up to the
/// given number of workers at once, each started when first needed and
/// kept until the verifier is dropped. `'a` is the scope of its workers,
/// which ends when [`with_verifier`] returns.
pub struct Verifier<'a> {
    keyring: KeyringFiles,
    max: usize,
    /// Starts the workers, which the threads that call the verifier share.
    spawner: &'a Spawner<'a>,
    pool: Mutex<Pool<'a>>,
    /// Signalled when a worker becomes idle or one fewer is running.
    changed: Condvar,
}

struct Pool<'a> {
    idle: Vec<VerifyWorker<'a>>,
    /// Workers running or being started, idle or not.
    running: usize,
}

/// Run `f` with a [`Verifier`] that checks signatures with `keyring`, in up
/// to `max` workers at once. One worker is started and loads the keyring
/// before `f` runs; if that fails, the error is returned as a
/// [`KeyringError`].
pub fn with_verifier<T>(
    workers: &Workers,
    keyring: KeyringFiles,
    max: usize,
    f: impl FnOnce(&Verifier) -> Result<T>,
) -> Result<T> {
    workers.with_spawner(|spawner| {
        let verifier = Verifier {
            keyring,
            max: max.max(1),
            spawner,
            pool: Mutex::new(Pool {
                idle: Vec::new(),
                running: 1,
            }),
            changed: Condvar::new(),
        };
        let worker = verifier
            .start()
            .map_err(|e| anyhow::Error::new(KeyringError(format!("{e:#}"))))?;
        verifier.pool.lock().unwrap().idle.push(worker);
        // The verifier, and with it its workers, ends here, before the
        // spawner's thread.
        f(&verifier)
    })
}

/// The keyring couldn't be loaded; see [`with_verifier`].
#[derive(Debug)]
pub struct KeyringError(String);

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyringError {}

impl<'a> Verifier<'a> {
    /// Check that `signature` (a `.sig` file's contents) is a valid
    /// signature of the whole of `archive` by a packager key. The archive
    /// is read from its start, from a new open file.
    pub fn verify(&self, signature: &[u8], archive: &File) -> Result<()> {
        ensure!(
            signature.len() as u64 <= MAX_SIGNATURE_SIZE,
            "signature file is too large"
        );
        let archive = reopen_read_only(archive)?;
        let mut worker = self.take()?;
        match worker.verify(signature, archive.as_fd()) {
            Ok(verdict) => {
                self.pool.lock().unwrap().idle.push(worker);
                self.changed.notify_one();
                verdict
            }
            Err(e) => {
                self.gone();
                worker.finish(Err(e))
            }
        }
    }

    /// An idle worker, or a new one if fewer than `max` are running.
    fn take(&self) -> Result<VerifyWorker<'a>> {
        let mut pool = self.pool.lock().unwrap();
        loop {
            if let Some(worker) = pool.idle.pop() {
                return Ok(worker);
            }
            if pool.running < self.max {
                pool.running += 1;
                drop(pool);
                return self.start().inspect_err(|_| self.gone());
            }
            pool = self.changed.wait(pool).unwrap();
        }
    }

    /// One worker fewer is running.
    fn gone(&self) {
        self.pool.lock().unwrap().running -= 1;
        self.changed.notify_one();
    }

    /// Start a worker and have it load the keyring.
    fn start(&self) -> Result<VerifyWorker<'a>> {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
        use rustix::pipe::{PipeFlags, pipe_with};
        let (input, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .context("creating socket")?;
        let (results_r, results_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
        let mut worker = VerifyWorker {
            worker: self.spawner.spawn(&VERIFY_WORKER, theirs, results_w)?,
            input,
            results: BufReader::new(File::from(results_r)),
        };
        let k = &self.keyring;
        let loaded = (|| {
            let files = [&k.certs, &k.trusted, &k.revoked]
                .map(reopen_read_only)
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            let fds: Vec<BorrowedFd> = files.iter().map(|f| f.as_fd()).collect();
            // The worker reads nothing else before it answers, so a failure
            // to send is explained by its answer.
            let sent = send(&worker.input, KEYRING, &[], &fds);
            match worker.receive()? {
                (READY, 0) => sent,
                (tag, len) => bail!("unexpected message {tag} ({len} bytes) from worker"),
            }
        })();
        match loaded {
            Ok(()) => Ok(worker),
            Err(e) => worker.finish(Err(e)).context("loading keyring"),
        }
    }
}

impl Drop for Verifier<'_> {
    /// End the idle workers (all of them, as none is in use while the
    /// verifier can be dropped), showing what they wrote to stderr.
    fn drop(&mut self) {
        let pool = self.pool.get_mut().unwrap_or_else(|e| e.into_inner());
        // Close all their input sockets first (left behind by the map), so
        // they finish at once: one after another, 8 took 18 ms.
        let workers: Vec<_> = pool.idle.drain(..).map(|w| (w.worker, w.results)).collect();
        for (worker, mut results) in workers {
            let result = read_result(&mut results).and_then(|json| {
                ensure!(json.is_empty(), "unexpected result from worker");
                Ok(())
            });
            if let Err(e) = worker.finish(result) {
                eprintln!("warning: {e:#}");
            }
        }
    }
}

/// The supervisor's side of a worker.
struct VerifyWorker<'a> {
    worker: Worker<Shared<'a>>,
    /// The input socket.
    input: OwnedFd,
    /// The result pipe.
    results: BufReader<File>,
}

impl VerifyWorker<'_> {
    /// Have the worker check one signature. The outer result says whether
    /// the worker did its part; the inner one is its verdict.
    fn verify(&mut self, signature: &[u8], archive: BorrowedFd) -> Result<Result<()>> {
        let sent = send(&self.input, ITEM, signature, &[archive]);
        let (tag, len) = self.receive()?;
        sent?;
        match tag {
            GOOD if len == 0 => Ok(Ok(())),
            BAD => {
                let msg = read_payload(&mut self.results, len, MAX_ERROR)?;
                let msg = sanitize(&String::from_utf8_lossy(&msg), false);
                Ok(Err(anyhow::anyhow!(msg)))
            }
            _ => bail!("unexpected message {tag} ({len} bytes) from worker"),
        }
    }

    /// The header of the worker's next message, other than `ERROR`, which
    /// is returned as the error.
    fn receive(&mut self) -> Result<(u8, usize)> {
        match read_header(&mut self.results).context("reading from worker")? {
            (ERROR, len) => Err(read_error(&mut self.results, len)),
            (DONE, len) => bail!("worker ended early ({len} bytes)"),
            header => Ok(header),
        }
    }

    /// End the worker after `result`, which is an error (see
    /// [`Worker::finish`]).
    fn finish<T>(self, result: Result<T>) -> Result<T> {
        drop(self.input);
        self.worker.finish(result)
    }
}

/// A new read-only open file of the regular file `file`, with its own file
/// offset, through `/proc/self/fd`. (Not something else, which opening
/// could block on or give the worker access to.)
fn reopen_read_only(file: &File) -> Result<File> {
    use rustix::fs::{Mode, OFlags};
    let meta = file.metadata().context("checking file")?;
    ensure!(meta.is_file(), "not a regular file");
    let path = format!("/proc/self/fd/{}", file.as_raw_fd());
    let flags = OFlags::RDONLY | OFlags::NOCTTY | OFlags::CLOEXEC;
    let fd = rustix::fs::open(&path, flags, Mode::empty()).context("opening file to read it")?;
    Ok(File::from(fd))
}

/// Send a message of `tag` and `payload` with `fds` attached.
fn send(socket: &OwnedFd, tag: u8, payload: &[u8], fds: &[BorrowedFd]) -> Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    ensure!(
        control.push(SendAncillaryMessage::ScmRights(fds)),
        "too many fds"
    );
    let tag = [tag];
    let iov = [IoSlice::new(&tag), IoSlice::new(payload)];
    let n = loop {
        match rustix::net::sendmsg(socket, &iov, &mut control, SendFlags::NOSIGNAL) {
            Err(rustix::io::Errno::INTR) => continue,
            r => break r.context("sending to worker")?,
        }
    };
    ensure!(n == 1 + payload.len(), "message to worker was cut off");
    Ok(())
}

/// A message to the worker: tag, payload and attached fds.
type Message<'b> = (u8, &'b [u8], Vec<OwnedFd>);

/// Worker side: the next message, as its tag and payload, with the fds
/// attached to it, or `None` when the input ends. Messages with more than
/// `max_fds` fds or a longer payload than `buf` holds are an error.
fn receive<'b>(
    socket: BorrowedFd,
    buf: &'b mut [u8],
    max_fds: usize,
) -> Result<Option<Message<'b>>> {
    // Room for more fds than expected, so extra ones are seen and refused
    // rather than cut off.
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = loop {
        let mut iov = [IoSliceMut::new(buf)];
        match rustix::net::recvmsg(socket, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC) {
            Err(rustix::io::Errno::INTR) => continue,
            r => break r.context("reading from supervisor")?,
        }
    };
    let mut fds = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    ensure!(
        !msg.flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC),
        "message from supervisor too large"
    );
    ensure!(fds.len() <= max_fds, "too many fds from supervisor");
    // Every message has a tag, so an empty one is the end of input.
    let Some((&tag, payload)) = buf[..msg.bytes].split_first() else {
        return Ok(None);
    };
    Ok(Some((tag, payload, fds)))
}

/// Entry point of the worker.
fn worker(args: Args) -> Result<Vec<u8>> {
    args.no_extra()?;
    let out = args.out;
    // SAFETY: the supervisor passes the input socket as fd 0.
    let input = unsafe { OwnedFd::from_raw_fd(0) };
    let policy = Policy {
        syscalls: SYSCALLS,
        max_memory: Some(MAX_MEMORY),
        ..Policy::default()
    };
    sandbox::confine(args.layers, &policy)?;
    let mut buf = vec![0; MAX_SIGNATURE_SIZE as usize + 2];
    let keyring = match receive(input.as_fd(), &mut buf, 3)? {
        Some((KEYRING, [], fds)) => {
            let [certs, trusted, revoked] = <[OwnedFd; 3]>::try_from(fds)
                .map_err(|_| anyhow::anyhow!("keyring needs three files"))?;
            let open = |fd: OwnedFd| BufReader::new(NoHints(File::from(fd)));
            Keyring::load(open(certs), open(trusted), open(revoked))?
        }
        _ => bail!("expected the keyring from supervisor"),
    };
    write_frame(out, READY, &[])?;
    out.flush()?;
    while let Some((tag, signature, fds)) = receive(input.as_fd(), &mut buf, 1)? {
        let archive = match (tag, <[OwnedFd; 1]>::try_from(fds)) {
            (ITEM, Ok([archive])) => File::from(archive),
            _ => bail!("unexpected message {tag} from supervisor"),
        };
        match keyring.verify(signature, NoHints(archive)) {
            Ok(_) => write_frame(out, GOOD, &[])?,
            Err(e) => {
                let mut msg = format!("{e:#}").into_bytes();
                msg.truncate(MAX_ERROR);
                write_frame(out, BAD, &msg)?;
            }
        }
        out.flush()?;
    }
    Ok(Vec::new())
}

/// Reads with plain `read` calls only, without the size hints (`statx`,
/// `lseek`) that [`File`]'s `read_to_end` asks for, which seccomp doesn't
/// allow.
struct NoHints(File);

impl Read for NoHints {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reopens_read_only() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"data").unwrap();
        let mut copy = reopen_read_only(&file).unwrap();
        let mut read = String::new();
        copy.read_to_string(&mut read).unwrap();
        assert_eq!(read, "data");
        assert!(copy.write_all(b"x").is_err());
        let (r, _w) = rustix::pipe::pipe().unwrap();
        let e = reopen_read_only(&File::from(r)).unwrap_err();
        assert!(e.to_string().contains("not a regular file"), "{e}");
    }
}
