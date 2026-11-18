//! Running programs in an image, for package code (install scripts and
//! hooks).
//!
//! The program runs under bubblewrap with the image as its root,
//! read-write: it sees nothing of the host's filesystem, processes or
//! network, and can't reach the store. `/proc` is read-only, with the parts
//! that show host-wide information hidden, `/dev` holds
//! only basic devices, `/tmp` and `/run` are tmpfs (not kept in the image)
//! and there is no `/sys`. It runs as root with only the capabilities to
//! change files' owners, modes and xattrs: when skl runs as root, in skl's
//! user namespace, so that owners mean the same inside; otherwise in a new
//! user namespace that maps skl's uid and gid to 0.
//!
//! [`run_captured`] also finds what the program changed, by comparing the
//! image with a snapshot taken before (see [`crate::diff`]).

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};

use crate::btrfs;
use crate::bwrap;
use crate::diff::{self, Change};
use crate::sandbox;
use crate::store::Store;
use crate::worker::{self, ImportStats, Workers};

/// Capabilities the program keeps: to change owners, modes, times and
/// xattrs (including `security.capability`) of any file in the image, and
/// to create entries regardless of permissions, as package code running as
/// root expects.
const CAPS: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_SETFCAP",
];

/// `PATH` of the program, as pacman's default for scriptlets.
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/bin";

/// Run `program` with `args` in the image whose root directory is `image`,
/// as root (see the module documentation), and wait for it. `program` is searched in the image's `PATH` unless it
/// contains a slash. The environment holds only `PATH`, and `PWD` (`/`),
/// which bwrap sets; stdin, stdout and stderr are inherited unless
/// `options` say otherwise. The program can't create user namespaces.
///
/// The returned status is bwrap's: the program's exit code, 128 + the
/// signal that killed it, or 1 if bwrap itself fails (it explains why on
/// stderr).
pub fn run(
    image: BorrowedFd,
    program: &OsStr,
    args: &[OsString],
    options: &Options,
) -> Result<ExitStatus> {
    let bwrap = bwrap::find()?;
    let filters = sandbox::no_userns_filters()
        .context("building seccomp filters")?
        .iter()
        .map(|program| pipe_holding(program))
        .collect::<Result<Vec<OwnedFd>>>()?;
    let filter_fds: Vec<BorrowedFd> = filters.iter().map(|f| f.as_fd()).collect();
    let mut cmd = bwrap::image_command(&bwrap, image, CAPS, &filter_fds, options.files)?;
    cmd.arg(program).args(args);
    let mut fds = vec![image.as_raw_fd()];
    fds.extend(filters.iter().map(|f| f.as_raw_fd()));
    fds.extend(options.files.iter().map(|(fd, _)| fd.as_raw_fd()));
    bwrap::inherit(&mut cmd, fds);
    cmd.env_clear().env("PATH", PATH).current_dir("/");
    let running = || format!("running {}", bwrap.display());
    if !options.escape_output {
        return cmd.status().with_context(running);
    }
    use rustix::pipe::{PipeFlags, pipe_with};
    let (r, w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
    cmd.stdin(Stdio::null())
        .stdout(w.try_clone().context("duplicating pipe")?)
        .stderr(w);
    let mut child = cmd.spawn().with_context(running)?;
    // The command holds the pipe's write end, which must be closed for
    // reading to end.
    drop(cmd);
    let copied = std::thread::scope(|s| {
        let copy = s.spawn(|| copy_escaped(File::from(r)));
        let status = child.wait().with_context(running);
        (status, copy.join().expect("copying output panicked"))
    });
    let status = copied.0?;
    copied.1.context("reading the program's output")?;
    Ok(status)
}

/// More of what [`run`] does.
#[derive(Default)]
pub struct Options<'a> {
    /// Files to put in the sandbox, read-only, at the paths given (under
    /// `/tmp` or `/run`, which aren't kept in the image), with the content
    /// read from the fds when the sandbox is set up.
    pub files: &'a [(BorrowedFd<'a>, &'a str)],
    /// Write the program's stdout and stderr to skl's stderr with control
    /// characters other than tab escaped, so that package code can't
    /// control the terminal; stdin is `/dev/null`. Otherwise stdin,
    /// stdout and stderr are inherited.
    pub escape_output: bool,
}

/// Copy what `r` yields to stderr, line by line, with control characters
/// other than tabs escaped.
fn copy_escaped(r: File) -> std::io::Result<()> {
    use std::io::BufRead;
    let mut r = std::io::BufReader::new(r);
    let mut line = Vec::new();
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        let text = String::from_utf8_lossy(line.strip_suffix(b"\n").unwrap_or(&line));
        let mut err = std::io::stderr().lock();
        writeln!(err, "{}", worker::sanitize(&text, true).replace('\n', ""))?;
    }
}

/// What [`run_captured`] found.
#[derive(Debug)]
pub struct Captured {
    /// See [`run`].
    pub status: ExitStatus,
    /// What the program changed in the image, in path order.
    pub changes: Vec<Change>,
    /// New file contents added to the store.
    pub stats: ImportStats,
    /// How the snapshot was removed: entry by entry is slow for large
    /// images, and suggests mounting with [`btrfs::USER_RM_OPTION`].
    pub snapshot_removal: btrfs::Removal,
}

/// [`run`] the program in `image`, which must be the root of a btrfs
/// subvolume on the same filesystem as `store`, and find what it changed,
/// whether it succeeded or not. New file contents are added to `store`.
///
/// Before the program starts, the image is snapshotted into the store's
/// `tmp/`, and the snapshot is compared with the image afterwards in a
/// worker (see [`crate::diff`]); it's removed after that. Taking the
/// snapshot waits until the coarse clock, which sets ctimes, has passed the
/// time of the snapshot (a few ms at most), so that a change can't leave a
/// ctime as it was before.
pub fn run_captured(
    workers: &Workers,
    store: &Store,
    image: BorrowedFd,
    program: &OsStr,
    args: &[OsString],
    options: &Options,
) -> Result<Captured> {
    let snapshot = Snapshot::new(store, image)?;
    wait_for_coarse_clock();
    let status = run(image, program, args, options)?;
    let (changes, stats) =
        diff::diff_in_worker(workers, store, snapshot.dir(), image).context("finding changes")?;
    let snapshot_removal = snapshot.remove()?;
    Ok(Captured {
        status,
        changes,
        stats,
        snapshot_removal,
    })
}

/// Wait until `CLOCK_REALTIME_COARSE`, which the kernel uses for most
/// timestamps, is past the current fine-grained time. Afterwards, any
/// change to an inode gives it a ctime later than any it had before (unless
/// the clock is set back meanwhile).
fn wait_for_coarse_clock() {
    let now = |clock| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes one timespec.
        unsafe { libc::clock_gettime(clock, &mut ts) };
        (ts.tv_sec, ts.tv_nsec)
    };
    let fine = now(libc::CLOCK_REALTIME);
    while now(libc::CLOCK_REALTIME_COARSE) <= fine {
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// A snapshot in the store's `tmp/`, removed when dropped.
struct Snapshot {
    tmp: OwnedFd,
    name: String,
    /// Open until the snapshot is removed.
    dir: Option<OwnedFd>,
}

impl Snapshot {
    fn new(store: &Store, image: BorrowedFd) -> Result<Snapshot> {
        let tmp = store.tmp_dir()?;
        let name = format!("snapshot-{}", store.unique_name());
        btrfs::snapshot_at(image, tmp.as_fd(), OsStr::new(&name))
            .context("taking a snapshot of the image")?;
        let mut snapshot = Snapshot {
            tmp,
            name,
            dir: None,
        };
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let dir = rustix::fs::openat(&snapshot.tmp, snapshot.name.as_str(), flags, Mode::empty())
            .context("opening snapshot")?;
        snapshot.dir = Some(dir);
        Ok(snapshot)
    }

    fn dir(&self) -> BorrowedFd<'_> {
        self.dir.as_ref().expect("snapshot not removed").as_fd()
    }

    fn remove(mut self) -> Result<btrfs::Removal> {
        Ok(self.remove_now()?.expect("not removed before"))
    }

    /// Remove the snapshot, unless that was done before (`None`).
    fn remove_now(&mut self) -> Result<Option<btrfs::Removal>> {
        if self.name.is_empty() {
            return Ok(None);
        }
        self.dir = None;
        let name = std::mem::take(&mut self.name);
        btrfs::remove_subvolume_at(self.tmp.as_fd(), OsStr::new(&name))
            .map(Some)
            .with_context(|| format!("removing snapshot tmp/{name} from the store"))
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        if let Err(e) = self.remove_now() {
            eprintln!("warning: {e:#}");
        }
    }
}

/// A pipe that holds `data`, with the write end closed. `data` must fit in
/// the pipe's buffer (64 KiB by default).
fn pipe_holding(data: &[u8]) -> Result<OwnedFd> {
    use rustix::pipe::{PipeFlags, pipe_with};
    let (r, w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
    std::fs::File::from(w)
        .write_all(data)
        .context("writing to pipe")?;
    Ok(r)
}

#[cfg(test)]
#[path = "../tests/common/minimal_image.rs"]
mod minimal_image;

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::ErrorKind;
    use std::path::Path;

    use super::*;

    /// Runs this test binary in a minimal image and checks what it can do
    /// there.
    #[test]
    fn program_sees_only_the_image() {
        if minimal_image::is_child() {
            return check_inside();
        }
        let image = tempfile::tempdir().unwrap();
        let root = image.path();
        minimal_image::populate(root);
        let dir = File::open(root).unwrap();
        let args = minimal_image::child_args("run::tests::program_sees_only_the_image");
        let status = run(
            dir.as_fd(),
            OsStr::new(minimal_image::CHILD),
            &args,
            &Options::default(),
        )
        .unwrap();
        assert!(status.success(), "child {status}");
        assert_eq!(std::fs::read(root.join("kept")).unwrap(), b"x");
        assert!(root.join("tmp").read_dir().unwrap().next().is_none());
    }

    fn check_inside() {
        assert!(rustix::process::getuid().is_root());
        let mut vars: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
        vars.sort();
        assert_eq!(vars, ["PATH", "PWD"]);
        std::fs::write("/kept", "x").unwrap();
        std::fs::write("/tmp/gone", "x").unwrap();
        let err = std::fs::write("/proc/sys/vm/drop_caches", "3").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EROFS));
        // Masked directories are empty and read-only, masked files can't be
        // opened; at least `interrupts` exists on every kernel.
        assert!(Path::new("/proc/interrupts").exists());
        for path in bwrap::MASKED_PROC {
            let Ok(m) = std::fs::metadata(path) else {
                continue;
            };
            if m.is_dir() {
                assert!(std::fs::read_dir(path).unwrap().next().is_none(), "{path}");
                let err = std::fs::write(Path::new(path).join("x"), "").unwrap_err();
                assert_eq!(err.raw_os_error(), Some(libc::EROFS), "{path}");
            } else {
                let err = File::open(path).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{path}");
            }
        }
        // No host processes: bwrap's init is pid 1.
        assert!(std::process::id() < 10, "pid {}", std::process::id());
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = socket.connect("192.0.2.1:9").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENETUNREACH));
        // No new user namespaces, but threads still work: libc falls back
        // from clone3 to clone.
        // SAFETY: fails, or creates a user namespace for this thread.
        let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((r, errno), (-1, Some(libc::EPERM)));
        // SAFETY: clone3 with a null argument only returns an error.
        let r = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((r, errno), (-1, Some(libc::ENOSYS)));
        std::thread::spawn(|| ()).join().unwrap();
        // The host's filesystem isn't there.
        let err = std::fs::metadata(env!("CARGO_MANIFEST_PATH")).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}
