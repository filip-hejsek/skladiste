//! Running programs in an image, for package code (install scripts and
//! hooks).
//!
//! The program runs under bubblewrap with the image as its root,
//! read-write: it sees nothing of the host's filesystem, processes or
//! network, and can't reach the store. `/proc` is read-only, `/dev` holds
//! only basic devices, `/tmp` and `/run` are tmpfs (not kept in the image)
//! and there is no `/sys`. It runs as root with only the capabilities to
//! change files' owners, modes and xattrs: when skl runs as root, in skl's
//! user namespace, so that owners mean the same inside; otherwise in a new
//! user namespace that maps skl's uid and gid to 0.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::process::ExitStatus;

use anyhow::{Context, Result};

use crate::bwrap;
use crate::sandbox;

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
/// which bwrap sets; stdin, stdout and stderr are inherited. The program can't create user namespaces.
///
/// The returned status is bwrap's: the program's exit code, 128 + the
/// signal that killed it, or 1 if bwrap itself fails (it explains why on
/// stderr).
pub fn run(image: BorrowedFd, program: &OsStr, args: &[OsString]) -> Result<ExitStatus> {
    let bwrap = bwrap::find()?;
    let filters = sandbox::no_userns_filters()
        .context("building seccomp filters")?
        .iter()
        .map(|program| pipe_holding(program))
        .collect::<Result<Vec<OwnedFd>>>()?;
    let filter_fds: Vec<BorrowedFd> = filters.iter().map(|f| f.as_fd()).collect();
    let mut cmd = bwrap::image_command(&bwrap, image, CAPS, &filter_fds);
    cmd.arg(program).args(args);
    let mut fds = vec![image.as_raw_fd()];
    fds.extend(filters.iter().map(|f| f.as_raw_fd()));
    bwrap::inherit(&mut cmd, fds);
    cmd.env_clear().env("PATH", PATH).current_dir("/");
    let status = cmd
        .status()
        .with_context(|| format!("running {}", bwrap.display()))?;
    Ok(status)
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
mod tests {
    use std::fs::File;
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;

    /// Where the test binary is copied in the image.
    const CHILD: &str = "/child";

    /// Runs this test binary in a minimal image (the binary, its dynamic
    /// loader, the libraries it has mapped, and the host's `/lib*` symlinks
    /// and `ld.so.cache`)
    /// and checks what the program can do there.
    #[test]
    fn program_sees_only_the_image() {
        if std::env::current_exe().unwrap() == Path::new(CHILD) {
            return check_inside();
        }
        let image = tempfile::tempdir().unwrap();
        let root = image.path();
        let copy = |from: &Path, to: &str| {
            let dest = root.join(to.trim_start_matches('/'));
            std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
            std::fs::copy(from, dest).unwrap();
        };
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        std::fs::write(root.join(&CHILD[1..]), &exe).unwrap();
        std::fs::set_permissions(root.join(&CHILD[1..]), PermissionsExt::from_mode(0o755)).unwrap();
        let interp = interpreter(&exe);
        copy(Path::new(interp), interp);
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let libs = maps
            .lines()
            .filter_map(|l| l.split_whitespace().nth(5))
            .filter(|p| p.starts_with("/usr/") || p.starts_with("/lib"));
        for lib in libs {
            copy(Path::new(lib), lib);
        }
        if Path::new("/etc/ld.so.cache").exists() {
            copy(Path::new("/etc/ld.so.cache"), "/etc/ld.so.cache");
        }
        for dir in ["/lib", "/lib32", "/lib64", "/libx32"] {
            if let Ok(target) = std::fs::read_link(dir) {
                let dest = root.join(&dir[1..]);
                if !dest.exists() {
                    std::os::unix::fs::symlink(target, dest).unwrap();
                }
            }
        }
        let dir = File::open(root).unwrap();
        let args: Vec<OsString> = ["--exact", "run::tests::program_sees_only_the_image"]
            .iter()
            .map(OsString::from)
            .chain([OsString::from("--nocapture")])
            .collect();
        let status = run(dir.as_fd(), OsStr::new(CHILD), &args).unwrap();
        assert!(status.success(), "child {status}");
        assert_eq!(std::fs::read(root.join("kept")).unwrap(), b"x");
        assert!(root.join("tmp").read_dir().unwrap().next().is_none());
    }

    /// The `PT_INTERP` path of a 64-bit ELF executable.
    fn interpreter(elf: &[u8]) -> &str {
        let u16_at = |o: usize| u16::from_ne_bytes(elf[o..o + 2].try_into().unwrap()) as usize;
        let u64_at = |o: usize| u64::from_ne_bytes(elf[o..o + 8].try_into().unwrap()) as usize;
        let (phoff, phentsize, phnum) = (u64_at(0x20), u16_at(0x36), u16_at(0x38));
        for ph in (0..phnum).map(|i| phoff + i * phentsize) {
            if u32::from_ne_bytes(elf[ph..ph + 4].try_into().unwrap()) == 3 {
                let (off, len) = (u64_at(ph + 8), u64_at(ph + 32));
                let path = &elf[off..off + len];
                return std::str::from_utf8(path.strip_suffix(b"\0").unwrap()).unwrap();
            }
        }
        panic!("no PT_INTERP");
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
