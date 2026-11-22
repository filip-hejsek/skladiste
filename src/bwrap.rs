//! Running workers in new namespaces with bubblewrap (`bwrap`).
//!
//! The worker's root is an empty read-only tmpfs holding only what is needed
//! to execute the `skl` binary (`/usr` and the `/lib*` directories or
//! symlinks of the host, for the dynamic loader) and the directories given
//! in [`Namespaces`], bound from fds. It gets new pid, network, ipc, uts and
//! cgroup namespaces, and a new user namespace unless it must keep the
//! supervisor's ids (see [`Namespaces::root_caps`]).
//!
//! [`image_command`] runs package code instead: the root is an image.

use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};

/// Where the `skl` binary is bound inside the sandbox.
pub(crate) const EXE: &str = "/skl";

/// Paths in `/proc` that [`image_command`] hides, because they show
/// host-wide information (other processes, kernel memory, hardware): the
/// default masked paths of runc, and files readable by root without
/// capabilities. Files are covered with the host's `/dev/null`, bound
/// `nodev`, so opening them fails with `EACCES`; directories with an empty
/// read-only tmpfs.
pub(crate) const MASKED_PROC: &[&str] = &[
    // runc's defaults.
    "/proc/acpi",
    "/proc/asound",
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/proc/timer_list",
    "/proc/timer_stats",
    // Mode 0400, no capability needed.
    "/proc/kpagecgroup",
    "/proc/kpagecount",
    "/proc/kpageflags",
    "/proc/pagetypeinfo",
    "/proc/slabinfo",
    "/proc/vmallocinfo",
];

/// Host directories (or symlinks to them) the dynamic loader may need.
const LIB_DIRS: &[&str] = &["/lib", "/lib32", "/lib64", "/libx32"];

/// A directory bound into the sandbox.
pub(crate) struct Mount<'a> {
    pub(crate) fd: BorrowedFd<'a>,
    /// Absolute path inside the sandbox.
    pub(crate) dest: &'static str,
    pub(crate) writable: bool,
}

/// The sandbox of one worker.
#[derive(Default)]
pub(crate) struct Namespaces<'a> {
    pub(crate) mounts: &'a [Mount<'a>],
    /// When skl runs as root: stay in the supervisor's user namespace,
    /// keeping only these capabilities, so that file owners mean the same
    /// inside and outside (needed to apply owners in a user namespace with a
    /// range of ids mapped). `None`: always use a new user namespace, which
    /// maps only the supervisor's own uid and gid.
    pub(crate) root_caps: Option<&'a [&'a str]>,
    /// Capabilities to keep in a new user namespace, where they apply only
    /// to files whose owner and group are skl's.
    pub(crate) userns_caps: &'a [&'a str],
}

/// Find `bwrap` in the supervisor's `PATH`.
pub(crate) fn find() -> Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("bwrap");
        if dir.is_absolute() && rustix::fs::access(&candidate, rustix::fs::Access::EXEC_OK).is_ok()
        {
            return Ok(candidate);
        }
    }
    bail!("bwrap (bubblewrap) not found in PATH; workers need it to run in new namespaces")
}

/// A command that runs `bwrap` with `ns`, executing the binary `exe` (an
/// fd, e.g. `O_PATH`) as [`EXE`]. Append the worker's arguments to it.
/// Returns the fds that the child must inherit (CLOEXEC cleared) for
/// `bwrap` to bind them; it closes them before executing the worker.
pub(crate) fn command(
    bwrap: &Path,
    exe: BorrowedFd,
    ns: &Namespaces,
) -> Result<(Command, Vec<RawFd>)> {
    let mut cmd = new_namespaces(bwrap);
    let mut fds = vec![exe.as_raw_fd()];
    let root = rustix::process::getuid().is_root();
    match ns.root_caps {
        Some(caps) if root => {
            cmd.args(["--cap-drop", "ALL"]);
            for cap in caps {
                cmd.args(["--cap-add", cap]);
            }
        }
        _ => {
            cmd.args(["--unshare-user", "--disable-userns"]);
            if root {
                cmd.args(["--cap-drop", "ALL"]);
            }
            for cap in ns.userns_caps {
                cmd.args(["--cap-add", cap]);
            }
        }
    }
    cmd.args(["--ro-bind", "/usr", "/usr"]);
    for dir in LIB_DIRS {
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.is_symlink() => {
                let target = std::fs::read_link(dir)?;
                cmd.arg("--symlink").arg(target).arg(dir);
            }
            Ok(m) if m.is_dir() => {
                cmd.args(["--ro-bind", dir, dir]);
            }
            _ => {}
        }
    }
    cmd.args(["--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache"]);
    cmd.arg("--ro-bind-fd").arg(fd_arg(exe)).arg(EXE);
    for m in ns.mounts {
        let opt = if m.writable {
            "--bind-fd"
        } else {
            "--ro-bind-fd"
        };
        cmd.arg(opt).arg(fd_arg(m.fd)).arg(m.dest);
        fds.push(m.fd.as_raw_fd());
    }
    // Last: makes the tmpfs root read-only, not the mounts beneath it.
    cmd.args(["--remount-ro", "/", "--chdir", "/", "--", EXE]);
    Ok((cmd, fds))
}

/// A command that runs `bwrap` with the directory `image` (an fd) as the
/// root, read-write, and executes the arguments appended to it there
/// (searched in the `PATH` given to bwrap). `filters` are seccomp programs
/// for the process to load (fds of a file or pipe holding raw BPF).
/// `files` are put read-only at their paths, with the content read from
/// the fds. The child must inherit `image`, `filters` and the fds of
/// `files` (see [`crate::fds::inherit`]).
///
/// New pid, net, ipc, uts and cgroup namespaces, as for workers. The
/// process runs as root with only `caps`: when skl runs as root, in the
/// supervisor's user namespace, so that the image's owners mean the same
/// inside; otherwise in a new user namespace that maps skl's uid and gid
/// to 0. `/proc` (for the new pid namespace) is read-only, since root in
/// the host's user namespace can write sysctls in `/proc/sys`, and
/// bwrap's cover over it is skipped for lack of write access to the
/// directory. The paths in [`MASKED_PROC`] that exist in the host's
/// `/proc` (the same kernel) are hidden; fails if the host has no `/proc`.
/// `/dev` has only the basic devices; `/tmp` and `/run` are
/// tmpfs, so their contents aren't kept in the image. Missing mount
/// points are created in the image. No `/sys`.
pub(crate) fn image_command(
    bwrap: &Path,
    image: BorrowedFd,
    caps: &[&str],
    filters: &[BorrowedFd],
    files: &[(BorrowedFd, &str)],
) -> Result<Command> {
    let mut cmd = new_namespaces(bwrap);
    if rustix::process::getuid().is_root() {
        cmd.args(["--cap-drop", "ALL"]);
    } else {
        cmd.args([
            "--unshare-user",
            "--disable-userns",
            "--uid",
            "0",
            "--gid",
            "0",
        ]);
    }
    for cap in caps {
        cmd.args(["--cap-add", cap]);
    }
    for fd in filters {
        cmd.arg("--add-seccomp-fd").arg(fd_arg(*fd));
    }
    cmd.arg("--bind-fd").arg(fd_arg(image));
    cmd.args(["/", "--proc", "/proc"]);
    if std::fs::symlink_metadata("/proc/self").is_err() {
        bail!("/proc is not mounted; needed to know which of its paths to hide");
    }
    for path in MASKED_PROC {
        // bwrap resolves the source in the host's root, so the image can't
        // redirect it.
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.is_dir() => cmd.args(["--tmpfs", path, "--remount-ro", path]),
            Ok(_) => cmd.args(["--ro-bind", "/dev/null", path]),
            Err(_) => continue,
        };
    }
    // Doesn't reach the tmpfs masks, so they get their own.
    cmd.args([
        "--remount-ro",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
    ]);
    for (fd, dest) in files {
        cmd.arg("--ro-bind-data").arg(fd_arg(*fd)).arg(dest);
    }
    cmd.args(["--chdir", "/", "--"]);
    Ok(cmd)
}

/// `bwrap` with new namespaces other than the user namespace.
fn new_namespaces(bwrap: &Path) -> Command {
    let mut cmd = Command::new(bwrap);
    cmd.args([
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--die-with-parent",
        "--new-session",
    ]);
    cmd
}

fn fd_arg(fd: BorrowedFd) -> String {
    fd.as_raw_fd().to_string()
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsFd;

    use super::*;

    const CHILD_VAR: &str = "SKL_BWRAP_TEST_CHILD";

    /// Runs this test binary inside the sandbox (as the child) and checks
    /// what it can see there.
    #[test]
    fn sandbox_has_only_its_mounts() {
        if std::env::var_os(CHILD_VAR).is_some() {
            return check_inside();
        }
        let bwrap = find().unwrap();
        let ro = tempfile::tempdir().unwrap();
        let rw = tempfile::tempdir().unwrap();
        std::fs::write(ro.path().join("f"), "x").unwrap();
        let ro_fd = File::open(ro.path()).unwrap();
        let rw_fd = File::open(rw.path()).unwrap();
        let exe = File::open(std::env::current_exe().unwrap()).unwrap();
        let ns = Namespaces {
            mounts: &[
                Mount {
                    fd: ro_fd.as_fd(),
                    dest: "/ro",
                    writable: false,
                },
                Mount {
                    fd: rw_fd.as_fd(),
                    dest: "/rw",
                    writable: true,
                },
            ],
            root_caps: None,
            userns_caps: &[],
        };
        let (mut cmd, fds) = command(&bwrap, exe.as_fd(), &ns).unwrap();
        cmd.args([
            "--exact",
            "bwrap::tests::sandbox_has_only_its_mounts",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(CHILD_VAR, "1");
        crate::fds::inherit(&mut cmd, fds);
        let status = cmd.status().unwrap();
        assert!(status.success(), "child {status}");
        assert_eq!(std::fs::read(rw.path().join("new")).unwrap(), b"y");
    }

    fn check_inside() {
        let mut top: Vec<String> = std::fs::read_dir("/")
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| !n.starts_with("lib") && n != "etc")
            .collect();
        top.sort();
        assert_eq!(top, ["ro", "rw", "skl", "usr"]);
        let erofs = Some(libc::EROFS);
        let chmod =
            std::fs::set_permissions("/ro/f", std::os::unix::fs::PermissionsExt::from_mode(0o600));
        assert_eq!(chmod.unwrap_err().raw_os_error(), erofs);
        assert_eq!(
            std::fs::write("/new", "y").unwrap_err().raw_os_error(),
            erofs
        );
        std::fs::write("/rw/new", "y").unwrap();
        // A new pid namespace, with bwrap's init as pid 1.
        assert!(std::process::id() < 10, "pid {}", std::process::id());
        // A new network namespace, with only a loopback interface: no route
        // to other addresses (connecting a UDP socket sends nothing).
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = socket.connect("192.0.2.1:9").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENETUNREACH));
        // No new user namespaces. unshare needs a single-threaded process.
        // SAFETY: the child makes only async-signal-safe calls.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            let errno = unsafe { *libc::__errno_location() };
            unsafe { libc::_exit(if r == 0 { 0 } else { errno }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(libc::WEXITSTATUS(status), libc::ENOSPC);
    }
}
