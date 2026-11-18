//! Confining the current process with Landlock and seccomp.
//!
//! Workers (see [`crate::worker`]) call [`confine`] before reading any input.
//! Landlock denies all filesystem access except beneath the directories in
//! the [`Policy`], denies TCP, and stops the process from signalling or
//! connecting to abstract sockets outside its sandbox. Seccomp then allows
//! only the system calls the worker needs and kills it on any other.
//!
//! Package code run in an image can't confine itself; bwrap loads the
//! filters of [`package_code_filters`] for it.

use std::collections::BTreeMap;
#[cfg(test)]
use std::fs::File;
use std::os::fd::BorrowedFd;

use anyhow::{Context, Result, bail};
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// Newest Landlock ABI whose restrictions are requested. Older kernels
/// enforce what they support (best effort); see [`confine`].
const LANDLOCK_ABI: ABI = ABI::V9;

/// Which sandboxing layers to apply. Turning one off is only possible in
/// builds with the `insecure` feature.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Layers {
    /// Start workers in new namespaces with bubblewrap (see [`crate::bwrap`]).
    /// Applied by the supervisor, not by [`confine`].
    pub(crate) namespaces: bool,
    pub(crate) landlock: bool,
    pub(crate) seccomp: bool,
}

impl Default for Layers {
    fn default() -> Self {
        Layers {
            namespaces: true,
            landlock: true,
            seccomp: true,
        }
    }
}

/// What a worker may do beyond computing and using the fds it already has.
#[derive(Default)]
pub(crate) struct Policy<'a> {
    /// Directories the process may access, and how. Everything else on the
    /// filesystem is denied.
    pub(crate) paths: Vec<(BorrowedFd<'a>, BitFlags<AccessFs>)>,
    /// System calls allowed in addition to [`BASE_SYSCALLS`].
    pub(crate) syscalls: &'a [i64],
    /// Allowed `ioctl` request numbers; no ioctls if empty.
    pub(crate) ioctls: &'a [u64],
    /// Limit on the address space in bytes (`RLIMIT_AS`), so a bug or
    /// malicious input can't exhaust the host's memory.
    pub(crate) max_memory: Option<u64>,
}

/// System calls every worker may make: I/O on its fds, memory management,
/// futexes, exiting, and what a panic needs.
const BASE_SYSCALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_close,
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_futex,
    libc::SYS_getrandom,
    libc::SYS_clock_gettime,
    libc::SYS_sched_yield,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigprocmask,
    libc::SYS_sigaltstack,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_tgkill,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// Restrict the calling process according to `policy`. Must be called while
/// the process is single-threaded, since seccomp applies to this thread only.
///
/// Resource limits are set as both soft and hard limits, so the process
/// can't raise them (seccomp also blocks `setrlimit`). They don't depend on
/// `layers`. Fails if a requested layer is unavailable. Landlock is applied best
/// effort: an older kernel that lacks some restrictions (e.g. TCP, which
/// seccomp also blocks) is accepted, a kernel without Landlock is not.
pub(crate) fn confine(layers: Layers, policy: &Policy) -> Result<()> {
    if let Some(max) = policy.max_memory {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let limit = Rlimit {
            current: Some(max),
            maximum: Some(max),
        };
        setrlimit(Resource::As, limit).context("limiting memory")?;
    }
    // glibc loads the time zone (`/etc/localtime`, absent in a worker, so
    // UTC) when `strftime` or `localtime` first needs it, which would be
    // a system call seccomp kills the worker for. Sequoia formats times
    // with `strftime` in error messages. Once loaded, it is kept as long as
    // `TZ` doesn't change (the environment is cleared).
    unsafe extern "C" {
        fn tzset();
    }
    // SAFETY: the worker is single-threaded here, and nothing else changes
    // the environment or time zone state.
    unsafe { tzset() };
    // Required for unprivileged Landlock and seccomp; also keeps exec from
    // gaining privileges if seccomp is off.
    rustix::thread::set_no_new_privs(true).context("setting no_new_privs")?;
    if layers.landlock {
        landlock(policy).context("enabling Landlock")?;
    }
    if layers.seccomp {
        seccomp(policy).context("enabling seccomp")?;
    }
    Ok(())
}

fn landlock(policy: &Policy) -> Result<()> {
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(LANDLOCK_ABI))?
        .handle_access(AccessNet::from_all(LANDLOCK_ABI))?
        .scope(Scope::from_all(LANDLOCK_ABI))?
        .create()?;
    for (fd, access) in &policy.paths {
        ruleset = ruleset.add_rule(PathBeneath::new(fd, *access))?;
    }
    let status = ruleset.restrict_self()?;
    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("Landlock is not supported or not enabled in this kernel");
    }
    Ok(())
}

fn seccomp(policy: &Policy) -> Result<()> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BASE_SYSCALLS
        .iter()
        .chain(policy.syscalls)
        .map(|&nr| (nr, Vec::new()))
        .collect();
    // Allows a system call if its second argument (an unsigned int for both
    // uses here) is one of `values`.
    let arg1_in = |values: &[u64]| -> Result<Vec<SeccompRule>> {
        values
            .iter()
            .map(|&v| {
                let cond = SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, v)?;
                Ok(SeccompRule::new(vec![cond])?)
            })
            .collect()
    };
    // Debug builds check that an fd is open before closing it.
    rules.insert(libc::SYS_fcntl, arg1_in(&[libc::F_GETFD as u64])?);
    if !policy.ioctls.is_empty() {
        rules.insert(libc::SYS_ioctl, arg1_in(policy.ioctls)?);
    }
    let arch = TargetArch::try_from(std::env::consts::ARCH)?;
    // An allowlist: also rejects x32 system calls, whose numbers have a high
    // bit set but share the x86_64 audit architecture.
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&program)?;
    Ok(())
}

/// Seccomp filters (raw BPF programs) for package code. They stop it from
/// creating user namespaces, since bwrap runs it in the supervisor's user
/// namespace, where `--disable-userns` isn't available: `unshare` and
/// `clone` with `CLONE_NEWUSER` fail with `EPERM`; `clone3` fails with
/// `ENOSYS`, since its flags are behind a pointer, and libc then falls back
/// to `clone`. Creating btrfs subvolumes and snapshots fails with `ENOTTY`,
/// as on another filesystem, so that programs that create them if they can
/// (`systemd-tmpfiles` for `/var/lib/machines`) make a directory instead:
/// the changes package code makes can't contain subvolumes. Everything
/// else is allowed. A separate program per error, since a seccompiler
/// filter has a single action on a match.
pub(crate) fn package_code_filters() -> Result<[Vec<u8>; 3]> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let newuser = || -> Result<Vec<SeccompRule>> {
        let flag = libc::CLONE_NEWUSER as u64;
        let cond = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(flag),
            flag,
        )?;
        Ok(vec![SeccompRule::new(vec![cond])?])
    };
    let mut flagged = BTreeMap::new();
    let mut whole = BTreeMap::new();
    for nr in with_x32(libc::SYS_unshare).chain(with_x32(libc::SYS_clone)) {
        flagged.insert(nr, newuser()?);
    }
    for nr in with_x32(libc::SYS_clone3) {
        whole.insert(nr, Vec::new());
    }
    // The request is an unsigned int.
    let ioctls = crate::btrfs::CREATE_IOCTLS
        .iter()
        .map(|&op| {
            let cond =
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, op.into())?;
            Ok(SeccompRule::new(vec![cond])?)
        })
        .collect::<Result<Vec<_>>>()?;
    // x32 has its own number for `ioctl` (514), not that of x86_64.
    #[cfg(target_arch = "x86_64")]
    let ioctl_nrs = [libc::SYS_ioctl, 0x4000_0000 | 514];
    #[cfg(not(target_arch = "x86_64"))]
    let ioctl_nrs = [libc::SYS_ioctl];
    let btrfs = ioctl_nrs.map(|nr| (nr, ioctls.clone())).into();
    let compile = |rules, errno: i32| -> Result<Vec<u8>> {
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(errno as u32),
            arch,
        )?;
        let program: BpfProgram = filter.try_into()?;
        Ok(program
            .iter()
            .flat_map(|f| {
                let mut b = [0; 8];
                b[..2].copy_from_slice(&f.code.to_ne_bytes());
                b[2] = f.jt;
                b[3] = f.jf;
                b[4..].copy_from_slice(&f.k.to_ne_bytes());
                b
            })
            .collect())
    };
    Ok([
        compile(flagged, libc::EPERM)?,
        compile(whole, libc::ENOSYS)?,
        compile(btrfs, libc::ENOTTY)?,
    ])
}

/// `nr`, and on x86_64 also its x32 number: x32 system calls pass a filter
/// for `AUDIT_ARCH_X86_64` with this bit set, so a filter that allows
/// everything else must name them too.
fn with_x32(nr: i64) -> impl Iterator<Item = i64> {
    #[cfg(target_arch = "x86_64")]
    let x32 = Some(nr | 0x4000_0000);
    #[cfg(not(target_arch = "x86_64"))]
    let x32 = None;
    std::iter::once(nr).chain(x32)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, ExitStatus};

    use super::*;

    const CHILD_VAR: &str = "SKL_SANDBOX_TEST_CHILD";

    /// Run `body` in a child process: this test binary, re-executed to run
    /// only test `name`. Confinement can't be undone, so it mustn't happen
    /// in the test process itself. Returns `None` in the child.
    fn in_child(name: &str, body: impl FnOnce()) -> Option<ExitStatus> {
        if std::env::var_os(CHILD_VAR).is_some() {
            body();
            return None;
        }
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("sandbox::tests::{name}"), "--nocapture"])
            .env(CHILD_VAR, "1")
            .status()
            .unwrap();
        Some(status)
    }

    #[test]
    fn landlock_limits_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("inside"), "x").unwrap();
        let status = in_child("landlock_limits_paths", || {
            let fd = File::open(dir.path()).unwrap();
            let policy = Policy {
                paths: vec![(fd.as_fd(), AccessFs::ReadFile | AccessFs::ReadDir)],
                ..Policy::default()
            };
            let layers = Layers {
                namespaces: false,
                landlock: true,
                seccomp: false,
            };
            confine(layers, &policy).unwrap();
            assert_eq!(std::fs::read(dir.path().join("inside")).unwrap(), b"x");
            let denied = std::io::ErrorKind::PermissionDenied;
            let outside = std::fs::read(env!("CARGO_MANIFEST_PATH")).unwrap_err();
            assert_eq!(outside.kind(), denied);
            let create = std::fs::write(dir.path().join("new"), "x").unwrap_err();
            assert_eq!(create.kind(), denied);
        });
        if let Some(status) = status {
            assert!(status.success(), "child {status}");
        }
    }

    #[test]
    fn memory_is_limited() {
        let status = in_child("memory_is_limited", || {
            let layers = Layers {
                namespaces: false,
                landlock: false,
                seccomp: false,
            };
            let policy = Policy {
                max_memory: Some(256 << 20),
                ..Policy::default()
            };
            confine(layers, &policy).unwrap();
            assert!(Vec::<u8>::new().try_reserve(16 << 20).is_ok());
            assert!(Vec::<u8>::new().try_reserve(512 << 20).is_err());
        });
        if let Some(status) = status {
            assert!(status.success(), "child {status}");
        }
    }

    fn seccomp_kills(name: &str, call: impl FnOnce()) {
        let status = in_child(name, || {
            let layers = Layers {
                namespaces: false,
                landlock: false,
                seccomp: true,
            };
            let policy = Policy {
                ioctls: &[libc::FICLONE],
                ..Policy::default()
            };
            confine(layers, &policy).unwrap();
            // Allowed: memory allocation and writing to an open fd.
            eprintln!("confined {:?}", vec![0u8; 1 << 20].len());
            call();
        });
        if let Some(status) = status {
            assert_eq!(status.signal(), Some(libc::SIGSYS), "child {status}");
        }
    }

    #[test]
    fn seccomp_kills_disallowed_syscall() {
        seccomp_kills("seccomp_kills_disallowed_syscall", || {
            let _ = std::fs::File::open("/");
        });
    }

    #[test]
    fn seccomp_kills_disallowed_ioctl() {
        seccomp_kills("seccomp_kills_disallowed_ioctl", || {
            let mut n: libc::c_int = 0;
            // SAFETY: FIONREAD writes one int.
            unsafe { libc::ioctl(0, libc::FIONREAD, &mut n) };
        });
    }
}
