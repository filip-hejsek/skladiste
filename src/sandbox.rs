//! Confining the current process with Landlock and seccomp.
//!
//! Workers (see [`crate::worker`]) call [`confine`] before reading any input.
//! Landlock denies all filesystem access except beneath the directories in
//! the [`Policy`], denies TCP, and stops the process from signalling or
//! connecting to abstract sockets outside its sandbox. Seccomp then allows
//! only the system calls the worker needs and kills it on any other.

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
