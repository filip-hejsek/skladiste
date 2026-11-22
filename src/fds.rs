//! Passing fds to child processes.

use std::fs::File;
use std::io::{self, Seek, Write};
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result};

/// Make the child of `cmd` inherit `fds` under their numbers, by clearing
/// CLOEXEC on them between fork and exec.
pub(crate) fn inherit(cmd: &mut Command, fds: Vec<RawFd>) {
    // SAFETY: fcntl is async-signal-safe, and only the child's fd table is
    // changed.
    unsafe {
        cmd.pre_exec(move || {
            for &fd in &fds {
                rustix::io::fcntl_setfd(BorrowedFd::borrow_raw(fd), rustix::io::FdFlags::empty())?;
            }
            Ok(())
        });
    }
}

/// Close every fd except stdio and `keep`, in a child that inherited them
/// (see [`inherit`]). Must run before anything in the process owns an fd.
pub(crate) fn close_other(keep: &[RawFd]) -> Result<()> {
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

/// A memfd named `name` holding `data`, at offset 0, for a child to read.
pub(crate) fn holding(name: &str, data: &[u8]) -> Result<OwnedFd> {
    let fd = rustix::fs::memfd_create(name, rustix::fs::MemfdFlags::CLOEXEC)
        .context("creating a memfd")?;
    let mut file = File::from(fd);
    file.write_all(data).context("writing to a memfd")?;
    file.rewind().context("writing to a memfd")?;
    Ok(file.into())
}
