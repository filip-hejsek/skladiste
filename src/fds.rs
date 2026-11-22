//! Passing fds to child processes.

use std::os::fd::{BorrowedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

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
