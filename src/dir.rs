//! Opening directories relative to a directory fd.

use std::ffi::OsStr;
use std::os::fd::{BorrowedFd, OwnedFd};

use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};

/// Open the directory `name` in `parent` for reading, without following
/// a symlink there.
pub(crate) fn open_dir(parent: BorrowedFd, name: &OsStr) -> Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(parent, name, flags, Mode::empty())
        .with_context(|| format!("opening {}", name.display()))
}
