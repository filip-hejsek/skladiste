//! Thin wrappers around the btrfs ioctls we need.

use std::ffi::OsStr;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rustix::fs::{Mode, OFlags};
use rustix::ioctl::{Setter, ioctl, opcode};

const BTRFS_IOCTL_MAGIC: u8 = 0x94;
const BTRFS_PATH_NAME_MAX: usize = 4087;

/// `struct btrfs_ioctl_vol_args`
#[repr(C)]
struct VolArgs {
    fd: i64,
    name: [u8; BTRFS_PATH_NAME_MAX + 1],
}

const SUBVOL_CREATE: rustix::ioctl::Opcode = opcode::write::<VolArgs>(BTRFS_IOCTL_MAGIC, 14);

/// Create a new subvolume at `path`. The parent directory must exist.
pub fn create_subvolume(path: &Path) -> Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .with_context(|| format!("invalid subvolume path {}", path.display()))?;
    let parent_fd = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {}", parent.display()))?;
    create_subvolume_at(parent_fd.as_fd(), name)
        .with_context(|| format!("creating subvolume {}", path.display()))
}

fn create_subvolume_at(parent: impl AsFd, name: &OsStr) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() > BTRFS_PATH_NAME_MAX {
        bail!("subvolume name too long");
    }
    let mut args = VolArgs {
        fd: 0,
        name: [0; BTRFS_PATH_NAME_MAX + 1],
    };
    args.name[..bytes.len()].copy_from_slice(bytes);
    // SAFETY: VolArgs matches the kernel's struct btrfs_ioctl_vol_args and the
    // opcode encodes its size and direction.
    let res = unsafe { ioctl(parent, Setter::<SUBVOL_CREATE, VolArgs>::new(args)) };
    match res {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::NOTTY) => bail!("not on a btrfs filesystem"),
        Err(e) => Err(e.into()),
    }
}
