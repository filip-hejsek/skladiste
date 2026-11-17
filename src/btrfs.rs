//! Thin wrappers around the btrfs ioctls we need.

use std::ffi::OsStr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use rustix::ioctl::{Setter, ioctl, opcode};

const BTRFS_IOCTL_MAGIC: u8 = 0x94;
const BTRFS_PATH_NAME_MAX: usize = 4087;

/// `struct btrfs_ioctl_vol_args`
#[repr(C)]
struct VolArgs {
    fd: i64,
    name: [u8; BTRFS_PATH_NAME_MAX + 1],
}

const SNAP_CREATE: rustix::ioctl::Opcode = opcode::write::<VolArgs>(BTRFS_IOCTL_MAGIC, 1);
const SUBVOL_CREATE: rustix::ioctl::Opcode = opcode::write::<VolArgs>(BTRFS_IOCTL_MAGIC, 14);
const SNAP_DESTROY: rustix::ioctl::Opcode = opcode::write::<VolArgs>(BTRFS_IOCTL_MAGIC, 15);

/// Inode number of a subvolume's root directory.
const FIRST_FREE_OBJECTID: u64 = 256;

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
    vol_ioctl::<SUBVOL_CREATE>(parent.as_fd(), 0, name)
}

/// Create a writable snapshot of the subvolume whose root directory is
/// `source`, named `name` in the directory `parent` (on the same
/// filesystem). Inode numbers and ctimes are those of the source.
pub fn snapshot_at(source: BorrowedFd, parent: BorrowedFd, name: &OsStr) -> Result<()> {
    let stat = rustix::fs::fstat(source).context("stat")?;
    if stat.st_ino != FIRST_FREE_OBJECTID {
        bail!("not the root of a btrfs subvolume");
    }
    vol_ioctl::<SNAP_CREATE>(parent, source.as_raw_fd().into(), name)
}

/// How [`remove_subvolume_at`] removed a subvolume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// With `BTRFS_IOC_SNAP_DESTROY`, in a few ms.
    Destroyed,
    /// Entry by entry, since the ioctl was not allowed: without
    /// `CAP_SYS_ADMIN`, it needs the filesystem mounted with
    /// `user_subvol_rm_allowed`.
    EntryByEntry,
}

/// Mount option that lets users destroy subvolumes they could otherwise
/// only empty; see [`Removal`].
pub const USER_RM_OPTION: &str = "user_subvol_rm_allowed";

/// Remove the subvolume `name` in `parent` with all its contents: with
/// `BTRFS_IOC_SNAP_DESTROY` where allowed (with `CAP_SYS_ADMIN`, or by a
/// user who can write to the subvolume's root on a filesystem mounted with
/// [`USER_RM_OPTION`]), otherwise by removing every entry and then the
/// empty subvolume (0.84 s for 20,000 entries; the ioctl takes 2 ms).
/// Symlinks aren't followed.
pub fn remove_subvolume_at(parent: BorrowedFd, name: &OsStr) -> Result<Removal> {
    // EPERM: neither CAP_SYS_ADMIN nor the mount option.
    match vol_ioctl::<SNAP_DESTROY>(parent, 0, name) {
        Ok(()) => return Ok(Removal::Destroyed),
        Err(e) if e.downcast_ref::<Errno>() == Some(&Errno::PERM) => {}
        Err(e) => return Err(e),
    }
    let dir = open_dir(parent, name)?;
    remove_contents(&dir)?;
    drop(dir);
    rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR).context("removing subvolume")?;
    Ok(Removal::EntryByEntry)
}

fn open_dir(parent: BorrowedFd, name: &OsStr) -> Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(parent, name, flags, Mode::empty())
        .with_context(|| format!("opening {}", name.display()))
}

/// Remove everything in `dir`, making directories writable where needed
/// (as owner).
fn remove_contents(dir: &OwnedFd) -> Result<()> {
    let mut names = Vec::new();
    for entry in Dir::read_from(dir).context("reading directory")? {
        let entry = entry.context("reading directory")?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push((OsStr::from_bytes(name).to_owned(), entry.file_type()));
        }
    }
    let mut made_writable = false;
    for (name, file_type) in names {
        let is_dir = match file_type {
            FileType::Unknown => {
                let stat = rustix::fs::statat(dir, &name, AtFlags::SYMLINK_NOFOLLOW)?;
                FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            }
            t => t == FileType::Directory,
        };
        if is_dir {
            let sub = open_dir(dir.as_fd(), &name)?;
            remove_contents(&sub)?;
        }
        let flags = if is_dir {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        let mut res = rustix::fs::unlinkat(dir, &name, flags);
        if res == Err(Errno::ACCESS) && !made_writable {
            rustix::fs::fchmod(dir, Mode::RWXU).context("making directory writable")?;
            made_writable = true;
            res = rustix::fs::unlinkat(dir, &name, flags);
        }
        res.with_context(|| format!("removing {}", name.display()))?;
    }
    Ok(())
}

/// An ioctl taking `struct btrfs_ioctl_vol_args` on `dir`.
fn vol_ioctl<const OPCODE: rustix::ioctl::Opcode>(
    dir: BorrowedFd,
    fd: i64,
    name: &OsStr,
) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() > BTRFS_PATH_NAME_MAX {
        bail!("subvolume name too long");
    }
    let mut args = VolArgs {
        fd,
        name: [0; BTRFS_PATH_NAME_MAX + 1],
    };
    args.name[..bytes.len()].copy_from_slice(bytes);
    // SAFETY: VolArgs matches the kernel's struct btrfs_ioctl_vol_args and the
    // opcode encodes its size and direction.
    let res = unsafe { ioctl(dir, Setter::<OPCODE, VolArgs>::new(args)) };
    match res {
        Ok(()) => Ok(()),
        Err(Errno::NOTTY) => bail!("not on a btrfs filesystem"),
        Err(e) => Err(e.into()),
    }
}
