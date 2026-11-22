//! The worker that compares trees (see [`KIND`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result, bail, ensure};
use landlock::AccessFs;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use super::Change;
use crate::manifest::{BlobId, Entry, EntryKind, XattrValue};
use crate::sandbox::{self, Policy};
use crate::store::BlobSink;
use crate::worker::{self, Args, Caps, Kind, RemoteSink};

/// The worker that compares trees: fd 0 is unused, fd 1 a socket, and the
/// tree before (a snapshot) and after are bound read-only at `/old` and
/// `/new`. It compares them with [`diff`] and streams the new contents to
/// the supervisor like an import; `DONE` holds the changes, which refer to
/// blobs by position. Read access to both trees, no ioctls.
pub(crate) const KIND: Kind = Kind {
    name: "diff",
    dirs: &[
        worker::Dir {
            path: "/old",
            writable: false,
        },
        worker::Dir {
            path: "/new",
            writable: false,
        },
    ],
    // To read every file and directory regardless of permissions (in a
    // new user namespace, those owned by skl's uid and gid).
    caps: Caps {
        root: Some(&["CAP_DAC_READ_SEARCH"]),
        userns: &["CAP_DAC_READ_SEARCH"],
    },
    main,
};

/// Address space limit of the worker, which holds the changes.
const MAX_MEMORY: u64 = 1 << 30;

/// System calls the worker makes besides [`sandbox`]'s basic set.
const SYSCALLS: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_getdents64,
    libc::SYS_newfstatat,
    libc::SYS_fstat,
    libc::SYS_statx,
    libc::SYS_readlinkat,
    libc::SYS_flistxattr,
    libc::SYS_fgetxattr,
];

fn main(mut args: Args) -> Result<Vec<u8>> {
    args.no_extra()?;
    let [old, new] = args.dirs()?;
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let policy = Policy {
        paths: vec![(old.as_fd(), read), (new.as_fd(), read)],
        syscalls: SYSCALLS,
        max_memory: Some(MAX_MEMORY),
        ..Policy::default()
    };
    sandbox::confine(args.layers, &policy)?;
    // The directories were opened with O_PATH; reading them needs real fds.
    let reopen = |fd: OwnedFd| {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        rustix::fs::openat(&fd, ".", flags, Mode::empty()).context("opening directory")
    };
    let changes = diff(reopen(old)?, reopen(new)?, &mut RemoteSink::new(args.out))?;
    Ok(serde_json::to_vec(&changes)?)
}

/// What [`super::diff`] does, in the worker: compare the trees, adding
/// the contents of added and modified files to `blobs`.
fn diff(old: OwnedFd, new: OwnedFd, blobs: &mut impl BlobSink) -> Result<Vec<Change<BlobId>>> {
    let old_root = rustix::fs::fstat(&old).context("stat")?;
    let new_root = rustix::fs::fstat(&new).context("stat")?;
    let mut walk = Walk {
        blobs,
        changes: Vec::new(),
        links: HashMap::new(),
        old_dev: old_root.st_dev,
        new_dev: new_root.st_dev,
    };
    let root_changed = !same_inode(&old_root, &new_root);
    walk.dir(&new, Some(&old), "", root_changed)?;
    Ok(walk.changes)
}

struct Walk<'a, S> {
    blobs: &'a mut S,
    changes: Vec<Change<BlobId>>,
    /// Inode numbers of the files with more than one link reported so far,
    /// and their first path.
    links: HashMap<u64, String>,
    old_dev: u64,
    new_dev: u64,
}

/// Same inode, unchanged since the snapshot was taken.
fn same_inode(old: &Stat, new: &Stat) -> bool {
    old.st_ino == new.st_ino
        && old.st_mode & libc::S_IFMT == new.st_mode & libc::S_IFMT
        && old.st_ctime == new.st_ctime
        && old.st_ctime_nsec == new.st_ctime_nsec
}

fn is_dir(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
}

impl<S: BlobSink> Walk<'_, S> {
    /// Compare the directory `new` at `path` with `old` (the directory at
    /// the same path before, if there was one). `changed`: whether
    /// entries may have been added or removed in it.
    fn dir(
        &mut self,
        new: &OwnedFd,
        old: Option<&OwnedFd>,
        path: &str,
        changed: bool,
    ) -> Result<()> {
        let names = list(new).with_context(|| format!("listing /{path}"))?;
        for name in &names {
            let child = join(path, name)?;
            let stat = rustix::fs::statat(new, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW)
                .with_context(|| format!("stat /{child}"))?;
            ensure!(
                stat.st_dev == self.new_dev,
                "/{child} is a mount point or subvolume"
            );
            let before = match old {
                Some(old) => stat_old(old, name).with_context(|| format!("stat old /{child}"))?,
                None => None,
            };
            let unchanged = before.as_ref().is_some_and(|b| same_inode(b, &stat));
            if !unchanged {
                let entry = self
                    .entry(new.as_fd(), name, &child, &stat)
                    .with_context(|| format!("reading /{child}"))?;
                self.changes.push(match before {
                    None => Change::Added(entry),
                    Some(_) => Change::Modified(entry),
                });
            }
            if is_dir(&stat) {
                let sub_new = open_dir(new.as_fd(), name)?;
                let sub_old = match (old, &before) {
                    (Some(old), Some(b)) if is_dir(b) => {
                        ensure!(
                            b.st_dev == self.old_dev,
                            "old /{child} is a mount point or subvolume"
                        );
                        Some(open_dir(old.as_fd(), name)?)
                    }
                    _ => None,
                };
                self.dir(&sub_new, sub_old.as_ref(), &child, !unchanged)?;
            }
        }
        if let (true, Some(old)) = (changed, old) {
            let names: BTreeSet<&[u8]> = names.iter().map(|n| n.as_bytes()).collect();
            for name in list(old).with_context(|| format!("listing old /{path}"))? {
                if !names.contains(name.as_bytes()) {
                    self.changes.push(Change::Removed(join(path, &name)?));
                }
            }
        }
        Ok(())
    }

    /// The entry for `name` in `dir`, with the content of a file added to
    /// the blob sink.
    fn entry(
        &mut self,
        dir: BorrowedFd,
        name: &OsStr,
        path: &str,
        stat: &Stat,
    ) -> Result<Entry<BlobId>> {
        let mut xattrs = BTreeMap::new();
        let kind = match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let fd = open_dir(dir, name)?;
                xattrs = read_xattrs(&fd)?;
                EntryKind::Dir
            }
            FileType::RegularFile => {
                if let Some(target) = self.links.get(&stat.st_ino) {
                    EntryKind::Hardlink {
                        target: target.clone(),
                    }
                } else {
                    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                    let fd =
                        rustix::fs::openat(dir, name, flags, Mode::empty()).context("opening")?;
                    let opened = rustix::fs::fstat(&fd).context("stat")?;
                    ensure!(opened.st_ino == stat.st_ino, "replaced while reading");
                    xattrs = read_xattrs(&fd)?;
                    let size = opened.st_size as u64;
                    let blob = self.blobs.add_blob(size, &mut File::from(fd))?;
                    if stat.st_nlink > 1 {
                        self.links.insert(stat.st_ino, path.to_owned());
                    }
                    EntryKind::File(blob)
                }
            }
            FileType::Symlink => {
                let target = rustix::fs::readlinkat(dir, name, Vec::new()).context("readlink")?;
                let target = target
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("symlink target is not UTF-8"))?;
                EntryKind::Symlink { target }
            }
            other => bail!("unsupported file type {other:?}"),
        };
        Ok(Entry {
            path: path.to_owned(),
            kind,
            mode: stat.st_mode & 0o7777,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mtime: stat.st_mtime,
            xattrs,
        })
    }
}

/// The entry `name` in the old tree, if there is one.
fn stat_old(dir: &OwnedFd, name: &OsStr) -> Result<Option<Stat>> {
    match rustix::fs::statat(dir, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat)),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Names in a directory, sorted, without `.` and `..`.
fn list(dir: &OwnedFd) -> Result<Vec<Box<OsStr>>> {
    let mut names = Vec::new();
    // Not `Dir::read_from`, which calls `fcntl(F_GETFL)`: the worker's
    // seccomp filter allows only `F_GETFD`.
    for entry in Dir::new(open_dir(dir.as_fd(), OsStr::new("."))?)? {
        let name = entry?.file_name().to_bytes().to_owned();
        if name != b"." && name != b".." {
            names.push(OsStr::from_bytes(&name).into());
        }
    }
    names.sort();
    Ok(names)
}

fn open_dir(dir: BorrowedFd, name: &OsStr) -> Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(dir, name, flags, Mode::empty())
        .with_context(|| format!("opening {}", name.display()))
}

fn join(dir: &str, name: &OsStr) -> Result<String> {
    let name = name
        .to_str()
        .with_context(|| format!("/{dir}: name {name:?} is not UTF-8"))?;
    Ok(if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    })
}

fn read_xattrs(fd: &OwnedFd) -> Result<BTreeMap<String, XattrValue>> {
    let mut xattrs = BTreeMap::new();
    let len = rustix::fs::flistxattr_query(fd).context("listing xattrs")?;
    if len == 0 {
        return Ok(xattrs);
    }
    let mut list = vec![0u8; len];
    let len = rustix::fs::flistxattr(fd, &mut list[..]).context("listing xattrs")?;
    for name in list[..len].split(|&b| b == 0).filter(|n| !n.is_empty()) {
        let name = std::str::from_utf8(name).context("xattr name is not UTF-8")?;
        let len = rustix::fs::fgetxattr_query(fd, name)
            .with_context(|| format!("reading xattr {name}"))?;
        let mut value = vec![0u8; len];
        let len = rustix::fs::fgetxattr(fd, name, &mut value[..])
            .with_context(|| format!("reading xattr {name}"))?;
        value.truncate(len);
        xattrs.insert(name.to_owned(), XattrValue(value));
    }
    Ok(xattrs)
}
