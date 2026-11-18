//! Changes between two trees: what a program run in an image changed,
//! compared with a snapshot taken before (see [`crate::run::run_captured`]).
//!
//! The snapshot keeps the inode numbers and ctimes of the image. Every
//! change to an inode (content, owner, mode, xattrs, times, links) sets its
//! ctime to the current time, which a sandboxed program can't set back, so
//! an entry is unchanged if it has the same inode number, type and ctime as
//! the entry at the same path in the snapshot. Only directories that
//! changed (their ctime moves when entries are added, removed or renamed)
//! are listed in the snapshot to find removed entries. The caller must make
//! sure that no inode changed in the image within the clock tick in which
//! the snapshot was taken (see [`crate::run::run_captured`]), or a change
//! could leave the ctime as it was.
//!
//! [`diff`] reads the image's contents, which are untrusted after package
//! code ran there, so `skl` runs it in a worker that only reads both trees
//! and streams new file contents to an [`BlobSink`], like an import
//! ([`diff_in_worker`]). The supervisor [validates](validate) the result.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result, bail, ensure};
use landlock::AccessFs;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::manifest::{BlobId, Content, Entry, EntryKind, Overlay, XattrValue, is_normal_path};
use crate::sandbox::{self, Policy};
use crate::store::{BlobSink, Store};
use crate::worker::{self, Args, Caps, ImportStats, Kind, RemoteSink, Workers};

/// The worker that compares trees: fd 0 is unused, fd 1 a socket, and the
/// tree before (a snapshot) and after are bound read-only at `/old` and
/// `/new`. It compares them with [`diff`] and streams the new contents to
/// the supervisor like an import; `DONE` holds the changes, which refer to
/// blobs by position. Read access to both trees, no ioctls.
pub(crate) const DIFF_WORKER: Kind = Kind {
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
    main: diff_main,
};

/// Address space limit of the diff worker, which holds the changes.
const DIFF_MAX_MEMORY: u64 = 1 << 30;

/// System calls the diff worker makes besides [`sandbox`]'s basic set.
const DIFF_SYSCALLS: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_getdents64,
    libc::SYS_newfstatat,
    libc::SYS_fstat,
    libc::SYS_statx,
    libc::SYS_readlinkat,
    libc::SYS_flistxattr,
    libc::SYS_fgetxattr,
];

/// Compare the tree `new` with `old` (see [`diff`]) in a worker that can
/// only read both, adding new file contents to `store`. The returned
/// changes are checked.
pub fn diff_in_worker(
    workers: &Workers,
    store: &Store,
    old: BorrowedFd,
    new: BorrowedFd,
) -> Result<(Vec<Change>, ImportStats)> {
    let (ours, theirs) = worker::stream_socket()?;
    let null = File::open("/dev/null").context("opening /dev/null")?;
    let w = workers.spawn(&DIFF_WORKER, null.into(), theirs, &[old, new], &[])?;
    let mut conn = worker::receiver(ours)?;
    let result = worker::receive_blobs(store, &mut conn).and_then(|(blobs, json, stats)| {
        let changes: Vec<Change<BlobId>> =
            serde_json::from_slice(&json).context("parsing changes from worker")?;
        let changes = changes
            .into_iter()
            .map(|c| c.resolve(&blobs))
            .collect::<Result<Vec<_>>>()?;
        validate(&changes)?;
        Ok((changes, stats))
    });
    drop(conn);
    w.finish(result)
}

fn diff_main(mut args: Args) -> Result<Vec<u8>> {
    args.no_extra()?;
    let [old, new] = args.dirs()?;
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let policy = Policy {
        paths: vec![(old.as_fd(), read), (new.as_fd(), read)],
        syscalls: DIFF_SYSCALLS,
        max_memory: Some(DIFF_MAX_MEMORY),
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

/// One change to an image. An added or modified entry replaces whatever was
/// at its path before, including a directory's contents; its new contents
/// are listed as entries of their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Change<F = Content> {
    /// An entry where the path didn't exist before.
    Added(Entry<F>),
    /// An entry that changed, or was replaced by another one.
    Modified(Entry<F>),
    /// A path that no longer exists, with everything beneath it.
    Removed(String),
}

impl<F> Change<F> {
    /// The path the change is about.
    pub fn path(&self) -> &str {
        match self {
            Change::Added(e) | Change::Modified(e) => &e.path,
            Change::Removed(path) => path,
        }
    }

    fn entry(&self) -> Option<&Entry<F>> {
        match self {
            Change::Added(e) | Change::Modified(e) => Some(e),
            Change::Removed(_) => None,
        }
    }
}

impl Change<BlobId> {
    /// Replace blob ids with the content they refer to; see
    /// [`Entry::resolve`].
    pub fn resolve(self, blobs: &[Content]) -> Result<Change> {
        Ok(match self {
            Change::Added(e) => Change::Added(e.resolve(blobs)?),
            Change::Modified(e) => Change::Modified(e.resolve(blobs)?),
            Change::Removed(path) => Change::Removed(path),
        })
    }
}

/// The entries and removals of an overlay package that makes `changes`
/// (see [`Overlay`]): added and modified entries replace what was at their
/// paths, and removed paths go with everything beneath them.
pub fn overlay(changes: Vec<Change>) -> (Vec<Entry>, Overlay) {
    let mut entries = Vec::new();
    let mut removed = Vec::new();
    for change in changes {
        match change {
            Change::Added(e) | Change::Modified(e) => entries.push(e),
            Change::Removed(path) => removed.push(path),
        }
    }
    (entries, Overlay { removed })
}

/// Check changes from a worker: valid entries, each path at most once,
/// and hard links only to a file entry that comes earlier. The image root
/// itself is never among the changes.
pub fn validate<F>(changes: &[Change<F>]) -> Result<()> {
    let mut paths = BTreeSet::new();
    let mut files = BTreeSet::new();
    for change in changes {
        let path = change.path();
        match change.entry() {
            Some(entry) => entry.validate()?,
            None => ensure!(is_normal_path(path)?, "invalid path: {path:?}"),
        }
        ensure!(paths.insert(path), "/{path} changed twice");
        match change.entry().map(|e| &e.kind) {
            Some(EntryKind::File(_)) => {
                files.insert(path);
            }
            Some(EntryKind::Hardlink { target }) => ensure!(
                files.contains(target.as_str()),
                "/{path}: hard link to /{target}, which isn't a file changed before"
            ),
            _ => {}
        }
    }
    Ok(())
}

/// Compare the tree `new` with `old` (both root directories, `new` a
/// changed copy of `old`, e.g. a snapshot) and return the changes in
/// path order (removals of a directory's entries after its other
/// changes). The contents of added and modified files are added to
/// `blobs`. Hard links are reported as a file entry for the first path
/// and hard link entries for the others. Symlinks aren't followed.
///
/// Fails on file types the manifest can't describe (devices, FIFOs,
/// sockets), on paths that aren't UTF-8, and on mount points or nested
/// subvolumes in `new`. Changes to the root directory itself are not
/// reported.
pub fn diff(old: OwnedFd, new: OwnedFd, blobs: &mut impl BlobSink) -> Result<Vec<Change<BlobId>>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, kind: EntryKind<BlobId>) -> Entry<BlobId> {
        Entry {
            path: path.into(),
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: BTreeMap::new(),
        }
    }

    #[test]
    fn validate_changes() {
        let file = |p| Change::Added(entry(p, EntryKind::File(BlobId { blob: 0 })));
        let link = |p, t: &str| {
            Change::Added(entry(
                p,
                EntryKind::Hardlink {
                    target: t.to_owned(),
                },
            ))
        };
        let removed = |p: &str| Change::Removed(p.to_owned());
        assert!(validate(&[file("a"), link("b", "a"), removed("c")]).is_ok());
        assert!(validate(&[link("b", "a"), file("a")]).is_err());
        assert!(validate(&[removed("a"), link("b", "a")]).is_err());
        assert!(validate(&[file("a"), removed("a")]).is_err());
        for bad in ["", "/a", "a/", "a/../b"] {
            assert!(validate(&[removed(bad)]).is_err(), "{bad:?}");
            assert!(validate(&[file(bad)]).is_err(), "{bad:?}");
        }
    }
}
