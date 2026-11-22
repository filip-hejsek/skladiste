//! The worker that installs files (see [`KIND`]).

use std::fs::File;
use std::io::BufReader;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result, bail};
use landlock::AccessFs;
use rustix::fs::{AtFlags, Gid, Mode, OFlags, ResolveFlags, Timespec, Timestamps, Uid, XattrFlags};
use rustix::io::Errno;

use super::Report;
use crate::manifest::{Content, Entry, EntryKind};
use crate::sandbox::{self, Policy};
use crate::store::Store;
use crate::worker::{self, Args, Caps, Kind};

/// The worker that installs files: fd 0 is the plan (JSON entries), fd 1 a
/// pipe for the result, and the store directory and image root are bound
/// at `/store` (read-only) and `/image`. It installs the files with
/// [`populate`], with read access to the store and write access to the
/// image.
pub(crate) const KIND: Kind = Kind {
    name: "install",
    dirs: &[
        worker::Dir {
            path: "/store",
            writable: false,
        },
        worker::Dir {
            path: "/image",
            writable: true,
        },
    ],
    // When skl runs as root: to set owners, then modes (including setuid
    // and setgid bits), times and xattrs (including `security.capability`)
    // of entries it no longer owns, and to create entries in directories
    // whose permissions don't allow it.
    caps: Caps {
        root: Some(&[
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_SETFCAP",
        ]),
        userns: &[],
    },
    main,
};

/// Address space limit of the worker, which holds the whole plan
/// (about 40 MiB were enough for an image of 17,000 entries).
const MAX_MEMORY: u64 = 4 << 30;

/// System calls the installer makes besides [`sandbox`]'s basic set.
const SYSCALLS: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_mkdirat,
    libc::SYS_symlinkat,
    libc::SYS_linkat,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_fchmod,
    libc::SYS_fsetxattr,
    libc::SYS_utimensat,
];

fn main(mut args: Args) -> Result<Vec<u8>> {
    args.no_extra()?;
    let [store, root] = args.dirs()?;
    let store = Store::from_dir(store);
    let image = AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSym
        | AccessFs::Refer;
    let policy = Policy {
        paths: vec![
            (store.dir(), AccessFs::ReadFile.into()),
            (root.as_fd(), image),
        ],
        syscalls: SYSCALLS,
        // Landlock doesn't restrict ioctls on regular files, and btrfs has
        // ioctls such as subvolume creation that work on any fd.
        ioctls: &[libc::FICLONE],
        max_memory: Some(MAX_MEMORY),
    };
    sandbox::confine(args.layers, &policy)?;
    // SAFETY: the supervisor passes the plan as fd 0.
    let plan = BufReader::new(unsafe { File::from_raw_fd(0) });
    let entries: Vec<Entry> = serde_json::from_reader(plan).context("reading plan")?;
    let report = populate(&store, entries.iter().collect(), root)?;
    Ok(serde_json::to_vec(&report)?)
}

/// Install `plan` (sorted by path) into the empty directory `root`. Uses only
/// the store's and the image's directory fds, so it runs in a worker
/// confined to them.
fn populate(store: &Store, plan: Vec<&Entry>, root: OwnedFd) -> Result<Report> {
    let mut inst = Installer {
        store,
        root,
        parent: None,
        report: Report::default(),
    };

    // Hard links go last because their targets may sort after them.
    let (hardlinks, others): (Vec<&Entry>, Vec<&Entry>) = plan
        .into_iter()
        .partition(|e| matches!(e.kind, EntryKind::Hardlink { .. }));
    let mut dirs = Vec::new();
    inst.create_all(others, |inst, entry| {
        match &entry.kind {
            EntryKind::Dir => {
                inst.create_dir(entry)?;
                dirs.push(entry);
            }
            EntryKind::File(_) => inst.create_file(entry)?,
            EntryKind::Symlink { target } => inst.create_symlink(entry, target)?,
            EntryKind::Hardlink { .. } => unreachable!(),
        }
        Ok(())
    })?;
    inst.create_all(hardlinks, |inst, entry| {
        let EntryKind::Hardlink { target } = &entry.kind else {
            unreachable!()
        };
        inst.create_hardlink(entry, target)
    })?;

    // Directory metadata is applied last, children before parents, so that
    // restrictive permissions and mtimes are not disturbed by later changes.
    inst.parent = None;
    for entry in dirs.iter().rev() {
        inst.finish_dir(entry)
            .with_context(|| format!("setting metadata of /{}", entry.path))?;
    }
    Ok(inst.report)
}

struct Installer<'a> {
    store: &'a Store,
    root: OwnedFd,
    /// Cached parent directory fd; consecutive entries usually share it.
    parent: Option<(String, OwnedFd)>,
    report: Report,
}

fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn timestamps(entry: &Entry) -> Timestamps {
    let t = Timespec {
        tv_sec: entry.mtime,
        tv_nsec: 0,
    };
    Timestamps {
        last_access: t,
        last_modification: t,
    }
}

/// The parent directory of an entry does not exist (yet).
#[derive(Debug)]
struct MissingParent(String);

impl std::fmt::Display for MissingParent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "parent directory /{} does not exist", self.0)
    }
}

impl std::error::Error for MissingParent {}

/// Errors that mean "not allowed in this environment" rather than a real failure.
fn is_permission_error(e: Errno) -> bool {
    matches!(
        e,
        Errno::PERM | Errno::INVAL | Errno::NOTSUP | Errno::ACCESS
    )
}

impl Installer<'_> {
    fn open_in_root(&self, path: &str, flags: OFlags) -> Result<OwnedFd, Errno> {
        let path = if path.is_empty() { "." } else { path };
        rustix::fs::openat2(
            &self.root,
            path,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
        )
    }

    /// Open the parent directory of `path` and return it with the final component.
    fn parent<'p>(&mut self, path: &'p str) -> Result<(&OwnedFd, &'p str)> {
        let (dir, name) = split(path);
        if !matches!(&self.parent, Some((p, _)) if p == dir) {
            let fd = match self.open_in_root(dir, OFlags::PATH | OFlags::DIRECTORY) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Err(MissingParent(dir.to_owned()).into()),
                Err(e) => {
                    return Err(e).with_context(|| format!("opening parent directory /{dir}"));
                }
            };
            self.parent = Some((dir.to_owned(), fd));
        }
        Ok((&self.parent.as_ref().unwrap().1, name))
    }

    /// Create `entries` in order. Entries whose parent directory is missing
    /// (e.g. because it is reached through a symlink to a path that sorts
    /// later) are retried until no more progress is made.
    fn create_all<'e>(
        &mut self,
        mut entries: Vec<&'e Entry>,
        mut create: impl FnMut(&mut Self, &'e Entry) -> Result<()>,
    ) -> Result<()> {
        loop {
            let mut deferred = Vec::new();
            let mut first_err = None;
            let count = entries.len();
            for entry in entries {
                match create(self, entry) {
                    Ok(()) => {}
                    Err(e) if e.is::<MissingParent>() => {
                        first_err.get_or_insert(e);
                        deferred.push(entry);
                    }
                    Err(e) => return Err(e.context(format!("installing /{}", entry.path))),
                }
            }
            if let Some(e) = first_err {
                if deferred.len() == count {
                    return Err(e.context(format!("installing /{}", deferred[0].path)));
                }
            } else {
                return Ok(());
            }
            // A newly created directory or symlink may have shadowed a cached
            // lookup result.
            self.parent = None;
            entries = deferred;
        }
    }

    fn chown(&mut self, res: Result<(), Errno>) -> Result<()> {
        match res {
            Err(e) if is_permission_error(e) => {
                self.report.chown_failures += 1;
                Ok(())
            }
            r => Ok(r.context("chown")?),
        }
    }

    fn set_xattrs(&mut self, fd: impl AsFd, entry: &Entry) -> Result<()> {
        for (name, value) in &entry.xattrs {
            match rustix::fs::fsetxattr(&fd, name.as_str(), &value.0, XattrFlags::empty()) {
                Ok(()) => {}
                Err(e) if is_permission_error(e) => self.report.xattr_failures += 1,
                Err(e) => return Err(e).with_context(|| format!("setting xattr {name}")),
            }
        }
        Ok(())
    }

    /// Apply owner, mode, xattrs and mtime to an open file or directory.
    /// Order matters: chown clears setuid bits and file capabilities.
    fn apply_metadata(&mut self, fd: &OwnedFd, entry: &Entry) -> Result<()> {
        let res = rustix::fs::fchown(
            fd,
            Some(Uid::from_raw(entry.uid)),
            Some(Gid::from_raw(entry.gid)),
        );
        self.chown(res)?;
        rustix::fs::fchmod(fd, Mode::from_raw_mode(entry.mode)).context("chmod")?;
        self.set_xattrs(fd, entry)?;
        rustix::fs::futimens(fd, &timestamps(entry)).context("setting mtime")?;
        Ok(())
    }

    fn create_dir(&mut self, entry: &Entry) -> Result<()> {
        let (parent, name) = self.parent(&entry.path)?;
        rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)).context("mkdir")?;
        self.report.dirs += 1;
        Ok(())
    }

    fn finish_dir(&mut self, entry: &Entry) -> Result<()> {
        let fd = self
            .open_in_root(
                &entry.path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            )
            .context("open")?;
        self.apply_metadata(&fd, entry)
    }

    fn create_file(&mut self, entry: &Entry) -> Result<()> {
        let EntryKind::File(Content { hash, .. }) = &entry.kind else {
            unreachable!()
        };
        let src = self.store.open_blob(hash)?;
        let (parent, name) = self.parent(&entry.path)?;
        let dst = rustix::fs::openat(
            parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .context("create")?;
        match rustix::fs::ioctl_ficlone(&dst, &src) {
            Ok(()) => {}
            Err(Errno::XDEV) => {
                bail!("reflink failed: store and image must be on the same btrfs filesystem")
            }
            Err(e) => return Err(e).context("reflink"),
        }
        self.apply_metadata(&dst, entry)?;
        self.report.files += 1;
        Ok(())
    }

    fn create_symlink(&mut self, entry: &Entry, target: &str) -> Result<()> {
        let (parent, name) = self.parent(&entry.path)?;
        rustix::fs::symlinkat(target, parent, name).context("symlink")?;
        let res = rustix::fs::chownat(
            parent,
            name,
            Some(Uid::from_raw(entry.uid)),
            Some(Gid::from_raw(entry.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        );
        let ts = timestamps(entry);
        let (parent, name) = self.parent(&entry.path)?;
        rustix::fs::utimensat(parent, name, &ts, AtFlags::SYMLINK_NOFOLLOW)
            .context("setting mtime")?;
        self.chown(res)?;
        self.report.symlinks += 1;
        Ok(())
    }

    fn create_hardlink(&mut self, entry: &Entry, target: &str) -> Result<()> {
        let (target_dir, target_name) = split(target);
        let target_parent = self
            .open_in_root(target_dir, OFlags::PATH | OFlags::DIRECTORY)
            .with_context(|| format!("opening /{target_dir}"))?;
        let (parent, name) = self.parent(&entry.path)?;
        rustix::fs::linkat(&target_parent, target_name, parent, name, AtFlags::empty())
            .with_context(|| format!("linking to /{target}"))?;
        self.report.hardlinks += 1;
        Ok(())
    }
}
