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
//! The image's contents are untrusted after package code ran there, so
//! [`diff`] compares the trees in a worker that only reads both and
//! streams new file contents to the supervisor, like an import. The
//! supervisor [validates](validate) the result.

use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::BorrowedFd;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::manifest::{BlobId, Content, Entry, EntryKind, Overlay, is_normal_path};
use crate::store::Store;
use crate::worker::{self, ImportStats, Workers};

pub(crate) mod diff_worker;

/// Compare the tree `new` with `old` (both root directories, `new` a
/// changed copy of `old`, e.g. a snapshot) and return the changes in
/// path order (removals of a directory's entries after its other
/// changes). The contents of added and modified files are added to
/// `store`. Hard links are reported as a file entry for the first path
/// and hard link entries for the others. Symlinks aren't followed.
///
/// Fails on file types the manifest can't describe (devices, FIFOs,
/// sockets), on paths that aren't UTF-8, and on mount points or nested
/// subvolumes in `new`. Changes to the root directory itself are not
/// reported.
///
/// The trees are compared in a worker that can only read both. The
/// returned changes are checked.
pub fn diff(
    workers: &Workers,
    store: &Store,
    old: BorrowedFd,
    new: BorrowedFd,
) -> Result<(Vec<Change>, ImportStats)> {
    let (ours, theirs) = worker::stream_socket()?;
    let null = File::open("/dev/null").context("opening /dev/null")?;
    let w = workers.spawn(&diff_worker::KIND, null.into(), theirs, &[old, new], &[])?;
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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
