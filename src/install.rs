//! Materialize packages from the store into a new image subvolume.
//!
//! All paths are resolved with `openat2(RESOLVE_IN_ROOT)`, so symlinks inside
//! the image (including absolute ones like `/bin -> usr/bin`) resolve relative
//! to the image root and can never reach the host filesystem.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry as MapEntry;
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};

use crate::btrfs;
use crate::manifest::{Entry, EntryKind, Hash, Package};
use crate::store::Store;
use crate::worker::{self, Workers};

pub(crate) mod install_worker;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub dirs: u64,
    pub files: u64,
    pub symlinks: u64,
    pub hardlinks: u64,
    /// Entries whose owner could not be set (e.g. running unprivileged).
    pub chown_failures: u64,
    /// Xattrs that could not be set (e.g. `security.*` without privileges).
    pub xattr_failures: u64,
}

/// Create a new subvolume named `name` in the directory `parent` and
/// install the packages with ids `packages` into it, in that order. A
/// path in two ordinary packages is an error, except directories, where
/// the first wins; an overlay ([`Package::overlay`]) replaces and removes
/// paths of the packages before it. The files are installed by a worker
/// that can access only the store and the new subvolume.
pub fn build(
    workers: &Workers,
    store: &Store,
    packages: &[Hash],
    parent: BorrowedFd,
    name: &OsStr,
) -> Result<Report> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.as_bytes().contains(&b'/'),
        "bad subvolume name {name:?}"
    );
    let packages = packages
        .iter()
        .map(|id| store.load_package(id))
        .collect::<Result<Vec<_>>>()?;
    let plan: Vec<&Entry> = merge(&packages)?.into_values().collect();
    btrfs::create_subvolume_at(parent, name).context("creating subvolume")?;
    let root = rustix::fs::openat(
        parent,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening the new subvolume")?;
    populate(workers, store, &plan, &root)
}

/// Install `plan` (sorted by path) into the empty directory `root`, in a
/// worker that can read only the store and write only beneath `root`. The store is bound read-only, so the worker can't
/// change metadata of its files either (Landlock doesn't restrict that).
fn populate(workers: &Workers, store: &Store, plan: &[&Entry], root: &OwnedFd) -> Result<Report> {
    use rustix::pipe::{PipeFlags, pipe_with};
    let (plan_r, plan_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
    let (result_r, result_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
    let dirs = [store.dir(), root.as_fd()];
    let w = workers.spawn(&install_worker::KIND, plan_r, result_w, &dirs, &[])?;
    // The worker reads the whole plan before it writes a result, unless
    // it fails; then its error message explains the broken pipe.
    let sent = worker::send_json(plan_w, plan);
    let result = worker::read_result(&mut File::from(result_r)).and_then(|json| {
        sent?;
        Ok(serde_json::from_slice(&json)?)
    });
    w.finish(result)
}

/// Combine the entries of `packages`, in order, into one path-sorted plan.
/// A path in two ordinary packages is an error, except directories, where
/// the first package to list one wins. An overlay (see
/// [`Package::overlay`]) removes its `removed` paths with everything
/// beneath them, and its entries replace what is at their paths; one
/// that isn't a directory replaces a directory with all its contents.
fn merge(packages: &[Package]) -> Result<BTreeMap<&str, &Entry>> {
    let mut plan: BTreeMap<&str, (&str, &Entry)> = BTreeMap::new();
    for pkg in packages {
        if let Some(overlay) = &pkg.overlay {
            for path in &overlay.removed {
                remove_tree(&mut plan, path);
            }
            for entry in &pkg.entries {
                let replaced = plan.insert(&entry.path, (&pkg.name, entry));
                if replaced.is_some_and(|(_, e)| e.kind == EntryKind::Dir)
                    && entry.kind != EntryKind::Dir
                {
                    remove_beneath(&mut plan, &entry.path);
                }
            }
            continue;
        }
        for entry in &pkg.entries {
            match plan.entry(&entry.path) {
                MapEntry::Vacant(v) => {
                    v.insert((&pkg.name, entry));
                }
                MapEntry::Occupied(o) => {
                    let (other_pkg, other) = o.get();
                    if !(other.kind == EntryKind::Dir && entry.kind == EntryKind::Dir) {
                        bail!(
                            "conflict: /{} exists in both {other_pkg} and {}",
                            entry.path,
                            pkg.name
                        );
                    }
                }
            }
        }
    }
    Ok(plan.into_iter().map(|(k, (_, e))| (k, e)).collect())
}

/// Remove `path` and everything beneath it from `plan`.
fn remove_tree<V>(plan: &mut BTreeMap<&str, V>, path: &str) {
    plan.remove(path);
    remove_beneath(plan, path);
}

/// Remove everything beneath `path` from `plan`.
fn remove_beneath<V>(plan: &mut BTreeMap<&str, V>, path: &str) {
    // Paths beneath sort between `path/` and `path0` ('0' follows '/').
    let (start, end) = (format!("{path}/"), format!("{path}0"));
    let beneath: Vec<&str> = plan
        .range::<str, _>((
            std::ops::Bound::Included(start.as_str()),
            std::ops::Bound::Excluded(end.as_str()),
        ))
        .map(|(k, _)| *k)
        .collect();
    for k in beneath {
        plan.remove(k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Content, Overlay};

    fn entry(path: &str, kind: EntryKind) -> Entry {
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

    fn file(path: &str, s: &str) -> Entry {
        let content = Content {
            hash: blake3::hash(s.as_bytes()).into(),
            size: s.len() as u64,
        };
        entry(path, EntryKind::File(content))
    }

    fn package(name: &str, entries: Vec<Entry>, removed: Option<&[&str]>) -> Package {
        Package {
            name: name.into(),
            version: "1".into(),
            entries,
            sections: BTreeMap::new(),
            overlay: removed.map(|r| Overlay {
                removed: r.iter().map(|p| (*p).to_owned()).collect(),
            }),
        }
    }

    fn short(s: &str) -> String {
        blake3::hash(s.as_bytes()).to_string()[..4].to_owned()
    }

    /// The plan's paths, with the start of the hash of files.
    fn summary(packages: &[Package]) -> Result<Vec<String>> {
        let plan = merge(packages)?;
        Ok(plan
            .values()
            .map(|e| match &e.kind {
                EntryKind::File(c) => format!("{} {}", e.path, &c.hash.to_string()[..4]),
                _ => e.path.clone(),
            })
            .collect())
    }

    #[test]
    fn ordinary_packages() {
        let dir = || entry("etc", EntryKind::Dir);
        let a = package("a", vec![dir(), file("etc/a", "a")], None);
        let b = package("b", vec![dir(), file("etc/b", "b")], None);
        assert_eq!(summary(&[a.clone(), b]).unwrap().len(), 3);
        let c = package("c", vec![file("etc/a", "c")], None);
        let e = summary(&[a, c]).unwrap_err().to_string();
        assert!(e.contains("conflict: /etc/a exists in both a and c"), "{e}");
    }

    #[test]
    fn overlays_replace_and_remove() {
        let base = package(
            "base",
            vec![
                entry("etc", EntryKind::Dir),
                file("etc/a", "a"),
                entry("usr", EntryKind::Dir),
                file("usr/b", "b"),
                entry("usr/lib", EntryKind::Dir),
                file("usr/lib/c", "c"),
                file("usr0", "d"),
            ],
            None,
        );
        let overlay = package(
            "scripts",
            vec![
                // Replaces the file; the directory "usr" stays with its
                // contents, but "usr/lib" becomes a file.
                file("etc/a", "new"),
                entry("usr", EntryKind::Dir),
                file("usr/lib", "lib"),
                file("var", "v"),
            ],
            Some(&["usr/b", "etc/gone"]),
        );
        assert_eq!(
            summary(&[base, overlay]).unwrap(),
            [
                "etc".to_owned(),
                format!("etc/a {}", short("new")),
                "usr".to_owned(),
                format!("usr/lib {}", short("lib")),
                format!("usr0 {}", short("d")),
                format!("var {}", short("v")),
            ]
        );
    }
}
