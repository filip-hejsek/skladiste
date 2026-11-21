//! Garbage collection: removing the blobs and objects that nothing refers
//! to.
//!
//! The roots are small files holding an id, outside `objects/`:
//! - `packages/<repo>/<key>`, the package indexes;
//! - `synthetic/<spec>`, the synthetic cache, which keeps both the build
//!   spec it is named by and the synthetic package it holds;
//! - `repos/<repo>/syncs/<time>`, the sync records, of which
//!   [`Options::keep_syncs`] can drop all but the latest.
//!
//! From the roots, the GC follows the references in objects' headers
//! ([`object::read_header`]), never reading a body, so it needs no
//! knowledge of any format's sections. Every blob and object that isn't
//! reached is removed. A root or reached object that is missing or can't
//! be read stops the GC before it removes anything: what such an object
//! refers to is unknown.
//!
//! The GC needs the store's lock exclusively ([`Store::open_exclusive`]),
//! so no other process can add a blob or object, find one present, or
//! record a reference while it decides what is garbage. That also makes
//! everything in `tmp/` a leftover of a process that was killed: named
//! files that replace others, and snapshots of
//! [`crate::run::run_captured`], which it removes too.
//!
//! Removing a blob frees only the extents no image shares: images are
//! reflinked copies, which keep their own references to the data.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io::BufReader;
use std::num::NonZeroUsize;
use std::os::fd::AsFd;

use anyhow::{Context, Result, ensure};
use rustix::fs::{AtFlags, FileType, OFlags};
use rustix::io::Errno;

use super::{Store, object_name};
use crate::btrfs;
use crate::manifest::Hash;
use crate::object::{self, Ref};

/// What [`Store::gc`] removes besides unreferenced contents.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Keep only the latest this many sync records of each repo (by fetch
    /// time), removing older ones and with them the databases only they
    /// refer to. `None` keeps them all.
    pub keep_syncs: Option<NonZeroUsize>,
    /// Only count what would be removed.
    pub dry_run: bool,
}

/// Counts of the files in `blobs/` or `objects/`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub kept: u64,
    pub removed: u64,
    /// The size of the removed files: more than is freed if images share
    /// their extents.
    pub removed_bytes: u64,
}

/// What [`Store::gc`] removed (or would remove, with
/// [`Options::dry_run`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Sync records removed by [`Options::keep_syncs`].
    pub syncs: u64,
    pub objects: Counts,
    pub blobs: Counts,
    /// Leftovers removed from `tmp/`.
    pub tmp: u64,
}

/// A root: the file it is in, and the object it names.
struct Root {
    file: String,
    id: Hash,
}

/// What is reached from the roots.
#[derive(Default)]
struct Live {
    objects: HashSet<Hash>,
    blobs: HashSet<Hash>,
}

impl Store {
    /// Remove the blobs and objects that no root refers to, directly or
    /// through other objects, and leftovers in `tmp/` (see the module
    /// documentation). The store must have been opened with
    /// [`Store::open_exclusive`].
    pub fn gc(&self, options: &Options) -> Result<Report> {
        ensure!(
            self.exclusive,
            "garbage collection needs the store opened exclusively"
        );
        let mut roots = Vec::new();
        self.index_roots("packages", &mut roots)?;
        self.synthetic_roots(&mut roots)?;
        let dropped = self.sync_roots(options.keep_syncs, &mut roots)?;
        let live = self.mark(&roots)?;

        let dry_run = options.dry_run;
        if !dry_run {
            // Roots first: if the GC is interrupted, what they kept is
            // garbage next time.
            for file in &dropped {
                rustix::fs::unlinkat(&self.dir, file.as_str(), AtFlags::empty())
                    .with_context(|| format!("removing {file}"))?;
            }
        }
        Ok(Report {
            syncs: dropped.len() as u64,
            objects: self.sweep("objects", &live.objects, dry_run)?,
            blobs: self.sweep("blobs", &live.blobs, dry_run)?,
            tmp: self.clean_tmp(dry_run)?,
        })
    }

    /// Entries of the directory `path` with their types, unsorted.
    fn typed_entries(&self, path: &str) -> Result<Vec<(String, FileType)>> {
        let mut entries = Vec::new();
        for name in self.list_dir(path)? {
            let full = format!("{path}/{name}");
            let stat = rustix::fs::statat(&self.dir, full.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .with_context(|| format!("checking {full}"))?;
            entries.push((name, FileType::from_raw_mode(stat.st_mode)));
        }
        Ok(entries)
    }

    /// Every file below the directory `path` as a root (the package
    /// indexes: `packages/@FORMAT/REPO/KEY`).
    fn index_roots(&self, path: &str, roots: &mut Vec<Root>) -> Result<()> {
        for (name, kind) in self.typed_entries(path)? {
            let file = format!("{path}/{name}");
            if kind == FileType::Directory {
                self.index_roots(&file, roots)?;
            } else {
                roots.push(self.root(file)?);
            }
        }
        Ok(())
    }

    /// The synthetic cache: each entry keeps the build spec it is named by
    /// and the package it holds.
    fn synthetic_roots(&self, roots: &mut Vec<Root>) -> Result<()> {
        for name in self.list_dir("synthetic")? {
            let file = format!("synthetic/{name}");
            let spec = parse_id(&name).with_context(|| format!("{file} isn't named by an id"))?;
            roots.push(self.root(file.clone())?);
            roots.push(Root { file, id: spec });
        }
        Ok(())
    }

    /// The sync records of every repo, except the older ones beyond
    /// `keep` per repo, which are returned (by file).
    fn sync_roots(&self, keep: Option<NonZeroUsize>, roots: &mut Vec<Root>) -> Result<Vec<String>> {
        let mut dropped = Vec::new();
        for (namespace, kind) in self.typed_entries("repos")? {
            if kind != FileType::Directory {
                continue;
            }
            for (name, kind) in self.typed_entries(&format!("repos/{namespace}"))? {
                let dir = format!("repos/{namespace}/{name}/syncs");
                if kind != FileType::Directory {
                    continue;
                }
                let mut syncs = match self.list_dir(&dir) {
                    Ok(syncs) => syncs,
                    Err(e) if e.root_cause().downcast_ref() == Some(&Errno::NOENT) => continue,
                    Err(e) => return Err(e),
                };
                // Fixed-width times: sorted by name is sorted by time.
                syncs.sort();
                let old = keep.map_or(0, |n| syncs.len().saturating_sub(n.get()));
                for (i, sync) in syncs.into_iter().enumerate() {
                    let file = format!("{dir}/{sync}");
                    if i < old {
                        dropped.push(file);
                    } else {
                        roots.push(self.root(file)?);
                    }
                }
            }
        }
        Ok(dropped)
    }

    /// The root in `file`, which must hold an id.
    fn root(&self, file: String) -> Result<Root> {
        let id = self
            .read_id(&file)?
            .with_context(|| format!("{file} disappeared"))?;
        Ok(Root { file, id })
    }

    /// Everything reachable from `roots`.
    fn mark(&self, roots: &[Root]) -> Result<Live> {
        let mut live = Live::default();
        // Objects still to read, with what refers to them (for messages).
        let mut stack = Vec::new();
        for root in roots {
            if live.objects.insert(root.id) {
                stack.push((root.id, root.file.clone()));
            }
        }
        while let Some((id, from)) = stack.pop() {
            let refs = self
                .read_header(&id)
                .with_context(|| format!("following {from}"))?;
            for r in refs {
                match r {
                    Ref::Blob(blob) => {
                        live.blobs.insert(blob);
                    }
                    Ref::Object(obj) => {
                        if live.objects.insert(obj) {
                            stack.push((obj, format!("object {id}")));
                        }
                    }
                }
            }
        }
        Ok(live)
    }

    /// The references in the header of object `id`, reading nothing of
    /// its body.
    fn read_header(&self, id: &Hash) -> Result<Vec<Ref>> {
        let name = object_name(id);
        let fd = self
            .openat(&name, OFlags::RDONLY, 0)
            .with_context(|| format!("opening object {id}"))?;
        object::read_header(&mut BufReader::new(File::from(fd)))
            .with_context(|| format!("reading object {id}"))
    }

    /// Remove the files in `base/ab/cdef…` (`blobs` or `objects`) whose
    /// hash isn't in `live`. Names that aren't a hash in the store's form
    /// are left alone.
    fn sweep(&self, base: &str, live: &HashSet<Hash>, dry_run: bool) -> Result<Counts> {
        let mut counts = Counts::default();
        for sub in self.list_dir(base)? {
            if sub.len() != 2 || !sub.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let dir = format!("{base}/{sub}");
            let mut removed_all = true;
            for name in self.list_dir(&dir)? {
                let file = format!("{dir}/{name}");
                let hash = match parse_id(&format!("{sub}{name}")) {
                    Some(hash) if !live.contains(&hash) => hash,
                    Some(_) => {
                        counts.kept += 1;
                        removed_all = false;
                        continue;
                    }
                    None => {
                        removed_all = false;
                        continue;
                    }
                };
                let stat = rustix::fs::statat(&self.dir, file.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .with_context(|| format!("checking {file}"))?;
                if !dry_run {
                    rustix::fs::unlinkat(&self.dir, file.as_str(), AtFlags::empty())
                        .with_context(|| format!("removing {base} {hash}"))?;
                }
                counts.removed += 1;
                counts.removed_bytes += stat.st_size as u64;
            }
            if removed_all && !dry_run {
                // `publish` creates it again when needed.
                match rustix::fs::unlinkat(&self.dir, dir.as_str(), AtFlags::REMOVEDIR) {
                    Ok(()) | Err(Errno::NOTEMPTY) => {}
                    Err(e) => return Err(e).with_context(|| format!("removing {dir}")),
                }
            }
        }
        Ok(counts)
    }

    /// Remove what killed processes left in `tmp/`: named files, and
    /// snapshots (`snapshot-*`), which are subvolumes. Anything else is
    /// left alone.
    fn clean_tmp(&self, dry_run: bool) -> Result<u64> {
        let tmp = self.tmp_dir()?;
        let mut removed = 0;
        for (name, kind) in self.typed_entries("tmp")? {
            let remove = match kind {
                FileType::RegularFile => true,
                FileType::Directory => name.starts_with("snapshot-"),
                _ => false,
            };
            if !remove {
                continue;
            }
            if !dry_run {
                let result = if kind == FileType::Directory {
                    btrfs::remove_subvolume_at(tmp.as_fd(), OsStr::new(&name)).map(drop)
                } else {
                    rustix::fs::unlinkat(&tmp, name.as_str(), AtFlags::empty()).map_err(Into::into)
                };
                result.with_context(|| format!("removing tmp/{name}"))?;
            }
            removed += 1;
        }
        Ok(removed)
    }
}

/// The hash `s` names, if `s` is one in the store's form (lowercase hex).
fn parse_id(s: &str) -> Option<Hash> {
    let hash: Hash = s.parse().ok()?;
    (hash.to_string() == s).then_some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::SyncRecord;
    use crate::store::InUse;
    use serde_json::json;
    use std::path::Path;

    fn blob(store: &Store, content: &str) -> Hash {
        store.add_blob(&mut content.as_bytes()).unwrap().hash
    }

    fn object(store: &Store, refs: &[Ref]) -> Hash {
        let body = json!((0..refs.len()).map(|i| json!({"#": i})).collect::<Vec<_>>());
        store.add_object(refs, &body).unwrap()
    }

    fn sync(store: &Store, db: Hash, fetched: &str) {
        let record = SyncRecord {
            hash: db,
            size: 1,
            url: "http://example.com/core.db".to_owned(),
            fetched: fetched.to_owned(),
            last_modified: None,
            etag: None,
            validator: None,
        };
        store.save_sync("@arch/core", &record).unwrap();
    }

    fn has_blob(store: &Store, hash: &Hash) -> bool {
        store.open_blob(hash).is_ok()
    }

    fn has_object(store: &Store, hash: &Hash) -> bool {
        store.read_object(hash).is_ok()
    }

    fn exclusive(path: &Path) -> Store {
        Store::open_exclusive_path(path).unwrap()
    }

    fn in_use<T>(r: Result<T>) -> bool {
        r.err().unwrap().root_cause().downcast_ref() == Some(&InUse)
    }

    #[test]
    fn removes_what_no_root_reaches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let (kept_blobs, kept_objects, dead_blobs, dead_objects);
        {
            let store = Store::init_path(path).unwrap();
            let [a, b, c, d, old_db, new_db, spec_blob] =
                ["a", "b", "c", "d", "old db", "new db", "spec"].map(|s| blob(&store, s));
            // A package, through the index, refers to `a` and an object
            // that refers to `b` (and to `a` again).
            let inner = object(&store, &[Ref::Blob(b), Ref::Blob(a)]);
            let pkg = object(&store, &[Ref::Blob(a), Ref::Object(inner)]);
            store.index_package("@arch/core", &c, &pkg).unwrap();
            // The synthetic cache keeps the spec and the package.
            let spec = object(&store, &[Ref::Blob(spec_blob)]);
            let synthetic = object(&store, &[Ref::Blob(d)]);
            store.save_synthetic(&spec, &synthetic).unwrap();
            store.add_repo("@arch/core", &json!({})).unwrap();
            sync(&store, old_db, "2026-01-01T00:00:00.000000Z");
            sync(&store, new_db, "2026-02-01T00:00:00.000000Z");
            // Garbage: an object nothing refers to, with a blob only it
            // refers to, and `c` (an index key, not a reference).
            let e = blob(&store, "e");
            let garbage = object(&store, &[Ref::Blob(e), Ref::Object(pkg)]);
            kept_blobs = vec![a, b, d, spec_blob, new_db];
            kept_objects = vec![inner, pkg, spec, synthetic];
            dead_blobs = vec![c, e, old_db];
            dead_objects = vec![garbage];
            std::fs::write(path.join("tmp/123-0"), "left over").unwrap();
            // Not an exclusive store.
            assert!(store.gc(&Options::default()).is_err());
        }

        let store = exclusive(path);
        let options = Options {
            keep_syncs: NonZeroUsize::new(1),
            dry_run: true,
        };
        let dry = store.gc(&options).unwrap();
        assert_eq!(dry.syncs, 1);
        assert_eq!(dry.tmp, 1);
        // The objects are also the two sync records, one of them dropped.
        assert_eq!((dry.objects.kept, dry.objects.removed), (5, 2));
        assert_eq!((dry.blobs.kept, dry.blobs.removed), (5, 3));
        assert_eq!(dry.blobs.removed_bytes, 1 + 1 + 6);
        for b in dead_blobs.iter().chain(&kept_blobs) {
            assert!(has_blob(&store, b));
        }
        assert!(path.join("tmp/123-0").exists());

        let report = store
            .gc(&Options {
                dry_run: false,
                ..options.clone()
            })
            .unwrap();
        assert_eq!(report, dry);
        for b in &kept_blobs {
            assert!(has_blob(&store, b));
        }
        for b in &dead_blobs {
            assert!(!has_blob(&store, b));
        }
        for o in &kept_objects {
            assert!(has_object(&store, o));
        }
        for o in &dead_objects {
            assert!(!has_object(&store, o));
        }
        assert!(!path.join("tmp/123-0").exists());
        assert_eq!(
            store.latest_sync("@arch/core").unwrap().unwrap().hash,
            kept_blobs[4]
        );
        let syncs = std::fs::read_dir(path.join("repos/@arch/core/syncs")).unwrap();
        assert_eq!(syncs.count(), 1);

        // Nothing more to remove.
        let again = store.gc(&Options::default()).unwrap();
        assert_eq!((again.syncs, again.objects.removed), (0, 0));
        assert_eq!((again.blobs.removed, again.tmp), (0, 0));
        assert_eq!((again.objects.kept, again.blobs.kept), (5, 5));
    }

    #[test]
    fn missing_object_stops_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let store = Store::init_path(path).unwrap();
        let a = blob(&store, "a");
        let lost = object(&store, &[Ref::Blob(a)]);
        let pkg = object(&store, &[Ref::Object(lost)]);
        store.index_package("@arch/core", &a, &pkg).unwrap();
        let garbage = blob(&store, "garbage");
        drop(store);
        std::fs::remove_file(path.join(object_name(&lost))).unwrap();

        let store = exclusive(path);
        let e = store.gc(&Options::default()).err().unwrap();
        assert!(format!("{e:#}").contains(&format!("object {pkg}")), "{e:#}");
        assert!(has_blob(&store, &garbage));
        assert!(has_blob(&store, &a));
    }

    #[test]
    fn exclusive_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let shared = Store::init_path(path).unwrap();
        assert!(in_use(Store::open_exclusive_path(path)));
        // Shared locks don't exclude each other.
        let other = Store::open_path(path).unwrap();
        drop(shared);
        assert!(in_use(Store::open_exclusive_path(path)));
        drop(other);
        let store = exclusive(path);
        assert!(in_use(Store::open_exclusive_path(path)));
        assert!(in_use(Store::migrate_path(path, true)));
        drop(store);
        exclusive(path);
    }
}
