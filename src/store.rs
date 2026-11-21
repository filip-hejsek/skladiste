//! Content-addressed store of blobs (file contents) and objects.
//!
//! Layout:
//! - `skl-store.json` — the store manifest ([`StoreManifest`]): marks the
//!   directory as a store and records the version of the store format
//! - `blobs/ab/cdef…` — file contents, named by BLAKE3 hash, read-only
//! - `objects/ab/cdef…` — skl's own records ([`crate::object`]), named by
//!   their address, read-only
//! - `packages/<repo>/<key>` — each repo's package index: the id of a
//!   package (its manifest object, see [`Package`]) by a key of the
//!   frontend's, e.g. the hash of the archive it was imported from
//!   (packages imported from files or URLs belong to their format's
//!   pseudo-repo `@FORMAT/@local`, see [`repo::LOCAL`])
//! - `synthetic/<spec>` — the id of the synthetic package that running
//!   package code made for a build spec ([`crate::spec`])
//! - `downloads/<repo>/<name>` — downloaded package archives (and their
//!   signatures), by repo and file name
//! - `repos/<repo>/config.json` — a repo's configuration (see
//!   [`crate::repo`]); its format is the frontend's
//! - `repos/<repo>/syncs/<time>` — the id of a record of each version of
//!   the repo's database that was fetched ([`SyncRecord`], an object); the
//!   database itself is a blob
//! - `keyrings/@FORMAT` — the id of the record of a format's keyring, the
//!   keys its packages are verified with (an object of the frontend's,
//!   e.g. [`crate::arch::keyring`]); created when the first is set
//! - `tmp/` — staging area for files being written: unnamed
//!   (`O_TMPFILE`) until complete and checked, except files that are
//!   replaced (index entries, the store manifest)
//!
//! `<repo>` is the repo's id `@FORMAT/NAME` (see [`repo::id`]), so it is
//! two directory levels, e.g. `repos/@arch/core/`.
//!
//! A new store is set up with [`Store::init`], an existing one opened with
//! [`Store::open`], which accepts only a store of the format version this
//! skl uses (see [`format`](mod@format) and [`Store::migrate`]); they take the store's
//! directory fd ([`Store::init_path`] and [`Store::open_path`]
//! open it from a path). Every access is relative to that fd, so the store
//! also works from a sandboxed process that was handed only the fd.
//!
//! An open store holds a lock on its directory (`flock`): shared, or
//! exclusive for garbage collection ([`Store::open_exclusive`],
//! [`Store::gc`]) and migrations, which then fail with [`InUse`] if
//! another process uses the store.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::manifest::{BlobId, Hash, Package};
use crate::object::{self, Object, Ref};
use crate::repo::{self, SyncRecord};
use crate::spec::BuildSpec;

pub mod format;
pub mod gc;

use format::{FORMATS, Formats};
pub use format::{FormatVersion, VersionProblem, WrongVersion};

pub struct Store {
    dir: OwnedFd,
    tmp_counter: AtomicU64,
    /// Whether this holds the store's lock exclusively (see [`lock`]).
    exclusive: bool,
}

/// The error when the store's lock is needed exclusively (by
/// [`Store::open_exclusive`] or [`Store::migrate`]) but another process
/// uses the store (found with [`anyhow::Error::downcast_ref`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InUse;

impl std::fmt::Display for InUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the store is in use by another process")
    }
}

impl std::error::Error for InUse {}

/// Take the store's lock: a `flock` on the store's directory, held until
/// every fd of that open directory is closed (also those passed to
/// workers). Every [`Store`] holds it shared, waiting while it is held
/// exclusively; the GC and migrations hold it exclusively, and fail with
/// [`InUse`] rather than wait. So nothing adds to the store while the GC
/// decides what is garbage, and nothing uses the store during a migration.
fn lock(dir: impl AsFd, exclusive: bool) -> Result<()> {
    use rustix::fs::FlockOperation;
    let op = if exclusive {
        FlockOperation::NonBlockingLockExclusive
    } else {
        FlockOperation::LockShared
    };
    match rustix::fs::flock(dir, op) {
        Ok(()) => Ok(()),
        Err(Errno::WOULDBLOCK) => Err(InUse.into()),
        Err(e) => Err(e).context("locking the store"),
    }
}

/// What [`Store::migrate`] did: `from` and `to` are equal if the store
/// already had the current version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migrated {
    pub from: FormatVersion,
    pub to: FormatVersion,
}

/// Result of adding one blob.
pub struct Added {
    pub hash: Hash,
    pub size: u64,
    /// False if an identical blob was already present.
    pub new: bool,
}

/// Destination for file contents found while importing a package.
///
/// Frontends write through this instead of using [`Store`] directly, so they
/// can run in a sandboxed process that has no access to the store. The sink
/// returns no hash, so a sink in another process needn't wait for the
/// receiver: the receiver hashes the content and resolves the returned ids
/// (see [`Package::resolve`](crate::manifest::Package::resolve)).
pub trait BlobSink {
    /// Add a blob of `size` bytes; `content` must yield exactly that.
    fn add_blob(&mut self, size: u64, content: &mut dyn Read) -> Result<BlobId>;
}

impl<T: BlobSink + ?Sized> BlobSink for &mut T {
    fn add_blob(&mut self, size: u64, content: &mut dyn Read) -> Result<BlobId> {
        (**self).add_blob(size, content)
    }
}

/// Why a directory isn't a store: the error of [`Store::open`] and
/// [`Store::open_path`] (found with [`anyhow::Error::downcast_ref`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAStore {
    /// There is nothing at the path.
    Missing,
    /// What is at the path isn't a directory.
    NotADirectory,
    /// The directory is empty.
    Empty,
    /// The directory isn't empty but has no store manifest (`skl-store.json`).
    NoManifest,
    /// A directory of the layout is missing (or isn't a directory).
    NoSubdir(&'static str),
}

impl std::fmt::Display for NotAStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotAStore::Missing => write!(f, "not a store: it doesn't exist"),
            NotAStore::NotADirectory => write!(f, "not a store: it isn't a directory"),
            NotAStore::Empty => write!(f, "not a store: it is empty"),
            NotAStore::NoManifest => write!(f, "not a store: it has no {MANIFEST}"),
            NotAStore::NoSubdir(sub) => write!(f, "not a store: it has no {sub}/ directory"),
        }
    }
}

impl std::error::Error for NotAStore {}

impl NotAStore {
    /// Whether [`Store::init_path`] would make it a store: it refuses a
    /// non-empty directory without a manifest and what isn't a directory.
    pub fn can_init(self) -> bool {
        match self {
            NotAStore::Missing | NotAStore::Empty | NotAStore::NoSubdir(_) => true,
            NotAStore::NotADirectory | NotAStore::NoManifest => false,
        }
    }
}

fn open_dir(path: &Path) -> Result<OwnedFd, Errno> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// The name of the store manifest.
const MANIFEST: &str = "skl-store.json";

/// The version of the store format this skl uses.
pub fn format_version() -> FormatVersion {
    FORMATS.current()
}

/// The store manifest, `skl-store.json` in the store's directory.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreManifest {
    /// The version of the store format.
    pub version: FormatVersion,
}

impl StoreManifest {
    fn to_json(&self) -> Result<Vec<u8>> {
        let mut data = serde_json::to_vec_pretty(self)?;
        data.push(b'\n');
        Ok(data)
    }
}

/// The directories of a store, see the module documentation.
const SUBDIRS: [&str; 7] = [
    "blobs",
    "objects",
    "packages",
    "synthetic",
    "downloads",
    "repos",
    "tmp",
];

fn mkdir_exist_ok(dir: impl AsFd, path: &str) -> Result<(), Errno> {
    match rustix::fs::mkdirat(dir, path, Mode::from_raw_mode(0o755)) {
        Err(Errno::EXIST) => Ok(()),
        r => r,
    }
}

/// Read and check the store manifest of `dir`, if it has one: fails with
/// [`WrongVersion`] if the store isn't of the version this skl uses.
fn read_manifest(dir: impl AsFd) -> Result<Option<StoreManifest>> {
    let manifest = read_manifest_unchecked(dir)?;
    if let Some(manifest) = &manifest {
        FORMATS.ensure_current(&manifest.version)?;
    }
    Ok(manifest)
}

/// Read the store manifest of `dir`, if it has one, whatever its version.
fn read_manifest_unchecked(dir: impl AsFd) -> Result<Option<StoreManifest>> {
    let fd = match rustix::fs::openat(
        dir,
        MANIFEST,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("opening {MANIFEST}")),
    };
    let mut data = Vec::new();
    File::from(fd)
        .read_to_end(&mut data)
        .with_context(|| format!("reading {MANIFEST}"))?;
    let manifest: StoreManifest =
        serde_json::from_slice(&data).with_context(|| format!("parsing {MANIFEST}"))?;
    Ok(Some(manifest))
}

/// Write the store manifest into `dir`, as an unnamed file linked into
/// place, so it is never seen incomplete. If a concurrent init wrote it
/// first, check that one.
fn write_manifest(dir: impl AsFd) -> Result<()> {
    let dir = dir.as_fd();
    let fd = rustix::fs::openat(
        dir,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .with_context(|| format!("creating {MANIFEST}"))?;
    let data = StoreManifest {
        version: format_version(),
    }
    .to_json()?;
    let mut file = File::from(fd);
    file.write_all(&data)
        .with_context(|| format!("writing {MANIFEST}"))?;
    match link_unnamed(&file, dir, MANIFEST) {
        Ok(()) => Ok(()),
        Err(Errno::EXIST) => read_manifest(dir).map(drop),
        Err(e) => Err(e).with_context(|| format!("linking {MANIFEST}")),
    }
}

/// Whether the directory `dir` has no entries.
fn is_empty(dir: impl AsFd) -> Result<bool> {
    for entry in rustix::fs::Dir::read_from(dir).context("reading the directory")? {
        let entry = entry.context("reading the directory")?;
        if ![&b"."[..], b".."].contains(&entry.file_name().to_bytes()) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Give the unnamed file `fd` the name `dest` in `dir`; fails with
/// `EEXIST` if the name is taken. Linking by the fd itself
/// (`AT_EMPTY_PATH`) needs `CAP_DAC_READ_SEARCH`, so this goes through
/// `/proc`.
fn link_unnamed(fd: impl AsFd, dir: impl AsFd, dest: &str) -> Result<(), Errno> {
    use std::os::fd::AsRawFd;
    let path = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());
    rustix::fs::linkat(rustix::fs::CWD, &path, dir, dest, AtFlags::SYMLINK_FOLLOW)
}

fn blob_name(hash: &Hash) -> String {
    let hex = hash.to_string();
    format!("blobs/{}/{}", &hex[..2], &hex[2..])
}

fn object_name(hash: &Hash) -> String {
    let hex = hash.to_string();
    format!("objects/{}/{}", &hex[..2], &hex[2..])
}

/// Largest object accepted when reading.
const MAX_OBJECT: u64 = 1 << 30;

/// `keyrings/@<format>`.
fn keyring_name(format: &str) -> Result<String> {
    repo::check_format(format)?;
    Ok(format!("keyrings/@{format}"))
}

/// `packages/<repo>/<key>`.
fn index_name(repo: &str, key: &Hash) -> Result<String> {
    repo::check_id(repo)?;
    Ok(format!("packages/{repo}/{key}"))
}

impl Store {
    /// Make the directory `dir` a store and use it. `dir` must be empty or
    /// already a store of the format version this skl uses; then the parts of the layout
    /// that are missing are created.
    pub fn init(dir: OwnedFd) -> Result<Store> {
        lock(&dir, false)?;
        // Emptiness is checked before the manifest: the manifest is the
        // first entry an init creates, so a concurrent init can't make a
        // directory found non-empty lack it.
        if is_empty(&dir)? {
            // The manifest comes first, so an interrupted init can be
            // repeated; until the layout is complete, `open` fails.
            write_manifest(&dir)?;
        } else {
            anyhow::ensure!(
                read_manifest(&dir)?.is_some(),
                "the directory isn't empty and has no {MANIFEST}, so it isn't a store"
            );
        }
        for sub in SUBDIRS {
            mkdir_exist_ok(&dir, sub).with_context(|| format!("creating {sub}/"))?;
        }
        Ok(Store::from_dir(dir))
    }

    /// Use the store in the directory `dir`, which [`Store::init`] has set
    /// up. Fails with [`NotAStore`] if it hasn't, and with
    /// [`WrongVersion`] if the store isn't of the format version this skl
    /// uses. Waits while another process holds the store exclusively (as
    /// [`Store::open_exclusive`] and [`Store::migrate`] do).
    pub fn open(dir: OwnedFd) -> Result<Store> {
        Store::open_locked(dir, false)
    }

    /// [`Store::open`], holding the store's lock exclusively, as the GC
    /// needs: fails with [`InUse`] if another process uses the store.
    pub fn open_exclusive(dir: OwnedFd) -> Result<Store> {
        Store::open_locked(dir, true)
    }

    fn open_locked(dir: OwnedFd, exclusive: bool) -> Result<Store> {
        lock(&dir, exclusive)?;
        // Emptiness first, as in `init`.
        if is_empty(&dir)? {
            return Err(NotAStore::Empty.into());
        }
        if read_manifest(&dir)?.is_none() {
            return Err(NotAStore::NoManifest.into());
        }
        for sub in SUBDIRS {
            match rustix::fs::statat(&dir, sub, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(s) if FileType::from_raw_mode(s.st_mode) == FileType::Directory => {}
                Ok(_) | Err(Errno::NOENT) => return Err(NotAStore::NoSubdir(sub).into()),
                Err(e) => return Err(e).with_context(|| format!("checking {sub}/")),
            }
        }
        let mut store = Store::from_dir(dir);
        store.exclusive = exclusive;
        Ok(store)
    }

    /// [`Store::init`] for the directory at `path`, which is created if
    /// needed (with its parents). A convenience for callers that have
    /// paths, such as the CLI.
    pub fn init_path(path: &Path) -> Result<Store> {
        std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
        let dir = open_dir(path).with_context(|| format!("opening {}", path.display()))?;
        Store::init(dir).with_context(|| format!("setting up the store in {}", path.display()))
    }

    /// [`Store::open`] for the directory at `path`. Fails with
    /// [`NotAStore`] also if there is no directory at `path`.
    pub fn open_path(path: &Path) -> Result<Store> {
        Store::open_path_locked(path, false)
    }

    /// [`Store::open_exclusive`] for the directory at `path`, as
    /// [`Store::open_path`].
    pub fn open_exclusive_path(path: &Path) -> Result<Store> {
        Store::open_path_locked(path, true)
    }

    fn open_path_locked(path: &Path, exclusive: bool) -> Result<Store> {
        let dir = match open_dir(path) {
            Ok(dir) => Ok(dir),
            Err(Errno::NOENT) => Err(NotAStore::Missing.into()),
            Err(Errno::NOTDIR) => Err(NotAStore::NotADirectory.into()),
            Err(e) => Err(anyhow::Error::from(e)),
        };
        dir.and_then(|dir| Store::open_locked(dir, exclusive))
            .with_context(|| format!("opening the store {}", path.display()))
    }

    /// Migrate the store in the directory `dir` to the format version this
    /// skl uses. Migrating a store of the latest stable version to a
    /// development version needs `allow_dev`: afterwards only builds of
    /// that development version can open it. Fails with [`WrongVersion`]
    /// if the store can't be migrated, and with [`InUse`] if another
    /// process uses the store (the migration holds its lock exclusively).
    pub fn migrate(dir: OwnedFd, allow_dev: bool) -> Result<Migrated> {
        Store::migrate_formats(dir, &FORMATS, allow_dev)
    }

    fn migrate_formats(dir: OwnedFd, formats: &Formats, allow_dev: bool) -> Result<Migrated> {
        lock(&dir, true)?;
        if is_empty(&dir)? {
            return Err(NotAStore::Empty.into());
        }
        let Some(manifest) = read_manifest_unchecked(&dir)? else {
            return Err(NotAStore::NoManifest.into());
        };
        let from = manifest.version;
        let store = Store::from_dir(dir);
        for step in formats.plan(&from, allow_dev)? {
            (step.migration)(store.dir())
                .with_context(|| format!("migrating the store to format version {}", step.to))?;
            let data = StoreManifest { version: step.to }.to_json()?;
            store.write_replace(MANIFEST, &data)?;
        }
        Ok(Migrated {
            from,
            to: formats.current(),
        })
    }

    /// [`Store::migrate`] for the directory at `path`.
    pub fn migrate_path(path: &Path, allow_dev: bool) -> Result<Migrated> {
        let dir = open_dir(path).with_context(|| format!("opening {}", path.display()))?;
        Store::migrate(dir, allow_dev)
            .with_context(|| format!("migrating the store {}", path.display()))
    }

    /// Use an already open store directory, e.g. one passed to a worker.
    /// Takes no lock: the process that opened it holds it.
    pub fn from_dir(dir: OwnedFd) -> Store {
        Store {
            dir,
            tmp_counter: AtomicU64::new(0),
            exclusive: false,
        }
    }

    /// The store's directory, e.g. for passing to a worker process.
    pub fn dir(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
    }

    fn openat(&self, path: &str, flags: OFlags, mode: u32) -> Result<OwnedFd, Errno> {
        rustix::fs::openat(
            &self.dir,
            path,
            flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(mode),
        )
    }

    /// Open a blob for reading.
    pub fn open_blob(&self, hash: &Hash) -> Result<OwnedFd> {
        let name = blob_name(hash);
        self.openat(&name, OFlags::RDONLY, 0)
            .with_context(|| format!("opening store blob {name}"))
    }

    /// Stream `content` into the store, returning its hash.
    /// Safe to call from several threads and processes at once: if the
    /// same blob is added concurrently, one of them adds it and the
    /// others report it as already present.
    pub fn add_blob(&self, content: &mut dyn Read) -> Result<Added> {
        let mut file = File::from(self.unnamed_file(0o600)?);
        let mut writer = HashingWriter {
            inner: &mut file,
            hasher: blake3::Hasher::new(),
        };
        let size = io::copy(content, &mut writer).context("writing blob")?;
        let hash: Hash = writer.hasher.finalize().into();

        let new = self.publish(&file, &blob_name(&hash))?;
        Ok(Added { hash, size, new })
    }

    /// Make the unnamed file `file` the read-only content-addressed file
    /// `dest` unless that exists already; returns whether it didn't.
    fn publish(&self, file: &File, dest: &str) -> Result<bool> {
        match rustix::fs::statat(&self.dir, dest, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Ok(false),
            Err(Errno::NOENT) => {}
            Err(e) => return Err(e).with_context(|| format!("checking {dest}")),
        }
        rustix::fs::fchmod(file, Mode::from_raw_mode(0o444))?;
        let (subdir, _) = dest.rsplit_once('/').unwrap();
        mkdir_exist_ok(&self.dir, subdir).with_context(|| format!("creating {subdir}"))?;
        // Another thread or process may have added the same file since
        // the check above; linking never replaces it.
        match self.link(file, dest) {
            Ok(()) => Ok(true),
            Err(Errno::EXIST) => Ok(false),
            Err(e) => Err(e).with_context(|| format!("linking {dest}")),
        }
    }

    /// Write the object with `body`, whose references are indexes into
    /// `refs`, in canonical form (see [`object::encode`]), and return its
    /// address. Safe to call concurrently, as [`Store::add_blob`].
    pub fn add_object(&self, refs: &[Ref], body: &serde_json::Value) -> Result<Hash> {
        let data = object::encode(refs, body)?;
        let hash = object::address(&data);
        let dest = object_name(&hash);
        if rustix::fs::statat(&self.dir, &dest, AtFlags::SYMLINK_NOFOLLOW).is_ok() {
            return Ok(hash);
        }
        let mut file = File::from(self.unnamed_file(0o600)?);
        file.write_all(&data).context("writing object")?;
        self.publish(&file, &dest)?;
        Ok(hash)
    }

    /// Read the object with address `hash`, checking that its bytes have
    /// that address and that its references are within its header.
    pub fn read_object(&self, hash: &Hash) -> Result<Object> {
        let name = object_name(hash);
        let fd = self
            .openat(&name, OFlags::RDONLY, 0)
            .with_context(|| format!("opening object {hash}"))?;
        let mut data = Vec::new();
        File::from(fd)
            .take(MAX_OBJECT + 1)
            .read_to_end(&mut data)
            .with_context(|| format!("reading object {hash}"))?;
        ensure!(
            data.len() as u64 <= MAX_OBJECT,
            "object {hash} is larger than {MAX_OBJECT} bytes"
        );
        ensure!(
            object::address(&data) == *hash,
            "object {hash} is corrupt: its content has another address"
        );
        object::decode(&data).with_context(|| format!("reading object {hash}"))
    }

    /// Create an unnamed file in `tmp/`, which is freed when closed unless
    /// it is saved.
    pub fn tmp_file(&self) -> Result<TmpFile<'_>> {
        Ok(TmpFile {
            store: self,
            file: File::from(self.unnamed_file(0o644)?),
        })
    }

    /// An `O_TMPFILE` in `tmp/`: nothing is left behind if the process is
    /// killed, and nobody can open it by name while it's being written.
    fn unnamed_file(&self, mode: u32) -> Result<OwnedFd> {
        self.openat("tmp", OFlags::RDWR | OFlags::TMPFILE, mode)
            .context("creating a file in tmp")
    }

    /// Give the unnamed file `fd` the name `dest`; fails with `EEXIST` if
    /// the name is taken (see [`link_unnamed`]).
    fn link(&self, fd: impl AsFd, dest: &str) -> Result<(), Errno> {
        link_unnamed(fd, &self.dir, dest)
    }

    /// Open `downloads/<repo>/<name>`, if it exists.
    pub fn open_download(&self, repo: &str, name: &str) -> Result<Option<File>> {
        let path = download_path(repo, name)?;
        match self.openat(&path, OFlags::RDONLY, 0) {
            Ok(fd) => Ok(Some(File::from(fd))),
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("opening {path}")),
        }
    }

    /// A name in `tmp/` unique among all processes using the store.
    fn tmp_name(&self) -> String {
        format!("tmp/{}", self.unique_name())
    }

    /// A name unique among all processes using the store, for an entry in
    /// [`Store::tmp_dir`].
    pub(crate) fn unique_name(&self) -> String {
        format!(
            "{}-{}",
            std::process::id(),
            self.tmp_counter.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// The `tmp/` directory, for entries named by [`Store::unique_name`].
    pub(crate) fn tmp_dir(&self) -> Result<OwnedFd> {
        self.openat("tmp", OFlags::RDONLY | OFlags::DIRECTORY, 0)
            .context("opening tmp")
    }

    /// Read a whole file, if it exists.
    fn read_file(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let fd = match self.openat(name, OFlags::RDONLY, 0) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("opening {name}")),
        };
        let mut data = Vec::new();
        File::from(fd)
            .read_to_end(&mut data)
            .with_context(|| format!("reading {name}"))?;
        Ok(Some(data))
    }

    fn read_json<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let Some(data) = self.read_file(name)? else {
            return Ok(None);
        };
        let value = serde_json::from_slice(&data).with_context(|| format!("parsing {name}"))?;
        Ok(Some(value))
    }

    /// Write `name` through a named file in `tmp/`, replacing any file
    /// there. Concurrent writes of the same file don't interfere; one of
    /// them wins.
    fn write_replace(&self, name: &str, data: &[u8]) -> Result<()> {
        let tmp = self.tmp_name();
        let fd = self
            .openat(&tmp, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL, 0o644)
            .with_context(|| format!("creating {tmp}"))?;
        let result = File::from(fd)
            .write_all(data)
            .with_context(|| format!("writing {tmp}"))
            .and_then(|()| {
                rustix::fs::renameat(&self.dir, &tmp, &self.dir, name)
                    .with_context(|| format!("moving {tmp} to {name}"))
            });
        if result.is_err() {
            let _ = rustix::fs::unlinkat(&self.dir, &tmp, AtFlags::empty());
        }
        result
    }

    /// Add the package manifest `pkg` as an object, after checking it, and
    /// return its address: the package's id.
    pub fn add_package(&self, pkg: &Package) -> Result<Hash> {
        pkg.validate()?;
        let (refs, body) = pkg.to_object()?;
        self.add_object(refs.as_slice(), &body)
    }

    /// The package with id `id`.
    pub fn load_package(&self, id: &Hash) -> Result<Package> {
        let obj = self.read_object(id)?;
        let pkg = Package::from_object(&obj).with_context(|| format!("reading package {id}"))?;
        pkg.validate()
            .with_context(|| format!("checking package {id}"))?;
        Ok(pkg)
    }

    /// The id of the package that `repo`'s index has under `key` (e.g.
    /// the hash of the archive it was made from), if any.
    pub fn indexed_package(&self, repo: &str, key: &Hash) -> Result<Option<Hash>> {
        self.read_id(&index_name(repo, key)?)
    }

    /// The id in the file `name`, if it exists.
    fn read_id(&self, name: &str) -> Result<Option<Hash>> {
        let Some(data) = self.read_file(name)? else {
            return Ok(None);
        };
        let id = std::str::from_utf8(&data)
            .ok()
            .and_then(|s| s.trim_ascii_end().parse().ok())
            .with_context(|| format!("{name} doesn't hold an id"))?;
        Ok(Some(id))
    }

    /// Write the build spec `spec` as an object, returning its id.
    pub fn add_build_spec(&self, spec: &BuildSpec) -> Result<Hash> {
        let (refs, body) = spec.to_object()?;
        self.add_object(refs.as_slice(), &body)
    }

    /// The id of the synthetic package recorded for the build spec
    /// `spec`, if any.
    pub fn synthetic(&self, spec: &Hash) -> Result<Option<Hash>> {
        self.read_id(&format!("synthetic/{spec}"))
    }

    /// Record `id` as the synthetic package of the build spec `spec`,
    /// replacing what was recorded before.
    pub fn save_synthetic(&self, spec: &Hash, id: &Hash) -> Result<()> {
        self.write_replace(&format!("synthetic/{spec}"), format!("{id}\n").as_bytes())
    }

    /// The id of the record of package format `format`'s keyring, if one
    /// was set.
    pub fn keyring(&self, format: &str) -> Result<Option<Hash>> {
        self.read_id(&keyring_name(format)?)
    }

    /// Make the object `id` the record of `format`'s keyring, replacing the
    /// one before.
    pub fn set_keyring(&self, format: &str, id: &Hash) -> Result<()> {
        let name = keyring_name(format)?;
        mkdir_exist_ok(&self.dir, "keyrings").context("creating keyrings")?;
        self.write_replace(&name, format!("{id}\n").as_bytes())
    }

    /// The keys in `repo`'s package index with the ids they hold, sorted
    /// by key.
    pub fn package_index(&self, repo: &str) -> Result<Vec<(Hash, Hash)>> {
        repo::check_id(repo)?;
        let dir = format!("packages/{repo}");
        if let Err(Errno::NOENT) = rustix::fs::statat(&self.dir, &dir, AtFlags::empty()) {
            return Ok(Vec::new());
        }
        let mut keys: Vec<Hash> = self
            .list_dir(&dir)?
            .iter()
            .filter_map(|n| n.parse().ok())
            .collect();
        keys.sort();
        let mut index = Vec::new();
        for key in keys {
            if let Some(id) = self.indexed_package(repo, &key)? {
                index.push((key, id));
            }
        }
        Ok(index)
    }

    /// Record the package `id` under `key` in `repo`'s package index,
    /// replacing what was there. Concurrent writes of the same key don't
    /// interfere; one of them wins.
    pub fn index_package(&self, repo: &str, key: &Hash, id: &Hash) -> Result<()> {
        let name = index_name(repo, key)?;
        mkdir_repo(&self.dir, "packages", repo)?;
        self.write_replace(&name, format!("{id}\n").as_bytes())
    }

    /// Remove `key` from `repo`'s package index. Returns whether it was
    /// there. The package's contents stay until [`Store::gc`].
    pub fn unindex_package(&self, repo: &str, key: &Hash) -> Result<bool> {
        let name = index_name(repo, key)?;
        remove_file(&self.dir, &name)
    }

    /// The names in `downloads/<repo>/`, sorted.
    pub fn downloads(&self, repo: &str) -> Result<Vec<String>> {
        repo::check_id(repo)?;
        let dir = format!("downloads/{repo}");
        if let Err(Errno::NOENT) = rustix::fs::statat(&self.dir, &dir, AtFlags::empty()) {
            return Ok(Vec::new());
        }
        let mut names = self.list_dir(&dir)?;
        names.sort();
        Ok(names)
    }

    /// Remove `downloads/<repo>/<name>`. Returns whether it was there.
    pub fn remove_download(&self, repo: &str, name: &str) -> Result<bool> {
        remove_file(&self.dir, &download_path(repo, name)?)
    }

    /// Add the repo with id `name` with `config` (in the frontend's
    /// format). Fails if the repo exists, or is a pseudo-repo.
    pub fn add_repo(&self, name: &str, config: &impl Serialize) -> Result<()> {
        let (format, repo_name) = repo::split_id(name)?;
        repo::check_name(repo_name)?;
        let parent = format!("repos/@{format}");
        mkdir_exist_ok(&self.dir, &parent).with_context(|| format!("creating {parent}"))?;
        let dir = format!("repos/{name}");
        match rustix::fs::mkdirat(&self.dir, &dir, Mode::from_raw_mode(0o755)) {
            Ok(()) => {}
            Err(Errno::EXIST) => bail!("repo {name} already exists"),
            Err(e) => return Err(e).with_context(|| format!("creating {dir}")),
        }
        let syncs = format!("{dir}/syncs");
        rustix::fs::mkdirat(&self.dir, &syncs, Mode::from_raw_mode(0o755))
            .with_context(|| format!("creating {syncs}"))?;
        self.write_replace(&format!("{dir}/config.json"), &serde_json::to_vec(config)?)
    }

    /// Configuration of repo `name`, which must exist.
    pub fn repo_config<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        repo::check_id(name)?;
        self.read_json(&format!("repos/{name}/config.json"))?
            .with_context(|| format!("no repo {name}"))
    }

    /// Ids of the configured repos of all formats, sorted.
    pub fn repos(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        for namespace in self.list_dir("repos")? {
            let format = namespace.strip_prefix('@').unwrap_or_default();
            if repo::check_format(format).is_err() {
                continue;
            }
            for name in self.list_dir(&format!("repos/{namespace}"))? {
                if repo::check_name(&name).is_ok() {
                    ids.push(format!("{namespace}/{name}"));
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Names in directory `path`, other than `.` and `..`, unsorted.
    fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        let fd = self
            .openat(path, OFlags::RDONLY | OFlags::DIRECTORY, 0)
            .with_context(|| format!("opening {path}"))?;
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(&fd).with_context(|| format!("reading {path}"))? {
            let entry = entry.with_context(|| format!("reading {path}"))?;
            let name = entry.file_name().to_string_lossy();
            if name != "." && name != ".." {
                names.push(name.into_owned());
            }
        }
        Ok(names)
    }

    /// Record a sync of repo `name`: write the record as an object and its
    /// id as `syncs/<fetched>`. Fails if a record by that name exists.
    pub fn save_sync(&self, name: &str, record: &SyncRecord) -> Result<()> {
        repo::check_id(name)?;
        anyhow::ensure!(
            record
                .fetched
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":.-".contains(&b)),
            "bad sync time {:?}",
            record.fetched
        );
        let (refs, body) = record.to_object()?;
        let id = self.add_object(refs.as_slice(), &body)?;
        let dest = format!("repos/{name}/syncs/{}", record.fetched);
        let mut file = File::from(self.unnamed_file(0o644)?);
        file.write_all(format!("{id}\n").as_bytes())
            .with_context(|| format!("writing {dest}"))?;
        self.link(&file, &dest)
            .with_context(|| format!("linking {dest}"))
    }

    /// The latest sync of repo `name` (by fetch time), if it was synced.
    pub fn latest_sync(&self, name: &str) -> Result<Option<SyncRecord>> {
        repo::check_id(name)?;
        let dir = format!("repos/{name}/syncs");
        let latest = self
            .list_dir(&dir)?
            .into_iter()
            .filter(|n| !n.starts_with('.'))
            .max();
        let Some(file) = latest else {
            return Ok(None);
        };
        let path = format!("{dir}/{file}");
        let id = self
            .read_id(&path)?
            .with_context(|| format!("{path} is gone"))?;
        let obj = self.read_object(&id)?;
        let record = SyncRecord::from_object(&obj).with_context(|| format!("reading {path}"))?;
        Ok(Some(record))
    }
}

/// Remove the file `name` in `dir`; returns whether it was there.
fn remove_file(dir: impl AsFd, name: &str) -> Result<bool> {
    match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {name}")),
    }
}

/// Create `<base>/<repo>` and its parent `<base>/@FORMAT` if needed, for
/// the id `repo` (checked before).
fn mkdir_repo(dir: impl AsFd, base: &str, repo: &str) -> Result<()> {
    let path = format!("{base}/{repo}");
    let parent = path.rsplit_once('/').unwrap().0;
    for p in [parent, &path] {
        mkdir_exist_ok(&dir, p).with_context(|| format!("creating {p}"))?;
    }
    Ok(())
}

/// `downloads/<repo>/<name>`, if `name` is a plain file name.
fn download_path(repo: &str, name: &str) -> Result<String> {
    repo::check_id(repo)?;
    anyhow::ensure!(
        !name.is_empty() && !name.starts_with('.') && !name.contains(['/', '\0']),
        "bad file name {name:?} for a download"
    );
    Ok(format!("downloads/{repo}/{name}"))
}

/// An unnamed file being written in the store's `tmp/` directory; freed
/// when dropped unless saved.
pub struct TmpFile<'a> {
    store: &'a Store,
    file: File,
}

impl TmpFile<'_> {
    pub fn file(&mut self) -> &mut File {
        &mut self.file
    }

    /// Save the file as `downloads/<repo>/<name>`, replacing any file
    /// there. Returns the open file.
    pub fn save_download(self, repo: &str, name: &str) -> Result<File> {
        let dest = download_path(repo, name)?;
        let dir = &self.store.dir;
        mkdir_repo(dir, "downloads", repo)?;
        // Linking doesn't replace, so remove the old file first. A
        // concurrent save of the same download can link in between; then
        // replace that one.
        loop {
            match rustix::fs::unlinkat(dir, &dest, AtFlags::empty()) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(e) => return Err(e).with_context(|| format!("removing {dest}")),
            }
            match self.store.link(&self.file, &dest) {
                Ok(()) => return Ok(self.file),
                Err(Errno::EXIST) => {}
                Err(e) => return Err(e).with_context(|| format!("linking download to {dest}")),
            }
        }
    }
}

struct HashingWriter<W> {
    inner: W,
    hasher: blake3::Hasher,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Hash everything `reader` yields (used to identify package archives).
pub fn hash_reader(reader: impl Read) -> io::Result<Hash> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(reader)?;
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;
    use std::os::unix::fs::PermissionsExt;

    fn not_a_store(r: Result<Store>) -> NotAStore {
        *r.err().unwrap().downcast_ref::<NotAStore>().unwrap()
    }

    #[test]
    fn open_needs_init() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        assert_eq!(not_a_store(Store::open_path(&root)), NotAStore::Missing);
        std::fs::write(&root, "").unwrap();
        assert_eq!(
            not_a_store(Store::open_path(&root)),
            NotAStore::NotADirectory
        );
        assert!(!NotAStore::NotADirectory.can_init());
        std::fs::remove_file(&root).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert_eq!(not_a_store(Store::open_path(&root)), NotAStore::Empty);
        // A directory with the layout but no manifest isn't a store.
        for sub in SUBDIRS {
            std::fs::create_dir(root.join(sub)).unwrap();
        }
        assert_eq!(not_a_store(Store::open_path(&root)), NotAStore::NoManifest);
        let e = Store::init_path(&root).err().unwrap();
        assert!(format!("{e:#}").contains("isn't empty"), "{e:#}");
        assert!(!NotAStore::NoManifest.can_init());
        for sub in SUBDIRS {
            std::fs::remove_dir(root.join(sub)).unwrap();
        }
        Store::init_path(&root).unwrap();
        Store::open_path(&root).unwrap();
        let manifest = std::fs::read(root.join(MANIFEST)).unwrap();
        let manifest: StoreManifest = serde_json::from_slice(&manifest).unwrap();
        assert_eq!(manifest.version, format_version());
        // Missing parts of the layout are reported.
        std::fs::remove_dir(root.join("blobs")).unwrap();
        let e = not_a_store(Store::open_path(&root));
        assert_eq!(e, NotAStore::NoSubdir("blobs"));
        Store::init_path(&root).unwrap();
        std::fs::remove_dir(root.join("tmp")).unwrap();
        std::os::unix::fs::symlink("blobs", root.join("tmp")).unwrap();
        let e = not_a_store(Store::open(File::open(&root).unwrap().into()));
        assert_eq!(e, NotAStore::NoSubdir("tmp"));
        // Setting up an existing store again fills in what's missing.
        std::fs::remove_file(root.join("tmp")).unwrap();
        Store::init_path(&root).unwrap();
        Store::open_path(&root).unwrap();
    }

    #[test]
    fn other_versions_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        Store::init_path(dir.path()).unwrap();
        for content in ["0", "1", r#""dev-000000000000""#] {
            let version: FormatVersion = serde_json::from_str(content).unwrap();
            std::fs::write(
                dir.path().join(MANIFEST),
                format!(r#"{{"version": {content}}}"#),
            )
            .unwrap();
            for e in [
                Store::open_path(dir.path()).err().unwrap(),
                Store::init_path(dir.path()).err().unwrap(),
                Store::migrate_path(dir.path(), true).err().unwrap(),
            ] {
                let wrong = e.downcast_ref::<WrongVersion>().unwrap();
                assert_eq!(wrong.found, version, "{e:#}");
                assert_eq!(wrong.current, format_version());
            }
        }
        std::fs::write(dir.path().join(MANIFEST), "{}").unwrap();
        let e = Store::open_path(dir.path()).err().unwrap();
        assert!(e.downcast_ref::<NotAStore>().is_none(), "{e:#}");
        assert!(
            format!("{e:#}").contains(&format!("parsing {MANIFEST}")),
            "{e:#}"
        );
    }

    fn mkdir_migration(name: &str) -> impl Fn(BorrowedFd<'_>) -> Result<()> {
        move |dir| Ok(mkdir_exist_ok(dir, name)?)
    }

    #[test]
    fn migrations() {
        use format::DevFormat;
        let formats = Formats {
            latest_stable: 2,
            migrations: &[|dir| mkdir_migration("two")(dir)],
            dev: Some(DevFormat {
                version: "dev-x",
                migration: Some(|dir| mkdir_migration("dev")(dir)),
            }),
        };
        formats.check();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let migrate = |allow_dev| {
            Store::migrate_formats(File::open(root).unwrap().into(), &formats, allow_dev)
        };
        let version = || {
            let data = std::fs::read(root.join(MANIFEST)).unwrap();
            serde_json::from_slice::<StoreManifest>(&data)
                .unwrap()
                .version
        };
        let e = migrate(false).err().unwrap();
        assert_eq!(*e.downcast_ref::<NotAStore>().unwrap(), NotAStore::Empty);
        Store::init_path(root).unwrap();
        std::fs::write(root.join(MANIFEST), r#"{"version": 1}"#).unwrap();
        // The step to the development version needs allow_dev, and nothing
        // is done without it.
        let e = migrate(false).err().unwrap();
        let wrong = e.downcast_ref::<WrongVersion>().unwrap();
        assert_eq!(
            wrong.problem,
            VersionProblem::NeedsMigration { to_dev: true }
        );
        assert!(!root.join("two").exists());
        let dev = FormatVersion::Dev("dev-x".into());
        let migrated = migrate(true).unwrap();
        assert_eq!(migrated.from, FormatVersion::Stable(1));
        assert_eq!(migrated.to, dev);
        assert!(root.join("two").is_dir() && root.join("dev").is_dir());
        assert_eq!(version(), dev);
        assert!(tmp_is_empty(root));
        assert_eq!(migrate(false).unwrap().from, dev);
        // A failed migration leaves the version of the last step done.
        let formats = Formats {
            dev: Some(DevFormat {
                version: "dev-y",
                migration: Some(|_| bail!("broken")),
            }),
            ..formats
        };
        std::fs::write(root.join(MANIFEST), r#"{"version": 1}"#).unwrap();
        let e = Store::migrate_formats(File::open(root).unwrap().into(), &formats, true)
            .err()
            .unwrap();
        assert!(format!("{e:#}").contains("broken"), "{e:#}");
        assert_eq!(version(), FormatVersion::Stable(2));
    }

    fn tmp_is_empty(root: &Path) -> bool {
        std::fs::read_dir(root.join("tmp"))
            .unwrap()
            .next()
            .is_none()
    }

    #[test]
    fn objects_are_linked_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_path(dir.path()).unwrap();
        let a = store.add_blob(&mut &b"hello"[..]).unwrap();
        assert!(a.new);
        assert_eq!(a.size, 5);
        let b = store.add_blob(&mut &b"hello"[..]).unwrap();
        assert!(!b.new);
        assert_eq!(a.hash, b.hash);
        let path = dir.path().join(blob_name(&a.hash));
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o444);
        assert!(tmp_is_empty(dir.path()));
    }

    #[test]
    fn objects_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_path(dir.path()).unwrap();
        let blob = store.add_blob(&mut &b"x"[..]).unwrap().hash;
        let body = serde_json::json!({"file": {"#": 0}});
        let id = store.add_object(&[Ref::Blob(blob)], &body).unwrap();
        assert_eq!(store.add_object(&[Ref::Blob(blob)], &body).unwrap(), id);
        let obj = store.read_object(&id).unwrap();
        assert_eq!(obj.refs, [Ref::Blob(blob)]);
        assert_eq!(obj.body, body);
        let path = dir.path().join(object_name(&id));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o444);
        assert!(tmp_is_empty(dir.path()));
        // A changed object no longer has its address.
        std::fs::set_permissions(&path, PermissionsExt::from_mode(0o644)).unwrap();
        let mut data = std::fs::read(&path).unwrap();
        data.push(b' ');
        std::fs::write(&path, data).unwrap();
        let e = store.read_object(&id).unwrap_err();
        assert!(format!("{e:#}").contains("corrupt"), "{e:#}");
        assert!(store.read_object(&blob).is_err());
    }

    #[test]
    fn packages_by_repo() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_path(dir.path()).unwrap();
        let hash = store.add_blob(&mut &b"archive"[..]).unwrap().hash;
        let pkg = |version: &str| Package {
            name: "a".into(),
            version: version.into(),
            entries: vec![],
            sections: [].into(),
            overlay: None,
        };
        let (one, two) = (pkg("1-1"), pkg("2-1"));
        let (id1, id2) = (
            store.add_package(&one).unwrap(),
            store.add_package(&two).unwrap(),
        );
        assert_ne!(id1, id2);
        assert_eq!(store.load_package(&id1).unwrap(), one);
        store.index_package("@arch/@local", &hash, &id1).unwrap();
        store.index_package("@arch/core", &hash, &id1).unwrap();
        store.index_package("@arch/core", &hash, &id2).unwrap();
        let load = |repo| store.indexed_package(repo, &hash).unwrap();
        assert_eq!(load("@arch/@local"), Some(id1));
        assert_eq!(load("@arch/core"), Some(id2));
        assert_eq!(load("@arch/extra"), None);
        assert_eq!(store.package_index("@arch/core").unwrap(), [(hash, id2)]);
        assert_eq!(store.package_index("@arch/extra").unwrap(), []);
        assert!(store.index_package("../x", &hash, &id1).is_err());
        let saved = dir.path().join(format!("packages/@arch/core/{hash}"));
        assert_eq!(std::fs::read_to_string(saved).unwrap(), format!("{id2}\n"));
        assert!(store.unindex_package("@arch/@local", &hash).unwrap());
        assert!(!store.unindex_package("@arch/@local", &hash).unwrap());
        assert_eq!(load("@arch/@local"), None);
        assert_eq!(load("@arch/core"), Some(id2));
        assert!(store.unindex_package("../x", &hash).is_err());
        // An invalid package isn't added.
        let mut bad = pkg("1");
        bad.sections.insert(
            "Arch".into(),
            crate::manifest::Section {
                value: serde_json::json!({}),
                blobs: vec![],
            },
        );
        assert!(store.add_package(&bad).is_err());
        // Synthetic packages by build spec.
        let spec = BuildSpec {
            packages: vec![id1],
            runner: "test 1".into(),
        };
        let spec = store.add_build_spec(&spec).unwrap();
        assert_eq!(store.synthetic(&spec).unwrap(), None);
        store.save_synthetic(&spec, &id2).unwrap();
        store.save_synthetic(&spec, &id1).unwrap();
        assert_eq!(store.synthetic(&spec).unwrap(), Some(id1));
        assert!(tmp_is_empty(dir.path()));
    }

    #[test]
    fn repos_and_syncs() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_path(dir.path()).unwrap();
        assert!(store.repos().unwrap().is_empty());
        store.add_repo("@deb/a", &"config deb").unwrap();
        store.add_repo("@arch/b", &"config b").unwrap();
        store.add_repo("@arch/a", &"config a").unwrap();
        let e = store.add_repo("@arch/a", &"again").unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        assert!(store.add_repo("../x", &"").is_err());
        assert!(store.add_repo("a", &"").is_err());
        assert!(store.add_repo("@arch/@local", &"").is_err());
        assert_eq!(store.repos().unwrap(), ["@arch/a", "@arch/b", "@deb/a"]);
        assert_eq!(store.repo_config::<String>("@arch/a").unwrap(), "config a");
        assert_eq!(store.repo_config::<String>("@deb/a").unwrap(), "config deb");
        assert!(store.repo_config::<String>("@arch/c").is_err());

        assert_eq!(store.latest_sync("@arch/a").unwrap(), None);
        let record = |fetched: &str| SyncRecord {
            hash: store.add_blob(&mut fetched.as_bytes()).unwrap().hash,
            size: 1,
            url: "http://x/a.db".into(),
            fetched: fetched.into(),
            last_modified: None,
            etag: Some("\"abc\"".to_owned()),
            validator: Some("\"abc\"".to_owned()),
        };
        let (old, new) = (
            record("2026-01-02T00:00:00.000000Z"),
            record("2026-01-10T00:00:00.000000Z"),
        );
        store.save_sync("@arch/a", &new).unwrap();
        store.save_sync("@arch/a", &old).unwrap();
        assert!(
            store.save_sync("@arch/a", &old).is_err(),
            "records aren't replaced"
        );
        assert!(store.save_sync("@arch/a", &record("../../x")).is_err());
        assert_eq!(store.latest_sync("@arch/a").unwrap(), Some(new));
        assert_eq!(store.latest_sync("@arch/b").unwrap(), None);
        assert!(tmp_is_empty(dir.path()));
    }

    #[test]
    fn downloads_replace_earlier_ones() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_path(dir.path()).unwrap();
        // Dropped unsaved: leaves nothing.
        store.tmp_file().unwrap().file().write_all(b"x").unwrap();
        for content in [&b"old"[..], b"new"] {
            let mut tmp = store.tmp_file().unwrap();
            tmp.file().write_all(content).unwrap();
            let mut file = tmp.save_download("@arch/core", "a.pkg").unwrap();
            file.rewind().unwrap();
            let mut read = Vec::new();
            file.read_to_end(&mut read).unwrap();
            assert_eq!(read, content);
        }
        let saved = std::fs::read(dir.path().join("downloads/@arch/core/a.pkg")).unwrap();
        assert_eq!(saved, b"new");
        assert!(tmp_is_empty(dir.path()));
        assert_eq!(store.downloads("@arch/extra").unwrap(), [""; 0]);
        let tmp = store.tmp_file().unwrap();
        tmp.save_download("@arch/core", "a.pkg.sig").unwrap();
        assert_eq!(
            store.downloads("@arch/core").unwrap(),
            ["a.pkg", "a.pkg.sig"]
        );
        assert!(store.remove_download("@arch/core", "a.pkg").unwrap());
        assert!(!store.remove_download("@arch/core", "a.pkg").unwrap());
        assert!(store.remove_download("@arch/core", "../x").is_err());
        assert_eq!(store.downloads("@arch/core").unwrap(), ["a.pkg.sig"]);
    }
}
