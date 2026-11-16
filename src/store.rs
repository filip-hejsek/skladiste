//! Content-addressed object store.
//!
//! Layout:
//! - `objects/ab/cdef…` — file contents, named by BLAKE3 hash, read-only
//! - `packages/<repo>/<hash>.json` — imported package manifests, by repo
//!   and the archive's hash (packages given as paths or URLs belong to
//!   the pseudo-repo [`repo::LOCAL`])
//! - `downloads/<repo>/<name>` — downloaded package archives (and their
//!   signatures), by repo and file name
//! - `repos/<repo>/config.json` — a repo's configuration (see
//!   [`crate::repo`]); its format is the frontend's
//! - `repos/<repo>/syncs/<time>.json` — a record of each version of the
//!   repo's database that was fetched ([`SyncRecord`]); the database
//!   itself is an object
//! - `tmp/` — staging area for files being written: unnamed
//!   (`O_TMPFILE`) until complete and checked, except manifests
//!
//! After [`Store::open`], every access is relative to the store's directory
//! fd, so the store also works from a sandboxed process that was handed only
//! that fd.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::manifest::{Hash, ObjectId, Package};
use crate::repo::{self, SyncRecord};

pub struct Store {
    dir: OwnedFd,
    tmp_counter: AtomicU64,
}

/// Result of adding one object.
pub struct Added {
    pub hash: Hash,
    pub size: u64,
    /// False if an identical object was already present.
    pub new: bool,
}

/// Destination for file contents found while importing a package.
///
/// Frontends write through this instead of using [`Store`] directly, so they
/// can run in a sandboxed process that has no access to the store. The sink
/// returns no hash, so a sink in another process needn't wait for the
/// receiver: the receiver hashes the content and resolves the returned ids
/// (see [`Package::resolve`](crate::manifest::Package::resolve)).
pub trait ObjectSink {
    /// Add an object of `size` bytes; `content` must yield exactly that.
    fn add_object(&mut self, size: u64, content: &mut dyn Read) -> Result<ObjectId>;
}

impl<T: ObjectSink + ?Sized> ObjectSink for &mut T {
    fn add_object(&mut self, size: u64, content: &mut dyn Read) -> Result<ObjectId> {
        (**self).add_object(size, content)
    }
}

fn mkdir_exist_ok(dir: impl AsFd, path: &str) -> Result<(), Errno> {
    match rustix::fs::mkdirat(dir, path, Mode::from_raw_mode(0o755)) {
        Err(Errno::EXIST) => Ok(()),
        r => r,
    }
}

fn object_name(hash: &Hash) -> String {
    let hex = hash.to_string();
    format!("objects/{}/{}", &hex[..2], &hex[2..])
}

/// `packages/<repo>/<hash>.json`.
fn package_name(repo: &str, hash: &Hash) -> Result<String> {
    repo::check_name_or_local(repo)?;
    Ok(format!("packages/{repo}/{hash}.json"))
}

impl Store {
    /// Open the store at `root`, creating its directory structure if needed.
    pub fn open(root: &Path) -> Result<Store> {
        std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
        let dir = rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening {}", root.display()))?;
        for sub in ["objects", "packages", "downloads", "repos", "tmp"] {
            mkdir_exist_ok(&dir, sub)
                .with_context(|| format!("creating {}", root.join(sub).display()))?;
        }
        Ok(Store::from_dir(dir))
    }

    /// Use an already open store directory, e.g. one passed to a worker.
    pub fn from_dir(dir: OwnedFd) -> Store {
        Store {
            dir,
            tmp_counter: AtomicU64::new(0),
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

    /// Open an object for reading.
    pub fn open_object(&self, hash: &Hash) -> Result<OwnedFd> {
        let name = object_name(hash);
        self.openat(&name, OFlags::RDONLY, 0)
            .with_context(|| format!("opening store object {name}"))
    }

    /// Stream `content` into the store, returning its hash.
    /// Safe to call from several threads and processes at once: if the
    /// same object is added concurrently, one of them adds it and the
    /// others report it as already present.
    pub fn add_object(&self, content: &mut dyn Read) -> Result<Added> {
        let mut file = File::from(self.unnamed_file(0o600)?);
        let mut writer = HashingWriter {
            inner: &mut file,
            hasher: blake3::Hasher::new(),
        };
        let size = io::copy(content, &mut writer).context("writing object")?;
        let hash: Hash = writer.hasher.finalize().into();

        let dest = object_name(&hash);
        match rustix::fs::statat(&self.dir, &dest, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                return Ok(Added {
                    hash,
                    size,
                    new: false,
                });
            }
            Err(Errno::NOENT) => {}
            Err(e) => return Err(e).with_context(|| format!("checking {dest}")),
        }
        rustix::fs::fchmod(&file, Mode::from_raw_mode(0o444))?;
        let (subdir, _) = dest.rsplit_once('/').unwrap();
        mkdir_exist_ok(&self.dir, subdir).with_context(|| format!("creating {subdir}"))?;
        // Another thread or process may have added the same object since
        // the check above; linking never replaces it.
        let new = match self.link(&file, &dest) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(e) => return Err(e).with_context(|| format!("linking object to {dest}")),
        };
        Ok(Added { hash, size, new })
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
    /// the name is taken. Linking by the fd itself (`AT_EMPTY_PATH`)
    /// needs `CAP_DAC_READ_SEARCH`, so this goes through `/proc`.
    fn link(&self, fd: impl AsFd, dest: &str) -> Result<(), Errno> {
        use std::os::fd::AsRawFd;
        let path = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());
        rustix::fs::linkat(
            rustix::fs::CWD,
            &path,
            &self.dir,
            dest,
            AtFlags::SYMLINK_FOLLOW,
        )
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
        format!(
            "tmp/{}-{}",
            std::process::id(),
            self.tmp_counter.fetch_add(1, Ordering::Relaxed)
        )
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

    /// The manifest of the package from `repo` whose archive has `hash`,
    /// if it was imported.
    pub fn load_package(&self, repo: &str, hash: &Hash) -> Result<Option<Package>> {
        self.read_json(&package_name(repo, hash)?)
    }

    /// Save the manifest of the package from `repo` whose archive has
    /// `hash`, replacing any saved before. Concurrent saves of the same
    /// package don't interfere; one of them wins.
    pub fn save_package(&self, repo: &str, hash: &Hash, pkg: &Package) -> Result<()> {
        let name = package_name(repo, hash)?;
        mkdir_exist_ok(&self.dir, &format!("packages/{repo}"))
            .with_context(|| format!("creating packages/{repo}"))?;
        self.write_replace(&name, &serde_json::to_vec(pkg)?)
    }

    /// Add repo `name` with `config` (in the frontend's format). Fails if
    /// the repo exists.
    pub fn add_repo(&self, name: &str, config: &impl Serialize) -> Result<()> {
        repo::check_name(name)?;
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
        repo::check_name(name)?;
        self.read_json(&format!("repos/{name}/config.json"))?
            .with_context(|| format!("no repo {name} (add it with `skl repo add`)"))
    }

    /// Names of the configured repos, sorted.
    pub fn repos(&self) -> Result<Vec<String>> {
        let mut names = self.list_dir("repos")?;
        names.retain(|n| repo::check_name(n).is_ok());
        names.sort();
        Ok(names)
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

    /// Record a sync of repo `name`, as `syncs/<fetched>.json`. Fails if
    /// a record by that name exists.
    pub fn save_sync(&self, name: &str, record: &SyncRecord) -> Result<()> {
        repo::check_name(name)?;
        anyhow::ensure!(
            record
                .fetched
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":.-".contains(&b)),
            "bad sync time {:?}",
            record.fetched
        );
        let dest = format!("repos/{name}/syncs/{}.json", record.fetched);
        let mut file = File::from(self.unnamed_file(0o644)?);
        file.write_all(&serde_json::to_vec(record)?)
            .with_context(|| format!("writing {dest}"))?;
        self.link(&file, &dest)
            .with_context(|| format!("linking {dest}"))
    }

    /// The latest sync of repo `name` (by fetch time), if it was synced.
    pub fn latest_sync(&self, name: &str) -> Result<Option<SyncRecord>> {
        repo::check_name(name)?;
        let dir = format!("repos/{name}/syncs");
        let latest = self
            .list_dir(&dir)?
            .into_iter()
            .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
            .max();
        match latest {
            Some(file) => self.read_json(&format!("{dir}/{file}")),
            None => Ok(None),
        }
    }
}

/// `downloads/<repo>/<name>`, if `name` is a plain file name.
fn download_path(repo: &str, name: &str) -> Result<String> {
    repo::check_name_or_local(repo)?;
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
        mkdir_exist_ok(dir, &format!("downloads/{repo}"))
            .with_context(|| format!("creating downloads/{repo}"))?;
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

    fn tmp_is_empty(root: &Path) -> bool {
        std::fs::read_dir(root.join("tmp"))
            .unwrap()
            .next()
            .is_none()
    }

    #[test]
    fn objects_are_linked_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let a = store.add_object(&mut &b"hello"[..]).unwrap();
        assert!(a.new);
        assert_eq!(a.size, 5);
        let b = store.add_object(&mut &b"hello"[..]).unwrap();
        assert!(!b.new);
        assert_eq!(a.hash, b.hash);
        let path = dir.path().join(object_name(&a.hash));
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o444);
        assert!(tmp_is_empty(dir.path()));
    }

    #[test]
    fn packages_by_repo() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let hash = store.add_object(&mut &b"archive"[..]).unwrap().hash;
        let pkg = |version: &str| Package {
            name: "a".into(),
            version: version.into(),
            entries: vec![],
        };
        store.save_package(repo::LOCAL, &hash, &pkg("1-1")).unwrap();
        store.save_package("core", &hash, &pkg("2-1")).unwrap();
        let load = |repo| store.load_package(repo, &hash).unwrap().map(|p| p.version);
        assert_eq!(load(repo::LOCAL).as_deref(), Some("1-1"));
        assert_eq!(load("core").as_deref(), Some("2-1"));
        assert_eq!(load("extra"), None);
        assert!(store.save_package("../x", &hash, &pkg("1")).is_err());
        assert!(
            dir.path()
                .join(format!("packages/core/{hash}.json"))
                .exists()
        );
    }

    #[test]
    fn repos_and_syncs() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert!(store.repos().unwrap().is_empty());
        store.add_repo("b", &"config b").unwrap();
        store.add_repo("a", &"config a").unwrap();
        let e = store.add_repo("a", &"again").unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        assert!(store.add_repo("../x", &"").is_err());
        assert_eq!(store.repos().unwrap(), ["a", "b"]);
        assert_eq!(store.repo_config::<String>("a").unwrap(), "config a");
        assert!(store.repo_config::<String>("c").is_err());

        assert_eq!(store.latest_sync("a").unwrap(), None);
        let record = |fetched: &str| SyncRecord {
            hash: store.add_object(&mut fetched.as_bytes()).unwrap().hash,
            size: 1,
            url: "http://x/a.db".into(),
            fetched: fetched.into(),
            last_modified: None,
        };
        let (old, new) = (
            record("2026-01-02T00:00:00.000000Z"),
            record("2026-01-10T00:00:00.000000Z"),
        );
        store.save_sync("a", &new).unwrap();
        store.save_sync("a", &old).unwrap();
        assert!(
            store.save_sync("a", &old).is_err(),
            "records aren't replaced"
        );
        assert!(store.save_sync("a", &record("../../x")).is_err());
        assert_eq!(store.latest_sync("a").unwrap(), Some(new));
        assert_eq!(store.latest_sync("b").unwrap(), None);
        assert!(tmp_is_empty(dir.path()));
    }

    #[test]
    fn downloads_replace_earlier_ones() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        // Dropped unsaved: leaves nothing.
        store.tmp_file().unwrap().file().write_all(b"x").unwrap();
        for content in [&b"old"[..], b"new"] {
            let mut tmp = store.tmp_file().unwrap();
            tmp.file().write_all(content).unwrap();
            let mut file = tmp.save_download("core", "a.pkg").unwrap();
            file.rewind().unwrap();
            let mut read = Vec::new();
            file.read_to_end(&mut read).unwrap();
            assert_eq!(read, content);
        }
        let saved = std::fs::read(dir.path().join("downloads/core/a.pkg")).unwrap();
        assert_eq!(saved, b"new");
        assert!(tmp_is_empty(dir.path()));
    }
}
