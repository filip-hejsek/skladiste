//! Content-addressed object store.
//!
//! Layout:
//! - `objects/ab/cdef…` — file contents, named by BLAKE3 hash, read-only
//! - `packages/<id>.json` — imported package manifests
//! - `downloads/<name>` — downloaded package archives (and their
//!   signatures), by file name
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

use anyhow::{Context, Result};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::manifest::{Hash, ObjectId, Package};

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

fn package_name(id: &str) -> String {
    format!("packages/{id}.json")
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
        for sub in ["objects", "packages", "downloads", "tmp"] {
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

    /// Open `downloads/<name>`, if it exists.
    pub fn open_download(&self, name: &str) -> Result<Option<File>> {
        let path = download_path(name)?;
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

    pub fn load_package(&self, id: &str) -> Result<Option<Package>> {
        let name = package_name(id);
        let fd = match self.openat(&name, OFlags::RDONLY, 0) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("opening {name}")),
        };
        let mut data = Vec::new();
        File::from(fd)
            .read_to_end(&mut data)
            .with_context(|| format!("reading {name}"))?;
        let pkg = serde_json::from_slice(&data).with_context(|| format!("parsing {name}"))?;
        Ok(Some(pkg))
    }

    /// Save a manifest under `id`, replacing any saved before. Concurrent
    /// saves of the same package don't interfere; one of them wins.
    pub fn save_package(&self, id: &str, pkg: &Package) -> Result<()> {
        let name = package_name(id);
        let json = serde_json::to_vec(pkg)?;
        let tmp = self.tmp_name();
        let fd = self
            .openat(&tmp, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL, 0o644)
            .with_context(|| format!("creating {tmp}"))?;
        let result = File::from(fd)
            .write_all(&json)
            .with_context(|| format!("writing {tmp}"))
            .and_then(|()| {
                rustix::fs::renameat(&self.dir, &tmp, &self.dir, &name)
                    .with_context(|| format!("moving {tmp} to {name}"))
            });
        if result.is_err() {
            let _ = rustix::fs::unlinkat(&self.dir, &tmp, AtFlags::empty());
        }
        result
    }
}

/// `downloads/<name>`, if `name` is a plain file name.
fn download_path(name: &str) -> Result<String> {
    anyhow::ensure!(
        !name.is_empty() && !name.starts_with('.') && !name.contains(['/', '\0']),
        "bad file name {name:?} for a download"
    );
    Ok(format!("downloads/{name}"))
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

    /// Save the file as `downloads/<name>`, replacing any file there.
    /// Returns the open file.
    pub fn save_download(self, name: &str) -> Result<File> {
        let dest = download_path(name)?;
        let dir = &self.store.dir;
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
    fn downloads_replace_earlier_ones() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        // Dropped unsaved: leaves nothing.
        store.tmp_file().unwrap().file().write_all(b"x").unwrap();
        for content in [&b"old"[..], b"new"] {
            let mut tmp = store.tmp_file().unwrap();
            tmp.file().write_all(content).unwrap();
            let mut file = tmp.save_download("a.pkg").unwrap();
            file.rewind().unwrap();
            let mut read = Vec::new();
            file.read_to_end(&mut read).unwrap();
            assert_eq!(read, content);
        }
        let saved = std::fs::read(dir.path().join("downloads/a.pkg")).unwrap();
        assert_eq!(saved, b"new");
        assert!(tmp_is_empty(dir.path()));
    }
}
