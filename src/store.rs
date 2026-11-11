//! Content-addressed object store.
//!
//! Layout:
//! - `objects/ab/cdef…` — file contents, named by BLAKE3 hash, read-only
//! - `packages/<id>.json` — imported package manifests
//! - `downloads/<name>` — downloaded package archives (and their
//!   signatures), by file name
//! - `tmp/` — staging area for files being written
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
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
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
        let tmp = self.tmp_name();
        let result = self.add_object_via(&tmp, content);
        if result.as_ref().map_or(true, |a| !a.new) {
            // Either failed or a duplicate; the temp file is not needed.
            let _ = rustix::fs::unlinkat(&self.dir, &tmp, AtFlags::empty());
        }
        result
    }

    /// Create a file in `tmp/`, removed unless it is saved.
    pub fn tmp_file(&self) -> Result<TmpFile<'_>> {
        let name = self.tmp_name();
        let fd = self
            .openat(&name, OFlags::RDWR | OFlags::CREATE | OFlags::EXCL, 0o644)
            .with_context(|| format!("creating {name}"))?;
        Ok(TmpFile {
            store: self,
            name,
            file: Some(File::from(fd)),
        })
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

    fn add_object_via(&self, tmp: &str, content: &mut dyn Read) -> Result<Added> {
        let fd = self
            .openat(tmp, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL, 0o600)
            .with_context(|| format!("creating {tmp}"))?;
        let mut file = File::from(fd);
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
        drop(file);
        let (subdir, _) = dest.rsplit_once('/').unwrap();
        mkdir_exist_ok(&self.dir, subdir).with_context(|| format!("creating {subdir}"))?;
        // Another thread or process may have added the same object since
        // the check above.
        let new = match rustix::fs::renameat_with(
            &self.dir,
            tmp,
            &self.dir,
            &dest,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(e) => return Err(e).with_context(|| format!("moving object to {dest}")),
        };
        Ok(Added { hash, size, new })
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

/// A file being written in the store's `tmp/` directory; removed when
/// dropped unless saved.
pub struct TmpFile<'a> {
    store: &'a Store,
    name: String,
    /// Taken when saved.
    file: Option<File>,
}

impl TmpFile<'_> {
    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().unwrap()
    }

    /// Move the file to `downloads/<name>`, replacing any file there.
    /// Returns the open file.
    pub fn save_download(mut self, name: &str) -> Result<File> {
        let dest = download_path(name)?;
        let dir = &self.store.dir;
        rustix::fs::renameat(dir, &self.name, dir, &dest)
            .with_context(|| format!("moving {} to {dest}", self.name))?;
        self.name.clear();
        Ok(self.file.take().unwrap())
    }
}

impl Drop for TmpFile<'_> {
    fn drop(&mut self) {
        if !self.name.is_empty() {
            let _ = rustix::fs::unlinkat(&self.store.dir, &self.name, AtFlags::empty());
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
