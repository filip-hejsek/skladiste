//! Content-addressed object store.
//!
//! Layout:
//! - `objects/ab/cdef…` — file contents, named by BLAKE3 hash, read-only
//! - `packages/<id>.json` — imported package manifests
//! - `tmp/` — staging area for objects being written
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

use crate::manifest::{Hash, Package};

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
/// can run in a sandboxed process that has no access to the store.
pub trait ObjectSink {
    fn add_object(&mut self, content: &mut dyn Read) -> Result<Added>;
}

impl ObjectSink for &Store {
    fn add_object(&mut self, content: &mut dyn Read) -> Result<Added> {
        Store::add_object(self, content)
    }
}

impl<T: ObjectSink + ?Sized> ObjectSink for &mut T {
    fn add_object(&mut self, content: &mut dyn Read) -> Result<Added> {
        (**self).add_object(content)
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
        for sub in ["objects", "packages", "tmp"] {
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
    pub fn add_object(&self, content: &mut dyn Read) -> Result<Added> {
        let tmp = format!(
            "tmp/{}-{}",
            std::process::id(),
            self.tmp_counter.fetch_add(1, Ordering::Relaxed)
        );
        let result = self.add_object_via(&tmp, content);
        if result.as_ref().map_or(true, |a| !a.new) {
            // Either failed or a duplicate; the temp file is not needed.
            let _ = rustix::fs::unlinkat(&self.dir, &tmp, AtFlags::empty());
        }
        result
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
        rustix::fs::renameat(&self.dir, tmp, &self.dir, &dest)
            .with_context(|| format!("moving object to {dest}"))?;
        Ok(Added {
            hash,
            size,
            new: true,
        })
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

    pub fn save_package(&self, id: &str, pkg: &Package) -> Result<()> {
        let name = package_name(id);
        let tmp = format!("{name}.tmp");
        let fd = self
            .openat(&tmp, OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC, 0o644)
            .with_context(|| format!("creating {tmp}"))?;
        File::from(fd)
            .write_all(&serde_json::to_vec(pkg)?)
            .with_context(|| format!("writing {tmp}"))?;
        rustix::fs::renameat(&self.dir, &tmp, &self.dir, &name)
            .with_context(|| format!("moving {tmp} to {name}"))?;
        Ok(())
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
