//! Content-addressed object store.
//!
//! Layout:
//! - `objects/ab/cdef…` — file contents, named by BLAKE3 hash, read-only
//! - `packages/<id>.json` — imported package manifests
//! - `tmp/` — staging area for objects being written

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};

use crate::manifest::{Hash, Package};

pub struct Store {
    root: PathBuf,
    tmp_counter: AtomicU64,
}

/// Result of adding one object.
pub struct Added {
    pub hash: Hash,
    pub size: u64,
    /// False if an identical object was already present.
    pub new: bool,
}

impl Store {
    /// Open the store at `root`, creating its directory structure if needed.
    pub fn open(root: &Path) -> Result<Store> {
        for sub in ["objects", "packages", "tmp"] {
            let dir = root.join(sub);
            fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(Store {
            root: root.to_owned(),
            tmp_counter: AtomicU64::new(0),
        })
    }

    pub fn object_path(&self, hash: &Hash) -> PathBuf {
        let hex = hash.to_string();
        self.root.join("objects").join(&hex[..2]).join(&hex[2..])
    }

    /// Stream `content` into the store, returning its hash.
    pub fn add_object(&self, content: &mut impl Read) -> Result<Added> {
        let tmp = self.root.join("tmp").join(format!(
            "{}-{}",
            std::process::id(),
            self.tmp_counter.fetch_add(1, Ordering::Relaxed)
        ));
        let result = self.add_object_via(&tmp, content);
        if result.as_ref().map_or(true, |a| !a.new) {
            // Either failed or a duplicate; the temp file is not needed.
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    fn add_object_via(&self, tmp: &Path, content: &mut impl Read) -> Result<Added> {
        let mut file =
            File::create_new(tmp).with_context(|| format!("creating {}", tmp.display()))?;
        let mut writer = HashingWriter {
            inner: &mut file,
            hasher: blake3::Hasher::new(),
        };
        let size = io::copy(content, &mut writer).context("writing object")?;
        let hash: Hash = writer.hasher.finalize().into();

        let dest = self.object_path(&hash);
        if dest.exists() {
            return Ok(Added {
                hash,
                size,
                new: false,
            });
        }
        file.set_permissions(fs::Permissions::from_mode(0o444))?;
        drop(file);
        let parent = dest.parent().unwrap();
        fs::create_dir_all(parent)?;
        fs::rename(tmp, &dest).with_context(|| format!("moving object to {}", dest.display()))?;
        Ok(Added {
            hash,
            size,
            new: true,
        })
    }

    fn package_path(&self, id: &str) -> PathBuf {
        self.root.join("packages").join(format!("{id}.json"))
    }

    pub fn load_package(&self, id: &str) -> Result<Option<Package>> {
        let path = self.package_path(id);
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let pkg =
            serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Some(pkg))
    }

    pub fn save_package(&self, id: &str, pkg: &Package) -> Result<()> {
        let path = self.package_path(id);
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec(pkg)?)?;
        fs::rename(&tmp, &path)?;
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

/// Hash a whole file (used to identify package archives).
pub fn hash_file(path: &Path) -> Result<Hash> {
    let mut hasher = blake3::Hasher::new();
    hasher
        .update_reader(File::open(path).with_context(|| format!("opening {}", path.display()))?)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(hasher.finalize().into())
}
