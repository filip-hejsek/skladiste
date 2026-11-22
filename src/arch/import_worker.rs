//! The worker that imports a package archive (see [`KIND`]).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::FromRawFd;

use anyhow::{Context, Result, bail};
use tar::EntryType;

use super::{ArchSection, hooks};
use crate::manifest::{BlobId, Entry, EntryKind, Package, XattrValue, normalize_path};
use crate::object::Index;
use crate::sandbox::{self, Policy};
use crate::store::BlobSink;
use crate::worker::{Args, Kind, NO_CAPS, RemoteSink};

/// Address space limit of the worker. Real packages need tens of MiB;
/// zstd's default limit on the decoding window is 128 MiB, and very large
/// packages have manifests of tens of MiB.
const MAX_MEMORY: u64 = 1 << 30;

/// The worker that imports a package archive: fd 0 is the archive, fd 1 a
/// socket. It parses the archive with [`import`] and streams each file's
/// content to the supervisor, which stores and hashes the blobs as they
/// arrive; `DONE` holds the manifest. Data flows only from the worker: it
/// never waits for the supervisor. No filesystem access, no ioctls.
pub(crate) const KIND: Kind = Kind {
    name: "import-arch",
    dirs: &[],
    caps: NO_CAPS,
    main,
};

fn main(args: Args) -> Result<Vec<u8>> {
    args.no_extra()?;
    // SAFETY: the supervisor passes the archive as fd 0.
    let archive = unsafe { File::from_raw_fd(0) };
    let policy = Policy {
        max_memory: Some(MAX_MEMORY),
        ..Policy::default()
    };
    sandbox::confine(args.layers, &policy)?;
    let pkg = import(archive, RemoteSink::new(args.out))?;
    Ok(serde_json::to_vec(&pkg)?)
}

/// Read a package archive, adding file contents to `blobs`.
fn import(archive: impl Read, mut blobs: impl BlobSink) -> Result<Package<BlobId, BlobId>> {
    let decoder = open_decoder(BufReader::new(archive))?;
    let mut archive = tar::Archive::new(decoder);

    let mut entries = Vec::new();
    let mut pkginfo = None;
    let mut install = None;
    let mut hooks = Vec::new();

    for tar_entry in archive.entries()? {
        let mut tar_entry = tar_entry?;
        let raw_path = tar_entry.path()?;
        let raw_path = raw_path
            .to_str()
            .with_context(|| format!("non-UTF-8 path: {}", raw_path.display()))?;
        let path = normalize_path(raw_path)?;

        // Package metadata lives in dot-files at the archive root.
        if path.starts_with('.') && !path.contains('/') {
            match path.as_str() {
                ".PKGINFO" => {
                    let mut s = String::new();
                    tar_entry.read_to_string(&mut s)?;
                    pkginfo = Some(parse_pkginfo(&s)?);
                }
                ".INSTALL" => {
                    let size = tar_entry.size();
                    install = Some(blobs.add_blob(size, &mut tar_entry)?);
                }
                _ => {}
            }
            continue;
        }
        if path.is_empty() {
            continue;
        }

        let header = tar_entry.header();
        let mode = header.mode()? & 0o7777;
        let uid = header.uid()?.try_into().context("uid out of range")?;
        let gid = header.gid()?.try_into().context("gid out of range")?;
        let mtime = header.mtime()?.try_into().context("mtime out of range")?;
        let entry_type = header.entry_type();
        let xattrs = read_xattrs(&mut tar_entry)?;

        let kind = match entry_type {
            EntryType::Directory => EntryKind::Dir,
            EntryType::Regular | EntryType::Continuous if hooks::hook_name(&path).is_some() => {
                let size = tar_entry.size();
                anyhow::ensure!(
                    size <= hooks::MAX_HOOK_SIZE,
                    "{path}: a hook larger than {} bytes",
                    hooks::MAX_HOOK_SIZE
                );
                let mut data = Vec::new();
                tar_entry.read_to_end(&mut data)?;
                let text = std::str::from_utf8(&data)
                    .with_context(|| format!("{path}: a hook that isn't UTF-8"))?;
                hooks.push(hooks::parse(&path, text)?);
                EntryKind::File(blobs.add_blob(size, &mut &data[..])?)
            }
            EntryType::Regular | EntryType::Continuous => {
                let size = tar_entry.size();
                EntryKind::File(blobs.add_blob(size, &mut tar_entry)?)
            }
            EntryType::Symlink => EntryKind::Symlink {
                target: link_name(&tar_entry, &path)?,
            },
            EntryType::Link => EntryKind::Hardlink {
                target: normalize_path(&link_name(&tar_entry, &path)?)?,
            },
            other => bail!("{path}: unsupported entry type {other:?}"),
        };

        entries.push(Entry {
            path,
            kind,
            mode,
            uid,
            gid,
            mtime,
            xattrs,
        });
    }

    let Some(info) = pkginfo else {
        bail!("missing .PKGINFO");
    };
    let section = ArchSection {
        depends: info.depends,
        provides: info.provides,
        conflicts: info.conflicts,
        install: install.map(|_| Index { index: 0 }),
        hooks,
    };
    Ok(Package {
        name: info.name,
        version: info.version,
        entries,
        sections: [section.into_section(install.into_iter().collect())?].into(),
        overlay: None,
    })
}

fn open_decoder<'a>(mut reader: impl BufRead + 'a) -> Result<Box<dyn Read + 'a>> {
    let magic = reader.fill_buf()?;
    if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Ok(Box::new(zstd::Decoder::with_buffer(reader)?))
    } else {
        bail!("unsupported compression (only zstd is supported)")
    }
}

fn link_name<R: Read>(entry: &tar::Entry<R>, path: &str) -> Result<String> {
    let target = entry
        .link_name()?
        .with_context(|| format!("{path}: link without target"))?;
    Ok(target
        .to_str()
        .with_context(|| format!("{path}: non-UTF-8 link target"))?
        .to_owned())
}

/// Extract xattrs from PAX headers (`SCHILY.xattr.<name>`, as written by bsdtar).
fn read_xattrs<R: Read>(entry: &mut tar::Entry<R>) -> Result<BTreeMap<String, XattrValue>> {
    let mut xattrs = BTreeMap::new();
    let Some(exts) = entry.pax_extensions()? else {
        return Ok(xattrs);
    };
    for ext in exts {
        let ext = ext?;
        if let Some(name) = ext.key()?.strip_prefix("SCHILY.xattr.") {
            xattrs.insert(name.to_owned(), XattrValue(ext.value_bytes().to_vec()));
        }
    }
    Ok(xattrs)
}

/// What skl reads from `.PKGINFO`.
#[derive(Debug, Default, PartialEq)]
struct PkgInfo {
    name: String,
    version: String,
    depends: Vec<String>,
    provides: Vec<String>,
    conflicts: Vec<String>,
}

/// Parse `.PKGINFO`: `pkgname`, `pkgver`, and each `depend`, `provides`
/// and `conflict`.
fn parse_pkginfo(s: &str) -> Result<PkgInfo> {
    let mut name = None;
    let mut version = None;
    let mut info = PkgInfo::default();
    for line in s.lines() {
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        let value = value.to_owned();
        match key {
            "pkgname" => name = Some(value),
            "pkgver" => version = Some(value),
            "depend" => info.depends.push(value),
            "provides" => info.provides.push(value),
            "conflict" => info.conflicts.push(value),
            _ => {}
        }
    }
    match (name, version) {
        (Some(name), Some(version)) => Ok(PkgInfo {
            name,
            version,
            ..info
        }),
        _ => bail!(".PKGINFO lacks pkgname or pkgver"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkginfo() {
        let s = "# Generated by makepkg\npkgname = bash\npkgbase = bash\npkgver = 5.3.3-1\n\
            depend = glibc\ndepend = readline>=8.3\noptdepend = bash-completion: x\n\
            provides = sh\nconflict = old-bash<5\n";
        assert_eq!(
            parse_pkginfo(s).unwrap(),
            PkgInfo {
                name: "bash".to_owned(),
                version: "5.3.3-1".to_owned(),
                depends: vec!["glibc".to_owned(), "readline>=8.3".to_owned()],
                provides: vec!["sh".to_owned()],
                conflicts: vec!["old-bash<5".to_owned()],
            }
        );
        assert!(parse_pkginfo("pkgname = bash\n").is_err());
    }
}
