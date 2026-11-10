//! Arch Linux package frontend: reads `.pkg.tar.zst` archives into the store.
//!
//! Install scriptlets (`.INSTALL`), `.MTREE` and `.BUILDINFO` are ignored for now.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};
use tar::EntryType;

use crate::manifest::{Entry, EntryKind, Package, XattrValue, normalize_path};
use crate::store::Store;

/// Statistics about an import.
#[derive(Default)]
pub struct ImportStats {
    pub files: u64,
    pub new_objects: u64,
    pub new_bytes: u64,
}

pub fn import(store: &Store, path: &Path) -> Result<(Package, ImportStats)> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let decoder = open_decoder(path, BufReader::new(file))?;
    let mut archive = tar::Archive::new(decoder);

    let mut stats = ImportStats::default();
    let mut entries = Vec::new();
    let mut pkginfo = None;

    for tar_entry in archive.entries()? {
        let mut tar_entry = tar_entry?;
        let raw_path = tar_entry.path()?;
        let raw_path = raw_path
            .to_str()
            .with_context(|| format!("non-UTF-8 path: {}", raw_path.display()))?;
        let path = normalize_path(raw_path)?;

        // Package metadata lives in dot-files at the archive root.
        if path.starts_with('.') && !path.contains('/') {
            if path == ".PKGINFO" {
                let mut s = String::new();
                tar_entry.read_to_string(&mut s)?;
                pkginfo = Some(parse_pkginfo(&s)?);
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
            EntryType::Regular | EntryType::Continuous => {
                let added = store.add_object(&mut tar_entry)?;
                stats.files += 1;
                if added.new {
                    stats.new_objects += 1;
                    stats.new_bytes += added.size;
                }
                EntryKind::File {
                    hash: added.hash,
                    size: added.size,
                }
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

    let Some((name, version)) = pkginfo else {
        bail!("{}: missing .PKGINFO", path.display());
    };
    Ok((
        Package {
            name,
            version,
            entries,
        },
        stats,
    ))
}

fn open_decoder<'a>(path: &Path, mut reader: BufReader<File>) -> Result<Box<dyn Read + 'a>> {
    use std::io::BufRead;
    let magic = reader.fill_buf()?;
    if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Ok(Box::new(zstd::Decoder::with_buffer(reader)?))
    } else {
        bail!(
            "{}: unsupported compression (only zstd is supported)",
            path.display()
        )
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

/// Parse `.PKGINFO`, returning `(pkgname, pkgver)`.
fn parse_pkginfo(s: &str) -> Result<(String, String)> {
    let mut name = None;
    let mut version = None;
    for line in s.lines() {
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        match key {
            "pkgname" => name = Some(value.to_owned()),
            "pkgver" => version = Some(value.to_owned()),
            _ => {}
        }
    }
    match (name, version) {
        (Some(n), Some(v)) => Ok((n, v)),
        _ => bail!(".PKGINFO lacks pkgname or pkgver"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkginfo() {
        let s = "# Generated by makepkg\npkgname = bash\npkgbase = bash\npkgver = 5.3.3-1\ndepend = glibc\n";
        assert_eq!(
            parse_pkginfo(s).unwrap(),
            ("bash".to_owned(), "5.3.3-1".to_owned())
        );
    }
}
