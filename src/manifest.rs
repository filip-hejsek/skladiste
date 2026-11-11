//! Format-independent description of a package's contents.
//!
//! Frontends (e.g. [`crate::arch`]) translate their native package format into
//! a [`Package`]; everything after that point works only with these types.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use anyhow::Context as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// BLAKE3 hash of a file's content; the address of an object in the store.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl From<blake3::Hash> for Hash {
    fn from(h: blake3::Hash) -> Self {
        Hash(*h.as_bytes())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_encode(&self.0))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

impl FromStr for Hash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let bytes = hex_decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("hash must be 32 bytes: {s}"))?;
        Ok(Hash(arr))
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A package as the core sees it: identity plus a list of filesystem entries.
///
/// `F` is what file entries refer to: [`Content`] in the store, or
/// [`ObjectId`] in a manifest that a frontend produced, before the
/// supervisor [resolves](Package::resolve) it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package<F = Content> {
    pub name: String,
    pub version: String,
    pub entries: Vec<Entry<F>>,
}

/// A file's content in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Content {
    pub hash: Hash,
    pub size: u64,
}

/// A file's content as a frontend refers to it: the position of the object
/// among those it sent to its [`ObjectSink`](crate::store::ObjectSink),
/// counting from 0. Only the receiving side knows the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectId {
    pub object: u64,
}

impl Package<ObjectId> {
    /// Replace object ids with the content they refer to; `objects` holds
    /// the content of each object in the order they were received.
    pub fn resolve(self, objects: &[Content]) -> anyhow::Result<Package> {
        let entries = self
            .entries
            .into_iter()
            .map(|e| {
                let kind = match e.kind {
                    EntryKind::File(ObjectId { object }) => EntryKind::File(
                        usize::try_from(object)
                            .ok()
                            .and_then(|i| objects.get(i))
                            .copied()
                            .with_context(|| format!("/{}: no object {object}", e.path))?,
                    ),
                    EntryKind::Dir => EntryKind::Dir,
                    EntryKind::Symlink { target } => EntryKind::Symlink { target },
                    EntryKind::Hardlink { target } => EntryKind::Hardlink { target },
                };
                Ok(Entry {
                    path: e.path,
                    kind,
                    mode: e.mode,
                    uid: e.uid,
                    gid: e.gid,
                    mtime: e.mtime,
                    xattrs: e.xattrs,
                })
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Package {
            name: self.name,
            version: self.version,
            entries,
        })
    }
}

impl<F> Package<F> {
    /// Check the invariants the rest of the core relies on.
    ///
    /// Frontends parse untrusted archives and may run in a sandboxed process,
    /// so their output is checked again by the code that stores it.
    pub fn validate(&self) -> anyhow::Result<()> {
        for entry in &self.entries {
            let path = &entry.path;
            anyhow::ensure!(
                !path.is_empty() && normalize_path(path)? == *path,
                "invalid path: {path:?}"
            );
            anyhow::ensure!(
                entry.mode & !0o7777 == 0,
                "/{path}: invalid mode {:o}",
                entry.mode
            );
            if let EntryKind::Hardlink { target } = &entry.kind {
                anyhow::ensure!(
                    !target.is_empty() && normalize_path(target)? == *target,
                    "/{path}: invalid hard link target {target:?}"
                );
            }
        }
        Ok(())
    }
}

/// One filesystem entry. `path` is relative to the image root, without a
/// leading or trailing slash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry<F = Content> {
    pub path: String,
    #[serde(flatten)]
    pub kind: EntryKind<F>,
    /// Permission bits including setuid/setgid/sticky (`0o7777` mask).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Modification time in seconds since the epoch.
    pub mtime: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub xattrs: BTreeMap<String, XattrValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum EntryKind<F = Content> {
    Dir,
    File(F),
    Symlink {
        target: String,
    },
    /// Hard link to another path in the same package.
    Hardlink {
        target: String,
    },
}

/// Raw xattr value, serialized as hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrValue(pub Vec<u8>);

impl Serialize for XattrValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for XattrValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        hex_decode(&s)
            .map(XattrValue)
            .map_err(serde::de::Error::custom)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        s.is_ascii() && s.len().is_multiple_of(2),
        "invalid hex string: {s}"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| anyhow::anyhow!("invalid hex string: {s}"))
        })
        .collect()
}

/// Normalize an archive path: strip `./` prefixes and trailing slashes, and
/// reject anything that could escape the image root.
pub fn normalize_path(raw: &str) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    for comp in raw.split('/') {
        match comp {
            "" | "." => {}
            ".." => anyhow::bail!("path contains '..': {raw}"),
            c => parts.push(c),
        }
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize() {
        assert_eq!(normalize_path("./usr/bin/").unwrap(), "usr/bin");
        assert_eq!(normalize_path("/etc//passwd").unwrap(), "etc/passwd");
        assert_eq!(normalize_path("./").unwrap(), "");
        assert!(normalize_path("usr/../etc").is_err());
    }

    #[test]
    fn validate() {
        let pkg = |path: &str| Package::<Content> {
            name: "p".into(),
            version: "1".into(),
            entries: vec![Entry {
                path: path.into(),
                kind: EntryKind::Dir,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
                xattrs: BTreeMap::new(),
            }],
        };
        assert!(pkg("usr/bin").validate().is_ok());
        for bad in ["", "/usr", "usr/", "usr//bin", "usr/./bin", "usr/../etc"] {
            assert!(pkg(bad).validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn resolve_object_ids() {
        let pkg = |object| Package {
            name: "p".into(),
            version: "1".into(),
            entries: vec![Entry {
                path: "f".into(),
                kind: EntryKind::File(ObjectId { object }),
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                xattrs: BTreeMap::new(),
            }],
        };
        let content = Content {
            hash: blake3::hash(b"x").into(),
            size: 1,
        };
        let resolved = pkg(1).resolve(&[content, content]).unwrap();
        assert_eq!(resolved.entries[0].kind, EntryKind::File(content));
        assert!(pkg(2).resolve(&[content, content]).is_err());
        assert!(pkg(u64::MAX).resolve(&[content]).is_err());
    }

    #[test]
    fn entry_json_roundtrip() {
        let e = Entry {
            path: "usr/bin/ping".into(),
            kind: EntryKind::File(Content {
                hash: blake3::hash(b"x").into(),
                size: 1,
            }),
            mode: 0o4755,
            uid: 0,
            gid: 0,
            mtime: 1,
            xattrs: [("security.capability".into(), XattrValue(vec![1, 2, 0xff]))].into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains(r#""type":"file""#));
        assert!(json.contains(r#""size":1"#));
        assert!(json.contains(r#""security.capability":"0102ff""#));
        assert_eq!(serde_json::from_str::<Entry>(&json).unwrap(), e);
    }
}
