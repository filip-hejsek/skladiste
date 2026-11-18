//! Format-independent description of a package's contents.
//!
//! Frontends (e.g. [`crate::arch`]) translate their native package format into
//! a [`Package`]; everything after that point works only with these types.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;

use anyhow::Context as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::object::{Index, Object, REF_KEY, Ref, Refs};

/// BLAKE3 hash of a file's content; the address of a blob in the store.
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

/// A package as the core sees it: identity, a list of filesystem entries,
/// and what each package format keeps about it.
///
/// `F` is what file contents are, and `B` what sections refer to: in the
/// store [`Content`] (hash and size) and [`Hash`](struct@Hash), or [`BlobId`] for both
/// in a manifest that a frontend produced, before the supervisor
/// [resolves](Package::resolve) it. In the store, a package is an object
/// ([`crate::object`]; [`Package::to_object`], [`Package::from_object`])
/// whose address is the package's id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Package<F = Content, B = Hash> {
    /// The name and version, as opaque strings for messages: the core
    /// doesn't compare them.
    pub name: String,
    pub version: String,
    pub entries: Vec<Entry<F>>,
    /// What each package format keeps about the package, by the format's
    /// name (e.g. `arch`): the core keeps it and doesn't read it.
    pub sections: BTreeMap<String, Section<B>>,
    /// Whether this is an overlay: a package that changes the packages
    /// installed before it, such as what package code changed. Its
    /// entries replace those at their paths (a directory's contents with
    /// it, unless the entry is a directory too), its hard links point
    /// only to its own files, and it removes paths. Ordinary packages can
    /// do neither.
    pub overlay: Option<Overlay>,
}

/// What an overlay package removes, besides the entries it replaces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overlay {
    /// Paths removed, each with everything beneath it.
    pub removed: Vec<String>,
}

/// A package format's part of a manifest: JSON of the format's own
/// schema, which can refer to blobs as `{"#": N}` (an
/// [`Index`] into `blobs`). The manifest doesn't keep the sizes of these
/// blobs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Section<B = Hash> {
    pub value: Value,
    pub blobs: Vec<B>,
}

impl<B> Section<B> {
    /// The blob that `index` (from [`Section::value`]) refers to.
    pub fn blob(&self, index: Index) -> anyhow::Result<&B> {
        usize::try_from(index.index)
            .ok()
            .and_then(|i| self.blobs.get(i))
            .with_context(|| format!("no blob {} in the section", index.index))
    }

    fn map<C>(self, f: impl FnMut(B) -> anyhow::Result<C>) -> anyhow::Result<Section<C>> {
        Ok(Section {
            value: self.value,
            blobs: self
                .blobs
                .into_iter()
                .map(f)
                .collect::<anyhow::Result<_>>()?,
        })
    }
}

/// A file's content in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Content {
    pub hash: Hash,
    pub size: u64,
}

/// A file's content as a frontend refers to it: the position of the blob
/// among those it sent to its [`BlobSink`](crate::store::BlobSink),
/// counting from 0. Only the receiving side knows the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobId {
    pub blob: u64,
}

/// A file's content as a manifest object stores it: the reference to the
/// blob, and its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    blob: Index,
    size: u64,
}

/// A package manifest as an object's body stores it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPackage {
    name: String,
    version: String,
    entries: Vec<Entry<Stored>>,
    sections: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    overlay: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    removed: Vec<String>,
}

/// The content of `blob` in `blobs` (in the order received).
fn content(blobs: &[Content], BlobId { blob }: BlobId) -> anyhow::Result<Content> {
    usize::try_from(blob)
        .ok()
        .and_then(|i| blobs.get(i))
        .copied()
        .with_context(|| format!("no blob {blob}"))
}

impl Package<BlobId, BlobId> {
    /// Replace blob ids with the content they refer to; `blobs` holds
    /// the content of each blob in the order they were received.
    pub fn resolve(self, blobs: &[Content]) -> anyhow::Result<Package> {
        let entries = self
            .entries
            .into_iter()
            .map(|e| e.resolve(blobs))
            .collect::<anyhow::Result<_>>()?;
        let sections = self
            .sections
            .into_iter()
            .map(|(name, s)| {
                let s = s
                    .map(|id| Ok(content(blobs, id)?.hash))
                    .with_context(|| format!("section {name}"))?;
                Ok((name, s))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Package {
            name: self.name,
            version: self.version,
            entries,
            sections,
            overlay: self.overlay,
        })
    }
}

impl Entry<BlobId> {
    /// Replace the blob id of a file with its content, as
    /// [`Package::resolve`] does.
    pub fn resolve(self, blobs: &[Content]) -> anyhow::Result<Entry> {
        let path = self.path.clone();
        self.map(|id| content(blobs, id).with_context(|| format!("/{path}")))
    }
}

impl<F> Entry<F> {
    /// The same entry with `f` applied to a file's content.
    pub fn map<G>(self, f: impl FnOnce(F) -> anyhow::Result<G>) -> anyhow::Result<Entry<G>> {
        let kind = match self.kind {
            EntryKind::File(c) => EntryKind::File(f(c)?),
            EntryKind::Dir => EntryKind::Dir,
            EntryKind::Symlink { target } => EntryKind::Symlink { target },
            EntryKind::Hardlink { target } => EntryKind::Hardlink { target },
        };
        Ok(Entry {
            path: self.path,
            kind,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime: self.mtime,
            xattrs: self.xattrs,
        })
    }
}

impl Package {
    /// The manifest as an object: its references and its body, which
    /// [`Store::add_object`](crate::store::Store::add_object) writes.
    pub fn to_object(&self) -> anyhow::Result<(Refs, Value)> {
        let mut refs = Refs::new();
        let entries = self
            .entries
            .iter()
            .map(|e| {
                e.clone().map(|c| {
                    Ok(Stored {
                        blob: refs.add(Ref::Blob(c.hash)),
                        size: c.size,
                    })
                })
            })
            .collect::<anyhow::Result<_>>()?;
        let sections = self
            .sections
            .iter()
            .map(|(name, s)| {
                let mut value = s.value.clone();
                renumber(&mut value, &mut |index| {
                    Ok(refs.add(Ref::Blob(*s.blob(index)?)))
                })
                .with_context(|| format!("section {name}"))?;
                Ok((name.clone(), value))
            })
            .collect::<anyhow::Result<_>>()?;
        let body = serde_json::to_value(StoredPackage {
            name: self.name.clone(),
            version: self.version.clone(),
            entries,
            sections,
            overlay: self.overlay.is_some(),
            removed: self
                .overlay
                .as_ref()
                .map(|o| o.removed.clone())
                .unwrap_or_default(),
        })?;
        Ok((refs, body))
    }

    /// The manifest in `obj`, as [`Package::to_object`] made it. Each
    /// section lists its blobs in the order of their first use in it.
    pub fn from_object(obj: &Object) -> anyhow::Result<Package> {
        let stored: StoredPackage =
            serde_json::from_value(obj.body.clone()).context("parsing the manifest")?;
        let entries = stored
            .entries
            .into_iter()
            .map(|e| {
                let path = e.path.clone();
                e.map(|s| {
                    Ok(Content {
                        hash: obj.blob(s.blob).with_context(|| format!("/{path}"))?,
                        size: s.size,
                    })
                })
            })
            .collect::<anyhow::Result<_>>()?;
        let sections = stored
            .sections
            .into_iter()
            .map(|(name, mut value)| {
                let mut blobs = Vec::new();
                let mut local = HashMap::new();
                renumber(&mut value, &mut |index| {
                    let hash = obj.blob(index)?;
                    let next = blobs.len() as u64;
                    let i = *local.entry(hash).or_insert(next);
                    if i == next {
                        blobs.push(hash);
                    }
                    Ok(Index { index: i })
                })
                .with_context(|| format!("section {name}"))?;
                Ok((name, Section { value, blobs }))
            })
            .collect::<anyhow::Result<_>>()?;
        anyhow::ensure!(
            stored.overlay || stored.removed.is_empty(),
            "a package that isn't an overlay removes paths"
        );
        Ok(Package {
            name: stored.name,
            version: stored.version,
            entries,
            sections,
            overlay: stored.overlay.then_some(Overlay {
                removed: stored.removed,
            }),
        })
    }
}

/// Replace every reference in `value` by what `f` makes of it.
fn renumber(
    value: &mut Value,
    f: &mut impl FnMut(Index) -> anyhow::Result<Index>,
) -> anyhow::Result<()> {
    match value {
        Value::Array(a) => a.iter_mut().try_for_each(|v| renumber(v, f)),
        Value::Object(m) if m.contains_key(REF_KEY) => {
            let index: Index = serde_json::from_value(Value::Object(std::mem::take(m)))
                .context("bad reference")?;
            *value = serde_json::to_value(f(index)?)?;
            Ok(())
        }
        Value::Object(m) => m.values_mut().try_for_each(|v| renumber(v, f)),
        _ => Ok(()),
    }
}

impl<F, B> Package<F, B> {
    /// Check the invariants the rest of the core relies on: valid
    /// entries, and sections with valid names that refer only to their
    /// own blobs.
    ///
    /// Frontends parse untrusted archives and may run in a sandboxed process,
    /// so their output is checked again by the code that stores it.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.entries.iter().try_for_each(Entry::validate)?;
        if let Some(overlay) = &self.overlay {
            let mut paths = std::collections::BTreeSet::new();
            let mut files = std::collections::BTreeSet::new();
            for e in &self.entries {
                anyhow::ensure!(paths.insert(&*e.path), "/{} is listed twice", e.path);
                match &e.kind {
                    EntryKind::File(_) => {
                        files.insert(&*e.path);
                    }
                    EntryKind::Hardlink { target } => anyhow::ensure!(
                        files.contains(&**target),
                        "/{}: hard link to /{target}, which isn't a file of the overlay listed before",
                        e.path
                    ),
                    _ => {}
                }
            }
            for path in &overlay.removed {
                anyhow::ensure!(is_normal_path(path)?, "invalid path: {path:?}");
                anyhow::ensure!(paths.insert(path), "/{path} is listed twice");
            }
        }
        for (name, section) in &self.sections {
            crate::repo::check_format(name)?;
            let count = section.blobs.len() as u64;
            let mut value = section.value.clone();
            renumber(&mut value, &mut |index| {
                anyhow::ensure!(index.index < count, "no blob {}", index.index);
                Ok(index)
            })
            .with_context(|| format!("section {name}"))?;
        }
        Ok(())
    }
}

impl<F> Entry<F> {
    /// Check the path, mode and hard link target, as
    /// [`Package::validate`] does for each entry.
    pub fn validate(&self) -> anyhow::Result<()> {
        let path = &self.path;
        anyhow::ensure!(is_normal_path(path)?, "invalid path: {path:?}");
        anyhow::ensure!(
            self.mode & !0o7777 == 0,
            "/{path}: invalid mode {:o}",
            self.mode
        );
        if let EntryKind::Hardlink { target } = &self.kind {
            anyhow::ensure!(
                is_normal_path(target)?,
                "/{path}: invalid hard link target {target:?}"
            );
        }
        Ok(())
    }
}

/// Whether `path` is non-empty and already normalized (see
/// [`normalize_path`]); an error if it contains `..`.
pub fn is_normal_path(path: &str) -> anyhow::Result<bool> {
    Ok(!path.is_empty() && normalize_path(path)? == path)
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

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[usize::from(b >> 4)].into());
        s.push(DIGITS[usize::from(b & 15)].into());
    }
    s
}

pub(crate) fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    let bad = || anyhow::anyhow!("invalid hex string: {s}");
    if !s.len().is_multiple_of(2) {
        return Err(bad());
    }
    let (pairs, _) = s.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| Ok(digit(hi).ok_or_else(bad)? << 4 | digit(lo).ok_or_else(bad)?))
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
    use serde_json::json;

    #[test]
    fn normalize() {
        assert_eq!(normalize_path("./usr/bin/").unwrap(), "usr/bin");
        assert_eq!(normalize_path("/etc//passwd").unwrap(), "etc/passwd");
        assert_eq!(normalize_path("./").unwrap(), "");
        assert!(normalize_path("usr/../etc").is_err());
    }

    fn entry<F>(path: &str, kind: EntryKind<F>) -> Entry<F> {
        Entry {
            path: path.into(),
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: BTreeMap::new(),
        }
    }

    fn package<F, B>(
        entries: Vec<Entry<F>>,
        sections: BTreeMap<String, Section<B>>,
    ) -> Package<F, B> {
        Package {
            name: "p".into(),
            version: "1".into(),
            entries,
            sections,
            overlay: None,
        }
    }

    fn content(s: &str) -> Content {
        Content {
            hash: blake3::hash(s.as_bytes()).into(),
            size: s.len() as u64,
        }
    }

    #[test]
    fn validate() {
        let pkg =
            |path: &str| package::<Content, Hash>(vec![entry(path, EntryKind::Dir)], [].into());
        assert!(pkg("usr/bin").validate().is_ok());
        for bad in ["", "/usr", "usr/", "usr//bin", "usr/./bin", "usr/../etc"] {
            assert!(pkg(bad).validate().is_err(), "{bad:?}");
        }
        let with_section = |name: &str, value| {
            let section = Section {
                value,
                blobs: vec![content("a").hash],
            };
            package::<Content, Hash>(vec![], [(name.to_owned(), section)].into())
        };
        assert!(
            with_section("arch", json!({"x": {"#": 0}}))
                .validate()
                .is_ok()
        );
        assert!(
            with_section("arch", json!({"x": {"#": 1}}))
                .validate()
                .is_err()
        );
        assert!(
            with_section("arch", json!({"#": 0, "x": 1}))
                .validate()
                .is_err()
        );
        assert!(with_section("Arch", json!({})).validate().is_err());
    }

    #[test]
    fn resolve_blob_ids() {
        let pkg = |blob, section_blob| {
            let section = Section {
                value: json!({"install": {"#": 0}}),
                blobs: vec![BlobId { blob: section_blob }],
            };
            package(
                vec![entry("f", EntryKind::File(BlobId { blob }))],
                [("arch".to_owned(), section)].into(),
            )
        };
        let (a, b) = (content("a"), content("b"));
        let resolved = pkg(1, 0).resolve(&[a, b]).unwrap();
        assert_eq!(resolved.entries[0].kind, EntryKind::File(b));
        assert_eq!(resolved.sections["arch"].blobs, [a.hash]);
        assert!(pkg(2, 0).resolve(&[a, b]).is_err());
        assert!(pkg(0, 2).resolve(&[a, b]).is_err());
        assert!(pkg(u64::MAX, 0).resolve(&[a]).is_err());
    }

    #[test]
    fn object_roundtrip() {
        let (a, b) = (content("a"), content("b"));
        let section = Section {
            value: json!({"depends": ["x"], "install": {"#": 1}, "more": [{"#": 0}]}),
            blobs: vec![a.hash, b.hash],
        };
        let pkg = package(
            vec![
                entry("z", EntryKind::File(a)),
                entry("y", EntryKind::File(a)),
                entry("d", EntryKind::Dir),
            ],
            [("arch".to_owned(), section)].into(),
        );
        let (refs, body) = pkg.to_object().unwrap();
        let data = crate::object::encode(refs.as_slice(), &body).unwrap();
        let obj = crate::object::decode(&data).unwrap();
        assert_eq!(obj.refs, [Ref::Blob(a.hash), Ref::Blob(b.hash)]);
        let text = std::str::from_utf8(&data).unwrap();
        assert!(
            text.contains(r##"{"blob":{"#":0},"gid":0,"mode":420,"mtime":0,"path":"z","size":1,"##),
            "{text}"
        );
        // Read back, the section lists its blobs in the order of first
        // use; that is the same package.
        let back = Package::from_object(&obj).unwrap();
        let swapped = Section {
            value: json!({"depends": ["x"], "install": {"#": 0}, "more": [{"#": 1}]}),
            blobs: vec![b.hash, a.hash],
        };
        let mut expected = pkg.clone();
        expected.sections.insert("arch".into(), swapped);
        assert_eq!(back, expected);
        let (refs, body) = back.to_object().unwrap();
        assert_eq!(crate::object::encode(refs.as_slice(), &body).unwrap(), data);
    }

    #[test]
    fn overlays() {
        let (a, b) = (content("a"), content("b"));
        let mut pkg = package::<Content, Hash>(
            vec![
                entry("etc/a", EntryKind::File(a)),
                entry(
                    "etc/b",
                    EntryKind::Hardlink {
                        target: "etc/a".into(),
                    },
                ),
            ],
            [].into(),
        );
        pkg.overlay = Some(Overlay {
            removed: vec!["usr/x".into()],
        });
        pkg.validate().unwrap();
        let (refs, body) = pkg.to_object().unwrap();
        assert_eq!(body["overlay"], json!(true));
        assert_eq!(body["removed"], json!(["usr/x"]));
        let data = crate::object::encode(refs.as_slice(), &body).unwrap();
        let back = Package::from_object(&crate::object::decode(&data).unwrap()).unwrap();
        assert_eq!(back, pkg);
        // Ordinary packages leave both out.
        let plain = package::<Content, Hash>(vec![entry("f", EntryKind::File(b))], [].into());
        let (_, body) = plain.to_object().unwrap();
        assert!(body.get("overlay").is_none() && body.get("removed").is_none());
        // Hard links only to files listed before, each path once.
        let mut bad = pkg.clone();
        bad.entries.reverse();
        assert!(bad.validate().is_err());
        let mut bad = pkg.clone();
        bad.overlay.as_mut().unwrap().removed.push("etc/a".into());
        assert!(bad.validate().is_err());
        let mut bad = pkg.clone();
        bad.overlay.as_mut().unwrap().removed.push("../x".into());
        assert!(bad.validate().is_err());
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
