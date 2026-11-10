//! Format-independent description of a package's contents.
//!
//! Frontends (e.g. [`crate::arch`]) translate their native package format into
//! a [`Package`]; everything after that point works only with these types.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub entries: Vec<Entry>,
}

/// One filesystem entry. `path` is relative to the image root, without a
/// leading or trailing slash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    #[serde(flatten)]
    pub kind: EntryKind,
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
pub enum EntryKind {
    Dir,
    File {
        hash: Hash,
        size: u64,
    },
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
    fn entry_json_roundtrip() {
        let e = Entry {
            path: "usr/bin/ping".into(),
            kind: EntryKind::File {
                hash: blake3::hash(b"x").into(),
                size: 1,
            },
            mode: 0o4755,
            uid: 0,
            gid: 0,
            mtime: 1,
            xattrs: [("security.capability".into(), XattrValue(vec![1, 2, 0xff]))].into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains(r#""type":"file""#));
        assert!(json.contains(r#""security.capability":"0102ff""#));
        assert_eq!(serde_json::from_str::<Entry>(&json).unwrap(), e);
    }
}
