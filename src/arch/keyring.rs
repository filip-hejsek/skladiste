//! The Arch keyring in the store: the keys that package signatures are
//! checked with.
//!
//! The keyring is a [`Record`], an object that refers to the three files
//! of an Arch keyring as blobs (as in `/usr/share/pacman/keyrings/`), and
//! to the `archlinux-keyring` package they were taken from, if any. The
//! store's `keyrings/@arch` holds the id of the current one
//! ([`Store::keyring`]). It is set from files the user trusts ([`init`]),
//! and updated from an imported `archlinux-keyring` package ([`update`]),
//! which the caller checked with the current keyring like any package. An
//! update never goes to an older version of the package.

use std::cmp::Ordering;
use std::fs::File;
use std::time::SystemTime;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::arch::repo::FORMAT;
use crate::arch::verify::{self, KeyringFiles, Verifier};
use crate::arch::version::vercmp;
use crate::manifest::{EntryKind, Hash};
use crate::object::{Index, Object, Ref, Refs};
use crate::store::Store;
use crate::worker::Workers;

/// The name of the package that has the keyring.
pub const PACKAGE: &str = "archlinux-keyring";

/// Where the package has the keyring's files: certificates, master keys,
/// revoked keys.
const PATHS: [&str; 3] = [
    "usr/share/pacman/keyrings/archlinux.gpg",
    "usr/share/pacman/keyrings/archlinux-trusted",
    "usr/share/pacman/keyrings/archlinux-revoked",
];

/// A keyring in the store: its files as blobs, and where they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// OpenPGP certificates (`archlinux.gpg`).
    pub certs: Hash,
    /// Master key fingerprints (`archlinux-trusted`).
    pub trusted: Hash,
    /// Revoked key fingerprints (`archlinux-revoked`).
    pub revoked: Hash,
    /// The package the files were taken from; `None` for files the user
    /// gave ([`init`]).
    pub package: Option<FromPackage>,
    /// When the keyring was set, by [`crate::repo::timestamp`].
    pub added: String,
}

/// The `archlinux-keyring` package a keyring was taken from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromPackage {
    pub id: Hash,
    pub version: String,
}

/// A record as an object's body stores it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    certs: Index,
    trusted: Index,
    revoked: Index,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package: Option<StoredPackage>,
    added: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPackage {
    id: Index,
    version: String,
}

impl Record {
    fn new(files: [Hash; 3], package: Option<FromPackage>) -> Record {
        let [certs, trusted, revoked] = files;
        Record {
            certs,
            trusted,
            revoked,
            package,
            added: crate::repo::timestamp(SystemTime::now()),
        }
    }

    fn blobs(&self) -> [Hash; 3] {
        [self.certs, self.trusted, self.revoked]
    }

    /// The record as an object: its references and body.
    pub fn to_object(&self) -> Result<(Refs, Value)> {
        let mut refs = Refs::new();
        let body = serde_json::to_value(Stored {
            certs: refs.add(Ref::Blob(self.certs)),
            trusted: refs.add(Ref::Blob(self.trusted)),
            revoked: refs.add(Ref::Blob(self.revoked)),
            package: self.package.as_ref().map(|p| StoredPackage {
                id: refs.add(Ref::Object(p.id)),
                version: p.version.clone(),
            }),
            added: self.added.clone(),
        })?;
        Ok((refs, body))
    }

    /// The record in `obj`.
    pub fn from_object(obj: &Object) -> Result<Record> {
        let s: Stored = serde_json::from_value(obj.body.clone())?;
        Ok(Record {
            certs: obj.blob(s.certs)?,
            trusted: obj.blob(s.trusted)?,
            revoked: obj.blob(s.revoked)?,
            package: s
                .package
                .map(|p| -> Result<_> {
                    Ok(FromPackage {
                        id: obj.object(p.id)?,
                        version: p.version,
                    })
                })
                .transpose()?,
            added: s.added,
        })
    }

    /// The keyring's files, opened from the store.
    pub fn files(&self, store: &Store) -> Result<KeyringFiles> {
        let open = |hash| store.open_blob(hash).map(File::from);
        Ok(KeyringFiles {
            certs: open(&self.certs)?,
            trusted: open(&self.trusted)?,
            revoked: open(&self.revoked)?,
        })
    }
}

/// The store has no Arch keyring; see [`init`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoKeyring;

impl std::fmt::Display for NoKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the store has no Arch keyring")
    }
}

impl std::error::Error for NoKeyring {}

/// The store's keyring, with the id of its record, if one was set.
pub fn current(store: &Store) -> Result<Option<(Hash, Record)>> {
    let Some(id) = store.keyring(FORMAT)? else {
        return Ok(None);
    };
    let obj = store.read_object(&id)?;
    let record = Record::from_object(&obj).with_context(|| format!("reading keyring {id}"))?;
    Ok(Some((id, record)))
}

/// Run `f` with a verifier that checks signatures with the store's
/// keyring, in up to `max` workers at once (see [`verify::with_verifier`]).
/// Fails with [`NoKeyring`] if there is none.
pub fn with_verifier<T>(
    workers: &Workers,
    store: &Store,
    max: usize,
    f: impl FnOnce(&Verifier) -> Result<T>,
) -> Result<T> {
    let (id, record) = current(store)?.ok_or(NoKeyring)?;
    let loading = || format!("loading keyring {id}");
    let files = record.files(store).with_context(loading)?;
    verify::with_verifier(workers, files, max, f).map_err(|e| {
        match e.is::<verify::KeyringError>() {
            true => e.context(loading()),
            false => e,
        }
    })
}

/// What [`init`] or [`update`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The store's keyring was already this one, or (for [`update`]) one
    /// taken from the same version of the package; it is kept.
    Unchanged(Record),
    /// The keyring was set, replacing `old` if there was one.
    Set { old: Option<Record>, new: Record },
}

/// Make the keyring `files` (which the user trusts) the store's keyring,
/// replacing any keyring there. Fails if they don't load as a keyring.
pub fn init(workers: &Workers, store: &Store, files: KeyringFiles) -> Result<Outcome> {
    let KeyringFiles {
        certs,
        trusted,
        revoked,
    } = files;
    let mut blobs = Vec::new();
    for (mut file, path) in [certs, trusted, revoked].into_iter().zip(PATHS) {
        let name = path.rsplit_once('/').unwrap().1;
        let meta = file
            .metadata()
            .with_context(|| format!("checking {name}"))?;
        ensure!(meta.is_file(), "{name} is not a regular file");
        let added = store
            .add_blob(&mut file)
            .with_context(|| format!("reading {name}"))?;
        blobs.push(added.hash);
    }
    let blobs: [Hash; 3] = blobs.try_into().unwrap();
    let old = current(store)?.map(|(_, record)| record);
    if let Some(old) = old.as_ref().filter(|old| old.blobs() == blobs) {
        return Ok(Outcome::Unchanged(old.clone()));
    }
    set(workers, store, old, Record::new(blobs, None))
}

/// Make the keyring in the `archlinux-keyring` package `id` the store's
/// keyring, unless the store's is from the same or a newer version of the
/// package. The package must have been imported from a repo and verified
/// with the store's keyring, as builds import packages. Fails if it has
/// another name, lacks a keyring file, or its files don't load as a
/// keyring.
pub fn update(workers: &Workers, store: &Store, id: &Hash) -> Result<Outcome> {
    let pkg = store.load_package(id)?;
    ensure!(
        pkg.name == PACKAGE,
        "package {id} is {}, not {PACKAGE}",
        pkg.name
    );
    let what = || format!("{PACKAGE} {}", pkg.version);
    let mut blobs = Vec::new();
    for path in PATHS {
        let entry = pkg.entries.iter().find(|e| e.path == path);
        match entry.map(|e| &e.kind) {
            Some(EntryKind::File(content)) => blobs.push(content.hash),
            Some(_) => bail!("/{path} in {} is not a file", what()),
            None => bail!("{} has no /{path}", what()),
        }
    }
    let blobs: [Hash; 3] = blobs.try_into().unwrap();
    let old = current(store)?.map(|(_, record)| record);
    if let Some(from) = old.as_ref().and_then(|old| old.package.as_ref()) {
        match vercmp(&pkg.version, &from.version) {
            Ordering::Less => bail!(
                "{} is older than the keyring's {PACKAGE} {}",
                what(),
                from.version
            ),
            Ordering::Equal => return Ok(Outcome::Unchanged(old.unwrap())),
            Ordering::Greater => {}
        }
    }
    let package = FromPackage {
        id: *id,
        version: pkg.version,
    };
    set(workers, store, old, Record::new(blobs, Some(package)))
}

/// Make `new` the store's keyring in place of `old`, once its files load
/// as one.
fn set(workers: &Workers, store: &Store, old: Option<Record>, new: Record) -> Result<Outcome> {
    let files = new.files(store)?;
    verify::with_verifier(workers, files, 1, |_| Ok(())).context("loading the new keyring")?;
    let (refs, body) = new.to_object()?;
    let id = store.add_object(refs.as_slice(), &body)?;
    store.set_keyring(FORMAT, &id)?;
    Ok(Outcome::Set { old, new })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips() {
        let h = |b| Hash([b; 32]);
        for package in [
            None,
            Some(FromPackage {
                id: h(4),
                version: "20261010-1".into(),
            }),
        ] {
            let record = Record {
                certs: h(1),
                trusted: h(2),
                revoked: h(2),
                package,
                added: "2026-11-21T10:00:00.000000Z".into(),
            };
            let (refs, body) = record.to_object().unwrap();
            let data = crate::object::encode(refs.as_slice(), &body).unwrap();
            let obj = crate::object::decode(&data).unwrap();
            assert_eq!(Record::from_object(&obj).unwrap(), record);
        }
    }
}
