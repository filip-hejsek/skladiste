//! Arch Linux package frontend: reads `.pkg.tar.zst` archives into the store.
//!
//! What skl needs of `.PKGINFO`, the install scriptlet (`.INSTALL`) and
//! the package's alpm hooks ([`hooks`]) are kept in the manifest's Arch
//! section ([`ArchSection`]); `.MTREE`, `.BUILDINFO` and `.CHANGELOG` are
//! ignored.
//!
//! The archive is untrusted input, so [`import`] parses it in a sandboxed
//! worker process that touches nothing but the archive and the socket it
//! streams file contents and the manifest to.

use std::fs::File;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::manifest::{BlobId, Package, Section};
use crate::object::Index;
use crate::store::Store;
use crate::worker::{self, ImportStats, Workers};

pub mod hooks;
pub mod keyring;
pub mod packages;
pub mod repo;
pub mod scripts;
pub mod signature;
pub mod verify;
pub mod version;

pub(crate) mod import_worker;

/// Parse an Arch package archive, adding its file contents to `store`.
/// The returned manifest is checked but not saved. The archive is parsed
/// in a worker that can access nothing but the archive.
pub fn import(workers: &Workers, store: &Store, archive: File) -> Result<(Package, ImportStats)> {
    let (ours, theirs) = worker::stream_socket()?;
    let w = workers.spawn(&import_worker::KIND, archive.into(), theirs, &[], &[])?;
    let mut conn = worker::receiver(ours)?;
    let result = worker::receive_blobs(store, &mut conn).and_then(|(blobs, json, stats)| {
        let pkg: Package<BlobId, BlobId> =
            serde_json::from_slice(&json).context("parsing manifest from worker")?;
        let pkg = pkg.resolve(&blobs)?;
        pkg.validate()?;
        Ok((pkg, stats))
    });
    drop(conn);
    w.finish(result)
}

/// The name of Arch's section in package manifests.
pub const SECTION: &str = "arch";

/// What a package manifest keeps for Arch, as its section [`SECTION`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchSection {
    /// Dependencies, provides and conflicts from `.PKGINFO`, in Arch's
    /// syntax (e.g. `glibc>=2.40`), checked when importing.
    pub depends: Vec<String>,
    pub provides: Vec<String>,
    pub conflicts: Vec<String>,
    /// The install scriptlet (`.INSTALL`): a blob of the section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<Index>,
    /// The package's alpm hooks, read from its hook files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<hooks::Hook>,
}

impl ArchSection {
    /// The Arch section of `pkg`.
    pub fn of<F>(pkg: &Package<F>) -> Result<ArchSection> {
        let section = pkg
            .sections
            .get(SECTION)
            .with_context(|| format!("package {} has no {SECTION} section", pkg.name))?;
        serde_json::from_value(section.value.clone())
            .with_context(|| format!("package {}: reading its {SECTION} section", pkg.name))
    }

    /// Check what the import worker made of a package: its hooks (the
    /// dependencies are checked by [`repo::package_candidate`]).
    pub fn validate(&self) -> Result<()> {
        self.hooks.iter().try_for_each(hooks::Hook::validate)
    }

    /// The section with this content, whose references are to `blobs`,
    /// and its name.
    pub fn into_section<F>(self, blobs: Vec<F>) -> Result<(String, Section<F>)> {
        let value = serde_json::to_value(self)?;
        Ok((SECTION.to_owned(), Section { value, blobs }))
    }
}
