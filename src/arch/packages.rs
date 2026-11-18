//! Getting Arch packages into the store: importing package files into
//! `@local` ([`import_local`]), and choosing packages for a build from
//! repos ([`load_sources`], [`choose`]) and importing those
//! ([`get_packages`]).
//!
//! Each import runs in its own worker (so a compromised worker can't
//! change another package's manifest), after the archive's signature was
//! verified. Downloads are verified before they are kept in the store,
//! and verified again whenever a later run uses them.

use std::cmp::Reverse;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail, ensure};
use sha2::{Digest, Sha256};

use crate::arch::repo::{self, DbEntry, LOCAL_REPO as LOCAL, Snapshot};
use crate::arch::signature::MAX_SIGNATURE_SIZE;
use crate::arch::verify::Verifier;
use crate::arch::{self, version};
use crate::download::{Request, Sink, fetch_and_run};
use crate::http::Url;
use crate::jobs::par_map;
use crate::manifest::{Hash, Package, hex_encode};
use crate::resolve::{self, Candidate, Target};
use crate::store::{Store, TmpFile, hash_reader};
use crate::worker::{ImportStats, Workers};

/// What importing packages needs. `'v`: the verifier's (see
/// [`Verifier`]).
pub struct Context<'a, 'v> {
    pub workers: &'a Workers,
    pub store: &'a Store,
    pub verifier: &'a Verifier<'v>,
    /// Number of packages to import at once, and of servers to download
    /// from at once.
    pub jobs: NonZeroUsize,
    /// Called with what happens, from the threads that do it.
    pub report: &'a (dyn Fn(Event) + Sync),
}

/// What happened while importing packages; see [`Context::report`].
pub enum Event<'a> {
    /// A package was downloaded, verified and kept in the store as `name`
    /// in `repo`'s downloads.
    Downloaded {
        repo: &'a str,
        name: &'a str,
        size: u64,
    },
    /// A package was imported.
    Imported {
        package: &'a Package,
        stats: &'a ImportStats,
    },
    /// A package given to [`import_local`] had been imported before.
    AlreadyImported(&'a Package),
}

/// A package for [`import_local`].
pub enum LocalPackage<'a> {
    File(LocalFile<'a>),
    /// A package to download, with its signature at the same URL with
    /// `.sig` appended.
    Url(Url),
}

/// A package file for [`import_local`], opened only when its import
/// begins, so that few files are open at once.
pub struct LocalFile<'a> {
    /// What to call the package in messages, e.g. its path.
    pub name: String,
    /// The archive's size, by which the largest are imported first.
    pub size: u64,
    /// Opens the archive and its signature.
    pub open: Box<dyn FnOnce() -> Result<(File, File)> + Send + 'a>,
}

/// A package for one of [`import_local`]'s jobs.
enum LocalArchive<'a> {
    File(LocalFile<'a>),
    /// A download that an earlier run kept in the store.
    Kept(&'a Url),
    /// A download of this run, verified and kept in the store.
    Fetched(&'a Url, File),
}

/// The size of a download in the store, if it is there.
fn kept_size(store: &Store, repo: &str, name: &str) -> Result<Option<u64>> {
    let file = store.open_download(repo, name)?;
    Ok(file.map(|f| f.metadata().map_or(0, |m| m.len())))
}

/// Import `packages` into `@local`. URLs that the store has no download
/// for are downloaded meanwhile, the signature before the archive; the
/// downloads are kept in the store's `downloads/@arch/@local/`, by file
/// name. The largest archives that are there are imported first, as they
/// take longest.
pub fn import_local(ctx: &Context, packages: Vec<LocalPackage>) -> Result<()> {
    // Before `ready`, which borrows from it.
    let mut urls = Vec::new();
    let mut ready = Vec::new();
    for package in packages {
        match package {
            LocalPackage::File(file) => ready.push((file.size, LocalArchive::File(file))),
            LocalPackage::Url(url) => urls.push(url),
        }
    }
    let mut missing = Vec::new();
    for url in &urls {
        let name = url.file_name();
        // Only verified downloads are kept, the archive first, so an
        // archive whose signature is there was complete.
        let sig = kept_size(ctx.store, LOCAL, &format!("{name}.sig"))?;
        match (sig, kept_size(ctx.store, LOCAL, name)?) {
            (Some(_), Some(size)) => ready.push((size, LocalArchive::Kept(url))),
            _ => missing.push(url),
        }
    }
    ready.sort_by_key(|&(size, _)| Reverse(size));
    let ready = ready.into_iter().map(|(_, archive)| archive).collect();
    // Nothing says what a URL should have, so if a file changes on the
    // server while it is downloaded, the new one is taken.
    let requests = missing
        .iter()
        .flat_map(|url| {
            [
                Request {
                    url: url.with_suffix(".sig"),
                    max_size: MAX_SIGNATURE_SIZE,
                    restart_if_changed: true,
                    sink: LocalSink::Signature(Vec::new()),
                },
                Request {
                    url: (*url).clone(),
                    max_size: u64::MAX,
                    restart_if_changed: true,
                    sink: LocalSink::Archive(ArchiveSink::new(ctx.store)),
                },
            ]
        })
        .collect();
    // The signature and the archive of each package, until both are there.
    type Parts<'a> = (Option<Vec<u8>>, Option<ArchiveSink<'a>>);
    let parts: Vec<Mutex<Parts>> = missing.iter().map(|_| Mutex::default()).collect();
    fetch_and_run(
        ctx.workers,
        ctx.jobs,
        ready,
        requests,
        |n, sink, _| {
            let url = missing[n / 2];
            let mut parts = parts[n / 2].lock().unwrap();
            match sink {
                LocalSink::Signature(sig) => parts.0 = Some(sig),
                LocalSink::Archive(archive) => parts.1 = Some(archive),
            }
            let (sig, archive) = match (parts.0.take(), parts.1.take()) {
                (Some(sig), Some(archive)) => (sig, archive),
                // The package's other file isn't there yet.
                rest => {
                    *parts = rest;
                    return Ok(None);
                }
            };
            let file = keep_download(ctx, LOCAL, url.file_name(), url, &sig, archive, None)?;
            Ok(Some(LocalArchive::Fetched(url, file)))
        },
        |archive| {
            let (file, what) = match archive {
                LocalArchive::File(LocalFile { name, open, .. }) => {
                    let (file, sig) = open()?;
                    let sig = read_signature(sig)
                        .with_context(|| format!("reading the signature of {name}"))?;
                    ctx.verifier
                        .verify(&sig, &file)
                        .with_context(|| format!("verifying {name}"))?;
                    (file, name)
                }
                LocalArchive::Kept(url) => (open_kept(ctx, url)?, url.to_string()),
                LocalArchive::Fetched(url, file) => (file, url.to_string()),
            };
            let (imported, new) = import_archive(ctx, file, &what, LOCAL, None)?;
            if !new {
                (ctx.report)(Event::AlreadyImported(&imported.package));
            }
            Ok(())
        },
    )?;
    Ok(())
}

/// A package in the store: its id and its manifest.
#[derive(Debug, Clone)]
pub struct Imported {
    pub id: Hash,
    pub package: Package,
}

/// What a repo offers to a build.
pub enum Source {
    /// The packages imported into `@local`, sorted by name, newest version
    /// first.
    Local(Vec<Imported>),
    /// A configured repo's latest snapshot.
    Synced(Box<Snapshot>),
}

/// What each of `repos` (ids) offers, loaded `jobs` at once: the latest
/// snapshot of a configured repo, or the imported packages for `@local`.
pub fn load_sources(
    workers: &Workers,
    store: &Store,
    repos: &[String],
    jobs: NonZeroUsize,
) -> Result<Vec<Source>> {
    par_map(repos, jobs, |repo| {
        if repo == LOCAL {
            load_local(store).map(Source::Local)
        } else {
            Snapshot::load(workers, store, repo).map(|s| Source::Synced(Box::new(s)))
        }
    })
}

/// All packages in `@local`'s index, sorted by name, newest version
/// first, so that the resolver prefers the newest that fits.
pub fn load_local(store: &Store) -> Result<Vec<Imported>> {
    let mut pkgs = Vec::new();
    for (_, id) in store.package_index(LOCAL)? {
        let package = store.load_package(&id)?;
        pkgs.push(Imported { id, package });
    }
    pkgs.sort_by(|a, b| {
        let (a, b) = (&a.package, &b.package);
        a.name
            .cmp(&b.name)
            .then_with(|| version::vercmp(&b.version, &a.version))
    });
    Ok(pkgs)
}

/// A package chosen for a build.
pub enum Chosen<'a> {
    /// An imported package.
    Local(&'a Imported),
    Repo(RepoPackage<'a>),
}

/// A package from a repo's snapshot, downloaded from `url`.
pub struct RepoPackage<'a> {
    /// The repo's id.
    pub repo: &'a str,
    pub entry: &'a DbEntry,
    pub url: Url,
}

impl RepoPackage<'_> {
    /// The package's signature, from the repo's database.
    fn signature(&self) -> Result<&[u8]> {
        let Self { repo, entry, .. } = self;
        entry.pgpsig.as_deref().with_context(|| {
            format!(
                "{repo}/{} has no signature in the repo's database",
                entry.filename
            )
        })
    }
}

/// Resolve `targets` with their dependencies against `sources`, in
/// priority order (see [`resolve`]); [`Target::repo`] is an index into
/// `sources`.
pub fn choose<'a>(sources: &'a [Source], targets: &[Target]) -> Result<Vec<Chosen<'a>>> {
    let candidates = sources
        .iter()
        .map(|source| match source {
            Source::Local(pkgs) => pkgs
                .iter()
                .map(|p| repo::package_candidate(&p.package))
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("in repo {LOCAL}")),
            Source::Synced(snapshot) => snapshot.candidates(),
        })
        .collect::<Result<Vec<_>>>()?;
    let candidates: Vec<&[Candidate]> = candidates.iter().map(Vec::as_slice).collect();
    let chosen = resolve::resolve(&candidates, targets, version::vercmp)?;
    chosen
        .into_iter()
        .map(|(r, i)| match &sources[r] {
            Source::Local(pkgs) => Ok(Chosen::Local(&pkgs[i])),
            Source::Synced(snapshot) => {
                let entry = &snapshot.entries[i];
                ensure!(
                    entry.arch == repo::ARCH || entry.arch == "any",
                    "package {}/{} is for {}, not {}",
                    snapshot.repo,
                    entry.name,
                    entry.arch,
                    repo::ARCH
                );
                Ok(Chosen::Repo(RepoPackage {
                    repo: &snapshot.repo,
                    url: snapshot.config.package_url(&entry.filename)?,
                    entry,
                }))
            }
        })
        .collect()
}

/// The ids of `chosen` if all of them are imported packages, which
/// [`get_packages`] needs no verifier for.
pub fn all_local(chosen: &[Chosen]) -> Option<Vec<Hash>> {
    chosen
        .iter()
        .map(|c| match c {
            Chosen::Local(pkg) => Some(pkg.id),
            Chosen::Repo(_) => None,
        })
        .collect()
}

/// The id of each of `chosen`, in the same order. Packages from
/// repo snapshots are verified, and imported where needed. Those that the
/// store has no download for are downloaded meanwhile, if `fetch` allows,
/// largest first by the size in the repo's database. Of the archives that
/// are there, the largest are imported first, as they take longest.
pub fn get_packages(ctx: &Context, chosen: &[Chosen], fetch: bool) -> Result<Vec<Hash>> {
    let mut packages: Vec<Option<Hash>> = Vec::new();
    let mut kept = Vec::new();
    let mut missing = Vec::new();
    for (i, chosen) in chosen.iter().enumerate() {
        let pkg = match chosen {
            Chosen::Local(pkg) => {
                packages.push(Some(pkg.id));
                continue;
            }
            Chosen::Repo(pkg) => pkg,
        };
        packages.push(None);
        pkg.signature()?;
        let (repo, name) = (pkg.repo, &pkg.entry.filename);
        match kept_size(ctx.store, repo, name)? {
            Some(size) => kept.push((size, i, pkg)),
            None => {
                ensure!(
                    fetch,
                    "{repo}/{name} is not in the store (use --fetch to download packages)"
                );
                missing.push((i, pkg));
            }
        }
    }
    kept.sort_by_key(|&(size, ..)| Reverse(size));
    missing.sort_by_key(|&(_, pkg)| Reverse(pkg.entry.csize));
    let ready = kept.into_iter().map(|(_, i, pkg)| (i, pkg, None)).collect();
    // The database says what each file is, so another version of one
    // can't be right.
    let requests = missing
        .iter()
        .map(|&(_, pkg)| Request {
            url: pkg.url.clone(),
            max_size: pkg.entry.csize,
            restart_if_changed: false,
            sink: ArchiveSink::new(ctx.store),
        })
        .collect();
    let imported = fetch_and_run(
        ctx.workers,
        ctx.jobs,
        ready,
        requests,
        |n, archive, _| {
            let (i, pkg) = missing[n];
            let (name, sig) = (&pkg.entry.filename, pkg.signature()?);
            let file = keep_download(ctx, pkg.repo, name, &pkg.url, sig, archive, Some(pkg.entry))?;
            Ok(Some((i, pkg, Some(file))))
        },
        |(i, pkg, fetched)| Ok((i, get_repo_package(ctx, pkg, fetched)?)),
    )?;
    for (i, pkg) in imported {
        packages[i] = Some(pkg);
    }
    packages
        .into_iter()
        .map(|pkg| pkg.context("a package was not imported"))
        .collect()
}

/// The id of a package from a repo's snapshot, importing its
/// archive if needed: `fetched`, which was downloaded and verified just
/// now, or else the download in the store, whose signature is checked
/// first, every time. The archive must have the SHA-256, and the package
/// the name and version, that the repo's database gives.
fn get_repo_package(ctx: &Context, pkg: &RepoPackage, fetched: Option<File>) -> Result<Hash> {
    let RepoPackage { repo, entry, .. } = pkg;
    let name = &entry.filename;
    let file = match fetched {
        Some(file) => file,
        None => {
            let file = ctx
                .store
                .open_download(repo, name)?
                .with_context(|| format!("{repo}/{name} is no longer in the store"))?;
            ctx.verifier.verify(pkg.signature()?, &file).with_context(|| {
                format!("verifying {name}, downloaded earlier (delete downloads/{repo}/{name} in the store to download it again)")
            })?;
            file
        }
    };
    let what = format!("{repo}/{name}");
    let (imported, _) = import_archive(ctx, file, &what, repo, Some(entry))?;
    check_identity(&imported.package, entry).with_context(|| format!("checking {what}"))?;
    Ok(imported.id)
}

/// The package in `file`, whose signature was verified, from the store,
/// importing it if needed (the second value tells whether it was). The
/// repo's index has packages by the hash of the archive file, so the same
/// file is imported once per repo. With `entry`, the SHA-256 must be the one it
/// gives. The file is the one that was verified (which the verification
/// worker read through its own open file), so the parsed content is the
/// content that was verified and hashed, unless the file is written to
/// meanwhile (see planning/BUGS.md; only the supervisor writes
/// downloads). Concurrent calls for the same archive each import it.
fn import_archive(
    ctx: &Context,
    mut file: File,
    what: &str,
    repo: &str,
    entry: Option<&DbEntry>,
) -> Result<(Imported, bool)> {
    file.seek(SeekFrom::Start(0))?;
    let mut sha256 = entry.map(|_| Sha256::new());
    let hash = hash_reader(Tee {
        inner: &mut file,
        sha256: sha256.as_mut(),
    })
    .with_context(|| format!("reading {what}"))?;
    if let (Some(entry), Some(sha256)) = (entry, sha256) {
        check_sha256(sha256, entry).with_context(|| format!("checking {what}"))?;
    }
    if let Some(id) = ctx.store.indexed_package(repo, &hash)? {
        let package = ctx.store.load_package(&id)?;
        return Ok((Imported { id, package }, false));
    }
    file.seek(SeekFrom::Start(0))?;
    let importing = || format!("importing {what}");
    let (pkg, stats) =
        arch::import_in_worker(ctx.workers, ctx.store, file).with_context(importing)?;
    // The metadata must be usable for dependency resolution.
    repo::package_candidate(&pkg).with_context(importing)?;
    if let Some(entry) = entry {
        check_identity(&pkg, entry).with_context(importing)?;
    }
    let id = ctx.store.add_package(&pkg)?;
    ctx.store.index_package(repo, &hash, &id)?;
    (ctx.report)(Event::Imported {
        package: &pkg,
        stats: &stats,
    });
    Ok((Imported { id, package: pkg }, true))
}

/// `.PKGINFO`'s name and version must be those of the database entry.
fn check_identity(pkg: &Package, entry: &DbEntry) -> Result<()> {
    ensure!(
        pkg.name == entry.name && pkg.version == entry.version,
        "the package is {} {}, but the repo's database says {} {}",
        pkg.name,
        pkg.version,
        entry.name,
        entry.version
    );
    Ok(())
}

fn check_sha256(sha256: Sha256, entry: &DbEntry) -> Result<()> {
    let actual = hex_encode(&sha256.finalize());
    let expected = &entry.sha256;
    ensure!(
        actual.eq_ignore_ascii_case(expected),
        "SHA-256 is {actual}, but the repo's database says {expected}",
    );
    Ok(())
}

/// Passes reads through, also hashing them with SHA-256 if wanted.
struct Tee<'a, R> {
    inner: R,
    sha256: Option<&'a mut Sha256>,
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(h) = self.sha256.as_mut() {
            h.update(&buf[..n]);
        }
        Ok(n)
    }
}

/// Writes a download to an unnamed file in the store, hashing it with
/// SHA-256. The file is created when the download begins, so downloads
/// that wait for their turn keep no file open.
struct ArchiveSink<'a> {
    store: &'a Store,
    tmp: Option<TmpFile<'a>>,
    sha256: Sha256,
    size: u64,
}

impl<'a> ArchiveSink<'a> {
    fn new(store: &'a Store) -> Self {
        ArchiveSink {
            store,
            tmp: None,
            sha256: Sha256::new(),
            size: 0,
        }
    }

    fn tmp(&mut self) -> Result<&mut TmpFile<'a>> {
        if self.tmp.is_none() {
            self.tmp = Some(self.store.tmp_file()?);
        }
        Ok(self.tmp.as_mut().unwrap())
    }
}

impl Sink for ArchiveSink<'_> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.tmp()?.file().write_all(data)?;
        self.sha256.update(data);
        self.size += data.len() as u64;
        Ok(())
    }

    fn restart(&mut self) -> Result<()> {
        *self = ArchiveSink::new(self.store);
        Ok(())
    }
}

/// Where a download for [`import_local`] goes.
enum LocalSink<'a> {
    /// Kept in memory.
    Signature(Vec<u8>),
    Archive(ArchiveSink<'a>),
}

impl Sink for LocalSink<'_> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        match self {
            LocalSink::Signature(sig) => Sink::write(sig, data),
            LocalSink::Archive(archive) => archive.write(data),
        }
    }

    fn restart(&mut self) -> Result<()> {
        match self {
            LocalSink::Signature(sig) => sig.restart(),
            LocalSink::Archive(archive) => archive.restart(),
        }
    }
}

/// The archive from `url` that an earlier run kept in the store, verified
/// again with the signature kept next to it.
fn open_kept(ctx: &Context, url: &Url) -> Result<File> {
    let name = url.file_name();
    let sig_name = format!("{name}.sig");
    let open = |name: &str| {
        let file = ctx.store.open_download(LOCAL, name)?;
        file.with_context(|| format!("{LOCAL}/{name} is no longer in the store"))
    };
    let (sig, file) = (open(&sig_name)?, open(name)?);
    let sig = read_signature(sig).with_context(|| format!("reading downloaded {sig_name}"))?;
    ctx.verifier.verify(&sig, &file).with_context(|| {
        format!("verifying {name}, downloaded earlier (delete downloads/{LOCAL}/{name} in the store to download it again)")
    })?;
    Ok(file)
}

/// Keep the finished download `archive` of `url` as `name` in `repo`'s
/// downloads if `sig` verifies it, with the signature next to it (`.sig`),
/// written after the archive: only verified downloads are kept. With
/// `entry`, the size and SHA-256 must be those it gives.
fn keep_download(
    ctx: &Context,
    repo: &str,
    name: &str,
    url: &Url,
    sig: &[u8],
    mut archive: ArchiveSink,
    entry: Option<&DbEntry>,
) -> Result<File> {
    let size = archive.size;
    if let Some(entry) = entry {
        ensure!(
            size == entry.csize,
            "{url} has {size} bytes, but the repo's database says {}",
            entry.csize
        );
        check_sha256(archive.sha256.clone(), entry)
            .with_context(|| format!("downloading {url}"))?;
    }
    // An empty download has no file yet.
    ctx.verifier
        .verify(sig, archive.tmp()?.file())
        .with_context(|| format!("verifying {url}"))?;
    let store = ctx.store;
    let file = archive.tmp.take().unwrap().save_download(repo, name)?;
    let sig_name = format!("{name}.sig");
    let mut sig_tmp = store.tmp_file()?;
    sig_tmp
        .file()
        .write_all(sig)
        .with_context(|| format!("writing {sig_name}"))?;
    sig_tmp.save_download(repo, &sig_name)?;
    (ctx.report)(Event::Downloaded { repo, name, size });
    Ok(file)
}

/// Read a signature file, which must be at most [`MAX_SIGNATURE_SIZE`]
/// bytes.
fn read_signature(file: File) -> Result<Vec<u8>> {
    let mut sig = Vec::new();
    file.take(MAX_SIGNATURE_SIZE + 1).read_to_end(&mut sig)?;
    if sig.len() as u64 > MAX_SIGNATURE_SIZE {
        bail!("signature file is too large");
    }
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::ArchSection;

    #[test]
    fn local_packages_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_path(dir.path()).unwrap();
        let add = |name: &str, version: &str, depends: &[&str]| {
            let id = format!("{name} {version}");
            let hash = store.add_blob(&mut id.as_bytes()).unwrap().hash;
            let section = ArchSection {
                depends: depends.iter().map(|d| (*d).to_owned()).collect(),
                ..ArchSection::default()
            };
            let pkg = Package {
                name: name.into(),
                version: version.into(),
                entries: vec![],
                sections: [section.into_section(vec![]).unwrap()].into(),
                overlay: None,
            };
            let id = store.add_package(&pkg).unwrap();
            store.index_package(LOCAL, &hash, &id).unwrap();
        };
        add("lib", "1.9-1", &[]);
        add("lib", "1.10-1", &[]);
        add("lib", "2.0-1", &[]);
        add("app", "1-1", &["lib<2"]);
        let sources = [Source::Local(load_local(&store).unwrap())];
        let build = |names: &[&str]| -> Vec<String> {
            let targets: Vec<Target> = names
                .iter()
                .map(|n| Target {
                    name: (*n).to_owned(),
                    repo: None,
                })
                .collect();
            let chosen = choose(&sources, &targets).unwrap();
            all_local(&chosen)
                .unwrap()
                .iter()
                .map(|id| {
                    let pkg = store.load_package(id).unwrap();
                    format!("{} {}", pkg.name, pkg.version)
                })
                .collect()
        };
        assert_eq!(build(&["lib"]), ["lib 2.0-1"]);
        assert_eq!(build(&["app"]), ["app 1-1", "lib 1.10-1"]);
    }
}
