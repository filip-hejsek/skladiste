//! `skl arch`: commands for Arch Linux packages and repos.

use std::cmp::Reverse;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};

use skladiste::arch;
use skladiste::arch::repo::{DbEntry, LOCAL_REPO as LOCAL, Snapshot, repo_id};
use skladiste::arch::signature;
use skladiste::arch::verify::{self, KeyringError, KeyringFiles, Verifier};
use skladiste::download::{Request, Sink};
use skladiste::http::Url;
use skladiste::install;
use skladiste::jobs::par_map;
use skladiste::manifest::Package;
use skladiste::resolve::{self, Candidate, Target};
use skladiste::store::{Store, TmpFile, hash_reader};
use skladiste::worker::Workers;

use super::{fetch_and_run, mib};

#[derive(Args)]
pub(crate) struct ArchArgs {
    /// Arch keyring to verify package signatures with, as the path without
    /// suffix: PREFIX.gpg, PREFIX-trusted and PREFIX-revoked are read.
    /// Needed for importing packages.
    #[arg(long, env = "SKL_KEYRING", value_name = "PREFIX", global = true)]
    keyring: Option<PathBuf>,

    #[command(subcommand)]
    command: ArchCommand,
}

#[derive(Subcommand)]
enum ArchCommand {
    /// Import Arch package files into the store, as the repo `@local`.
    ///
    /// Packages are files or http(s) URLs. The signature is read from the
    /// same path or URL with `.sig` appended. Builds can use the imported
    /// packages with `--repo @local`. Downloads are kept in the store's
    /// `downloads/@arch/@local/` directory and not downloaded again for the
    /// same file name. Redirects are not followed.
    Import {
        /// Package files or URLs.
        #[arg(required = true, value_name = "FILE|URL")]
        packages: Vec<OsString>,
    },
    /// Create a new image subvolume containing the given packages and
    /// their dependencies.
    ///
    /// Install scripts are not run.
    Build {
        /// Path of the new subvolume (must not exist).
        #[arg(short, long)]
        output: PathBuf,
        /// Download the databases of the repos first, as `skl arch sync`
        /// does.
        #[arg(long)]
        sync: bool,
        /// Download packages that aren't in the store yet. Without this,
        /// a build uses the network only for `--sync`.
        #[arg(long)]
        fetch: bool,
        /// Repo to take packages from (repeatable, in priority order): a
        /// repo added with `skl arch repo add`, of which the latest sync is
        /// used, or `@local` for the packages imported with `skl arch
        /// import`. Repos are given by name (`core`) or by id
        /// (`@arch/core`).
        #[arg(long = "repo", value_name = "REPO", required = true)]
        repos: Vec<String>,
        /// Package names: `NAME`, or `REPO/NAME` to take it from that repo.
        #[arg(required = true, value_name = "PACKAGE")]
        packages: Vec<String>,
    },
    /// Manage Arch repos.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// Download the databases of Arch repos.
    ///
    /// Every version is kept; builds use the latest. Repos synced together
    /// get their new versions only once all of them were downloaded and
    /// read.
    Sync {
        /// Repos to sync [default: all].
        repos: Vec<String>,
    },
}

#[derive(Subcommand)]
enum RepoCommand {
    /// Add an Arch repo.
    Add {
        /// Name of the repo in skl.
        name: String,
        /// Server URL in the format of pacman's `Server`, e.g.
        /// `https://geo.mirror.pkgbuild.com/$repo/os/$arch` ($arch is
        /// x86_64).
        server: String,
        /// Name of the database on the server (`core` for core.db)
        /// [default: NAME].
        #[arg(long)]
        db: Option<String>,
    },
    /// List Arch repos with their server and the time of their latest
    /// sync.
    List,
}

/// Run `skl arch`.
pub(crate) fn run(
    args: ArchArgs,
    workers: &Workers,
    store: &Store,
    jobs: NonZeroUsize,
) -> Result<()> {
    let keyring = args.keyring.as_deref();
    match args.command {
        ArchCommand::Import { packages } => {
            with_verifier(workers, keyring, jobs, |verifier| {
                let ctx = Ctx {
                    workers,
                    store,
                    verifier,
                };
                import_local(&ctx, &packages, jobs)
            })?;
        }
        ArchCommand::Build {
            output,
            sync: sync_first,
            fetch,
            repos,
            packages,
        } => {
            if output.symlink_metadata().is_ok() {
                bail!("{} already exists", output.display());
            }
            let repos = repos
                .iter()
                .map(|r| repo_id(r))
                .collect::<Result<Vec<_>>>()?;
            let targets = packages
                .iter()
                .map(|arg| parse_target(arg, &repos))
                .collect::<Result<Vec<_>>>()?;
            let synced: Vec<String> = repos.iter().filter(|r| *r != LOCAL).cloned().collect();
            if sync_first && !synced.is_empty() {
                sync(workers, store, synced, jobs)?;
            }
            let sources = load_sources(workers, store, &repos, jobs)?;
            let chosen = choose(&sources, &targets)?;
            let packages = if chosen.iter().any(|c| matches!(c, Chosen::Repo(_))) {
                with_verifier(workers, keyring, jobs, |verifier| {
                    let ctx = Ctx {
                        workers,
                        store,
                        verifier,
                    };
                    get_packages(&ctx, &chosen, fetch, jobs)
                })?
            } else {
                chosen
                    .iter()
                    .filter_map(|c| match c {
                        Chosen::Local(pkg) => Some((*pkg).clone()),
                        Chosen::Repo(_) => None,
                    })
                    .collect()
            };
            let r = install::build(workers, store, &packages, &output)?;
            eprintln!(
                "built {}: {} files, {} dirs, {} symlinks, {} hard links",
                output.display(),
                r.files,
                r.dirs,
                r.symlinks,
                r.hardlinks
            );
            if r.chown_failures > 0 {
                eprintln!(
                    "warning: could not set owner of {} entries (try running as root or in a user namespace)",
                    r.chown_failures
                );
            }
            if r.xattr_failures > 0 {
                eprintln!("warning: could not set {} xattrs", r.xattr_failures);
            }
        }
        ArchCommand::Repo {
            command: RepoCommand::Add { name, server, db },
        } => {
            skladiste::repo::check_name(&name)?;
            let config = arch::repo::Config::new(&server, db.as_deref().unwrap_or(&name))?;
            store.add_repo(&repo_id(&name)?, &config)?;
        }
        ArchCommand::Repo {
            command: RepoCommand::List,
        } => {
            for id in arch_repos(store)? {
                let config: arch::repo::Config = store.repo_config(&id)?;
                let name = skladiste::repo::split_id(&id)?.1;
                let synced = match store.latest_sync(&id)? {
                    Some(record) => record.fetched,
                    None => "never synced".to_owned(),
                };
                println!("{name}\t{}\t{}\t{synced}", config.db, config.server);
            }
        }
        ArchCommand::Sync { repos } => {
            let repos = repos
                .iter()
                .map(|r| repo_id(r))
                .collect::<Result<Vec<_>>>()?;
            sync(workers, store, repos, jobs)?;
        }
    }
    Ok(())
}

/// The ids of the configured Arch repos, sorted.
fn arch_repos(store: &Store) -> Result<Vec<String>> {
    let mut ids = store.repos()?;
    ids.retain(|id| skladiste::repo::split_id(id).is_ok_and(|(f, _)| f == arch::repo::FORMAT));
    Ok(ids)
}

/// Download the databases of the repos with ids `repos` (all Arch repos if
/// empty), and record the new versions once all of them were downloaded
/// and read.
fn sync(workers: &Workers, store: &Store, repos: Vec<String>, jobs: NonZeroUsize) -> Result<()> {
    let repos = if repos.is_empty() {
        arch_repos(store)?
    } else {
        repos
    };
    if repos.is_empty() {
        bail!("no repos (add one with `skl arch repo add`)");
    }
    let configs = repos
        .iter()
        .map(|name| store.repo_config(name))
        .collect::<Result<Vec<arch::repo::Config>>>()?;
    let requests = configs
        .iter()
        .map(arch::repo::db_request)
        .collect::<Result<Vec<_>>>()?;
    let urls: Vec<Url> = requests.iter().map(|r| r.url.clone()).collect();
    let mut synced = fetch_and_run(
        workers,
        jobs,
        Vec::new(),
        requests,
        |i, data, downloaded| {
            let record = arch::repo::db_record(store, &urls[i], &data, downloaded)?;
            Ok(Some((i, record)))
        },
        |(i, record)| {
            let entries = arch::repo::load_db(workers, store, &record)?;
            Ok((i, record, entries.len()))
        },
    )?;
    synced.sort_by_key(|&(i, ..)| i);
    for (i, record, packages) in &synced {
        let name = &repos[*i];
        store.save_sync(name, record)?;
        eprintln!(
            "synced {name}: {packages} packages ({:.1} MiB)",
            mib(record.size)
        );
    }
    Ok(())
}

/// `'v`: the verifier's (see [`Verifier`]).
struct Ctx<'a, 'v> {
    workers: &'a Workers,
    store: &'a Store,
    verifier: &'a Verifier<'v>,
}

/// A package file given to `skl arch import`.
enum LocalSource {
    Path(PathBuf),
    Url(Url),
}

/// A package for one of `skl arch import`'s jobs.
enum LocalArchive<'a> {
    /// A file, with its signature in the `.sig` file next to it.
    Path(&'a Path),
    /// A download that an earlier run kept in the store.
    Kept(&'a Url),
    /// A download of this run, verified and kept in the store.
    Fetched(&'a Url, File),
}

/// What a repo offers to a build.
enum RepoSource {
    /// The packages imported with `skl arch import`, sorted by name, newest
    /// version first.
    Local(Vec<Package>),
    /// A configured repo's latest snapshot.
    Synced(Box<Snapshot>),
}

/// A package chosen for a build.
enum Chosen<'a> {
    /// An imported package.
    Local(&'a Package),
    Repo(RepoPackage<'a>),
}

/// A package from a repo's snapshot, downloaded from `url`.
struct RepoPackage<'a> {
    repo: &'a str,
    entry: &'a DbEntry,
    url: Url,
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

/// Read a package argument of `build`: `NAME`, or `REPO/NAME` where `REPO`
/// (a name or an id, see [`repo_id`]) is one of `repos` (ids).
fn parse_target(arg: &str, repos: &[String]) -> Result<Target> {
    let (repo, name) = match arg.rsplit_once('/') {
        Some((repo, name)) => (Some(repo_id(repo)), name),
        None => (None, arg),
    };
    ensure!(
        arch::repo::check_name(name).is_ok() && repo.as_ref().is_none_or(Result::is_ok),
        "{arg:?} is not NAME or REPO/NAME (to build with package files, \
         import them with `skl arch import` and use --repo @local)"
    );
    let repo = repo
        .map(|repo| {
            let repo = repo?;
            repos
                .iter()
                .position(|r| *r == repo)
                .with_context(|| format!("{arg}: repo {repo} is not among --repo"))
        })
        .transpose()?;
    Ok(Target {
        name: name.to_owned(),
        repo,
    })
}

/// What each of `repos` offers: the latest snapshot of a configured repo,
/// or the imported packages for `@local`.
fn load_sources(
    workers: &Workers,
    store: &Store,
    repos: &[String],
    jobs: NonZeroUsize,
) -> Result<Vec<RepoSource>> {
    let sources = par_map(repos, jobs, |repo| {
        if repo == LOCAL {
            load_local(store).map(RepoSource::Local)
        } else {
            Snapshot::load(workers, store, repo).map(|s| RepoSource::Synced(Box::new(s)))
        }
    })?;
    for source in &sources {
        match source {
            RepoSource::Local(pkgs) => {
                eprintln!("using {LOCAL} ({} imported packages)", pkgs.len());
            }
            RepoSource::Synced(s) => eprintln!(
                "using {} as synced at {} ({} packages)",
                s.repo,
                s.record.fetched,
                s.entries.len()
            ),
        }
    }
    Ok(sources)
}

/// The manifests of all packages in `@local`, sorted by name, newest
/// version first, so that the resolver prefers the newest that fits.
fn load_local(store: &Store) -> Result<Vec<Package>> {
    let mut pkgs = Vec::new();
    for hash in store.packages(LOCAL)? {
        if let Some(pkg) = store.load_package(LOCAL, &hash)? {
            pkgs.push(pkg);
        }
    }
    pkgs.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| arch::version::vercmp(&b.version, &a.version))
    });
    Ok(pkgs)
}

/// Resolve `targets` with their dependencies against `sources`, in
/// priority order (see [`resolve`]).
fn choose<'a>(sources: &'a [RepoSource], targets: &[Target]) -> Result<Vec<Chosen<'a>>> {
    let candidates = sources
        .iter()
        .map(|source| match source {
            RepoSource::Local(pkgs) => pkgs
                .iter()
                .map(arch::repo::package_candidate)
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("in repo {LOCAL}")),
            RepoSource::Synced(snapshot) => snapshot.candidates(),
        })
        .collect::<Result<Vec<_>>>()?;
    let candidates: Vec<&[Candidate]> = candidates.iter().map(Vec::as_slice).collect();
    let chosen = resolve::resolve(&candidates, targets, arch::version::vercmp)?;
    eprintln!(
        "resolved {} packages ({} requested)",
        chosen.len(),
        targets.len()
    );
    chosen
        .into_iter()
        .map(|(r, i)| match &sources[r] {
            RepoSource::Local(pkgs) => Ok(Chosen::Local(&pkgs[i])),
            RepoSource::Synced(snapshot) => {
                let entry = &snapshot.entries[i];
                ensure!(
                    entry.arch == arch::repo::ARCH || entry.arch == "any",
                    "package {}/{} is for {}, not {}",
                    snapshot.repo,
                    entry.name,
                    entry.arch,
                    arch::repo::ARCH
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

/// The size of a download in the store, if it is there.
fn kept_size(store: &Store, repo: &str, name: &str) -> Result<Option<u64>> {
    let file = store.open_download(repo, name)?;
    Ok(file.map(|f| f.metadata().map_or(0, |m| m.len())))
}

/// Import the package files `args` (paths or URLs) into `@local`, `jobs`
/// at once, each by its own worker (so a compromised worker can't change
/// another package's manifest). URLs that the store has no download for
/// are downloaded meanwhile, the signature (`.sig`) before the archive.
/// The largest archives that are there are imported first, as they take
/// longest.
fn import_local(ctx: &Ctx, args: &[OsString], jobs: NonZeroUsize) -> Result<()> {
    let sources = args
        .iter()
        .map(|arg| match arg.to_str() {
            Some(s) if Url::is_url(s) => Ok(LocalSource::Url(Url::parse(s)?)),
            _ => Ok(LocalSource::Path(arg.into())),
        })
        .collect::<Result<Vec<_>>>()?;
    let mut ready = Vec::new();
    let mut missing = Vec::new();
    for source in &sources {
        match source {
            LocalSource::Path(path) => {
                let size = path.metadata().map_or(0, |m| m.len());
                ready.push((size, LocalArchive::Path(path)));
            }
            LocalSource::Url(url) => {
                let name = url.file_name();
                // Only verified downloads are kept, the archive first, so
                // an archive whose signature is there was complete.
                let sig = kept_size(ctx.store, LOCAL, &format!("{name}.sig"))?;
                match (sig, kept_size(ctx.store, LOCAL, name)?) {
                    (Some(_), Some(size)) => ready.push((size, LocalArchive::Kept(url))),
                    _ => missing.push(url),
                }
            }
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
                    max_size: signature::MAX_SIGNATURE_SIZE,
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
        jobs,
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
                LocalArchive::Path(path) => {
                    let file =
                        File::open(path).with_context(|| format!("opening {}", path.display()))?;
                    let sig_path = with_suffix(path, ".sig");
                    let sig = File::open(&sig_path)
                        .with_context(|| format!("opening {}", sig_path.display()))?;
                    let sig = read_signature(sig)
                        .with_context(|| format!("reading {}", sig_path.display()))?;
                    ctx.verifier
                        .verify(&sig, &file)
                        .with_context(|| format!("verifying {}", path.display()))?;
                    (file, path.display().to_string())
                }
                LocalArchive::Kept(url) => (open_kept(ctx, url)?, url.to_string()),
                LocalArchive::Fetched(url, file) => (file, url.to_string()),
            };
            let (pkg, new) = import_archive(ctx, file, &what, LOCAL, None)?;
            if !new {
                eprintln!("{} {} was already imported", pkg.name, pkg.version);
            }
            Ok(())
        },
    )?;
    Ok(())
}

/// The manifest of each of `chosen`, in the same order. Packages from
/// repo snapshots are verified, and imported where needed, `jobs` at once,
/// each import by its own worker (so a compromised worker can't change
/// another package's manifest). Those that the store has no download for
/// are downloaded meanwhile, if `fetch` allows, largest first by the size
/// in the repo's database. Of the archives that are there, the largest
/// are imported first, as they take longest.
fn get_packages(
    ctx: &Ctx,
    chosen: &[Chosen],
    fetch: bool,
    jobs: NonZeroUsize,
) -> Result<Vec<Package>> {
    let mut packages: Vec<Option<Package>> = Vec::new();
    let mut kept = Vec::new();
    let mut missing = Vec::new();
    for (i, chosen) in chosen.iter().enumerate() {
        let pkg = match chosen {
            Chosen::Local(pkg) => {
                packages.push(Some((*pkg).clone()));
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
        jobs,
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

/// Load the manifest of a package from a repo's snapshot, importing its
/// archive if needed: `fetched`, which was downloaded and verified just
/// now, or else the download in the store, whose signature is checked
/// first, every time. The archive must have the SHA-256, and the package
/// the name and version, that the repo's database gives.
fn get_repo_package(ctx: &Ctx, pkg: &RepoPackage, fetched: Option<File>) -> Result<Package> {
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
    let (pkg, _) = import_archive(ctx, file, &what, repo, Some(entry))?;
    check_identity(&pkg, entry).with_context(|| format!("checking {what}"))?;
    Ok(pkg)
}

/// Load the manifest of the package in `file`, whose signature was
/// verified, from the store, importing it if needed (the second value
/// tells whether it was). Packages are identified by their repo and the
/// hash of the archive file. With `entry`, the SHA-256 must be the one it
/// gives. The file is the one that was verified (which the verification
/// worker read through its own open file), so the parsed content is the
/// content that was verified and hashed, unless the file is written to
/// meanwhile (see planning/BUGS.md; only the supervisor writes
/// downloads). Concurrent calls for the same archive each import it.
fn import_archive(
    ctx: &Ctx,
    mut file: File,
    what: &str,
    repo: &str,
    entry: Option<&DbEntry>,
) -> Result<(Package, bool)> {
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
    if let Some(pkg) = ctx.store.load_package(repo, &hash)? {
        return Ok((pkg, false));
    }
    file.seek(SeekFrom::Start(0))?;
    let importing = || format!("importing {what}");
    let (pkg, stats) =
        arch::import_in_worker(ctx.workers, ctx.store, file).with_context(importing)?;
    // The metadata must be usable for dependency resolution.
    arch::repo::package_candidate(&pkg).with_context(importing)?;
    if let Some(entry) = entry {
        check_identity(&pkg, entry).with_context(importing)?;
    }
    ctx.store.save_package(repo, &hash, &pkg)?;
    eprintln!(
        "imported {} {}: {} files, {} new objects ({:.1} MiB)",
        pkg.name,
        pkg.version,
        stats.files,
        stats.new_objects,
        mib(stats.new_bytes)
    );
    Ok((pkg, true))
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
    let actual = sha256.finalize();
    let expected = &entry.sha256;
    ensure!(
        hex(&actual).eq_ignore_ascii_case(expected),
        "SHA-256 is {}, but the repo's database says {expected}",
        hex(&actual)
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

/// Where a download for `skl arch import` goes.
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
fn open_kept(ctx: &Ctx, url: &Url) -> Result<File> {
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
    ctx: &Ctx,
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
    eprintln!("downloaded {repo}/{name} ({:.1} MiB)", mib(size));
    Ok(file)
}

/// Read a signature file, which must be at most
/// [`signature::MAX_SIGNATURE_SIZE`] bytes.
fn read_signature(file: File) -> Result<Vec<u8>> {
    let mut sig = Vec::new();
    file.take(signature::MAX_SIGNATURE_SIZE + 1)
        .read_to_end(&mut sig)?;
    if sig.len() as u64 > signature::MAX_SIGNATURE_SIZE {
        bail!("signature file is too large");
    }
    Ok(sig)
}

/// Run `f` with a verifier that checks signatures with the keyring
/// `PREFIX.gpg`, `PREFIX-trusted`, `PREFIX-revoked`, in up to `jobs`
/// workers at once.
fn with_verifier<T>(
    workers: &Workers,
    prefix: Option<&Path>,
    jobs: NonZeroUsize,
    f: impl FnOnce(&Verifier) -> Result<T>,
) -> Result<T> {
    let prefix = prefix.context("no keyring given (--keyring or SKL_KEYRING)")?;
    let loading = || format!("loading keyring {}", prefix.display());
    let open = |suffix| {
        let path = with_suffix(prefix, suffix);
        File::open(&path).with_context(|| format!("opening {}", path.display()))
    };
    let files = (|| -> Result<KeyringFiles> {
        Ok(KeyringFiles {
            certs: open(".gpg")?,
            trusted: open("-trusted")?,
            revoked: open("-revoked")?,
        })
    })()
    .with_context(loading)?;
    verify::with_verifier(workers, files, jobs.get(), f).map_err(|e| match e.is::<KeyringError>() {
        true => e.context(loading()),
        false => e,
    })
}

/// `path` with `suffix` appended to its last component.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = OsString::from(path);
    s.push(suffix);
    s.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_arguments() {
        let repos = ["@arch/core".to_owned(), LOCAL.to_owned()];
        let parse = |s: &str| parse_target(s, &repos).map(|t| (t.repo, t.name));
        assert_eq!(parse("bash").unwrap(), (None, "bash".to_owned()));
        assert_eq!(parse("core/bash").unwrap(), (Some(0), "bash".to_owned()));
        assert_eq!(
            parse("@arch/core/bash").unwrap(),
            (Some(0), "bash".to_owned())
        );
        assert_eq!(parse("@local/bash").unwrap(), (Some(1), "bash".to_owned()));
        assert_eq!(
            parse("@arch/@local/bash").unwrap(),
            (Some(1), "bash".to_owned())
        );
        let e = parse("extra/bash").unwrap_err().to_string();
        assert!(e.contains("not among --repo"), "{e}");
        for bad in [
            "./bash-5.3-1-x86_64.pkg.tar.zst",
            "core/a/b",
            "/abs/path",
            "https://x/a.pkg.tar.zst",
            "",
        ] {
            let e = parse(bad).unwrap_err().to_string();
            assert!(e.contains("skl arch import"), "{e}");
        }
    }

    #[test]
    fn local_packages_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let add = |name: &str, version: &str, depends: &[&str]| {
            let id = format!("{name} {version}");
            let hash = store.add_object(&mut id.as_bytes()).unwrap().hash;
            let pkg = Package {
                name: name.into(),
                version: version.into(),
                depends: depends.iter().map(|d| (*d).to_owned()).collect(),
                provides: vec![],
                conflicts: vec![],
                entries: vec![],
            };
            store.save_package(LOCAL, &hash, &pkg).unwrap();
        };
        add("lib", "1.9-1", &[]);
        add("lib", "1.10-1", &[]);
        add("lib", "2.0-1", &[]);
        add("app", "1-1", &["lib<2"]);
        let sources = [RepoSource::Local(load_local(&store).unwrap())];
        let build = |names: &[&str]| -> Vec<String> {
            let targets: Vec<Target> = names
                .iter()
                .map(|n| parse_target(n, &[LOCAL.to_owned()]).unwrap())
                .collect();
            choose(&sources, &targets)
                .unwrap()
                .iter()
                .map(|c| match c {
                    Chosen::Local(pkg) => format!("{} {}", pkg.name, pkg.version),
                    Chosen::Repo(_) => unreachable!(),
                })
                .collect()
        };
        assert_eq!(build(&["lib"]), ["lib 2.0-1"]);
        assert_eq!(build(&["@local/app"]), ["app 1-1", "lib 1.10-1"]);
    }
}
