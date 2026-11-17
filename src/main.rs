use std::cmp::Reverse;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, sync_channel};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use skladiste::arch;
use skladiste::arch::repo::{DbEntry, Snapshot};
use skladiste::arch::signature::{self, Keyring};
use skladiste::http::{RootCerts, Url};
use skladiste::install;
use skladiste::jobs::{both, default_jobs, par_map, par_map_iter};
use skladiste::manifest::Package;
use skladiste::repo::LOCAL;
use skladiste::resolve::{self, Candidate, Target};
use skladiste::store::{Store, TmpFile, hash_reader};
use skladiste::worker::{self, Downloaded, Request, Sink, Workers};

#[derive(Parser)]
#[command(name = "skl", about = "Content-addressed package manager on btrfs")]
struct Cli {
    /// Store directory (must be on the same btrfs filesystem as images).
    #[arg(long, env = "SKL_STORE")]
    store: Option<PathBuf>,

    /// Arch keyring to verify package signatures with, as the path without
    /// suffix: PREFIX.gpg, PREFIX-trusted and PREFIX-revoked are read.
    /// Needed for importing packages.
    #[arg(long, env = "SKL_KEYRING", value_name = "PREFIX")]
    keyring: Option<PathBuf>,

    /// PEM file of root certificates to check HTTPS servers against,
    /// instead of the Mozilla roots built into skl (e.g. a CA bundle such
    /// as /etc/ssl/certs/ca-certificates.crt).
    #[arg(long, env = "SKL_CA_CERTS", value_name = "FILE")]
    ca_certs: Option<PathBuf>,

    /// Number of packages to import (or repo databases to read) at once,
    /// and of servers to download from at once [default: number of CPUs].
    #[arg(short, long, global = true)]
    jobs: Option<NonZeroUsize>,

    /// Run workers without new namespaces and bubblewrap (INSECURE).
    #[cfg(feature = "insecure")]
    #[arg(long)]
    insecure_no_namespaces: bool,

    /// Run workers without Landlock (INSECURE).
    #[cfg(feature = "insecure")]
    #[arg(long)]
    insecure_no_landlock: bool,

    /// Run workers without seccomp filters (INSECURE).
    #[cfg(feature = "insecure")]
    #[arg(long)]
    insecure_no_seccomp: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Import Arch package files into the store, as the repo `@local`.
    ///
    /// Packages are files or http(s) URLs. The signature is read from the
    /// same path or URL with `.sig` appended. Builds can use the imported
    /// packages with `--repo @local`. Downloads are kept in the store's
    /// `downloads/@local/` directory and not downloaded again for the
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
        /// Download the databases of the repos first, as `skl sync` does.
        #[arg(long)]
        sync: bool,
        /// Download packages that aren't in the store yet. Without this,
        /// a build uses the network only for `--sync`.
        #[arg(long)]
        fetch: bool,
        /// Repo to take packages from (repeatable, in priority order): a
        /// repo added with `skl repo add`, of which the latest sync is
        /// used, or `@local` for the packages imported with `skl import`.
        #[arg(long = "repo", value_name = "REPO", required = true)]
        repos: Vec<String>,
        /// Package names: `NAME`, or `REPO/NAME` to take it from that repo.
        #[arg(required = true, value_name = "PACKAGE")]
        packages: Vec<String>,
    },
    /// Manage repos.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// Run a program in an image, as root, sandboxed with bubblewrap.
    ///
    /// The program sees only the image, read-write, with a read-only /proc,
    /// basic devices in /dev, and empty tmpfs on /tmp and /run. It has no
    /// network and can't see host processes. When skl runs as root, the
    /// program keeps only the capabilities to change files' owners and
    /// permissions; otherwise it runs in a new user namespace that maps
    /// skl's uid and gid to root, and changing owners to other ids fails.
    /// The environment holds only PATH and PWD. skl exits with the
    /// program's exit code.
    Run {
        /// Root directory of the image.
        image: PathBuf,
        /// Program to run, searched in the image's PATH unless it contains
        /// a slash.
        program: OsString,
        /// Arguments of the program.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Download the databases of repos.
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
    /// List repos with the time of their latest sync.
    List,
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|a| a == worker::SUBCOMMAND) {
        return worker::main(args);
    }
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    if let Command::Run {
        image,
        program,
        args,
    } = &cli.command
    {
        let dir = File::open(image).with_context(|| format!("opening {}", image.display()))?;
        ensure!(
            dir.metadata()?.is_dir(),
            "{} is not a directory",
            image.display()
        );
        let status = skladiste::run::run(dir.as_fd(), program, args)?;
        let code = status
            .code()
            .or_else(|| status.signal().map(|s| 128 + s))
            .unwrap_or(1);
        return Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)));
    }
    let mut workers = Workers::new("/proc/self/exe");
    #[cfg(feature = "insecure")]
    {
        if cli.insecure_no_namespaces {
            workers.disable_namespaces();
        }
        if cli.insecure_no_landlock {
            workers.disable_landlock();
        }
        if cli.insecure_no_seccomp {
            workers.disable_seccomp();
        }
    }
    if let Some(path) = &cli.ca_certs {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let roots = RootCerts::from_pem(&pem)
            .with_context(|| format!("loading root certificates from {}", path.display()))?;
        workers.set_root_certs(roots);
    }
    let store = cli
        .store
        .as_deref()
        .context("no store given (--store or SKL_STORE)")?;
    let store = Store::open(store)?;
    let jobs = cli.jobs.unwrap_or_else(default_jobs);
    let keyring = || -> Result<Keyring> {
        let prefix = cli
            .keyring
            .as_deref()
            .context("no keyring given (--keyring or SKL_KEYRING)")?;
        load_keyring(prefix)
    };
    match cli.command {
        Command::Import { packages } => {
            let keyring = keyring()?;
            let ctx = Ctx {
                workers: &workers,
                store: &store,
                keyring: &keyring,
            };
            import_local(&ctx, &packages, jobs)?;
        }
        Command::Build {
            output,
            sync: sync_first,
            fetch,
            repos,
            packages,
        } => {
            if output.symlink_metadata().is_ok() {
                bail!("{} already exists", output.display());
            }
            let targets = packages
                .iter()
                .map(|arg| parse_target(arg, &repos))
                .collect::<Result<Vec<_>>>()?;
            let synced: Vec<String> = repos.iter().filter(|r| *r != LOCAL).cloned().collect();
            if sync_first && !synced.is_empty() {
                sync(&workers, &store, synced, jobs)?;
            }
            let sources = load_sources(&workers, &store, &repos, jobs)?;
            let chosen = choose(&sources, &targets)?;
            let packages = if chosen.iter().any(|c| matches!(c, Chosen::Repo(_))) {
                let keyring = keyring()?;
                let ctx = Ctx {
                    workers: &workers,
                    store: &store,
                    keyring: &keyring,
                };
                get_packages(&ctx, &chosen, fetch, jobs)?
            } else {
                chosen
                    .iter()
                    .filter_map(|c| match c {
                        Chosen::Local(pkg) => Some((*pkg).clone()),
                        Chosen::Repo(_) => None,
                    })
                    .collect()
            };
            let r = install::build(&workers, &store, &packages, &output)?;
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
        Command::Repo {
            command: RepoCommand::Add { name, server, db },
        } => {
            let config = arch::repo::Config::new(&server, db.as_deref().unwrap_or(&name))?;
            store.add_repo(&name, &config)?;
        }
        Command::Repo {
            command: RepoCommand::List,
        } => {
            for name in store.repos()? {
                let config: arch::repo::Config = store.repo_config(&name)?;
                let synced = match store.latest_sync(&name)? {
                    Some(record) => record.fetched,
                    None => "never synced".to_owned(),
                };
                println!("{name}\t{}\t{}\t{synced}", config.db, config.server);
            }
        }
        Command::Sync { repos } => sync(&workers, &store, repos, jobs)?,
        Command::Run { .. } => unreachable!("handled above"),
    }
    Ok(ExitCode::SUCCESS)
}

/// Download the databases of `repos` (all if empty), and record the new
/// versions once all of them were downloaded and read.
fn sync(workers: &Workers, store: &Store, repos: Vec<String>, jobs: NonZeroUsize) -> Result<()> {
    let repos = if repos.is_empty() {
        store.repos()?
    } else {
        repos
    };
    if repos.is_empty() {
        bail!("no repos (add one with `skl repo add`)");
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

/// Downloads that wait for a job, at most; the download stage waits when
/// there are more. Each can keep a file open.
const MAX_WAITING: usize = 64;

/// Download `requests`, and meanwhile run `job` on up to `jobs` threads:
/// on what `downloaded` makes of each finished download (if anything),
/// and on the items in `ready`, in their order. Returns the results of
/// `job` in no particular order.
///
/// Downloads go one after another per server, in the order of `requests`
/// (see [`Workers::download_all`]). `downloaded` is called with the index
/// of the request, on the thread that downloads from its server, so the
/// next download from there waits for it. Finished downloads are taken
/// before items of `ready`, so that the download stage isn't held up.
///
/// Once something fails, no new downloads or jobs start; those under way
/// finish.
fn fetch_and_run<S: Sink, T: Send, R: Send>(
    workers: &Workers,
    jobs: NonZeroUsize,
    ready: Vec<T>,
    requests: Vec<Request<S>>,
    downloaded: impl Fn(usize, S, Downloaded) -> Result<Option<T>> + Sync,
    job: impl Fn(T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    let failed = &AtomicBool::new(false);
    let downloaded = &downloaded;
    let (tx, rx) = sync_channel(MAX_WAITING);
    let feed = Feed {
        downloads: rx,
        ready: ready.into_iter(),
    };
    let (downloads, results) = std::thread::scope(|s| {
        // Owns the sender, so the jobs end when the downloads have.
        let stage = s.spawn(move || {
            workers.download_all(requests, jobs, failed, |i, sink, download| {
                if let Some(item) = downloaded(i, sink, download)? {
                    // Fails only once the jobs have stopped for a failure.
                    let _ = tx.send(item);
                }
                Ok(())
            })
        });
        let results = par_map_iter(feed, jobs, failed, job);
        let downloads = stage
            .join()
            .unwrap_or_else(|p| std::panic::resume_unwind(p));
        (downloads, results)
    });
    Ok(both(downloads, results)?.1)
}

/// What the jobs of [`fetch_and_run`] work on.
struct Feed<T> {
    downloads: Receiver<T>,
    ready: std::vec::IntoIter<T>,
}

impl<T> Iterator for Feed<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if let Ok(item) = self.downloads.try_recv() {
            return Some(item);
        }
        self.ready.next().or_else(|| self.downloads.recv().ok())
    }
}

struct Ctx<'a> {
    workers: &'a Workers,
    store: &'a Store,
    keyring: &'a Keyring,
}

/// A package file given to `skl import`.
enum LocalSource {
    Path(PathBuf),
    Url(Url),
}

/// A package for one of `skl import`'s jobs.
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
    /// The packages imported with `skl import`, sorted by name, newest
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
/// is one of `repos`.
fn parse_target(arg: &str, repos: &[String]) -> Result<Target> {
    let (repo, name) = match arg.split_once('/') {
        Some((repo, name)) => (Some(repo), name),
        None => (None, arg),
    };
    let known = |repo: &str| repo == LOCAL || skladiste::repo::check_name(repo).is_ok();
    ensure!(
        arch::repo::check_name(name).is_ok() && repo.is_none_or(known),
        "{arg:?} is not NAME or REPO/NAME (to build with package files, \
         import them with `skl import` and use --repo {LOCAL})"
    );
    let repo = repo
        .map(|repo| {
            repos
                .iter()
                .position(|r| r == repo)
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
                    let mut file =
                        File::open(path).with_context(|| format!("opening {}", path.display()))?;
                    let sig_path = with_suffix(path, ".sig");
                    let sig = File::open(&sig_path)
                        .with_context(|| format!("opening {}", sig_path.display()))?;
                    let sig = read_signature(sig)
                        .with_context(|| format!("reading {}", sig_path.display()))?;
                    verify(ctx.keyring, &sig, &mut file)
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
            let mut file = ctx
                .store
                .open_download(repo, name)?
                .with_context(|| format!("{repo}/{name} is no longer in the store"))?;
            verify(ctx.keyring, pkg.signature()?, &mut file).with_context(|| {
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
/// gives. The file is read from the same open file as it was verified
/// from, so the parsed content is the content that was verified and
/// hashed, unless the file is written to meanwhile (see planning/BUGS.md;
/// only the supervisor writes downloads). Concurrent calls for the same
/// archive each import it.
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
    let (pkg, stats) = ctx
        .workers
        .import_arch(ctx.store, file)
        .with_context(importing)?;
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

/// Where a download for `skl import` goes.
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
    let (sig, mut file) = (open(&sig_name)?, open(name)?);
    let sig = read_signature(sig).with_context(|| format!("reading downloaded {sig_name}"))?;
    verify(ctx.keyring, &sig, &mut file).with_context(|| {
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
    verify(ctx.keyring, sig, archive.tmp()?.file()).with_context(|| format!("verifying {url}"))?;
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

/// Check `file`'s signature from its start.
fn verify(keyring: &Keyring, sig: &[u8], file: &mut File) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    keyring.verify(sig, &*file)?;
    Ok(())
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Load the keyring `PREFIX.gpg`, `PREFIX-trusted`, `PREFIX-revoked`.
fn load_keyring(prefix: &Path) -> Result<Keyring> {
    let open = |suffix| {
        let path = with_suffix(prefix, suffix);
        File::open(&path)
            .map(BufReader::new)
            .with_context(|| format!("opening {}", path.display()))
    };
    Keyring::load(open(".gpg")?, open("-trusted")?, open("-revoked")?)
        .with_context(|| format!("loading keyring {}", prefix.display()))
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
        let repos = ["core".to_owned(), LOCAL.to_owned()];
        let parse = |s: &str| parse_target(s, &repos).map(|t| (t.repo, t.name));
        assert_eq!(parse("bash").unwrap(), (None, "bash".to_owned()));
        assert_eq!(parse("core/bash").unwrap(), (Some(0), "bash".to_owned()));
        assert_eq!(parse("@local/bash").unwrap(), (Some(1), "bash".to_owned()));
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
            assert!(e.contains("skl import"), "{e}");
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

    #[test]
    fn downloads_come_before_ready_items() {
        let (tx, rx) = sync_channel(4);
        let mut feed = Feed {
            downloads: rx,
            ready: vec![1, 2].into_iter(),
        };
        tx.send(10).unwrap();
        assert_eq!(feed.next(), Some(10));
        assert_eq!(feed.next(), Some(1));
        tx.send(11).unwrap();
        assert_eq!(feed.next(), Some(11));
        assert_eq!(feed.next(), Some(2));
        // Nothing is ready: waits for the downloads, until they end.
        tx.send(12).unwrap();
        drop(tx);
        assert_eq!(feed.next(), Some(12));
        assert_eq!(feed.next(), None);
    }

    #[test]
    fn jobs_without_downloads() {
        // No worker is started without requests.
        let workers = Workers::new("/nonexistent");
        let jobs = NonZeroUsize::new(3).unwrap();
        let run = |fail: Option<u32>| {
            let requests: Vec<Request<Vec<u8>>> = Vec::new();
            fetch_and_run(
                &workers,
                jobs,
                (0..20).collect(),
                requests,
                |_, _, _| Ok(None),
                |n: u32| {
                    ensure!(Some(n) != fail, "job {n} failed");
                    Ok(n * 2)
                },
            )
        };
        let mut results = run(None).unwrap();
        results.sort();
        assert_eq!(results, (0..20).map(|n| n * 2).collect::<Vec<_>>());
        assert_eq!(run(Some(7)).unwrap_err().to_string(), "job 7 failed");
    }
}
