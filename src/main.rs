use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use skladiste::arch;
use skladiste::arch::repo::{DbEntry, Snapshot};
use skladiste::arch::signature::{self, Keyring};
use skladiste::http::{RootCerts, Url};
use skladiste::install;
use skladiste::jobs::{default_jobs, par_map};
use skladiste::manifest::Package;
use skladiste::repo::LOCAL;
use skladiste::resolve::{self, Candidate, Target};
use skladiste::store::{Store, hash_reader};
use skladiste::worker::{self, Workers};

#[derive(Parser)]
#[command(name = "skl", about = "Content-addressed package manager on btrfs")]
struct Cli {
    /// Store directory (must be on the same btrfs filesystem as images).
    #[arg(long, env = "SKL_STORE")]
    store: PathBuf,

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

    /// Number of packages (or repo databases) to download and import at
    /// once [default: number of CPUs].
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
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
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
    let store = Store::open(&cli.store)?;
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
            let packages = if chosen.iter().any(|c| matches!(c, Chosen::Repo { .. })) {
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
                        Chosen::Repo { .. } => None,
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
    }
    Ok(())
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
    let synced = par_map(&configs, jobs, |config| {
        let record = arch::repo::fetch_db(workers, store, config)?;
        let entries = arch::repo::load_db(workers, store, &record)?;
        Ok((record, entries.len()))
    })?;
    for (name, (record, packages)) in repos.iter().zip(&synced) {
        store.save_sync(name, record)?;
        eprintln!(
            "synced {name}: {packages} packages ({:.1} MiB)",
            mib(record.size)
        );
    }
    Ok(())
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
    /// A package from a repo's snapshot, downloaded from `url`.
    Repo {
        repo: &'a str,
        entry: &'a DbEntry,
        url: Url,
    },
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
                Ok(Chosen::Repo {
                    repo: &snapshot.repo,
                    url: snapshot.config.package_url(&entry.filename)?,
                    entry,
                })
            }
        })
        .collect()
}

/// Call `f` on each item, `jobs` at once, starting with the largest
/// `key`; the results are in the order of `items`.
fn par_map_largest_first<T: Sync, K: Ord + Copy + Sync, R: Send>(
    items: &[T],
    jobs: NonZeroUsize,
    key: impl Fn(&T) -> K,
    f: impl Fn(&T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    let mut order: Vec<(usize, K)> = items.iter().map(key).enumerate().collect();
    order.sort_by_key(|&(_, key)| std::cmp::Reverse(key));
    let mut results = par_map(&order, jobs, |&(i, _)| Ok((i, f(&items[i])?)))?;
    results.sort_by_key(|&(i, _)| i);
    Ok(results.into_iter().map(|(_, r)| r).collect())
}

/// The size of a download in the store, if it is there.
fn downloaded(store: &Store, repo: &str, name: &str) -> Option<u64> {
    match store.open_download(repo, name) {
        Ok(Some(f)) => Some(f.metadata().map_or(0, |m| m.len())),
        _ => None,
    }
}

/// Import the package files `args` (paths or URLs) into `@local`, `jobs`
/// at once, each by its own worker (so a compromised worker can't change
/// another package's manifest). Downloads start first, then the largest
/// archives, as they take longest.
fn import_local(ctx: &Ctx, args: &[OsString], jobs: NonZeroUsize) -> Result<()> {
    let sources = args
        .iter()
        .map(|arg| match arg.to_str() {
            Some(s) if Url::is_url(s) => Ok(LocalSource::Url(Url::parse(s)?)),
            _ => Ok(LocalSource::Path(arg.into())),
        })
        .collect::<Result<Vec<_>>>()?;
    let key = |source: &LocalSource| match source {
        LocalSource::Path(p) => (false, p.metadata().map_or(0, |m| m.len())),
        LocalSource::Url(url) => {
            downloaded(ctx.store, LOCAL, url.file_name()).map_or((true, 0), |n| (false, n))
        }
    };
    par_map_largest_first(&sources, jobs, key, |source| {
        let (file, what) = match source {
            LocalSource::Path(path) => {
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
            LocalSource::Url(url) => (fetch(ctx, url)?, url.to_string()),
        };
        let (pkg, new) = import_archive(ctx, file, &what, LOCAL, None)?;
        if !new {
            eprintln!("{} {} was already imported", pkg.name, pkg.version);
        }
        Ok(())
    })?;
    Ok(())
}

/// The manifest of each of `chosen`, in the same order. Packages from
/// repo snapshots are verified, and downloaded (if `fetch`) and imported
/// where needed (see [`get_repo_package`]), `jobs` at once, each import by
/// its own worker (so a compromised worker can't change another package's
/// manifest). Downloads start first, largest first by the size in the
/// repo's database, then the largest archives, as they take longest.
fn get_packages(
    ctx: &Ctx,
    chosen: &[Chosen],
    fetch: bool,
    jobs: NonZeroUsize,
) -> Result<Vec<Package>> {
    let key = |chosen: &Chosen| match chosen {
        Chosen::Local(_) => (false, 0),
        Chosen::Repo { repo, entry, .. } => {
            downloaded(ctx.store, repo, &entry.filename).map_or((true, entry.csize), |n| (false, n))
        }
    };
    par_map_largest_first(chosen, jobs, key, |chosen| match chosen {
        Chosen::Local(pkg) => Ok((*pkg).clone()),
        Chosen::Repo { repo, entry, url } => get_repo_package(ctx, repo, entry, url, fetch),
    })
}

/// Load the manifest of a package from a repo's snapshot, importing the
/// archive if needed, and downloading it first if it isn't in the store
/// and `fetch` allows. The signature is checked first, every time, also
/// for earlier downloads. The archive must have the SHA-256, and the
/// package the name and version, that the repo's database gives.
fn get_repo_package(
    ctx: &Ctx,
    repo: &str,
    entry: &DbEntry,
    url: &Url,
    fetch: bool,
) -> Result<Package> {
    let file = fetch_from_repo(ctx, repo, entry, url, fetch)?;
    let what = format!("{repo}/{}", entry.filename);
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

/// Writes through, hashing with SHA-256.
struct Sha256Writer<W> {
    inner: W,
    sha256: Sha256,
}

impl<W: Write> Write for Sha256Writer<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sha256.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The verified archive from `url`: downloaded earlier, or now. Only
/// verified downloads are kept, the archive first, so an archive whose
/// signature is there was complete.
fn fetch(ctx: &Ctx, url: &Url) -> Result<File> {
    let name = url.file_name();
    let sig_name = format!("{name}.sig");
    let store = ctx.store;
    if let Some(sig) = store.open_download(LOCAL, &sig_name)?
        && let Some(mut file) = store.open_download(LOCAL, name)?
    {
        let sig = read_signature(sig).with_context(|| format!("reading downloaded {sig_name}"))?;
        verify(ctx.keyring, &sig, &mut file).with_context(|| {
            format!("verifying {name}, downloaded earlier (delete downloads/{LOCAL}/{name} in the store to download it again)")
        })?;
        return Ok(file);
    }
    let sig_url = url.with_suffix(".sig");
    let mut sig = Vec::new();
    ctx.workers
        .download(&sig_url, &mut sig, signature::MAX_SIGNATURE_SIZE)
        .with_context(|| format!("downloading {sig_url}"))?;
    download_package(ctx, LOCAL, name, url, &sig, None)
}

/// The verified archive of a package in a repo: downloaded earlier, or
/// now if `fetch` allows. The signature, size and SHA-256 come from the
/// repo's database.
fn fetch_from_repo(ctx: &Ctx, repo: &str, entry: &DbEntry, url: &Url, fetch: bool) -> Result<File> {
    let name = &entry.filename;
    let sig = entry
        .pgpsig
        .as_deref()
        .with_context(|| format!("{repo}/{name} has no signature in the repo's database"))?;
    if let Some(mut file) = ctx.store.open_download(repo, name)? {
        verify(ctx.keyring, sig, &mut file).with_context(|| {
            format!("verifying {name}, downloaded earlier (delete downloads/{repo}/{name} in the store to download it again)")
        })?;
        return Ok(file);
    }
    ensure!(
        fetch,
        "{repo}/{name} is not in the store (use --fetch to download packages)"
    );
    download_package(ctx, repo, name, url, sig, Some(entry))
}

/// Download `url` and keep it as `name` in `repo`'s downloads if `sig`
/// verifies, with the signature next to it (`.sig`), written after the
/// archive. With `entry`, the size and SHA-256 must be those it gives.
fn download_package(
    ctx: &Ctx,
    repo: &str,
    name: &str,
    url: &Url,
    sig: &[u8],
    entry: Option<&DbEntry>,
) -> Result<File> {
    let store = ctx.store;
    let mut tmp = store.tmp_file()?;
    let max_size = entry.map_or(u64::MAX, |e| e.csize);
    let (size, sha256) = {
        let mut w = Sha256Writer {
            inner: BufWriter::with_capacity(64 << 10, tmp.file()),
            sha256: Sha256::new(),
        };
        let size = ctx
            .workers
            .download(url, &mut w, max_size)
            .and_then(|d| Ok(w.flush().map(|()| d.size)?))
            .with_context(|| format!("downloading {url}"))?;
        (size, w.sha256)
    };
    if let Some(entry) = entry {
        ensure!(
            size == entry.csize,
            "{url} has {size} bytes, but the repo's database says {}",
            entry.csize
        );
        check_sha256(sha256, entry).with_context(|| format!("downloading {url}"))?;
    }
    verify(ctx.keyring, sig, tmp.file()).with_context(|| format!("verifying {url}"))?;
    let file = tmp.save_download(repo, name)?;
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
                    Chosen::Repo { .. } => unreachable!(),
                })
                .collect()
        };
        assert_eq!(build(&["lib"]), ["lib 2.0-1"]);
        assert_eq!(build(&["@local/app"]), ["app 1-1", "lib 1.10-1"]);
    }

    #[test]
    fn largest_first() {
        let order = std::sync::Mutex::new(Vec::new());
        let items = [2, 9, 4];
        let out = par_map_largest_first(
            &items,
            NonZeroUsize::MIN,
            |&n| n,
            |&n| {
                order.lock().unwrap().push(n);
                Ok(n * 10)
            },
        )
        .unwrap();
        assert_eq!(out, [20, 90, 40]);
        assert_eq!(*order.lock().unwrap(), [9, 4, 2]);
    }
}
